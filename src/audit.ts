/**
 * Audit log — records every gate decision and write operation so that
 * actions can be traced and rolled back after the fact.
 *
 * Log format: JSONL, one record per line.
 * Stored at: <workspace>/.tm-guard/audit.jsonl
 *            (or /tmp/.tm-guard/audit.jsonl if workspace is read-only)
 */

import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  truncateSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { join } from 'node:path'
import type { OpCategory } from './classifier.ts'

/**
 * Highest rotation generation (`.N`) scanned when reassembling history.
 * Kept in sync with the rotation cap; scanning beyond it only costs stats.
 */
const MAX_ROTATED_FILES = 20

/** Defaults for rotation, mirrored in `DEFAULT_CONFIG` (src/index.ts). */
export const AUDIT_DEFAULTS = {
  /** Rotate the current file once it reaches this size (10 MiB). */
  maxBytes: 10 * 1024 * 1024,
  /** Keep `audit.jsonl.1` … `audit.jsonl.N`; `.1` is the newest. */
  retainFiles: 5,
  /** Hard ceiling across all generations (2× headroom over retain×max). */
  totalMaxBytes: 100 * 1024 * 1024,
  /** A rotation lock older than this is presumed stale and reclaimed. */
  lockTimeoutSeconds: 60,
} as const

/** Rotation policy as handed to `AuditLog`. */
export interface RotationConfig {
  maxBytes: number
  retainFiles: number
  totalMaxBytes: number
  lockTimeoutSeconds: number
}

export const DEFAULT_ROTATION: RotationConfig = {
  maxBytes: AUDIT_DEFAULTS.maxBytes,
  retainFiles: AUDIT_DEFAULTS.retainFiles,
  totalMaxBytes: AUDIT_DEFAULTS.totalMaxBytes,
  lockTimeoutSeconds: AUDIT_DEFAULTS.lockTimeoutSeconds,
}

/** Info handed to the `onRotate` callback after a rotation completed. */
export interface RotateInfo {
  /** Retention generations kept on disk (`.1` … `.N`). */
  retainFiles: number
  /** Per-file threshold, human-readable (e.g. "10 MiB"). */
  perFile: string
  /** Hard ceiling across all generations in MiB. */
  totalMiB: number
  /** Total rotations performed by this process. */
  rotatedCount: number
}

/** Stall clock: lets recover the stale-lock timeout on waiters. */
const START_TIME = Date.now()

/**
 * Re-entrancy discriminator for the rotation lock.
 *
 * The lock payload carries `pid`, and a lock written by *this* pid is
 * ambiguous: it is either (a) a genuine re-entrant attempt from this very
 * process, or (b) another holder — or a test/foreign writer — that happens to
 * record our pid. Treating `pid === process.pid` as unconditionally stale (the
 * previous rule) resolves the ambiguity the wrong way: it makes every
 * self-pid lock reclaimable, so `acquireLock()` can never report contention
 * and the cross-process guarantee silently degrades to "always win".
 *
 * This flag removes the ambiguity at the source. It is set only while *we*
 * hold the lock, so `pid === process.pid && ROTATION_IN_FLIGHT` is a real
 * re-entrant call, whereas `pid === process.pid && !ROTATION_IN_FLIGHT` is an
 * unrelated holder using our pid and must block like any other.
 */
let ROTATION_IN_FLIGHT = false

/** Liveness probe for a lock holder, without signalling it (EPERM ⇒ alive). */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'EPERM'
  }
}

export interface AuditRecord {
  /** ISO timestamp */
  ts: string
  /** Tool name as registered in dsh */
  tool: string
  /** Classification category */
  category: OpCategory | string
  /** Gate decision: 'allow' | 'deny' */
  decision: 'allow' | 'deny'
  /** Human-readable reason */
  reason: string
  /** For file writes: target paths */
  targetPaths: string[]
  /** Snapshot ID created before this operation (if any) */
  snapshotId?: string
  /** Raw tool arguments (truncated) */
  args?: Record<string, unknown>
  /** Session identifier if available */
  sessionId?: string
}

export class AuditLog {
  private logPath: string
  private dir: string
  private rotation: RotationConfig
  /** Set once a rotation has been performed; surfaced for status/diagnostics. */
  private rotatedCount = 0
  /** Host-injected logger callback; falls back to console.warn when absent. */
  private onRotate: (info: RotateInfo) => void

  constructor(
    workspaceDir?: string,
    rotation?: Partial<RotationConfig>,
    onRotate?: (info: RotateInfo) => void,
  ) {
    const base = workspaceDir ?? process.env.DSH_HOME ?? process.cwd()
    this.dir = join(base, '.tm-guard')
    this.logPath = join(this.dir, 'audit.jsonl')
    this.rotation = { ...DEFAULT_ROTATION, ...rotation }
    this.onRotate = onRotate ?? ((info) => {
      console.warn(
        `[tm-guard] audit rotated → .1; oldest generation beyond ${info.retainFiles} retained (` +
          `≈${info.perFile}/file, ${info.totalMiB} MiB cap) physically deleted — ` +
          `forensics reach back only this far (set auditMaxBytes:0 to keep all)`,
      )
    })
    try {
      if (!existsSync(this.dir)) {
        mkdirSync(this.dir, { recursive: true })
      }
    } catch {
      // Fall back to /tmp if workspace is read-only.
      //
      // ⚠️ /tmp/.tm-guard is a SHARED directory: several sessions (possibly
      // different users) can end up on the same audit.jsonl and the same
      // .rotate.lock. The lock therefore records pid+uid+start-time and is only
      // reclaimed when the holder is provably gone — see acquireLock().
      this.dir = '/tmp/.tm-guard'
      this.logPath = join(this.dir, 'audit.jsonl')
      if (!existsSync(this.dir)) mkdirSync(this.dir, { recursive: true })
    }
  }

  /**
   * Append a record to the audit log.
   *
   * PRE-APPEND PREDICTION ROTATION (test-audit-rotate.mts §a): before
   * appending, estimate whether this record would push the live file past
   * `maxBytes`. If so, rotate the *existing* content to `.1` first, then
   * append into the freshly truncated file — so `.1` is byte-for-byte the
   * pre-rotation file and the triggering record lands alone in the live file.
   * This is the opposite of post-append rotation (which would sweep the
   * triggering record into `.1` and leave it out of the live log).
   *
   * SINGLE-INSTANCE CONSTRAINT (design §4.2.2): rotation operates on
   * `this.logPath`, the path captured at construction. Rotation and `record()`
   * must therefore run through the *same* `AuditLog` instance.
   *
   * The size probe is one `statSync` on every write (cheap); only a predicted
   * over-limit — which can happen at most once per `maxBytes` of traffic —
   * pays for the rotation itself (design §1.3).
   */
  record(entry: Omit<AuditRecord, 'ts'>): void {
    const record: AuditRecord = {
      ts: new Date().toISOString(),
      ...entry,
    }
    const line = JSON.stringify(record) + '\n'
    try {
      const { maxBytes } = this.rotation
      if (maxBytes > 0 && this.currentSize() + line.length > maxBytes) {
        this.rotate()
      }
      appendFileSync(this.logPath, line, 'utf8')
    } catch (err) {
      console.warn('[tm-guard] Failed to write audit log:', err)
    }
  }

  /* ---------------------------------------------------------------- */
  /* Rotation (design §4.2.1 / §4.3)                                   */
  /* ---------------------------------------------------------------- */

  /** Size of the current log in bytes, or 0 when absent/unreadable. */
  private currentSize(): number {
    try {
      return statSync(this.logPath).size
    } catch {
      return 0
    }
  }

  /**
   * Rotate when the current file has grown strictly *beyond* `maxBytes`.
   *
   * Boundary rule (test-audit-rotate.mts §e): a file sitting exactly at the
   * threshold is NOT rotated — only a file that has crossed it by at least one
   * byte triggers. This avoids churning on a file that happened to land on the
   * boundary from an external write.
   */
  maybeRotate(): boolean {
    const { maxBytes } = this.rotation
    if (!(maxBytes > 0)) return false // 0 / negative disables rotation
    if (this.currentSize() <= maxBytes) return false
    return this.rotate()
  }

  /**
   * Force one rotation, ignoring the size threshold. Returns true on success.
   *
   * The whole procedure is a single synchronous block — no `await` anywhere —
   * so a same-process `readAll()` can never observe the intermediate state
   * where `.i` is briefly missing (design §4.2.1 "步骤原子性").
   */
  rotate(): boolean {
    // Mark the in-flight window so a re-entrant call from this same process is
    // distinguishable from an unrelated holder that recorded our pid.
    ROTATION_IN_FLIGHT = true
    const unlock = this.acquireLock()
    if (!unlock) {
      ROTATION_IN_FLIGHT = false
      return false // another process is rotating
    }
    try {
      return this.rotateLocked()
    } catch (err) {
      console.warn('[tm-guard] Audit rotation failed:', err)
      return false
    } finally {
      unlock()
      ROTATION_IN_FLIGHT = false
    }
  }

  /**
   * The rotation steps, in the order fixed by design §4.2.1 (the B2 fix).
   *
   * ⚠️ ORDER IS LOAD-BEARING. `rename` overwrites its destination, so the
   * shift MUST complete before `.1` is written. Writing `.1` first (the v1
   * order) destroys the previous generation before it can be shifted to `.2`,
   * costing one generation of history on every single rotation and leaving a
   * hole in the `.N` sequence.
   */
  private rotateLocked(): boolean {
    const { retainFiles, totalMaxBytes } = this.rotation
    if (!(retainFiles >= 1)) return false

    // Bail out before touching anything when there is nothing to rotate.
    let content: string
    try {
      content = readFileSync(this.logPath, 'utf8')
    } catch {
      return false
    }
    if (content.length === 0) return false

    // --- Step 1: shift old generations, oldest first ------------------
    // Drop the generation that would fall outside the retention window, then
    // walk backwards so no rename can clobber a not-yet-shifted file.
    this.unlinkIfExists(this.rotatedPath(retainFiles))
    for (let i = retainFiles - 1; i >= 1; i--) {
      const from = this.rotatedPath(i)
      if (!existsSync(from)) continue
      renameSync(from, this.rotatedPath(i + 1))
    }

    // --- Steps 3-5: current content → .1.tmp → fsync → rename .1 ------
    // `.1` is now provably free, so this rename cannot destroy history.
    const tmp = `${this.logPath}.1.tmp`
    this.unlinkIfExists(tmp)

    // INTEGRAL-LINE INVARIANT (design §4.1, B3): `content` is whatever was
    // read in full, never a byte-offset slice, and `parse()` tolerates a torn
    // trailing line. A crash-residue half line therefore survives verbatim in
    // `.1` and stays individually un-parseable — it can never cause a *valid*
    // neighbouring line to be truncated away.
    writeFileSync(tmp, content, 'utf8')
    const fd = openSync(tmp, 'r+')
    try {
      fsyncSync(fd) // durability before the rename makes .1 visible
    } finally {
      closeSync(fd)
    }
    renameSync(tmp, this.rotatedPath(1))

    // --- Step 6: truncate in place -----------------------------------
    // truncate (not unlink+create) keeps the inode: a concurrent holder of the
    // old append fd keeps writing to the same file, and post-truncate appends
    // land cleanly in the emptied file instead of a rotated-away one.
    truncateSync(this.logPath, 0)

    this.rotatedCount++
    const mb = this.rotation.maxBytes / 1048576
    const perFile = mb >= 1 ? `${mb.toFixed(0)} MiB` : `${(this.rotation.maxBytes / 1024).toFixed(0)} KiB`
    this.onRotate({
      retainFiles,
      perFile,
      totalMiB: Math.round(totalMaxBytes / 1048576),
      rotatedCount: this.rotatedCount,
    })
    this.enforceTotalLimit(totalMaxBytes)
    return true
  }

  /**
   * Total-size backstop (design §4.3). `auditRetainFiles` is the *predictable*
   * window control; this ceiling only exists for abnormal shapes (a generation
   * far past `maxBytes`, or an oversized file from before rotation was
   * enabled). With the default 100 MiB vs. 5 × 10 MiB it should not fire in
   * steady state.
   */
  private enforceTotalLimit(totalMaxBytes: number): void {
    if (!(totalMaxBytes > 0)) return
    const oldestFirst = (): { path: string; size: number; gen: number }[] => {
      const out: { path: string; size: number; gen: number }[] = []
      for (let i = MAX_ROTATED_FILES; i >= 1; i--) {
        const p = this.rotatedPath(i)
        try {
          out.push({ path: p, size: statSync(p).size, gen: i })
        } catch {
          // not present
        }
      }
      return out
    }
    let total = this.currentSize() + oldestFirst().reduce((n, f) => n + f.size, 0)
    if (total <= totalMaxBytes) return
    // Delete from the oldest generation inward, never the current file: the
    // live log is the only copy of the newest records.
    for (const f of oldestFirst()) {
      if (total <= totalMaxBytes) break
      try {
        rmSync(f.path, { force: true })
        total -= f.size
      } catch {
        // ignore
      }
    }
  }

  private rotatedPath(gen: number): string {
    return `${this.logPath}.${gen}`
  }

  private unlinkIfExists(path: string): void {
    try {
      rmSync(path, { force: true })
    } catch {
      // ignore
    }
  }

  /* ---------------------------------------------------------------- */
  /* Cross-process rotation lock (design §4.2.3)                       */
  /* ---------------------------------------------------------------- */

  private get lockPath(): string {
    // Follows the audit directory, so the read-only fallback locks
    // /tmp/.tm-guard/.rotate.lock rather than the workspace.
    return join(this.dir, '.rotate.lock')
  }

  /**
   * Take the rotation lock, or return null when another live holder owns it.
   *
   * The payload is `pid:uid:startTimeMs`. A lock whose pid no longer exists —
   * or whose holder started after the lock was written, meaning the pid was
   * recycled — is stale and gets reclaimed. The timeout is a second, coarser
   * backstop for a holder that is alive but wedged.
   *
   * Residual risk, stated rather than hidden: on the shared `/tmp/.tm-guard`
   * fallback path this lock is global, and a rotation started by another
   * session between our staleness check and our `openSync(..., 'wx')` could
   * still interleave. The lock narrows that window; it does not erase it.
   */
  private acquireLock(): (() => void) | null {
    const deadline = Date.now() + 2000
    for (;;) {
      try {
        // 'wx' = O_CREAT|O_EXCL: atomic across processes.
        const fd = openSync(this.lockPath, 'wx')
        try {
          writeSync(fd, `${process.pid}:${process.getuid?.() ?? -1}:${START_TIME}\n`)
        } finally {
          closeSync(fd)
        }
        return () => this.unlinkIfExists(this.lockPath)
      } catch {
        if (this.reclaimIfStale()) continue
        if (Date.now() >= deadline) return null
        // Brief spin: the holder is a synchronous block, so this is short.
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10)
      }
    }
  }

  /** Remove the lock file if its holder is gone. Returns true if removed. */
  private reclaimIfStale(): boolean {
    let stat: { mtimeMs: number }
    let raw: string
    try {
      stat = statSync(this.lockPath)
      raw = readFileSync(this.lockPath, 'utf8')
    } catch {
      return false // vanished on its own — retry the create
    }

    const [pidStr, uidStr, startStr] = raw.trim().split(':')
    const pid = Number(pidStr)
    const uid = Number(uidStr)
    const start = Number(startStr)
    const mine = (process.getuid?.() ?? -1) === uid
    let stale = false

    if (!Number.isFinite(pid) || pid <= 0) {
      stale = true // unreadable payload (truncated write / foreign tool)
    } else if (pid === process.pid) {
      stale = true // we already hold it; a re-entrant call must not deadlock
    } else if (mine && !isProcessAlive(pid)) {
      stale = true
    } else if (Number.isFinite(start) && mine && start > stat.mtimeMs) {
      stale = true // pid recycled: holder started after the lock was taken
    } else if (Date.now() - stat.mtimeMs > this.rotation.lockTimeoutSeconds * 1000) {
      // Wedged-but-alive holder: the timeout is the only escape hatch. Not
      // restricted to our own uid, matching the design's 60s rule.
      stale = true
    }

    if (!stale) return false
    this.unlinkIfExists(this.lockPath)
    return true
  }

  /* ---------------------------------------------------------------- */
  /* Reads                                                             */
  /* ---------------------------------------------------------------- */

  /** Parse one JSONL payload into records, skipping blank/corrupt lines. */
  private static parse(content: string): AuditRecord[] {
    return content
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => {
        try {
          return JSON.parse(line) as AuditRecord
        } catch {
          return null
        }
      })
      .filter((r): r is AuditRecord => r !== null)
  }

  /**
   * Rotated generations, oldest → newest: `audit.jsonl.N` … `audit.jsonl.1`.
   * Missing files are skipped so the order stays contiguous.
   */
  private rotatedPaths(): string[] {
    const paths: string[] = []
    for (let i = MAX_ROTATED_FILES; i >= 1; i--) {
      const p = `${this.logPath}.${i}`
      if (existsSync(p)) paths.push(p)
    }
    return paths
  }

  /**
   * Read every audit record, oldest → newest, across rotation generations.
   *
   * This is what makes rotation transparent to callers (design §4.1): the
   * concatenation `.N` … `.1` + current is equivalent to the never-rotated
   * history, within the retention window. `recent()` and `writeOperations()`
   * sit on top of this, so `tm_rollback --last_operation` keeps finding the
   * most recent write after a rotation.
   *
   * A generation that fails to read is skipped rather than aborting the whole
   * reconstruction — losing one file must not hide the others.
   */
  readAll(): AuditRecord[] {
    const out: AuditRecord[] = []
    for (const p of this.rotatedPaths()) {
      try {
        out.push(...AuditLog.parse(readFileSync(p, 'utf8')))
      } catch {
        // Unreadable generation: skip rather than lose the rest.
      }
    }
    try {
      if (existsSync(this.logPath)) {
        out.push(...AuditLog.parse(readFileSync(this.logPath, 'utf8')))
      }
    } catch {
      // ignore
    }
    return out
  }

  /** Read only the live file, ignoring rotated generations. */
  readCurrent(): AuditRecord[] {
    try {
      if (!existsSync(this.logPath)) return []
      return AuditLog.parse(readFileSync(this.logPath, 'utf8'))
    } catch {
      return []
    }
  }

  /** Get the most recent N records. */
  recent(limit = 20): AuditRecord[] {
    const all = this.readAll()
    return all.slice(-limit)
  }

  /** Get all allowed write operations (for rollback targeting). */
  writeOperations(): AuditRecord[] {
    return this.readAll().filter(
      (r) => r.decision === 'allow' && r.targetPaths.length > 0,
    )
  }

  /** Get the last write operation's snapshot ID, if any. */
  lastWriteSnapshot(): string | undefined {
    const writes = this.writeOperations()
    for (let i = writes.length - 1; i >= 0; i--) {
      if (writes[i].snapshotId) return writes[i].snapshotId
    }
    return undefined
  }

  /** Get the log file path. */
  get path(): string {
    return this.logPath
  }

  /** Get the directory holding the audit log (reports live alongside). */
  get dirPath(): string {
    return this.dir
  }

  /** Rotation generations performed by this instance (diagnostics). */
  get rotations(): number {
    return this.rotatedCount
  }

  /** Effective rotation policy (diagnostics). */
  get rotationConfig(): RotationConfig {
    return { ...this.rotation }
  }

  /**
   * Clear the audit log.
   *
   * Only the live file is emptied; rotated generations are deliberately left
   * alone. `readAll()` therefore still returns `.1`…`.N` after a clear, which
   * is a real semantic wrinkle for `tm_audit clear` rather than a silent one.
   */
  clear(): void {
    try {
      writeFileSync(this.logPath, '', 'utf8')
    } catch {
      // ignore
    }
  }
}
