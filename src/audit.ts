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

  constructor(workspaceDir?: string) {
    const base = workspaceDir ?? process.env.DSH_HOME ?? process.cwd()
    this.dir = join(base, '.tm-guard')
    this.logPath = join(this.dir, 'audit.jsonl')
    try {
      if (!existsSync(this.dir)) {
        mkdirSync(this.dir, { recursive: true })
      }
    } catch {
      // Fall back to /tmp if workspace is read-only
      this.dir = '/tmp/.tm-guard'
      this.logPath = join(this.dir, 'audit.jsonl')
      if (!existsSync(this.dir)) mkdirSync(this.dir, { recursive: true })
    }
  }

  /** Append a record to the audit log. */
  record(entry: Omit<AuditRecord, 'ts'>): void {
    const record: AuditRecord = {
      ts: new Date().toISOString(),
      ...entry,
    }
    try {
      appendFileSync(this.logPath, JSON.stringify(record) + '\n', 'utf8')
    } catch (err) {
      console.warn('[tm-guard] Failed to write audit log:', err)
    }
  }

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
   * On-disk order in the *current* file is preserved. Rotated generations are
   * prepended, so the result is chronological as long as rotation keeps
   * generations ordered. Callers that only care about the current file's raw
   * count (e.g. tm_status) keep using `readAll()`; this method exists so that
   * rotation does not silently discard history.
   */
  readAllGenerations(): AuditRecord[] {
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

  /** Read all audit records from the current file. */
  readAll(): AuditRecord[] {
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

  /** Clear the audit log. */
  clear(): void {
    try {
      writeFileSync(this.logPath, '', 'utf8')
    } catch {
      // ignore
    }
  }
}
