/**
 * tmutil wrapper — macOS Time Machine local snapshot management.
 *
 * All commands shell out to `/usr/bin/tmutil`.  Local APFS snapshots are
 * created with `tmutil localsnapshot` (no sudo required on normal user
 * volumes) and listed with `tmutil listlocalsnapshots`.
 */

import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const TMUTIL = '/usr/bin/tmutil'

// `tmutil destinationinfo` prints "Name : <x>" / "ID   : <x>" (colon) on
// modern macOS; older builds used "Name = <x>". Accept both.
const DEST_CONFIGURED_RE = /^\s*(Name|ID)\s*[:=]/m

export interface SnapshotInfo {
  /** Full snapshot name, e.g. com.apple.TimeMachine.2026-09-06-120000.local */
  name: string
  /** Parsed date string, e.g. 2026-09-06-120000 */
  date: string
  /** JS Date when the snapshot was created */
  createdAt: Date
}

export interface TmStatus {
  /** Whether a Time Machine destination is configured */
  destinationConfigured: boolean
  /** Raw destinationinfo output (truncated) */
  raw: string
  /** Whether local snapshots exist on the root volume */
  hasLocalSnapshots: boolean
  /** Count of local snapshots */
  snapshotCount: number
}

/* ------------------------------------------------------------------ */
/* Low-level helpers                                                   */
/* ------------------------------------------------------------------ */

async function run(args: string[]): Promise<string> {
  const { stdout } = await execFileAsync(TMUTIL, args, {
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  })
  return stdout.trim()
}

function parseSnapshotName(line: string): SnapshotInfo | null {
  const trimmed = line.trim()
  if (!trimmed) return null
  // Expected: com.apple.TimeMachine.2026-09-06-120000.local
  // Other lines (e.g. the "Snapshots for disk /:" header) are ignored.
  const m = trimmed.match(/^com\.apple\.TimeMachine\.(.+)\.local$/)
  if (!m) return null
  const date = m[1]
  // date format: YYYY-MM-DD-HHMMSS
  const dm = date.match(/^(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})$/)
  const createdAt = dm
    ? new Date(
        Number(dm[1]),
        Number(dm[2]) - 1,
        Number(dm[3]),
        Number(dm[4]),
        Number(dm[5]),
        Number(dm[6]),
      )
    : new Date(0)
  return { name: trimmed, date, createdAt }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/** Create a new local APFS snapshot. Returns the snapshot date string. */
export async function createSnapshot(): Promise<string> {
  const out = await run(['localsnapshot'])
  // Output looks like: "Created local snapshot with date: 2026-09-06-120000"
  const m = out.match(/(\d{4}-\d{2}-\d{2}-\d{6})/)
  return m ? m[1] : out
}

/** List all local snapshots on the given volume (default: /). */
export async function listSnapshots(
  volume = '/',
): Promise<SnapshotInfo[]> {
  const out = await run(['listlocalsnapshots', volume])
  return out
    .split('\n')
    .map(parseSnapshotName)
    .filter((s): s is SnapshotInfo => s !== null)
    .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
}

/** Get the most recent local snapshot, or null if none exist. */
export async function latestSnapshot(
  volume = '/',
): Promise<SnapshotInfo | null> {
  const snaps = await listSnapshots(volume)
  return snaps.length > 0 ? snaps[snaps.length - 1] : null
}

/**
 * Check whether a path is excluded from Time Machine backups.
 * Returns true if the path IS excluded (i.e. NOT protected).
 */
export async function isPathExcluded(path: string): Promise<boolean> {
  try {
    const out = await run(['isexcluded', path])
    // Output: "[Excluded] /path"  or  "[Included] /path"  or  "[Unset] /path"
    if (out.startsWith('[Excluded]')) return true
    return false
  } catch {
    // If tmutil fails, conservatively treat as excluded
    return true
  }
}

/**
 * Check whether a path is on a volume that Time Machine protects.
 * A path is considered protected when:
 *   1. It is not explicitly excluded from TM
 *   2. It resides under one of the allowed protected path prefixes
 */
export async function isPathProtected(
  path: string,
  protectedPrefixes: string[],
): Promise<boolean> {
  const normalized = path.startsWith('~')
    ? path.replace('~', process.env.HOME ?? '')
    : path
  const absolute = normalized.startsWith('/')
    ? normalized
    : `${process.cwd()}/${normalized}`

  // Must be under a protected prefix (directory-boundary match, so that
  // prefix "/Users/you/work" does not also cover "/Users/you/work-evil").
  const underPrefix = protectedPrefixes.some((p) => {
    const pref = p.replace(/\/+$/, '')
    return absolute === pref || absolute.startsWith(pref + '/')
  })
  if (!underPrefix) return false

  // Must not be excluded from Time Machine
  return !(await isPathExcluded(absolute))
}

/** Get Time Machine configuration status. */
export async function getTmStatus(): Promise<TmStatus> {
  let destinationConfigured = false
  let raw = ''
  try {
    raw = await run(['destinationinfo'])
    destinationConfigured = DEST_CONFIGURED_RE.test(raw)
  } catch {
    raw = 'Time Machine destination not configured or unavailable.'
  }

  let snapshots: SnapshotInfo[] = []
  try {
    snapshots = await listSnapshots('/')
  } catch {
    // ignore
  }

  return {
    destinationConfigured,
    raw: raw.slice(0, 500),
    hasLocalSnapshots: snapshots.length > 0,
    snapshotCount: snapshots.length,
  }
}

/* ------------------------------------------------------------------ */
/* Backup control — trigger a backup to the TM disk (SD) + progress    */
/* ------------------------------------------------------------------ */

export interface BackupStatus {
  /** Whether a backup is currently running */
  running: boolean
  /** Progress 0..100 when running; -1 when idle/unknown */
  percent: number
  /** Phase/state string reported by backupd (e.g. "Copying"), if any */
  phase?: string
  /** Raw `tmutil status` output */
  raw: string
}

/** Parse the NeXTSTEP-plist output of `tmutil status`. */
export function parseBackupStatus(raw: string): BackupStatus {
  const get = (key: string): string | undefined => {
    const m = raw.match(new RegExp(`\\b${key}\\s*=\\s*"?([^";]*)"?\\s*;`))
    return m ? m[1].trim() : undefined
  }
  const running = get('Running') === '1'
  let percent = -1
  const pctRaw = get('Percent')
  if (pctRaw !== undefined) {
    const n = Number(pctRaw)
    if (!Number.isNaN(n) && n >= 0) {
      // backupd reports a 0..1 fraction; tolerate a 0..100 value too.
      percent = n <= 1 ? Math.round(n * 100) : Math.round(n)
    }
  }
  const phase = get('Phase') ?? get('BackupPhase') ?? get('State')
  return { running, percent, phase, raw }
}

/** Get the current Time Machine backup progress. */
export async function getBackupStatus(): Promise<BackupStatus> {
  const raw = await run(['status'])
  return parseBackupStatus(raw)
}

/**
 * Trigger a Time Machine backup to the configured destination (the SD
 * disk). Completing a backup makes a fresh, browsable restore point.
 *
 * @param block  When true, wait until the backup finishes (long timeout);
 *               when false, start it in the background and return at once.
 */
export async function startBackup(block: boolean): Promise<void> {
  const args = ['startbackup', '--auto']
  if (block) args.push('--block')
  await execFileAsync(TMUTIL, args, {
    timeout: block ? 900_000 : 60_000,
  })
}

/* ------------------------------------------------------------------ */
/* Time Machine browsable backups (the "recover old versions" path)    */
/* ------------------------------------------------------------------ */

/**
 * Root where macOS mounts Time Machine local snapshots for browsing.
 * Requires Full Disk Access for the calling app (terminal/node).
 */
const TM_BROWSE_ROOT = '/Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb'

export interface TmBackup {
  /** Snapshot date id, e.g. 2026-09-06-095440 */
  date: string
  /** Absolute path to the snapshot's Data volume root */
  dataRoot: string
  /** JS Date parsed from the date id */
  createdAt: Date
}

/** Parse a YYYY-MM-DD-HHMMSS date id into a Date (epoch on failure). */
function parseSnapshotDate(date: string): Date {
  const m = date.match(/^(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})$/)
  return m
    ? new Date(
        Number(m[1]), Number(m[2]) - 1, Number(m[3]),
        Number(m[4]), Number(m[5]), Number(m[6]),
      )
    : new Date(0)
}

/**
 * List Time Machine snapshots that are actually MOUNTED and browsable
 * (i.e. a backup cycle completed — roughly hourly when the TM disk is
 * connected). On-demand `tmutil localsnapshot` checkpoints are NOT
 * browsable without root, so they do not appear here.
 *
 * Recognises two on-disk layouts:
 *   1. Local-snapshot browser mount:
 *      /Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb/<host>/<date>/Data
 *   2. TM destination volume mounted under /Volumes/<name>/:
 *      /Volumes/<name>/<YYYY-MM-DD-HHMMSS>[.previous]/Data
 *      (identified by backup_manifest.plist at the volume root)
 */
export function listBrowsableBackups(): TmBackup[] {
  const backups: TmBackup[] = []
  const seen = new Set<string>()

  // 1. Traditional localsnapshots browser mount.
  try {
    for (const host of readdirSync(TM_BROWSE_ROOT)) {
      const hostDir = join(TM_BROWSE_ROOT, host)
      let dates: string[]
      try {
        dates = readdirSync(hostDir)
      } catch {
        continue
      }
      for (const date of dates) {
        const dataRoot = join(hostDir, date, 'Data')
        if (existsSync(dataRoot)) {
          backups.push({ date, dataRoot, createdAt: parseSnapshotDate(date) })
          seen.add(dataRoot)
        }
      }
    }
  } catch {
    // No Full Disk Access, or TM browser volume not mounted.
  }

  // 2. TM destination volumes mounted under /Volumes/<name>/.
  //    These carry backup_manifest.plist at the root and one date-dir
  //    per completed backup (optionally suffixed .previous).
  try {
    for (const vol of readdirSync('/Volumes')) {
      const mount = join('/Volumes', vol)
      if (!existsSync(join(mount, 'backup_manifest.plist'))) continue
      let entries: string[]
      try {
        entries = readdirSync(mount)
      } catch {
        continue
      }
      for (const entry of entries) {
        const m = entry.match(/^(\d{4}-\d{2}-\d{2}-\d{6})(\.previous)?$/)
        if (!m) continue
        const date = m[1]
        const dataRoot = join(mount, entry, 'Data')
        if (existsSync(dataRoot) && !seen.has(dataRoot)) {
          backups.push({ date, dataRoot, createdAt: parseSnapshotDate(date) })
          seen.add(dataRoot)
        }
      }
    }
  } catch {
    // /Volumes not readable — fall through.
  }

  return backups.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
}

/** Pick a browsable backup: exact date, latest before a date, or latest. */
function pickBackup(
  backups: TmBackup[],
  snapshotDate?: string,
  beforeDate?: Date,
): TmBackup | undefined {
  if (snapshotDate) {
    return backups.find((b) => b.date === snapshotDate)
  }
  if (beforeDate) {
    const before = backups.filter((b) => b.createdAt < beforeDate)
    return before.length > 0 ? before[before.length - 1] : backups[backups.length - 1]
  }
  return backups[backups.length - 1]
}

/* ------------------------------------------------------------------ */
/* Rollback — multi-strategy file restoration                         */
/* ------------------------------------------------------------------ */

/**
 * Get the underlying disk device of the volume that CONTAINS `path`
 * (e.g. /Users/... -> the Data volume /dev/disk3s5 on sealed-system-volume
 * Macs). Mounting a snapshot of the wrong volume — e.g. "/" on modern macOS
 * resolves to the sealed System volume (/dev/disk3s1s1), which fails with
 * "Resource busy" and does not contain user files — makes Strategy 2
 * unusable even where root is available.
 */
async function getDiskDeviceForPath(path: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('/bin/df', ['-P', path], {
      timeout: 10_000,
    })
    const lines = stdout.trim().split('\n')
    if (lines.length < 2) return null
    // First column is the device, e.g. /dev/disk3s5
    const device = lines[1].split(/\s+/)[0]
    return device ?? null
  } catch {
    return null
  }
}

/**
 * Mount an APFS snapshot read-only at a temporary path.
 * Returns the mount path, or null if mounting failed (e.g. needs sudo).
 */
async function mountSnapshot(
  snapshotName: string,
  device: string,
): Promise<string | null> {
  const mountPath = `/tmp/tm-guard-snap-${Date.now()}`
  try {
    mkdirSync(mountPath, { recursive: true })
    await execFileAsync(
      '/sbin/mount_apfs',
      ['-o', 'ro,nobrowse,noowners', '-s', snapshotName, device, mountPath],
      { timeout: 15_000 },
    )
    return mountPath
  } catch {
    // mount_apfs may require sudo or may fail for sealed system volumes
    return null
  }
}

/** Unmount a previously mounted snapshot. */
async function unmountSnapshot(mountPath: string): Promise<void> {
  try {
    await execFileAsync('/sbin/umount', [mountPath], { timeout: 10_000 })
  } catch {
    // ignore — best effort
  }
}

/**
 * Verify that a path exists after restore (sanity check).
 */
function verifyRestore(targetPath: string): boolean {
  try {
    return existsSync(targetPath)
  } catch {
    return false
  }
}

export interface RollbackResult {
  success: boolean
  message: string
  snapshotUsed?: string
  strategy?: 'tm-backup' | 'manual-mount' | 'manual'
  restoredPaths: string[]
}

/**
 * Recover a file/directory from a previous Time Machine state.
 *
 * Time Machine RECOVERS old versions of files that were backed up; it does
 * not erase files created after the last backup. Two strategies:
 *
 *   1. Browsable TM backup (preferred, no root): copies the file out of a
 *      mounted, completed backup under Backups.backupdb. These exist once a
 *      backup cycle finishes (~hourly when the TM disk is connected) and
 *      require Full Disk Access for the calling app.
 *   2. Mount the on-demand local APFS snapshot (needs root/sudo): covers the
 *      fine-grained `tmutil localsnapshot` checkpoints, but mounting needs
 *      administrator rights the agent does not have non-interactively.
 *
 * @param targetPath  Absolute path to restore.
 * @param snapshotDate  Snapshot date id (optional; latest backup if omitted).
 * @param beforeDate  If set, use the latest backup BEFORE this date.
 */
export async function rollbackPath(
  targetPath: string,
  snapshotDate?: string,
  beforeDate?: Date,
): Promise<RollbackResult> {
  const normalizedTarget = targetPath.startsWith('~')
    ? targetPath.replace('~', process.env.HOME ?? '')
    : targetPath

  /* --- Strategy 1: recover from a browsable, already-completed TM backup --- */
  const backups = listBrowsableBackups()
  const chosen = pickBackup(backups, snapshotDate, beforeDate)
  if (chosen) {
    // User files live under the snapshot's Data volume root.
    const src = `${chosen.dataRoot}${normalizedTarget}`
    if (existsSync(src)) {
      try {
        await execFileAsync('/bin/cp', ['-R', src, normalizedTarget], {
          timeout: 60_000,
        })
        if (verifyRestore(normalizedTarget)) {
          return {
            success: true,
            message: `Recovered ${normalizedTarget} from Time Machine backup ${chosen.date} (${chosen.createdAt.toLocaleString()}).`,
            snapshotUsed: chosen.date,
            strategy: 'tm-backup',
            restoredPaths: [normalizedTarget],
          }
        }
      } catch {
        // copy failed — fall through to manual guidance
      }
    }
  }

  /* --- Strategy 2: mount the on-demand local snapshot (needs root/sudo) --- */
  let snaps: SnapshotInfo[] = []
  try {
    snaps = await listSnapshots('/')
  } catch {
    // ignore — handled by the failure message below
  }
  let snap: SnapshotInfo | undefined
  if (snapshotDate) {
    snap = snaps.find((s) => s.date === snapshotDate)
  } else if (beforeDate) {
    const before = snaps.filter((s) => s.createdAt < beforeDate)
    snap = before.length > 0 ? before[before.length - 1] : snaps[snaps.length - 1]
  } else {
    snap = snaps[snaps.length - 1]
  }

  const device = await getDiskDeviceForPath(normalizedTarget)
  if (snap && device) {
    const mountPath = await mountSnapshot(snap.name, device)
    if (mountPath) {
      try {
        for (const cand of [
          `${mountPath}${normalizedTarget}`,
          `${mountPath}/Data${normalizedTarget}`,
        ]) {
          if (existsSync(cand)) {
            try {
              await execFileAsync('/bin/cp', ['-R', cand, normalizedTarget], {
                timeout: 60_000,
              })
              if (verifyRestore(normalizedTarget)) {
                return {
                  success: true,
                  message: `Restored ${normalizedTarget} from local snapshot ${snap.date} (manual mount).`,
                  snapshotUsed: snap.date,
                  strategy: 'manual-mount',
                  restoredPaths: [normalizedTarget],
                }
              }
            } catch {
              // try next candidate
            }
          }
        }
      } finally {
        await unmountSnapshot(mountPath)
      }
    }
  }

  /* --- Failure: explain which case we're in and how to recover manually --- */
  const latestBackup = backups.length > 0 ? backups[backups.length - 1] : undefined
  const lines = [
    `Could not automatically recover ${normalizedTarget}.`,
    '',
  ]
  if (!latestBackup) {
    lines.push(
      'No browsable Time Machine backup is available yet. Backups complete about',
      'hourly when the TM backup disk (SD) is connected, and reading them needs',
      'Full Disk Access for the app running dsh (System Settings → Privacy &',
      'Security → Full Disk Access).',
    )
  } else if (chosen && !existsSync(`${chosen.dataRoot}${normalizedTarget}`)) {
    lines.push(
      `The file does not exist in the latest backup (${chosen.date}, ${chosen.createdAt.toLocaleString()}).`,
      'Time Machine recovers previous versions of files — it cannot undo a file',
      'that was created after the last backup. For a newly created file, just',
      'delete it directly (or use git).',
    )
  } else {
    lines.push(
      `A backup exists (latest: ${latestBackup.date}) but could not be copied automatically.`,
    )
  }
  lines.push(
    '',
    'To recover manually:',
    '  1. Click the Time Machine icon in the menu bar → "Enter Time Machine"',
    `  2. Navigate to: ${normalizedTarget}`,
    '  3. Pick the version on the timeline and click "Restore"',
    '',
    'Fine-grained local snapshots can be mounted with administrator rights:',
    `  sudo mount_apfs -o ro,nobrowse -s ${snap?.name ?? 'com.apple.TimeMachine.<date>.local'} ${device ?? '<data-volume-device — see: df -P /System/Volumes/Data>'} /tmp/tmsnap`,
    `  cp -R "/tmp/tmsnap${normalizedTarget}" "${normalizedTarget}"`,
    '  sudo umount /tmp/tmsnap',
  )
  return {
    success: false,
    message: lines.join('\n'),
    snapshotUsed: latestBackup?.date ?? snap?.date,
    strategy: 'manual',
    restoredPaths: [],
  }
}

/**
 * Roll back multiple paths to the same snapshot.
 * Returns per-path results.
 */
export async function rollbackPaths(
  paths: string[],
  snapshotDate?: string,
): Promise<RollbackResult[]> {
  const results: RollbackResult[] = []
  for (const p of paths) {
    results.push(await rollbackPath(p, snapshotDate))
  }
  return results
}

/* ------------------------------------------------------------------ */
/* TM Health Check — fail-closed safety net                           */
/* ------------------------------------------------------------------ */

export interface TmHealth {
  /** Overall health: true only when all checks pass */
  healthy: boolean
  /** Time Machine backup destination is configured */
  destinationConfigured: boolean
  /** At least one local APFS snapshot exists */
  hasSnapshots: boolean
  /** Number of local snapshots */
  snapshotCount: number
  /** The workspace paths are protected by Time Machine */
  workspaceProtected: boolean
  /** Which protected paths failed the protection check */
  unprotectedPaths: string[]
  /** Human-readable summary of what's wrong (empty if healthy) */
  issues: string[]
  /** When this health report was generated */
  checkedAt: Date
}

/** Cache for health check results to avoid spamming tmutil */
let healthCache: { result: TmHealth; expiresAt: number } | null = null
const HEALTH_CACHE_TTL_MS = 60_000 // 1 minute

/**
 * Check whether Time Machine is healthy enough to serve as a rollback safety net.
 *
 * A healthy TM means:
 *   1. A backup destination is configured
 *   2. At least one local snapshot exists
 *   3. All protected workspace paths are included in TM backups
 *
 * Results are cached for HEALTH_CACHE_TTL_MS to avoid running tmutil
 * on every tool call.
 */
export async function getTmHealth(
  protectedPaths: string[],
  forceRefresh = false,
): Promise<TmHealth> {
  const now = Date.now()
  if (!forceRefresh && healthCache && healthCache.expiresAt > now) {
    return healthCache.result
  }

  const issues: string[] = []

  // 1. Destination configured?
  let destinationConfigured = false
  try {
    const destRaw = await run(['destinationinfo'])
    destinationConfigured = DEST_CONFIGURED_RE.test(destRaw)
  } catch {
    // tmutil may fail if TM is disabled
  }
  if (!destinationConfigured) {
    issues.push('Time Machine backup destination is NOT configured')
  }

  // 2. Snapshots exist?
  let snapshotCount = 0
  try {
    const snaps = await listSnapshots('/')
    snapshotCount = snaps.length
  } catch {
    // ignore
  }
  const hasSnapshots = snapshotCount > 0
  if (!hasSnapshots) {
    issues.push('No local Time Machine snapshots exist (nothing to roll back to)')
  }

  // 3. Workspace paths protected?
  const unprotectedPaths: string[] = []
  for (const p of protectedPaths) {
    try {
      const excluded = await isPathExcluded(p)
      // Also check that the path exists and is on a TM-backed volume
      if (excluded) {
        unprotectedPaths.push(p)
      }
    } catch {
      unprotectedPaths.push(p)
    }
  }
  const workspaceProtected = unprotectedPaths.length === 0
  if (!workspaceProtected) {
    issues.push(
      `Workspace paths NOT protected by Time Machine: ${unprotectedPaths.join(', ')}`,
    )
  }

  const result: TmHealth = {
    healthy: destinationConfigured && hasSnapshots && workspaceProtected,
    destinationConfigured,
    hasSnapshots,
    snapshotCount,
    workspaceProtected,
    unprotectedPaths,
    issues,
    checkedAt: new Date(),
  }

  healthCache = { result, expiresAt: now + HEALTH_CACHE_TTL_MS }
  return result
}

/**
 * Invalidate the health cache. Call this after creating a snapshot or
 * changing TM configuration so the next check gets fresh data.
 */
export function invalidateHealthCache(): void {
  healthCache = null
}
