/**
 * Plugin state — small, durable JSON blob stored at `.tm-guard/state.json`.
 *
 * Why this exists: the turn reporter used to track "how many audit records
 * have I already reported?" as an *array index* (`readAll().length`). That
 * invariant silently breaks the moment the audit log rotates or is trimmed:
 * the visible length shrinks below the stored index, `slice(idx)` returns
 * `[]`, and the turn report is skipped — then the index is rewritten to the
 * smaller length and later turns re-report records that were already
 * reported. Neither failure is observable to the user.
 *
 * The fix is a watermark keyed on *stable record identity* rather than on
 * position in a mutable array: the `(ts, tool)` pair of the last record that
 * was reported. Resolving that pair against whatever records are currently
 * visible gives the correct resume point regardless of rotation, and when the
 * watermark has been rotated away entirely we degrade to "report everything
 * visible" plus a warning — bounded and observable, unlike silent skipping.
 *
 * The module is deliberately free of dsh/ctx dependencies so it is unit
 * testable and reusable; all IO failures degrade to in-memory defaults.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { AuditRecord } from './audit.ts'

/** Identifies the last audit record already folded into a turn report. */
export interface ReportWatermark {
  /** ISO timestamp of that record. */
  ts: string
  /** Tool name of that record — disambiguates same-millisecond records. */
  tool: string
}

export interface TmGuardState {
  /** Last reported audit record; `null` means "nothing reported yet". */
  reportWatermark: ReportWatermark | null
  /** Global monotonic audit-record counter (rotation-layer sequence). */
  auditTotalCount: number
  /** How many times the audit log has been rotated. */
  auditRotatedCount: number
  /** Last automatic-cleanup run, ISO timestamp. */
  lastGcAt?: string
  /** HEAD sha observed at the last automatic-cleanup run. */
  lastGcHead?: string
}

const DEFAULT_STATE: TmGuardState = {
  reportWatermark: null,
  auditTotalCount: 0,
  auditRotatedCount: 0,
}

/** Where state.json lives for a given `.tm-guard` directory. */
export function statePath(dir: string): string {
  return join(dir, 'state.json')
}

/**
 * Coerce arbitrary parsed JSON into a valid state object. A hand-edited or
 * half-written file must never crash the plugin or silently corrupt the
 * watermark into a wrong-but-valid shape.
 */
export function normalizeState(raw: unknown): TmGuardState {
  if (raw === null || typeof raw !== 'object') return { ...DEFAULT_STATE }
  const r = raw as Record<string, unknown>
  let watermark: ReportWatermark | null = null
  const w = r.reportWatermark
  if (w !== null && typeof w === 'object') {
    const { ts, tool } = w as Record<string, unknown>
    if (typeof ts === 'string' && typeof tool === 'string') {
      watermark = { ts, tool }
    }
    // Any other shape is treated as "no watermark" rather than a guess.
  }
  const num = (v: unknown): number =>
    typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0
  return {
    reportWatermark: watermark,
    auditTotalCount: num(r.auditTotalCount),
    auditRotatedCount: num(r.auditRotatedCount),
    ...(typeof r.lastGcAt === 'string' ? { lastGcAt: r.lastGcAt } : {}),
    ...(typeof r.lastGcHead === 'string' ? { lastGcHead: r.lastGcHead } : {}),
  }
}

/**
 * Read state from `<dir>/state.json`. Missing/corrupt files yield defaults —
 * never throws.
 */
export function readState(dir: string): TmGuardState {
  try {
    const p = statePath(dir)
    if (!existsSync(p)) return { ...DEFAULT_STATE }
    return normalizeState(JSON.parse(readFileSync(p, 'utf8')))
  } catch {
    return { ...DEFAULT_STATE }
  }
}

/**
 * Atomically persist state (tmp file + rename). Best-effort: a read-only
 * workspace degrades to in-memory-only behaviour instead of failing the gate.
 * Returns true when the write landed.
 */
export function writeState(dir: string, state: TmGuardState): boolean {
  const p = statePath(dir)
  const tmp = `${p}.tmp`
  try {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n', 'utf8')
    renameSync(tmp, p)
    return true
  } catch {
    return false
  }
}

/* ------------------------------------------------------------------ */
/* Watermark resolution                                                */
/* ------------------------------------------------------------------ */

/** True when two records share the same stable identity `(ts, tool)`. */
export function sameIdentity(a: ReportWatermark, b: AuditRecord): boolean {
  return a.ts === b.ts && a.tool === b.tool
}

export interface ResolveResult {
  /** Records that have not yet been reported. */
  activity: AuditRecord[]
  /**
   * Index of the watermark record in `records`, or -1 when it is not visible
   * (rotated away / audit cleared).
   */
  index: number
  /**
   * True when a watermark existed but could not be located — the caller
   * should warn once, because a duplicate report is possible.
   */
  watermarkLost: boolean
}

/**
 * Resolve a watermark against the currently visible records.
 *
 * - watermark `null` → nothing has been reported; everything is activity
 *   (first run of a fresh install *does* report what is on disk, matching the
 *   original boot behaviour of seeding the counter from `readAll().length`
 *   only when a state file already existed).
 * - watermark found → everything strictly after its *last* occurrence.
 *   "Last" matters: `(ts, tool)` can repeat, and taking the earliest match
 *   would re-emit the duplicates in between.
 * - watermark missing → all records, flagged via `watermarkLost`.
 */
export function resolveWatermark(
  records: AuditRecord[],
  watermark: ReportWatermark | null,
): ResolveResult {
  if (watermark === null) {
    return { activity: records.slice(), index: -1, watermarkLost: false }
  }
  let idx = -1
  for (let i = records.length - 1; i >= 0; i--) {
    if (sameIdentity(watermark, records[i])) {
      idx = i
      break
    }
  }
  if (idx === -1) {
    return { activity: records.slice(), index: -1, watermarkLost: true }
  }
  return { activity: records.slice(idx + 1), index: idx, watermarkLost: false }
}

/** Watermark for the newest record in a list, or `null` when empty. */
export function watermarkOf(records: AuditRecord[]): ReportWatermark | null {
  const last = records[records.length - 1]
  return last ? { ts: last.ts, tool: last.tool } : null
}
