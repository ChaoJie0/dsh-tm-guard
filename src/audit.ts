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
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import type { OpCategory } from './classifier.ts'

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

  /** Read all audit records. */
  readAll(): AuditRecord[] {
    try {
      if (!existsSync(this.logPath)) return []
      const content = readFileSync(this.logPath, 'utf8')
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
