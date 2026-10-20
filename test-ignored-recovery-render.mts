// Pure-render tests for ignored-file recovery markers (status.ts / audit shape).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  renderStatusReport,
  type StatusInput,
  type StatusConfigView,
} from './src/status.ts'
import { AuditLog, type AuditRecord } from './src/audit.ts'

const CONFIG: StatusConfigView = {
  protectedPaths: ['/p'], denyReadPaths: [], denyNetwork: true, denySystem: true,
  failClosed: true, requireTaskSnapshot: true, autoApprove: false, snapshotCooldownSeconds: 30,
}

function baseInput(audit: AuditLog, recentDecisions: AuditRecord[]): StatusInput {
  return {
    platformSupported: true,
    platform: 'darwin',
    health: { healthy: true, issues: [], destinationConfigured: true, localSnapshots: 1, workspaceProtected: true, checkedAt: new Date() } as any,
    status: { destinationConfigured: true, hasLocalSnapshots: true, snapshotCount: 1, raw: '' } as any,
    latest: { name: 'x', date: '2026-10-20-120000', createdAt: new Date() } as any,
    config: CONFIG,
    audit,
    auditCount: recentDecisions.length,
    writeCount: recentDecisions.length,
    recentDecisions,
  }
}

test('status render: counts no targets in Recent and marks per-line; absent field is safe', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ifr-render-'))
  mkdirSync(join(dir, '.tm-guard'), { recursive: true })
  const audit = new AuditLog(dir)
  const old: AuditRecord = {
    ts: '2026-10-20T00:00:00Z', tool: 'legacy', category: 'file_write',
    decision: 'allow', reason: 'old', targetPaths: ['/p/a'],
  }
  const withNo: AuditRecord = {
    ts: '2026-10-20T00:01:00Z', tool: 'bash', category: 'file_write',
    decision: 'allow', reason: 'x', targetPaths: ['/p/.env.local'],
    gitRecovery: [{ path: '/p/.env.local', state: 'no' }],
  }
  const withYes: AuditRecord = {
    ts: '2026-10-20T00:02:00Z', tool: 'write', category: 'file_write',
    decision: 'allow', reason: 'x', targetPaths: ['/p/t.txt'],
    gitRecovery: [{ path: '/p/t.txt', state: 'yes' }],
  }
  const out = renderStatusReport(baseInput(audit, [withYes, withNo, old]))
  assert.match(out, /git-unrecoverable \(ignored\) targets in recent window: 1/)
  const noLine = out.split('\n').find((l) => l.includes('[file_write] bash'))
  assert.ok(noLine?.includes('git=no(1)'))
  // yes and old lines carry no marker
  const yesLine = out.split('\n').find((l) => l.includes('[file_write] write'))
  assert.ok(yesLine && !yesLine.includes('git=no'))
  const oldLine = out.split('\n').find((l) => l.includes('[file_write] legacy'))
  assert.ok(oldLine && !oldLine.includes('git=no'))
  void writeFileSync
})

test('status render: zero no targets -> no aggregate line at all', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ifr-render2-'))
  mkdirSync(join(dir, '.tm-guard'), { recursive: true })
  const audit = new AuditLog(dir)
  const rec: AuditRecord = {
    ts: '2026-10-20T00:00:00Z', tool: 'write', category: 'file_write',
    decision: 'allow', reason: 'x', targetPaths: ['/p/t.txt'],
    gitRecovery: [{ path: '/p/t.txt', state: 'yes' }, { path: '/p/u.txt', state: 'unknown' }],
  }
  const out = renderStatusReport(baseInput(audit, [rec]))
  assert.ok(!out.includes('git-unrecoverable'))
  assert.ok(!out.includes('git=no'))
})
