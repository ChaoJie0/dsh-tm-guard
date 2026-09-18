// Smoke test for the acceptance verifier (feedback layer 3).
// Pure logic + real filesystem reads — no dsh/tmutil needed.
// Run: node test-verify.mts
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { verifyTurn } from './src/verify.ts'
import type { AuditRecord } from './src/audit.ts'

let pass = 0
let fail = 0

function check(name: string, cond: boolean, extra = '') {
  if (cond) {
    pass++
  } else {
    fail++
    console.log(`FAIL: ${name}${extra ? ` — ${extra}` : ''}`)
  }
}

const PROTECTED = ['/tmp/tm-guard-home']
const ts = '2026-09-06T13:00:00.000Z'

// --- Scenario 1: everything verified (real temp files) ---
const dir = mkdtempSync(join(tmpdir(), 'tm-guard-verify-'))
// For the "all good" scenarios the temp dir itself is the protected prefix
// (files genuinely live there); the escape scenario below keeps the real
// protected prefix to prove out-of-range detection.
const PROTECTED_TMP = [dir]
const game = join(dir, 'racing-game.html')
const note = join(dir, 'notes.md')
mkdirSync(join(dir, '.git'))
writeFileSync(game, '<html></html>')
writeFileSync(note, 'hi')

const okRecords: AuditRecord[] = [
  {
    ts, tool: 'write', category: 'file_write', decision: 'allow',
    reason: 'Allowed (file_write on TM-protected path)',
    targetPaths: [game],
  },
  {
    ts, tool: 'write', category: 'file_write', decision: 'allow',
    reason: 'Allowed (file_write on TM-protected path)',
    targetPaths: [note],
  },
  {
    ts, tool: 'bash', category: 'file_write', decision: 'deny',
    reason: 'BLOCKED (file_write on path NOT protected by Time Machine)',
    targetPaths: ['/tmp/nonexistent-guard-check.js'],
  },
  {
    ts, tool: 'bash', category: 'network', decision: 'deny',
    reason: 'BLOCKED (network, not TM-rollback-able)',
    targetPaths: [],
  },
]

const v1 = verifyTurn({
  records: okRecords,
  artifacts: [game, note],
  protectedPaths: PROTECTED_TMP,
  snapshotCount: 24,
})
check('场景1 全部通过 ok', v1.ok)
check('4 项检查', v1.checks.length === 4)
check('产物存在性通过', v1.checks[0].pass && v1.checks[0].detail.includes('2 个产物'))
check('写路径保护通过', v1.checks[1].pass)
check('拦截无副作用通过', v1.checks[2].pass)
check('回滚就绪通过', v1.checks[3].pass && v1.checks[3].detail.includes('24 个'))
check('markdown 含结论已核验', v1.markdown.includes('✅ 已核验'))
check('markdown 含检查表', v1.markdown.includes('| 检查项 | 结果 | 明细 |'))

// --- Scenario 2: artifact missing ---
const v2 = verifyTurn({
  records: okRecords,
  artifacts: [game, join(dir, 'ghost.html')],
  protectedPaths: PROTECTED_TMP,
  snapshotCount: 24,
})
check('场景2 缺失产物 ok=false', !v2.ok)
check('场景2 产物检查失败', !v2.checks[0].pass && v2.checks[0].detail.includes('缺失 1'))
check('场景2 结论有疑点', v2.markdown.includes('⚠️ 有疑点'))

// --- Scenario 3: write escaped protection ---
const v3 = verifyTurn({
  records: [
    {
      ts, tool: 'write', category: 'file_write', decision: 'allow',
      reason: 'Allowed',
      targetPaths: ['/tmp/escaped.js'],
    },
  ],
  artifacts: ['/tmp/escaped.js'],
  protectedPaths: PROTECTED,
})
check('场景3 越界写 ok=false', !v3.ok)
check('场景3 写路径保护失败', !v3.checks[1].pass && v3.checks[1].detail.includes('越界写'))
check('场景3 结论有疑点', v3.markdown.includes('⚠️ 有疑点'))

// --- Scenario 4: denied write left a side effect ---
const sideFile = join(dir, 'side-effect.txt')
writeFileSync(sideFile, 'x')
const v4 = verifyTurn({
  records: [
    {
      ts, tool: 'bash', category: 'file_write', decision: 'deny',
      reason: 'BLOCKED (file_write on path NOT protected)',
      targetPaths: [sideFile],
    },
  ],
  artifacts: [],
  protectedPaths: PROTECTED_TMP,
  snapshotCount: 3,
})
check('场景4 副作用 ok=false', !v4.ok)
check('场景4 拦截副作用检查失败', !v4.checks[2].pass && v4.checks[2].detail.includes('疑点'))
check('场景4 结论有疑点', v4.markdown.includes('⚠️ 有疑点'))

// --- Scenario 5: no writes at all (read-only turn) ---
const v5 = verifyTurn({
  records: [
    {
      ts, tool: 'read', category: 'read', decision: 'allow',
      reason: 'Allowed (read)', targetPaths: [game],
    },
  ],
  artifacts: [],
  protectedPaths: PROTECTED_TMP,
  snapshotCount: 24,
})
check('场景5 只读回合 ok', v5.ok)
check('场景5 无产物说明', v5.checks[0].pass && v5.checks[0].detail.includes('无写操作'))
check('场景5 回滚就绪（无写也过）', v5.checks[3].pass)

rmSync(dir, { recursive: true, force: true })

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail > 0 ? 1 : 0)
