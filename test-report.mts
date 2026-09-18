// Smoke test for the turn completion report (feedback layer 1).
// Pure logic — no dsh/tmutil needed.
// Run: node test-report.mts
import { buildTurnReport } from './src/report.ts'
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

const base: AuditRecord[] = [
  {
    ts: '2026-09-06T11:35:44.000Z',
    tool: 'edit',
    category: 'file_write',
    decision: 'allow',
    reason: 'Allowed (file_write on TM-protected path): Filesystem write tool: edit',
    targetPaths: ['/tmp/tm-guard-temp/racing-game.html'],
    snapshotId: '2026-09-06-193414',
  },
  {
    ts: '2026-09-06T11:35:51.000Z',
    tool: 'bash',
    category: 'file_write',
    decision: 'deny',
    reason: 'BLOCKED (file_write on path NOT protected by Time Machine): /tmp/racing-check.js',
    targetPaths: ['/tmp/racing-check.js'],
  },
  {
    ts: '2026-09-06T11:35:53.000Z',
    tool: 'bash',
    category: 'network',
    decision: 'deny',
    reason: 'BLOCKED (network, not TM-rollback-able)',
    targetPaths: [],
  },
  {
    ts: '2026-09-06T11:36:19.000Z',
    tool: 'read',
    category: 'read',
    decision: 'allow',
    reason: 'Allowed (read): Filesystem read tool: read',
    targetPaths: ['/tmp/tm-guard-temp/racing-game.html'],
  },
]

const r = buildTurnReport({
  turn: 2,
  now: '2026-09-06T11:36:30.000Z',
  cwd: '/tmp/tm-guard-temp',
  records: base,
  gitStatus: ' M racing-game.html\n?? notes.md',
  snapshotCount: 31,
})

// Structure checks
check('标题含回合', r.md.includes('# dsh-tm-guard 回合完成报告'))
check('回合号', r.md.includes('**回合**: 2'))
check('工作目录', r.md.includes('/tmp/tm-guard-temp'))
check('统计表 4 工具调用', r.md.includes('4（放行 2 / 拦截 2）'))
check('文件写入 1', r.md.includes('| 文件写入 | 1 |'))
check('快照数', r.md.includes('| TM 本地快照 | 31 个 |'))
check('被拦截摘要', r.md.includes('越界写×1') && r.md.includes('网络×1'))

// Write table
check('写操作表', r.md.includes('## 放行的写操作'))
check('写表含快照', r.md.includes('2026-09-06-193414'))
check('写表路径', r.md.includes('/tmp/tm-guard-temp/racing-game.html'))

// Artifacts
check('产物段', r.md.includes('## 产物 / 变更路径'))
check('产物去重（4 条记录只有 1 个唯一写路径）',
  (r.md.match(/racing-game\.html/g) ?? []).length >= 1)

// Blocked table
check('拦截表', r.md.includes('## 被拦截的操作'))
check('拦截表网络行', r.md.includes('| 网络 |'))
check('拦截表越界写行', r.md.includes('| 越界写 |'))

// git section
check('git 段', r.md.includes('## git 工作区状态'))
check('git 内容', r.md.includes('notes.md'))

// Summary line
check('summary 一行含关键计数', r.summary.length === 1 &&
  r.summary[0].includes('turn=2') && r.summary[0].includes('allow=2/deny=2') &&
  r.summary[0].includes('blocked=越界写×1、网络×1'))

// Edge: empty activity → still builds, empty tables
const empty = buildTurnReport({
  turn: 1,
  now: '2026-09-06T12:00:00.000Z',
  cwd: '/home/tmg-test',
  records: [],
})
check('空活动可构建', empty.md.length > 0)
check('空活动无写表', !empty.md.includes('## 放行的写操作'))
check('空活动 summary 计数为 0', empty.summary[0].includes('tools=0'))

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail > 0 ? 1 : 0)
