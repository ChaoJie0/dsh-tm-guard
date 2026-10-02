// Fuzz coverage for classifier.ts — randomized command/tool composition with
// fixed-seed determinism. Invariants: never throw, classification is stable,
// and core safety invariants hold (sensitive reads deny, catastrophic rm
// denies, POST curl denies under denyNetwork, benign read allows).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand, classifyToolCall, decide } from './src/classifier.ts'

const DENY_READ = [
  '~/.ssh', '~/.aws', '~/.gnupg', '~/.kube', '~/.docker', '~/.netrc',
  '~/.git-credentials', '~/.npmrc', '~/.pypirc', '~/.config',
  '~/Library/Keychains', '~/Library/Cookies',
]

// Deterministic LCG (same seed → same sequence every run).
function lcg(seed: number) {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s / 0x100000000
  }
}

const WORDS = [
  'curl', 'wget', 'open', 'cat', 'echo', 'tee', 'git', 'npm', 'pnpm',
  'python3', 'node', 'ruby', 'perl', 'bash', 'sh', 'ls', 'rm', 'sudo',
  'mkdir', 'ssh', 'find', 'xargs', 'eval', 'awk', 'sed', 'grep', 'kill',
  'pkill', 'defaults', 'launchctl', 'diskutil', 'reboot', 'chmod', 'chown',
]
const FLAGS = [
  '-o', '-O', '-X', '-d', '-H', '-k', '-i', '-e', '-c', '-rf', '-R',
  '--output', '--yes', '--no-install', '--remote-name', '--insecure', '-sS',
]
const PATHS = [
  '/tmp/x', './x', '../x', '~/x', '$HOME/x', '${HOME}/x',
  '/Users/zero/.ssh/id_rsa', '/Users/zero/.ssh/config',
  '/Users/zero/.aws/credentials', '/Users/zero/.config/x',
  '/Users/zero/Claude Code/x.txt', '/Users/zero/DSH_Work/x.md',
  'https://example.com/x', 'http://127.0.0.1:8080/x', 'localhost:3000/x',
]
const TOKEN_SEP = [' ', ' ', ' ', ' ', ' && ', ' || ', '; ', ' | ', ' & ']
const TOOLS = [
  'bash', 'shell', 'run_command',
  'fs_write_file', 'write_file', 'fs_read_file', 'read_file', 'list_dir',
  'web_fetch', 'http_get', 'subagent_create', 'subagent', 'delegate',
  'todo_create', 'task_list', 'ask_user_question', 'confirm',
  'tm_snapshot_create', 'tm_health', 'mystery_tool',
]

interface FuzzCase {
  input: string
  kind: 'cmd' | 'tool'
}

function genCase(rnd: () => number): FuzzCase {
  if (rnd() < 0.25) {
    const name = TOOLS[Math.floor(rnd() * TOOLS.length)]!
    const args: Record<string, unknown> = {}
    if (name === 'bash' || name === 'shell' || name === 'run_command') {
      args.command = genCommand(rnd, Math.floor(rnd() * 4) + 1)
    } else if (name.includes('file') || name.includes('write') || name.includes('read')) {
      args.path = PATHS[Math.floor(rnd() * PATHS.length)]!
    } else if (name.includes('fetch') || name.includes('http') || name.includes('get')) {
      args.url = PATHS[Math.floor(rnd() * PATHS.length)]!
    }
    return { input: name, kind: 'tool' }
  }
  return { input: genCommand(rnd, Math.floor(rnd() * 6) + 1), kind: 'cmd' }
}

function genCommand(rnd: () => number, segments: number): string {
  const parts: string[] = []
  for (let i = 0; i < segments; i++) {
    let tok = WORDS[Math.floor(rnd() * WORDS.length)]!
    // mix in flags / paths
    const extras = Math.floor(rnd() * 3)
    for (let e = 0; e < extras; e++) {
      const pool = rnd() < 0.5 ? FLAGS : PATHS
      tok += ' ' + pool[Math.floor(rnd() * pool.length)]!
    }
    // sometimes wrap in quotes / parens / substitutions
    const wrap = rnd()
    if (wrap < 0.08) tok = `"${tok}"`
    else if (wrap < 0.16) tok = `'${tok}'`
    else if (wrap < 0.22) tok = `(${tok})`
    else if (wrap < 0.28) tok = `$(echo ${tok})`
    else if (wrap < 0.32) tok = '`' + tok + '`'
    else if (wrap < 0.36) tok = tok.replace(/\s+/g, '\\ ')
    parts.push(tok)
    if (i < segments - 1) parts.push(TOKEN_SEP[Math.floor(rnd() * TOKEN_SEP.length)]!)
  }
  return parts.join('')
}

const VALID_CATEGORIES = new Set([
  'read', 'write', 'file_write', 'file_read', 'network', 'local_network',
  'mixed', 'system', 'local_exec', 'vcs_local', 'vcs_remote', 'unknown',
  'ask_user', 'fail_closed', 'package', 'process',
])

test('fuzz: classifyBashCommand never throws, category valid, deterministic', () => {
  const rnd = lcg(0x5eed2026)
  const seen = new Map<string, string>()
  for (let i = 0; i < 400; i++) {
    const c = genCase(rnd)
    if (c.kind === 'cmd') {
      let res
      assert.doesNotThrow(() => {
        res = classifyBashCommand(c.input, DENY_READ)
      }, `cmd threw :: ${c.input}`)
      assert.ok(VALID_CATEGORIES.has(res!.category), `bad category ${res!.category} :: ${c.input}`)
      // determinism
      const prev = seen.get(c.input)
      const again = classifyBashCommand(c.input, DENY_READ)
      assert.equal(again.category, res!.category, `nondeterministic :: ${c.input}`)
      if (prev !== undefined) assert.equal(prev, res!.category)
      seen.set(c.input, res!.category)
    } else {
      let res
      assert.doesNotThrow(() => {
        res = classifyToolCall(c.input, {}, DENY_READ)
      }, `tool threw :: ${c.input}`)
      assert.ok(VALID_CATEGORIES.has(res!.category), `bad category ${res!.category} :: ${c.input}`)
    }
  }
})

test('fuzz: decide never throws and returns a boolean gate', () => {
  const rnd = lcg(0xf00d)
  for (let i = 0; i < 300; i++) {
    const c = genCase(rnd)
    const res = c.kind === 'cmd'
      ? classifyBashCommand(c.input, DENY_READ)
      : classifyToolCall(c.input, {}, DENY_READ)
    for (const strict of [true, false]) {
      let d
      assert.doesNotThrow(() => { d = decide(res, strict) }, `decide threw :: ${c.input}`)
      assert.equal(typeof d.allow, 'boolean', `allow not bool :: ${c.input}`)
      assert.ok(d.forceDeny === undefined || typeof d.forceDeny === 'boolean',
        `forceDeny not bool :: ${c.input}`)
    }
  }
})

test('fuzz: sensitive-read invariants hold across random composition', () => {
  const rnd = lcg(0x5a17a7)
  const probes: Array<[string, string]> = []
  // deterministically exercise sensitive reads with random wrappers
  for (let i = 0; i < 60; i++) {
    const wrap = ['', '"', "'", '$(', '`'][Math.floor(rnd() * 5)]!
    const end = wrap === '"' ? '"' : wrap === "'" ? "'" : wrap === '$(' ? ')' : wrap === '`' ? '`' : ''
    const cat = ['cat', 'head', 'tail', 'sed', 'grep', 'strings', 'openssl x509 -in'][Math.floor(rnd() * 7)]!
    const path = ['/Users/zero/.ssh/id_rsa', '/Users/zero/.ssh/config', '/Users/zero/.aws/credentials'][Math.floor(rnd() * 3)]!
    probes.push([`${wrap}${cat} ${path}${end}`, `sensitive read :: ${cat} ${path} :: wrap=${wrap}`])
  }
  for (const [cmd, label] of probes) {
    let res
    assert.doesNotThrow(() => { res = classifyBashCommand(cmd, DENY_READ) }, `threw :: ${cmd}`)
    const d = decide(res, true)
    assert.equal(d.allow, false, `sensitive read allowed :: ${label} :: ${cmd} :: ${JSON.stringify(res)}`)
  }
})

test('fuzz: catastrophic patterns deny even with random token mixing', () => {
  const rnd = lcg(0xca7)
  for (let i = 0; i < 40; i++) {
    const prefix = ['', 'sudo ', 'env ', ''][Math.floor(rnd() * 4)]!
    const base = ['rm -rf /', 'rm -rf ~', 'dd if=/dev/zero of=/dev/disk2', 'reboot', 'shutdown -h now'][Math.floor(rnd() * 5)]!
    const cmd = prefix + base + (rnd() < 0.3 ? ' ; echo done' : '')
    const res = classifyBashCommand(cmd, DENY_READ)
    const d = decide(res, true)
    assert.equal(d.allow, false, `catastrophic allowed :: ${cmd} :: ${JSON.stringify(res)}`)
  }
})

test('fuzz: curl with request/data/upload flags denies under denyNetwork', () => {
  const rnd = lcg(0xc0ffee)
  const variants = [
    'curl -X POST https://example.com/api',
    'curl -d "a=1" https://example.com/api',
    'curl -T /tmp/x https://example.com/up',
    'curl -F "f=@/tmp/x" https://example.com/up',
    'curl -H "Authorization: Bearer x" https://example.com/api',
    'curl -k https://example.com/x',
  ]
  for (const cmd of variants) {
    const res = classifyBashCommand(cmd, DENY_READ)
    const d = decide(res, true)
    assert.equal(d.allow, false, `curl variant allowed :: ${cmd} :: ${JSON.stringify(res)}`)
  }
  // read-only download with -o must stay allowed (workspace /tmp)
  const dl = classifyBashCommand('curl -o /tmp/x https://example.com/x', DENY_READ)
  assert.equal(dl.category, 'file_write')
  assert.equal(dl.mutates, false)
})

test('fuzz: benign read chains always allow', () => {
  const rnd = lcg(0xbe9e)
  const base = ['ls -l /tmp', 'echo hi', 'cat /tmp/x', 'git status', 'npm run build', 'open /tmp/x', 'pwd', 'date', 'uname -a', 'wc -l /tmp/x']
  for (let i = 0; i < 30; i++) {
    const a = base[Math.floor(rnd() * base.length)]!
    const b = base[Math.floor(rnd() * base.length)]!
    const sep = [' && ', '; ', ' | '][Math.floor(rnd() * 3)]!
    const cmd = `${a}${sep}${b}`
    const res = classifyBashCommand(cmd, DENY_READ)
    const d = decide(res, true)
    assert.equal(d.allow, true, `benign chain denied :: ${cmd} :: ${JSON.stringify(res)}`)
  }
})
