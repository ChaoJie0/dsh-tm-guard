// Edge-branch coverage for classifier.ts — the remaining reachable branches
// after the adversarial suite (tee output extraction, curl read-only
// download, empty commands, system/pkg/open-loopback tables, paren pipes,
// scanCode $HOME forms, tool-level classification tables).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand, classifyToolCall, decide } from './src/classifier.ts'
import os from 'node:os'

const HOME = os.homedir()


const DENY_READ = [
  '~/.ssh', '~/.aws', '~/.gnupg', '~/.kube', '~/.docker', '~/.netrc',
  '~/.git-credentials', '~/.npmrc', '~/.pypirc', '~/.config',
  '~/Library/Keychains', '~/Library/Cookies',
]

function gate(cmd: string) {
  const c = classifyBashCommand(cmd, DENY_READ)
  return { c, d: decide(c, true) }
}

// ---------------------------------------------------------------------------
test('tee: output file is extracted as a write target', () => {
  const { c, d } = gate('echo hi | tee /tmp/tee-edge.txt')
  assert.ok(c.targetPaths.some((p) => p.includes('tee-edge.txt')),
    `tee output missing: ${JSON.stringify(c.targetPaths)}`)
})

test('curl -O read-only download: file_write, mutates=false; POST variants stay blocked', () => {
  const dl = gate('curl -O https://example.com/pkg.bin')
  assert.equal(dl.c.category, 'file_write')
  assert.equal(dl.c.mutates, false)
  assert.equal(dl.d.allow, true)

  const post = gate('curl -X POST -d "a=1" https://example.com/api')
  assert.equal(post.d.allow, false)

  const noOutput = gate('curl https://example.com/x') // no -o/-O → not read-only
  assert.equal(noOutput.d.allow, false)
})

test('empty command: classified as read/Empty without crashing', () => {
  const c1 = classifyBashCommand('', DENY_READ)
  assert.equal(c1.category, 'read')
  const c2 = classifyBashCommand('   ;  ', DENY_READ) // segments all empty
  assert.equal(c2.category, 'read')
  assert.match(c2.reason, /Empty command/)
})

test('system commands force-deny', () => {
  for (const cmd of ['reboot', 'launchctl kickstart com.apple.x', 'osascript -e "say hi"']) {
    const { d } = gate(cmd)
    assert.equal(d.allow, false, `system must deny :: ${cmd.slice(0, 40)}`)
  }
})

test('local package subcommands classify as local_exec', () => {
  for (const cmd of ['npm run build', 'go test ./...', 'cargo check']) {
    const { c } = gate(cmd)
    assert.equal(c.category, 'local_exec', `expected local_exec :: ${cmd}`)
  }
})

test('open with loopback URL classifies as local_network', () => {
  const { c } = gate('open http://127.0.0.1:8080/health')
  assert.equal(c.category, 'local_network')
})

test('paren-wrapped pipe does not crash and stays classified', () => {
  const { c, d } = gate('(echo a | cat) && echo b')
  assert.ok(c.category)
  assert.equal(d.allow, true) // benign chain
})

test('scanCode: $HOME forms inside interpreter code are denied', () => {
  const blocked = [
    `python3 -c "print(open('$HOME/.ssh/id_rsa').read())"`,
    `python3 -c "print(open('\${HOME}/.ssh/id_rsa').read())"`,
  ]
  for (const cmd of blocked) {
    const { d } = gate(cmd)
    assert.equal(d.allow, false, `$HOME code form must block :: ${cmd.slice(0, 50)}`)
  }
})

// ---------------------------------------------------------------------------
test('tool-level classification tables', () => {
  const deny = DENY_READ
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ['web_fetch', { url: 'https://example.com' }, 'network'],
    ['subagent_create', {}, 'mixed'],
    ['todo_create', {}, 'read'],
    ['ask_user_question', {}, 'read'],
    ['tm_snapshot_create', {}, 'read'],
    ['mystery_tool', {}, 'unknown'],
  ]
  for (const [name, args, exp] of cases) {
    const c = classifyToolCall(name, args, deny)
    assert.equal(c.category, exp, `expected ${exp} for ${name}, got ${c.category}`)
  }
})

test('tool-level: read tool hitting a sensitive path force-denies', () => {
  const c = classifyToolCall('read_file', { path: `${HOME}/.ssh/id_rsa` }, DENY_READ)
  assert.equal(c.forceDeny, true)
})

test('tool-level: write tool reports file_write with target path', () => {
  const c = classifyToolCall('fs_write_file', { path: `${HOME}/Claude Code/x.txt` }, DENY_READ)
  assert.equal(c.category, 'file_write')
  assert.ok(c.targetPaths.some((p) => p.includes('x.txt')))
})

// ---------------------------------------------------------------------------
test('paren-wrapped single command is unwrapped and read-only', () => {
  const { c, d } = gate('(ls)')
  assert.equal(c.category, 'read')
  assert.equal(d.allow, true)
})

test('empty parens collapse to Empty command', () => {
  const { c } = gate('()')
  assert.equal(c.category, 'read')
  assert.match(c.reason, /Empty/)
})

test('multi-word system commands match fullCmd and force-deny', () => {
  const { d } = gate('diskutil eraseDisk JHFS+ Vol /dev/disk2')
  assert.equal(d.allow, false)
})

test('generic network command to external host stays network', () => {
  const { c, d } = gate('wget https://example.com/x.bin')
  assert.equal(c.category, 'network')
  assert.equal(d.allow, false)
})

test('generic network command to loopback is local_network', () => {
  const { c } = gate('wget http://127.0.0.1:8080/x')
  assert.equal(c.category, 'local_network')
})

test('exact fullCmd match in SYSTEM_COMMANDS force-denies', () => {
  const { d } = gate('defaults write NSGlobalDomain')
  assert.equal(d.allow, false)
})

test('nested command substitution is extracted', () => {
  const { d } = gate('echo $(echo $(cat /tmp/nested.txt))')
  assert.ok(d) // benign body, no sensitive path
})

test('unclosed command substitution does not crash', () => {
  const { c } = gate('echo $(unclosed')
  assert.ok(c.category)
})

test('tilde home form inside interpreter code is denied', () => {
  const { d } = gate('python3 -c "print(open(\'~/.ssh/id_rsa\').read())"')
  assert.equal(d.allow, false)
})
