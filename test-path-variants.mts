// Sensitive-path variant matrix — case-insensitivity (macOS default APFS),
// double-slash collapsing, dot-segment resolution, and prefix-boundary
// non-false-positives.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand, classifyToolCall } from './src/classifier.ts'

const DENY_READ = [
  '~/.ssh', '~/.aws', '~/.gnupg', '~/.kube', '~/.docker', '~/.netrc',
  '~/.git-credentials', '~/.npmrc', '~/.pypirc', '~/.config',
  '~/Library/Keychains', '~/Library/Cookies',
]

function mustDeny(cmd: string, label: string) {
  const c = classifyBashCommand(cmd, DENY_READ)
  assert.equal(c.forceDeny, true,
    `expected forced deny :: ${label} :: ${cmd} :: ${JSON.stringify(c)}`)
}

function mustAllow(cmd: string, label: string) {
  const c = classifyBashCommand(cmd, DENY_READ)
  assert.notEqual(c.forceDeny, true,
    `unexpected forced deny :: ${label} :: ${cmd} :: ${JSON.stringify(c)}`)
}

// macOS default filesystem is case-insensitive: `.SSH` == `.ssh`.
test('case variants of sensitive dirs are denied (macOS semantics)', () => {
  for (const cmd of [
    'cat /Users/zero/.SSH/id_rsa',
    'cat /Users/zero/.ssh/ID_RSA',
    'cat ~/.AWS/credentials',
    'cat ~/.aws/CREDENTIALS',
    'cat ~/.CONFIG/x',
    'cat ~/.GIT-CREDENTIALS',
    'cat ~/Library/keychains/x',
    'cat ~/library/Cookies/x',
    'head /Users/Zero/.Ssh/id_rsa',
  ]) {
    mustDeny(cmd, 'case variant')
  }
})

test('double-slash variants resolve to the same sensitive path', () => {
  for (const cmd of [
    // NOTE: a leading `//` collapses to `/` (POSIX), so `//Users//.ssh`
    // is /Users/.ssh — NOT the user's .ssh. Use interior double slashes:
    'cat /Users//zero//.ssh//id_rsa',
    'cat /Users/zero//.ssh//id_rsa',
    'cat ~//.ssh/id_rsa',
    'cat $HOME//.ssh/id_rsa',
    'cat /Users/zero/.ssh//config',
  ]) {
    mustDeny(cmd, 'double slash')
  }
})

test('dot-segment variants resolve into the sensitive path', () => {
  for (const cmd of [
    'cat /Users/zero/.ssh/../.ssh/id_rsa',
    'cat $HOME/.ssh/./id_rsa',
    'cat ~/.ssh/./config',
    'cat /Users/zero/.//.ssh/id_rsa',
  ]) {
    mustDeny(cmd, 'dot segment')
  }
})

test('prefix-boundary neighbors are NOT denied (no false positives)', () => {
  for (const cmd of [
    'cat ~/.ssh2/x',
    'cat ~/.ssh_backup/x',
    'cat ~/.ssh.bak/x',
    'cat ~/.awsome/x',
    'cat /Users/zero/.sshconfig/x',
  ]) {
    mustAllow(cmd, 'prefix neighbor')
  }
})

test('tool-level path variants force-deny too', () => {
  for (const p of [
    '/Users/zero/.SSH/id_rsa',
    '/Users/zero/.ssh/../.ssh/id_rsa',
    '/Users//zero//.ssh//id_rsa',
  ]) {
    const c = classifyToolCall('read_file', { path: p }, DENY_READ)
    assert.equal(c.forceDeny, true, `tool variant allowed :: ${p} :: ${JSON.stringify(c)}`)
  }
})

test('sensitive-file suffix inside an allowed dir still denies', () => {
  // .ssh/config.bak is still under .ssh — must deny (directory-prefix semantics)
  mustDeny('cat ~/.ssh/config.bak', 'suffix inside sensitive dir')
})
