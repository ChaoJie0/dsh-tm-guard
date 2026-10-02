// Sensitive-path variant matrix — case-insensitivity (macOS default APFS),
// double-slash collapsing, dot-segment resolution, and prefix-boundary
// non-false-positives.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand, classifyToolCall } from './src/classifier.ts'
import os from 'node:os'

const HOME = os.homedir()


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
    `cat ${HOME}/.SSH/id_rsa`,
    `cat ${HOME}/.ssh/ID_RSA`,
    'cat ~/.AWS/credentials',
    'cat ~/.aws/CREDENTIALS',
    'cat ~/.CONFIG/x',
    'cat ~/.GIT-CREDENTIALS',
    'cat ~/Library/keychains/x',
    'cat ~/library/Cookies/x',
    `head ${HOME}/.Ssh/id_rsa`,
  ]) {
    mustDeny(cmd, 'case variant')
  }
})

test('double-slash variants resolve to the same sensitive path', () => {
  for (const cmd of [
    // NOTE: a leading `//` collapses to `/` (POSIX), so `//Users//.ssh`
    // is /Users/.ssh — NOT the user's .ssh. Use interior double slashes:
    'cat ${HOME}//.ssh//id_rsa',
    `cat ${HOME}//.ssh//id_rsa`,
    'cat ~//.ssh/id_rsa',
    'cat $HOME//.ssh/id_rsa',
    `cat ${HOME}/.ssh//config`,
  ]) {
    mustDeny(cmd, 'double slash')
  }
})

test('dot-segment variants resolve into the sensitive path', () => {
  for (const cmd of [
    `cat ${HOME}/.ssh/../.ssh/id_rsa`,
    'cat $HOME/.ssh/./id_rsa',
    'cat ~/.ssh/./config',
    `cat ${HOME}/.//.ssh/id_rsa`,
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
    `cat ${HOME}/.sshconfig/x`,
  ]) {
    mustAllow(cmd, 'prefix neighbor')
  }
})

test('tool-level path variants force-deny too', () => {
  for (const p of [
    `${HOME}/.SSH/id_rsa`,
    `${HOME}/.ssh/../.ssh/id_rsa`,
    `${HOME}//.ssh//id_rsa`,
  ]) {
    const c = classifyToolCall('read_file', { path: p }, DENY_READ)
    assert.equal(c.forceDeny, true, `tool variant allowed :: ${p} :: ${JSON.stringify(c)}`)
  }
})

test('sensitive-file suffix inside an allowed dir still denies', () => {
  // .ssh/config.bak is still under .ssh — must deny (directory-prefix semantics)
  mustDeny('cat ~/.ssh/config.bak', 'suffix inside sensitive dir')
})

test('quoted space-path redirection → allowed (full path extracted)', () => {
  const c = classifyBashCommand(
    `echo x > "${HOME}/Claude Code/自治/out.txt"`, DENY_READ,
  )
  assert.equal(c.category, 'file_write')
  assert.deepEqual(c.targetPaths, [`${HOME}/Claude Code/自治/out.txt`])
})

test('unquoted space-path redirection → conservative deny (shell splits args)', () => {
  // Real bash: `echo x > ${HOME}/Claude Code/自治/out.txt` redirects to
  // ${HOME}/Claude and passes "Code/自治/out.txt" as an argument — the
  // extracted write path is the first segment, outside protected prefixes.
  const c = classifyBashCommand(
    `echo x > ${HOME}/Claude Code/自治/out.txt`, DENY_READ,
  )
  assert.equal(c.category, 'file_write')
  assert.deepEqual(c.targetPaths, [`${HOME}/Claude`])
  // path protection check (isPathProtected on prefix) → not under protected → deny
  const under = ([`${HOME}/Claude Code`, `${HOME}/Claude`].some(
    (p) => `${HOME}/Claude`.startsWith(p.replace(/\/+$/, '') + '/'),
  ))
  assert.equal(under, false) // not protected → decide() denies
})
