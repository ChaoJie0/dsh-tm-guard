// Adversarial classifier tests — bypass attempts against the permission gate.
// REG group: variants the classifier must keep blocking (regression lock).
// GAP group: KNOWN BYPASSES, asserted to fail on purpose — they must go green
//            when the classifier is fixed (test-driven: red first, green after).
//
// Probe baseline (2026-10-01): $HOME expansion and `cd <dir> && cat <rel>` were
// both classified allow=true — see GAP group.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import { classifyBashCommand, decide } from './src/classifier.ts'

const HOME = os.homedir()
const DENY_READ = [
  '~/.ssh', '~/.aws', '~/.gnupg', '~/.kube', '~/.docker', '~/.netrc',
  '~/.git-credentials', '~/.npmrc', '~/.pypirc', '~/.config',
  '~/Library/Keychains', '~/Library/Cookies',
]
const PROTECTED = [`${HOME}/Claude Code`, '/Applications/Study', `${HOME}/DSH_Work`]

function gate(cmd) {
  const c = classifyBashCommand(cmd, DENY_READ)
  return { c, d: decide(c, true) }
}

// ---------------------------------------------------------------------------
// REG — must stay blocked (all probed as allow=false, most forceDeny=true)
// ---------------------------------------------------------------------------
test('REG: path-normalization / glob / stream variants stay blocked', () => {
  const blocked = [
    'cat ~/.ssh/../.ssh/id_rsa',          // .. traversal
    'cat ~/.ssh/*',                       // glob
    'cat ~/.ssh/id_rsa 2>/dev/null | base64', // pipe + stderr redirect
    'base64 < ~/.ssh/id_rsa',             // input redirect
    'cat <(cat ~/.ssh/id_rsa)',           // process substitution
    'c\\at ~/.ssh/id_rsa',                // backslash inside token
    'CAT ~/.ssh/id_rsa',                  // uppercase (bash is case-sensitive)
    'ls -- ~/.ssh',                       // -- end-of-options
    'ssh -i ~/.ssh/id_rsa user@host',     // ssh key flag
    'env HOME=/tmp cat ~/.ssh/id_rsa',    // env override attempt
    'cat ~/.ssh/id_rsa > /tmp/leak.txt',  // write outside protected via redirect
  ]
  for (const cmd of blocked) {
    const { c, d } = gate(cmd)
    assert.equal(d.allow, false, `must block :: ${cmd.slice(0, 52)}`)
    assert.equal(c.forceDeny, true, `must forceDeny :: ${cmd.slice(0, 52)}`)
  }
})

test('REG: benign variants stay allowed (no over-blocking)', () => {
  const allowed = [
    'echo $HOME',                         // prints home path only, no file read
    `echo hello > "${HOME}/Claude Code/自治/x.txt"`,
    `ls ${HOME}/DSH_Work`,
  ]
  for (const cmd of allowed) {
    const { d } = gate(cmd)
    assert.equal(d.allow, true, `must allow :: ${cmd.slice(0, 52)}`)
  }
})

// ---------------------------------------------------------------------------
// GAP — KNOWN BYPASSES. These MUST be blocked; they are currently allowed.
// Fix the classifier, then these turn green. Do not weaken/remove these tests.
// ---------------------------------------------------------------------------
test('GAP: $HOME variable expansion must not bypass sensitive-read deny', () => {
  for (const cmd of [
    'cat $HOME/.ssh/id_rsa',
    'cat ${HOME}/.ssh/id_rsa',
    'cat "$HOME/.ssh/id_rsa"',
    'cat $HOME/.ssh/config',
  ]) {
    const { d } = gate(cmd)
    assert.equal(d.allow, false, `GAP must block \$HOME :: ${cmd.slice(0, 52)}`)
  }
})

test('GAP: cd into sensitive dir + relative read must not bypass', () => {
  for (const cmd of [
    'cd ~/.ssh && cat id_rsa',
    'cd ~/.ssh; cat id_rsa',
    'cd ~/.ssh && ls',
    'cd ~/.ssh && cat ../.ssh/id_rsa',
  ]) {
    const { d } = gate(cmd)
    assert.equal(d.allow, false, `GAP must block cd-then-read :: ${cmd.slice(0, 52)}`)
  }
})

test('GAP: command substitution $(...) and backticks must not bypass', () => {
  for (const cmd of [
    'echo $(cat ~/.ssh/id_rsa)',
    'echo `cat ~/.ssh/id_rsa`',
    `echo $(cat ${HOME}/.ssh/id_rsa)`,
    'echo $(cat $HOME/.ssh/id_rsa)',
    'x=$(cat ~/.ssh/id_rsa); echo $x',
    'echo $(cat ~/.ssh/config | grep Host)',
  ]) {
    const { d } = gate(cmd)
    assert.equal(d.allow, false, `GAP must block cmd-subst :: ${cmd.slice(0, 52)}`)
  }
})

test('GAP: interpreter -c/-e code strings must not smuggle sensitive reads', () => {
  for (const cmd of [
    `python3 -c "print(open('${HOME}/.ssh/id_rsa').read())"`,
    `python3 -c 'print(open("${HOME}/.ssh/id_rsa").read())'`,
    `node -e "console.log(require('fs').readFileSync('${HOME}/.ssh/id_rsa'))"`,
    `ruby -e 'puts File.read("${HOME}/.ssh/id_rsa")'`,
    `perl -e 'print readfile("${HOME}/.ssh/id_rsa")'`,
    'python3 -c "import os; print(open(os.path.expanduser(\'~/.ssh/id_rsa\')).read())"',
  ]) {
    const { d } = gate(cmd)
    assert.equal(d.allow, false, `GAP must block interpreter read :: ${cmd.slice(0, 52)}`)
  }
})

// GAP5 (probed 2026-10-02): `find / -name id_rsa -exec cat {} \;` was allow=true —
// the sensitive path only appears as `-name id_rsa` + `{}` placeholder, so the
// literal-path scan misses it, while find resolves the real ~/.ssh/id_rsa.
test('GAP: find -exec private-key name + content-read pair must not bypass', () => {
  const cmds = [
    'find / -name id_rsa -exec cat {} \\;',
    'find / -name id_ed25519 -exec cat {} \\;',
    'find / -name id_rsa -exec head -n 5 {} \\;',
    'find / -name id_rsa -exec sed -n p {} \\;',
    'find / -name id_rsa -exec strings {} \\;',
    'find / -name id_rsa -exec od -c {} \\;',
  ]
  for (const cmd of cmds) {
    const { d } = gate(cmd)
    assert.equal(d.allow, false, `GAP must block find-exec sensitive read :: ${cmd.slice(0, 52)}`)
  }
})

test('REG: find -exec generic names / name-only listing stay allowed', () => {
  const allowed = [
    'find / -name "*.ts" -exec cat {} \\;',
    'find / -name "*.log" -exec tail -n 5 {} \\;',
    'find . -name "*.json" -exec cat {} \\;',
    'find / -name id_rsa -print', // lists names only, never reads content
    'find / -name id_rsa -exec ls -la {} \\;',
  ]
  for (const cmd of allowed) {
    const { d } = gate(cmd)
    assert.equal(d.allow, true, `REG must not over-block :: ${cmd.slice(0, 52)}`)
  }
})
