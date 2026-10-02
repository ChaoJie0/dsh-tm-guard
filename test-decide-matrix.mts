// decide() truth-table matrix — Cartesian product of (category × forceDeny ×
// pathsProtected × targetPaths shape) asserting the exact gate output.
// Plus an integration pass: real classifyBashCommand output for every category
// fed into decide must match the same expected table.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand, classifyToolCall, decide } from './src/classifier.ts'
import type { ClassifyResult } from './src/classifier.ts'

const DENY_READ = [
  '~/.ssh', '~/.aws', '~/.gnupg', '~/.kube', '~/.docker', '~/.netrc',
  '~/.git-credentials', '~/.npmrc', '~/.pypirc', '~/.config',
  '~/Library/Keychains', '~/Library/Cookies',
]

const ALL_CATEGORIES = [
  'read', 'file_write', 'file_read', 'network', 'local_network', 'local_exec',
  'vcs_local', 'vcs_remote', 'system', 'package', 'process', 'mixed', 'unknown',
] as const

interface Expect { allow: boolean; snapshot: boolean }

// Expected gate for each (category, pathsProtected, tempOnly) from decide():
function expectedGate(
  category: string,
  pathsProtected: boolean,
  tempOnly: boolean,
  forceDeny: boolean,
): Expect {
  if (forceDeny) return { allow: false, snapshot: false }
  switch (category) {
    case 'read':
    case 'vcs_local':
    case 'local_exec':
    case 'local_network':
      return { allow: true, snapshot: false }
    // 'file_read' is not produced by the classifier today — it must fall
    // through to the fail-closed default (never allow an unlisted category).
    case 'file_write':
      if (pathsProtected) return { allow: true, snapshot: true }
      if (tempOnly) return { allow: true, snapshot: false }
      return { allow: false, snapshot: false }
    case 'network':
    case 'vcs_remote':
    case 'package':
    case 'process':
    case 'system':
      return { allow: false, snapshot: false }
    case 'mixed':
    case 'unknown':
    case 'file_read':
    default:
      return { allow: false, snapshot: false }
  }
}

function mkResult(
  category: string,
  forceDeny: boolean,
  tempOnly: boolean,
): ClassifyResult {
  return {
    category: category as ClassifyResult['category'],
    reason: `synthetic ${category}`,
    targetPaths: tempOnly ? ['/tmp/x'] : category === 'file_write' ? ['/Users/zero/Claude Code/x'] : [],
    forceDeny,
  }
}

test('decide: full truth table over category × forceDeny × pathsProtected × temp', () => {
  for (const category of ALL_CATEGORIES) {
    for (const forceDeny of [true, false]) {
      for (const pathsProtected of [true, false]) {
        for (const tempOnly of [true, false]) {
          const res = mkResult(category, forceDeny, tempOnly)
          const d = decide(res, pathsProtected)
          const exp = expectedGate(category, pathsProtected, tempOnly, forceDeny)
          assert.equal(d.allow, exp.allow,
            `allow mismatch :: ${category} fd=${forceDeny} pp=${pathsProtected} temp=${tempOnly} :: got ${JSON.stringify(d)}`)
          assert.equal(d.shouldSnapshot, exp.snapshot,
            `snapshot mismatch :: ${category} fd=${forceDeny} pp=${pathsProtected} temp=${tempOnly}`)
          assert.equal(typeof d.category, 'string', `category missing :: ${category}`)
          assert.ok(d.reason.length > 0, `reason missing :: ${category}`)
        }
      }
    }
  }
})

// Real classifier output for each category, then decide() must match the table.
test('decide: real classifications feed the same truth table', () => {
  const producers: Record<string, () => ClassifyResult> = {
    read: () => classifyBashCommand('cat /tmp/x', DENY_READ),
    // (sed also classifies as read — no file_read category exists today)
    file_write: () => classifyBashCommand('echo hi > /tmp/out.txt', DENY_READ),
    network: () => classifyBashCommand('curl https://example.com/x', DENY_READ),
    local_network: () => classifyBashCommand('curl http://127.0.0.1:8080/x', DENY_READ),
    local_exec: () => classifyBashCommand('npm run build', DENY_READ),
    vcs_local: () => classifyBashCommand('git status', DENY_READ),
    vcs_remote: () => classifyBashCommand('git push origin main', DENY_READ),
    system: () => classifyBashCommand('reboot', DENY_READ),
    package: () => classifyBashCommand('npx cowsay hi', DENY_READ),
    process: () => classifyBashCommand('kill 1234', DENY_READ),
    mixed: () => classifyToolCall('subagent_create', {}, DENY_READ),
    unknown: () => classifyToolCall('mystery_tool', {}, DENY_READ),
  }
  for (const [category, produce] of Object.entries(producers)) {
    const res = produce()
    assert.equal(res.category, category,
      `producer mismatch :: ${category} got ${res.category}`)
    for (const pp of [true, false]) {
      const d = decide(res, pp)
      const tempOnly = res.targetPaths.length > 0 &&
        res.targetPaths.every((p) => p.startsWith('/tmp'))
      const exp = expectedGate(res.category, pp, tempOnly, res.forceDeny ?? false)
      assert.equal(d.allow, exp.allow,
        `real allow mismatch :: ${category} pp=${pp} :: ${JSON.stringify(res)} -> ${JSON.stringify(d)}`)
    }
  }
})

test('decide: forceDeny wins regardless of category', () => {
  for (const category of ALL_CATEGORIES) {
    const res = mkResult(category, true, false)
    const d = decide(res, true)
    assert.equal(d.allow, false, `forceDeny allow :: ${category}`)
    assert.match(d.reason, /forced deny/, `reason marker :: ${category}`)
  }
})
