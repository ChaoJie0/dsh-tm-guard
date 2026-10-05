// U-18 — sensitive-path list externalised, extended, and made additive.
//
// Three problems are locked down here:
//   1. The default deny-read list was hardcoded inline in index.ts, so it
//      drifted as the ecosystem grew. The two years since v0.2.0 produced a
//      generation of agent/CLI credential stores (~/.cursor, ~/.codex,
//      ~/.gemini, …) that the old list did not cover at all. Those are real
//      gaps: an autonomous agent reading ~/.codex/auth.json or ~/.cursor/mcp.json
//      obtains long-lived tokens for other execution surfaces.
//   2. The list now lives in src/sensitive-paths.ts as DEFAULT_SENSITIVE_PATHS —
//      data that a reviewer can audit independently of the gate logic.
//   3. `config.denyReadPaths` used to REPLACE the defaults, so a profile that
//      appended one project path silently dropped every cloud/agent credential
//      entry. It is now additive, with `denyReadPathsReplace: true` as the
//      explicit opt-in to the old behaviour.
//
// Behaviour is asserted through the real gate (classify + apply), not just by
// comparing arrays — a list entry that never reaches the classifier protects
// nothing.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execSync } from 'node:child_process'
import { DEFAULT_SENSITIVE_PATHS, mergeDenyReadPaths } from './src/sensitive-paths.ts'
import { DEFAULT_CONFIG, apply } from './src/index.ts'
import { classifyBashCommand } from './src/classifier.ts'
import { __setExecOverride } from './src/tm.ts'
import { __setGitOverride } from './src/git.ts'

let ORIG_CWD = ''
let ROOT = ''

function mockCtx() {
  const hooks: Record<string, any[]> = {}
  return {
    hooks,
    ctx: {
      on(ev: string, fn: any) { (hooks[ev] ??= []).push(fn); return this },
      tools: { register() {} },
      systemPrompt: { section() {} },
      inject() {},
    },
  }
}

/** The effective deny list a config produces (pure, no apply needed). */
function listFor(config?: { denyReadPaths?: string[]; denyReadPathsReplace?: boolean }): string[] {
  const replace = config?.denyReadPathsReplace ?? false
  return mergeDenyReadPaths(config?.denyReadPaths, replace)
}

/** True when the classifier denies reading `cmd` under `denyPaths`. */
function isDenied(cmd: string, denyPaths: string[]): boolean {
  return classifyBashCommand(cmd, denyPaths).forceDeny === true
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = mkdtempSync(join(tmpdir(), 'tm-sens-'))
  execSync(`git init -q ${ROOT} && git -C ${ROOT} config user.email t@t && git -C ${ROOT} config user.name t`)
  execSync(`echo base > ${join(ROOT, 'base.txt')} && git -C ${ROOT} add -A && git -C ${ROOT} commit -qm baseline`)
  process.chdir(ROOT)
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') {
      return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
    if (a[0] === 'localsnapshot') {
      return { stdout: 'com.apple.TimeMachine.2026-10-06-120000.local\n' }
    }
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
})

after(() => {
  __setExecOverride(null)
  __setGitOverride(null)
  process.chdir(ORIG_CWD)
  rmSync(ROOT, { recursive: true, force: true })
})

/* ---------------------------------------------------------------- */
/* a. the list is externalised and DEFAULT_CONFIG mirrors it          */
/* ---------------------------------------------------------------- */

test('U-18a: DEFAULT_SENSITIVE_PATHS is exported and DEFAULT_CONFIG mirrors it', () => {
  assert.ok(Array.isArray(DEFAULT_SENSITIVE_PATHS), 'must be an array')
  assert.ok(DEFAULT_SENSITIVE_PATHS.length >= 19, `list has ${DEFAULT_SENSITIVE_PATHS.length} entries`)
  assert.deepEqual(
    DEFAULT_CONFIG.denyReadPaths,
    [...DEFAULT_SENSITIVE_PATHS],
    'DEFAULT_CONFIG.denyReadPaths must mirror the exported constant',
  )
  // A defensive copy, not the same array: DEFAULT_CONFIG is exported, and a
  // caller mutating it in place must not corrupt the module constant.
  assert.notEqual(
    DEFAULT_CONFIG.denyReadPaths,
    DEFAULT_SENSITIVE_PATHS,
    'DEFAULT_CONFIG must hold a copy, not alias the module constant',
  )
})

/* ---------------------------------------------------------------- */
/* b. the newly covered agent/CLI credential locations                */
/* ---------------------------------------------------------------- */

test('U-18b: ~/.aws/credentials is in the default denyReadPaths', () => {
  assert.ok(
    DEFAULT_CONFIG.denyReadPaths.includes('~/.aws/credentials') ||
    DEFAULT_CONFIG.denyReadPaths.includes('~/.aws'),
    `expected ~/.aws/credentials (or the ~/.aws prefix) in ${JSON.stringify(DEFAULT_CONFIG.denyReadPaths)}`,
  )
  assert.ok(DEFAULT_CONFIG.denyReadPaths.includes('~/.ssh/config') || DEFAULT_CONFIG.denyReadPaths.includes('~/.ssh'))
  assert.ok(DEFAULT_CONFIG.denyReadPaths.includes('~/.netrc'))
  assert.ok(DEFAULT_CONFIG.denyReadPaths.includes('~/.gnupg'))
  assert.ok(DEFAULT_CONFIG.denyReadPaths.includes('~/.ssh'))
})

test('U-18b: agent/CLI credential stores are covered by the defaults', () => {
  const required = [
    '~/.config/gh/hosts.yml', // GitHub CLI OAuth token
    '~/.cursor',
    '~/.codex',
    '~/.aws/credentials',
    '~/.gnupg',
    '~/.ssh',
    '~/.netrc',
  ]
  for (const p of required) {
    assert.ok(
      DEFAULT_CONFIG.denyReadPaths.includes(p),
      `default denyReadPaths is missing ${p}`,
    )
  }
})

test('U-18b: the new agent credential paths are actually DENIED by the gate', () => {
  const deny = DEFAULT_CONFIG.denyReadPaths
  // These are the concrete pre-fix gaps: all three were ALLOWED before U-18.
  const mustDeny = [
    'cat ~/.cursor/mcp.json',
    'ls ~/.cursor/',
    'cat ~/.codex/auth.json',
    'cat ~/.codex/config.toml',
    'cat ~/.config/gh/hosts.yml',
    'cat ~/.aws/credentials',
    'cat ~/.ssh/config',
    'cat ~/.gnupg/secring.gpg',
    'cat ~/.netrc',
  ]
  for (const cmd of mustDeny) {
    assert.equal(isDenied(cmd, deny), true, `default list must deny: ${cmd}`)
  }
})

test('U-18b: pre-existing credential coverage is not regressed', () => {
  const deny = DEFAULT_CONFIG.denyReadPaths
  for (const cmd of [
    'cat ~/.ssh/id_rsa',
    'cat ~/.npmrc',
    'cat ~/.git-credentials',
    'cat ~/.pypirc',
    'cat ~/.kube/config',
    'cat ~/.docker/config.json',
    'cat ~/Library/Keychains/login.keychain-db',
    'cat ~/Library/Cookies/Cookies.binarycookies',
  ]) {
    assert.equal(isDenied(cmd, deny), true, `must stay denied: ${cmd}`)
  }
})

test('U-18b: redirection smuggling of a new agent credential is still denied', () => {
  const deny = DEFAULT_CONFIG.denyReadPaths
  assert.equal(
    isDenied('cat ~/.codex/auth.json > project/out.txt', deny),
    true,
    'writing a credential into the workspace must remain denied',
  )
})

/* ---------------------------------------------------------------- */
/* c. merge semantics: additive by default, replace on opt-in        */
/* ---------------------------------------------------------------- */

test('U-18c: user paths are APPENDED to the defaults (defaults survive)', () => {
  const user = '~/work/private-credentials'
  const merged = listFor({ denyReadPaths: [user] })
  assert.ok(merged.includes(user), 'user path must be present')
  // The critical assertion: every default survives a user addition.
  for (const p of DEFAULT_SENSITIVE_PATHS) {
    assert.ok(merged.includes(p), `default ${p} was dropped by a user addition`)
  }
  assert.equal(merged.length, DEFAULT_SENSITIVE_PATHS.length + 1)
})

test('U-18c: additive merge still denies both the default and the user path', () => {
  const merged = listFor({ denyReadPaths: ['~/work/private-credentials'] })
  assert.equal(isDenied('cat ~/.aws/credentials', merged), true, 'default must still be denied')
  assert.equal(isDenied('cat ~/work/private-credentials/token', merged), true, 'user path must be denied')
})

test('U-18c: duplicate user entries do not duplicate list entries', () => {
  const merged = listFor({ denyReadPaths: ['~/.ssh', '~/.ssh', '~/extra'] })
  assert.equal(merged.filter((p) => p === '~/.ssh').length, 1, '~/.ssh must appear once')
  assert.equal(merged.length, DEFAULT_SENSITIVE_PATHS.length + 1)
})

test('U-18c: denyReadPathsReplace=true replaces the defaults outright', () => {
  const user = ['~/.ssh', '/opt/secrets']
  const merged = listFor({ denyReadPaths: user, denyReadPathsReplace: true })
  assert.deepEqual(merged, user, 'replace mode must yield exactly the user list')
  for (const p of DEFAULT_SENSITIVE_PATHS) {
    if (!user.includes(p)) {
      assert.equal(merged.includes(p), false, `replace mode must drop default ${p}`)
    }
  }
  // And the dropped default is genuinely no longer enforced.
  assert.equal(isDenied('cat ~/.codex/auth.json', merged), false, 'replaced-away default must not be enforced')
  assert.equal(isDenied('cat /opt/secrets/token', merged), true, 'user path must be enforced')
})

test('U-18c: replace with an empty list disables the restriction (documented opt-out)', () => {
  const merged = listFor({ denyReadPaths: [], denyReadPathsReplace: true })
  assert.deepEqual(merged, [])
  assert.equal(isDenied('cat ~/.ssh/id_rsa', merged), false, 'empty replace list disables the deny set')
})

test('U-18c: DEFAULT_CONFIG defaults to additive (denyReadPathsReplace=false)', () => {
  assert.equal(DEFAULT_CONFIG.denyReadPathsReplace, false)
})

test('U-18c: apply() wires the additive merge into the live gate', async () => {
  // End-to-end: a config that adds one path must NOT disable credential denial.
  const { ctx, hooks } = mockCtx()
  const prev = console.warn, prevErr = console.error, prevLog = console.log
  console.warn = () => {}; console.error = () => {}; console.log = () => {}
  try {
    apply(ctx as any, {
      protectedPaths: [ROOT],
      denyReadPaths: ['~/work/private-credentials'],
    })
  } finally {
    console.warn = prev; console.error = prevErr; console.log = prevLog
  }
  const gate = hooks['tools/pre-execute'][0]
  const next = () => Promise.resolve({ kind: 'allow', reason: 'next' })
  const denied = await gate({ name: 'bash', arguments: { command: 'cat ~/.codex/auth.json' } }, next)
  assert.equal(denied.kind, 'deny', 'a user addition must not drop the default credential denial')
  const added = await gate({ name: 'bash', arguments: { command: 'cat ~/work/private-credentials/token' } }, next)
  assert.equal(added.kind, 'deny', 'the user-added path must be enforced')
})

test('U-18c: replace mode in apply() drops the defaults in the live gate', async () => {
  const { ctx, hooks } = mockCtx()
  const prev = console.warn, prevErr = console.error, prevLog = console.log
  const warns: string[] = []
  console.warn = (...a: unknown[]) => { warns.push(a.map(String).join(' ')) }
  console.error = () => {}; console.log = () => {}
  try {
    apply(ctx as any, {
      protectedPaths: [ROOT],
      denyReadPathsReplace: true,
      denyReadPaths: ['~/only-this'],
    })
  } finally {
    console.warn = prev; console.error = prevErr; console.log = prevLog
  }
  const gate = hooks['tools/pre-execute'][0]
  const next = () => Promise.resolve({ kind: 'allow', reason: 'next' })
  const nowAllowed = await gate({ name: 'bash', arguments: { command: 'cat ~/.codex/auth.json' } }, next)
  assert.equal(nowAllowed.kind, 'allow', 'replaced-away default must genuinely stop being denied')
  // Replacement is fail-open, so it must never be silent.
  const notice = warns.find((l) => l.includes('denyReadPathsReplace=true'))
  assert.ok(notice, `replace mode must warn about dropped defaults: ${JSON.stringify(warns)}`)
  assert.match(notice!, /~\/\.codex/, 'the warning should name the dropped defaults')
})

test('U-18c: apply() without a denyReadPaths key keeps the full default list', async () => {
  const { ctx, hooks } = mockCtx()
  const prev = console.warn, prevErr = console.error, prevLog = console.log
  console.warn = () => {}; console.error = () => {}; console.log = () => {}
  try {
    apply(ctx as any, { protectedPaths: [ROOT] })
  } finally {
    console.warn = prev; console.error = prevErr; console.log = prevLog
  }
  const gate = hooks['tools/pre-execute'][0]
  const next = () => Promise.resolve({ kind: 'allow', reason: 'next' })
  for (const cmd of ['cat ~/.aws/credentials', 'cat ~/.cursor/mcp.json', 'cat ~/.codex/auth.json']) {
    const r = await gate({ name: 'bash', arguments: { command: cmd } }, next)
    assert.equal(r.kind, 'deny', `default config must deny: ${cmd}`)
  }
})

test('U-18c: malformed denyReadPaths (non-string entries) degrades safely', () => {
  // A hand-edited cordis.patch.yml can carry numbers/nulls. They must be
  // dropped rather than reaching the matcher, and the defaults must survive.
  const merged = mergeDenyReadPaths(
    ['~/.custom', 42, null, undefined] as unknown as string[],
    false,
  )
  assert.ok(merged.includes('~/.custom'))
  assert.equal(merged.some((p) => typeof p !== 'string'), false, 'only strings may reach the matcher')
  for (const p of DEFAULT_SENSITIVE_PATHS) assert.ok(merged.includes(p))
})
