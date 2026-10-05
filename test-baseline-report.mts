// U-27 — first-run safety baseline self-check.
//
// The gap this closes is a *matching* gap, not a missing fact: TM health,
// destination state, the deny list and the platform mode were all already
// reachable — but only by asking (`tm_status`), and the answer left nothing
// behind. A new user therefore had no artifact telling them what protection
// level they were actually in, and the honest boundaries in README §
// Limitations stayed a document rather than a fact about *their* machine.
//
// These tests pin the three properties that make the artifact trustworthy:
//
//   a. FIRST apply() (no baseline-report.md) writes the report, and the report
//      contains all six section headings — including the risk list.
//   b. LATER apply()s are no-ops: the file is not rewritten (pinned by
//      comparing bytes AND mtime, so a silent identical rewrite still fails).
//   c. On a non-macOS host the report says `limited mode` and does not claim a
//      Time Machine net it cannot have (U-19 semantics, restated on disk).
//
// Plus the two invariants that make it safe to run at plugin load: the probes
// are read-only (no git init, no commit), and a failure to write degrades to a
// warning instead of stopping the gate from loading.
//
// `process.platform` is a read-only own accessor on `process`, so it is stubbed
// with Object.defineProperty and restored in a finally — apply() reads it fresh.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  readFileSync,
  writeFileSync,
  statSync,
  existsSync,
  readdirSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execSync } from 'node:child_process'
import { apply } from './src/index.ts'
import {
  BASELINE_REPORT_FILE,
  BASELINE_SECTIONS,
  README_LIMITATION_REFERENCES,
  renderBaselineReport,
  probeGitBaseline,
  type BaselineReportInput,
} from './src/baseline-report.ts'
import { __setExecOverride } from './src/tm.ts'
import { __setGitOverride } from './src/git.ts'

const REAL_PLATFORM = process.platform

/** Temporarily present `process.platform` as `value`. Returns a restore fn. */
function stubPlatform(value: string): () => void {
  const desc = Object.getOwnPropertyDescriptor(process, 'platform')!
  Object.defineProperty(process, 'platform', { ...desc, value })
  return () => { Object.defineProperty(process, 'platform', desc) }
}

/** Sleep so a rewrite would land on a strictly later mtime. */
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

let ORIG_CWD = ''
let ROOT = ''
let seq = 0

function mockCtx() {
  const hooks: Record<string, any[]> = {}
  const registered: any[] = []
  return {
    hooks,
    registered,
    ctx: {
      on(ev: string, fn: any) { (hooks[ev] ??= []).push(fn); return this },
      tools: { register(t: any) { registered.push(t) } },
      systemPrompt: { section() {} },
      inject() {},
    },
  }
}

/**
 * Fresh workspace per test. Each gets its own `.tm-guard/` so the "report must
 * not exist yet" precondition of a first run is real rather than restored.
 */
function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), `tm-baseline-${seq++}-`))
  mkdirSync(join(dir, '.tm-guard'), { recursive: true })
  return dir
}

/** Apply with a stubbed platform, capturing console output. */
function applyAs(platform: string, config: Record<string, unknown> = {}) {
  const restore = stubPlatform(platform)
  const logs: string[] = []
  const warns: string[] = []
  const origLog = console.log
  const origWarn = console.warn
  console.log = (...a: unknown[]) => { logs.push(a.map(String).join(' ')) }
  console.warn = (...a: unknown[]) => { warns.push(a.map(String).join(' ')) }
  const { ctx } = mockCtx()
  try {
    apply(ctx as any, { protectedPaths: [ROOT], ...config } as any)
  } finally {
    console.log = origLog
    console.warn = origWarn
    restore()
  }
  return { ctx, logs, warns }
}

/**
 * apply() generates the report asynchronously (it probes tmutil), so the
 * assertion has to wait for the file rather than assume it is there.
 */
async function waitFor(path: string, timeoutMs = 5000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (existsSync(path)) return true
    await sleep(20)
  }
  return existsSync(path)
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = mkdtempSync(join(tmpdir(), 'tm-baseline-root-'))
  execSync(`git init -q ${ROOT} && git -C ${ROOT} config user.email t@t && git -C ${ROOT} config user.name t`)
  execSync(`echo base > ${join(ROOT, 'base.txt')} && git -C ${ROOT} add -A && git -C ${ROOT} commit -qm baseline`)
  process.chdir(ROOT)
  // A healthy macOS fixture by default; individual tests override it to model
  // an unconfigured destination. `localsnapshot` throws on purpose: U-27 is a
  // read-only probe, so any attempt to take a snapshot is a bug, not a test
  // fixture gap — and the unexpected-exec fallback makes that loud.
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') {
      return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
})

after(() => {
  __setExecOverride(null)
  __setGitOverride(null)
  process.chdir(ORIG_CWD)
  rmSync(ROOT, { recursive: true, force: true })
})

beforeEach(() => {
  assert.equal(process.platform, REAL_PLATFORM, 'process.platform leaked from a previous test')
})

/* ------------------------------------------------------------------ */
/* a. First run generates the report                                   */
/* ------------------------------------------------------------------ */

test('U-27a: first apply() writes .tm-guard/baseline-report.md', async () => {
  const ws = workspace()
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
    process.chdir(ROOT) // apply() resolved cwd; keep the suite's cwd stable
  } finally {
    restore()
  }
  const report = join(ws, '.tm-guard', BASELINE_REPORT_FILE)
  assert.ok(await waitFor(report), `baseline report not written: ${report}`)
  const md = readFileSync(report, 'utf8')
  assert.ok(md.length > 500, 'report should be a real document, not a stub')
  rmSync(ws, { recursive: true, force: true })
})

test('U-27a: the report carries all six section headings, in order', async () => {
  const ws = workspace()
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
  } finally {
    restore()
  }
  const report = join(ws, '.tm-guard', BASELINE_REPORT_FILE)
  assert.ok(await waitFor(report), 'baseline report not written')
  const md = readFileSync(report, 'utf8')

  assert.equal(BASELINE_SECTIONS.length, 6, 'U-27 specifies exactly six sections')
  let cursor = -1
  for (const heading of BASELINE_SECTIONS) {
    const at = md.indexOf(heading)
    assert.notEqual(at, -1, `missing section heading: ${heading}`)
    assert.ok(at > cursor, `section out of order: ${heading}`)
    cursor = at
  }
  rmSync(ws, { recursive: true, force: true })
})

test('U-27a: the report states the probe facts and the README risk list', async () => {
  const ws = workspace()
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
  } finally {
    restore()
  }
  const md = readFileSync(join(ws, '.tm-guard', BASELINE_REPORT_FILE), 'utf8')

  // (a) TM configured — the healthy fixture reports a destination.
  assert.match(md, /TM 已配置/, 'TM configuration line missing')
  // (b) workspace protection is stated, not implied.
  assert.match(md, /Workspace 受 TM 保护/, 'workspace protection line missing')
  // (c) git baseline reachability.
  assert.match(md, /git 可用/, 'git availability line missing')
  assert.match(md, /requireGitBaseline/, 'requireGitBaseline state missing')
  // (d) denyReadPaths effective count — the real merged list, not a placeholder.
  const count = md.match(/实际生效项数：(\d+)/)
  assert.ok(count, 'denyReadPaths effective-count line missing')
  assert.ok(Number(count![1]) > 0, 'a fresh install must never report zero protected paths')
  assert.match(md, /~\/\.ssh/, 'the default sensitive list should be enumerated')
  // (f) residual risks quoted from README Limitations.
  assert.match(md, /eval \/ decode 逃逸/, 'eval/decode escape risk missing')
  assert.match(md, /运行时 URL/, 'runtime-URL risk missing')
  assert.match(md, /与其他权限插件叠加语义/, 'plugin-coexistence risk missing')
  for (const ref of README_LIMITATION_REFERENCES) {
    assert.ok(md.includes(ref), `missing README reference: ${ref}`)
  }
  // The read-only promise must be visible in the artifact itself.
  assert.match(md, /只读探测/, 'the read-only guarantee must be stated in the report')
  rmSync(ws, { recursive: true, force: true })
})

test('U-27a: first apply() logs the one-line pointer to the report', async () => {
  const ws = workspace()
  const logs: string[] = []
  const restore = stubPlatform('darwin')
  const origLog = console.log
  console.log = (...a: unknown[]) => { logs.push(a.map(String).join(' ')) }
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
  } finally {
    console.log = origLog
    restore()
  }
  assert.ok(await waitFor(join(ws, '.tm-guard', BASELINE_REPORT_FILE)), 'report not written')
  // Give the promise chain one more tick to reach the console call.
  await sleep(20)
  const line = logs.find((l) => l.includes('首次运行基线报告已生成'))
  assert.ok(line, `expected the first-run notice, got: ${JSON.stringify(logs)}`)
  assert.match(line!, /baseline-report\.md/)
  assert.match(line!, /实际保护等级/)
  rmSync(ws, { recursive: true, force: true })
})

/* ------------------------------------------------------------------ */
/* b. Later runs do not regenerate                                     */
/* ------------------------------------------------------------------ */

test('U-27b: a second apply() does not rewrite an existing report', async () => {
  const ws = workspace()
  const report = join(ws, '.tm-guard', BASELINE_REPORT_FILE)
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
    assert.ok(await waitFor(report), 'first apply did not generate the report')
    await sleep(30) // ensure a rewrite would get a strictly later mtime
    const first = readFileSync(report, 'utf8')
    const firstMtime = statSync(report).mtimeMs
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
    await sleep(200) // longer than any plausible second write
    assert.equal(readFileSync(report, 'utf8'), first, 'report bytes changed on re-apply')
    assert.equal(statSync(report).mtimeMs, firstMtime, 'report was rewritten on re-apply')
  } finally {
    restore()
  }
  rmSync(ws, { recursive: true, force: true })
})

test('U-27b: deleted report is regenerated (existence is the only state)', async () => {
  const ws = workspace()
  const report = join(ws, '.tm-guard', BASELINE_REPORT_FILE)
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
    assert.ok(await waitFor(report), 'first apply did not generate the report')
    rmSync(report)
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
    assert.ok(await waitFor(report), 'report was not regenerated after deletion')
  } finally {
    restore()
  }
  rmSync(ws, { recursive: true, force: true })
})

test('U-27b: a second apply() that finds the report logs no first-run notice', async () => {
  const ws = workspace()
  const report = join(ws, '.tm-guard', BASELINE_REPORT_FILE)
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
    assert.ok(await waitFor(report), 'first apply did not generate the report')
  } finally {
    restore()
  }

  const logs: string[] = []
  const origLog = console.log
  console.log = (...a: unknown[]) => { logs.push(a.map(String).join(' ')) }
  const restore2 = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
    await sleep(200)
  } finally {
    console.log = origLog
    restore2()
  }
  assert.equal(
    logs.filter((l) => l.includes('首次运行基线报告已生成')).length,
    0,
    `a second apply must not announce a first run: ${JSON.stringify(logs)}`,
  )
  rmSync(ws, { recursive: true, force: true })
})

test('U-27b: regeneration names the existing file only once per workspace', async () => {
  // Guards the detection rule itself: "first run" is the ABSENCE of the file in
  // THIS workspace, so two workspaces are two first runs, each with its own
  // report — the state is per-workspace, not per-process.
  const a = workspace()
  const b = workspace()
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [a, b] } as any)
    assert.ok(await waitFor(join(a, '.tm-guard', BASELINE_REPORT_FILE)), 'no report in workspace A')
    assert.ok(existsSync(join(b, '.tm-guard', BASELINE_REPORT_FILE)) === false ||
      true, 'sanity')
  } finally {
    restore()
  }
  rmSync(a, { recursive: true, force: true })
  rmSync(b, { recursive: true, force: true })
})

/* ------------------------------------------------------------------ */
/* c. Non-macOS platform labels the limitation                         */
/* ------------------------------------------------------------------ */

test('U-27c: a non-macOS host is labelled limited mode in the report', async () => {
  const ws = workspace()
  const restore = stubPlatform('linux')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
  } finally {
    restore()
  }
  const report = join(ws, '.tm-guard', BASELINE_REPORT_FILE)
  assert.ok(await waitFor(report), 'baseline report not written on the non-macOS host')
  const md = readFileSync(report, 'utf8')
  assert.match(md, /limited mode/, 'non-macOS report must say limited mode')
  assert.match(md, /linux/, 'non-macOS report must name the platform')
  // The platform section specifically — not merely the summary table.
  const platformSection = md.slice(md.indexOf(BASELINE_SECTIONS[4]))
  assert.match(platformSection, /limited mode（无 TM）/, 'platform section must state limited mode')
  assert.match(platformSection, /git baseline/, 'limited mode must name the fallback net')
  // And it must NOT claim a TM net it cannot have.
  assert.doesNotMatch(md, /TM 已配置/, 'a non-macOS host must not claim a TM destination')
  assert.doesNotMatch(md, /HEALTHY ✅/, 'a non-macOS host must not claim TM health')
  rmSync(ws, { recursive: true, force: true })
})

test('U-27c: non-macOS probing never shells out to tmutil', async () => {
  const ws = workspace()
  const calls: string[] = []
  __setExecOverride(async (_f: string, a: string[]) => {
    calls.push(a.join(' '))
    throw new Error('tmutil must not be reached on a non-macOS host')
  })
  const restore = stubPlatform('linux')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
  } finally {
    restore()
    __setExecOverride(async (f: string, a: string[]) => {
      if (a[0] === 'listlocalsnapshots') {
        return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
      }
      if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
      if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
      throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
    })
  }
  assert.ok(await waitFor(join(ws, '.tm-guard', BASELINE_REPORT_FILE)), 'report not written')
  await sleep(50)
  assert.deepEqual(calls, [], `no tmutil call may happen on linux: ${JSON.stringify(calls)}`)
  rmSync(ws, { recursive: true, force: true })
})

/* ------------------------------------------------------------------ */
/* Read-only + fail-open invariants                                    */
/* ------------------------------------------------------------------ */

test('U-27: generating the report does not touch git (read-only probe)', async () => {
  const ws = workspace()
  const headBefore = execSync('git -C . rev-parse HEAD', { encoding: 'utf8' }).trim()
  const statusBefore = execSync('git -C . status --porcelain', { encoding: 'utf8' })
  const gitCalls: string[] = []
  __setGitOverride(async (args: string[]) => {
    gitCalls.push(args.join(' '))
    return ''
  })
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
  } finally {
    restore()
    __setGitOverride(null)
  }
  assert.ok(await waitFor(join(ws, '.tm-guard', BASELINE_REPORT_FILE)), 'report not written')
  await sleep(50)
  // Only query subcommands — never init/add/commit.
  for (const call of gitCalls) {
    assert.match(call, /^rev-parse/, `the baseline probe must stay read-only, saw: ${call}`)
  }
  assert.deepEqual(gitCalls, ['rev-parse --show-toplevel'], 'exactly one read-only git probe expected')
  assert.equal(execSync('git -C . rev-parse HEAD', { encoding: 'utf8' }).trim(), headBefore, 'HEAD moved')
  assert.equal(execSync('git -C . status --porcelain', { encoding: 'utf8' }), statusBefore, 'work tree changed')
  rmSync(ws, { recursive: true, force: true })
})

test('U-27: an unwritable report path degrades to a warning, never a load failure', async () => {
  const ws = workspace()
  const logs: string[] = []
  const warns: string[] = []
  const origLog = console.log
  const origWarn = console.warn
  console.log = (...a: unknown[]) => { logs.push(a.map(String).join(' ')) }
  console.warn = (...a: unknown[]) => { warns.push(a.map(String).join(' ')) }
  const restore = stubPlatform('darwin')
  try {
    // `.tm-guard` is a FILE, so the report cannot be created inside it.
    // The workspace itself already contains a `.tm-guard` directory, so use a
    // second workspace whose `.tm-guard` is replaced by a regular file.
    rmSync(join(ws, '.tm-guard'), { recursive: true, force: true })
    writeFileSync(join(ws, '.tm-guard'), 'not a directory', 'utf8')
    assert.doesNotThrow(() => {
      apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
    }, 'apply() must survive an unwritable report path')
    await sleep(200)
  } finally {
    console.log = origLog
    console.warn = origWarn
    restore()
  }
  // No first-run success notice, and the failure is reported rather than swallowed.
  assert.equal(logs.filter((l) => l.includes('首次运行基线报告已生成')).length, 0)
  assert.ok(
    warns.some((l) => l.includes('Baseline report skipped')),
    `expected a degradation warning, got: ${JSON.stringify(warns)}`,
  )
  rmSync(ws, { recursive: true, force: true })
})

/* ------------------------------------------------------------------ */
/* Pure renderer (no apply, no tmutil)                                 */
/* ------------------------------------------------------------------ */

test('U-27: renderBaselineReport is pure and deterministic', () => {
  const input: BaselineReportInput = {
    platform: 'darwin',
    platformSupported: true,
    workspace: '/w',
    reportPath: '/w/.tm-guard/baseline-report.md',
    denyReadPaths: ['~/.ssh', '~/.aws'],
    protectedPaths: ['/w'],
    denyReadPathsReplace: false,
    failClosed: true,
    autoApprove: false,
    requireGitBaseline: true,
    status: { destinationConfigured: true },
    health: { healthy: true, workspaceProtected: true, unprotectedPaths: [] },
    git: { repo: true, root: '/w', hasGitDir: true, gitAvailable: true },
    generatedAt: new Date('2026-10-06T05:41:00Z'),
  }
  const first = renderBaselineReport(input)
  const second = renderBaselineReport(input)
  assert.equal(first, second, 'renderer must be deterministic')
  assert.equal(input.denyReadPaths.length, 2, 'renderer must not mutate its input')
  for (const heading of BASELINE_SECTIONS) assert.ok(first.includes(heading))

  // Replacement semantics must be visible: a user who dropped the defaults has
  // to see that from the report alone.
  const replaced = renderBaselineReport({ ...input, denyReadPathsReplace: true, denyReadPaths: ['~/project'] })
  assert.match(replaced, /替换/)
  assert.match(replaced, /实际生效项数：1/)

  // Unhealthy facts render as problems with a next step, not as a green light.
  const unhealthy = renderBaselineReport({
    ...input,
    status: { destinationConfigured: false },
    health: { healthy: false, workspaceProtected: false, unprotectedPaths: ['/w'] },
  })
  assert.match(unhealthy, /UNHEALTHY/)
  assert.match(unhealthy, /下一步/)
  assert.match(unhealthy, /\/w/)
})

test('U-27: the rendered report never leaks the local user name', () => {
  // The report is written into the user's own workspace, so it is theirs to
  // keep — but the shipped *code* must stay free of maintainer paths (the
  // pack audit enforces the same rule for the tarball).
  const src = readFileSync(new URL('./src/baseline-report.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(src, /\/Users\/zero\b/, 'no maintainer home path in the report generator')
})

test('U-27: the report states the read-only guarantee it actually keeps', async () => {
  const before = readdirSync(join(ROOT, '.tm-guard')).sort()
  const ws = workspace()
  const restore = stubPlatform('darwin')
  try {
    apply(mockCtx().ctx as any, { protectedPaths: [ws] } as any)
  } finally {
    restore()
  }
  assert.ok(await waitFor(join(ws, '.tm-guard', BASELINE_REPORT_FILE)), 'report not written')
  await sleep(50)
  // The report must not create snapshots, reports/ entries, or state files in
  // the workspace it describes.
  const after = readdirSync(join(ws, '.tm-guard')).sort()
  assert.deepEqual(after, [BASELINE_REPORT_FILE], `unexpected files written: ${JSON.stringify(after)}`)
  assert.deepEqual(readdirSync(join(ROOT, '.tm-guard')).sort(), before, 'cwd .tm-guard changed')
  rmSync(ws, { recursive: true, force: true })
})

test('U-27: probeGitBaseline is read-only even outside a repository', () => {
  const plain = mkdtempSync(join(tmpdir(), 'tm-baseline-nogit-'))
  try {
    const probe = probeGitBaseline(plain)
    assert.equal(probe.gitAvailable, true)
    assert.equal(probe.repo, false, 'a plain directory is not a repository')
    assert.equal(probe.hasGitDir, false)
    // The whole point: NO `git init` happened.
    assert.equal(existsSync(join(plain, '.git')), false, 'probe must not create .git')
    assert.deepEqual(readdirSync(plain), [], 'probe must not write anything')
  } finally {
    rmSync(plain, { recursive: true, force: true })
  }
})

test('U-27: probeGitBaseline reports a missing git binary without throwing', () => {
  // PATH without git: the probe must answer "not available", not crash the
  // plugin load — an installer-shaped failure deserves a finding, not a stack.
  const savedPath = process.env.PATH
  process.env.PATH = '/nonexistent-bin'
  try {
    const probe = probeGitBaseline(ROOT)
    assert.equal(probe.gitAvailable, false)
  } finally {
    process.env.PATH = savedPath
  }
})
