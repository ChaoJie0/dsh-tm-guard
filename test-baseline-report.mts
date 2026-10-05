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
//   a. FIRST apply() (no baseline-report.md in the workspace) writes the report,
//      and the report contains all six section headings — including the risk
//      list quoted from README Limitations.
//   b. LATER apply()s are no-ops: the file is not rewritten (pinned by comparing
//      bytes AND mtime, so even an identical silent rewrite fails), and the
//      first-run notice is printed exactly once per workspace.
//   c. On a non-macOS host the report says `limited mode`, names the git
//      baseline as the only rollback net, and does not claim a Time Machine net
//      it cannot have (U-19 semantics, restated on disk).
//
// Plus the invariants that make this safe to run at plugin load: the probes are
// read-only (no git init/commit, no tmutil on non-macOS, nothing but the report
// written into the workspace), and an unwritable report path degrades to a
// warning instead of stopping the gate from loading.
//
// Two harness details worth stating, because both encode a decision:
//
//   * The workspace under test is selected by chdir'ing into it. There is no
//     other seam: apply() builds its single `AuditLog` from `process.cwd()`
//     (design §4.2.2 — one instance, one `.tm-guard/`), and `.tm-guard/` is
//     where U-27 writes. The suite therefore restores the original cwd after
//     every test, and `ROOT` keeps the git repo the gate itself resolves.
//   * `apply()` is called between console capture boundaries, so the report —
//     which is written synchronously on the first run — is asserted directly
//     rather than raced against a promise.
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

/** Fresh workspace per test: its own `.tm-guard/`, so "first run" is real. */
function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), `tm-baseline-${seq++}-`))
  mkdirSync(join(dir, '.tm-guard'), { recursive: true })
  return dir
}

/**
 * Queue a workspace for removal at process exit.
 *
 * Deliberately NOT `t.after(cleanup)`: node:test tears per-test hooks down
 * after the test settles, which would delete the workspace while an assertion
 * failure is still formatting its message (and is racy for the async tests).
 * Deferring every removal to one exit hook keeps all of them independent of
 * test timing.
 */
const pendingCleanup: string[] = []
function planCleanup(dir: string): void {
  pendingCleanup.push(dir)
}

/** console.log capture that can be opened and closed around several apply()s. */
function logCapture() {
  const logs: string[] = []
  const warns: string[] = []
  const origLog = console.log
  const origWarn = console.warn
  return {
    logs,
    warns,
    open() {
      console.log = (...a: unknown[]) => { logs.push(a.map(String).join(' ')) }
      console.warn = (...a: unknown[]) => { warns.push(a.map(String).join(' ')) }
    },
    close() {
      console.log = origLog
      console.warn = origWarn
    },
  }
}

/**
 * Run one apply() against `workspace` with `platform` presented as current.
 * Fully synchronous: the first-run report is written before apply() returns.
 */
function applyIn(workspace: string, platform: string, config: Record<string, unknown> = {}) {
  const restorePlatform = stubPlatform(platform)
  const savedCwd = process.cwd()
  process.chdir(workspace)
  try {
    const m = mockCtx()
    apply(m.ctx as any, { protectedPaths: [workspace], ...config } as any)
    return m
  } finally {
    process.chdir(savedCwd)
    restorePlatform()
  }
}

function reportOf(workspace: string): string {
  return join(workspace, '.tm-guard', BASELINE_REPORT_FILE)
}

/**
 * Wait until the asynchronous TM refinement has replaced the placeholder.
 * The report itself is written synchronously (that is the point of U-27's
 * first-run contract); only section 1 is filled in later.
 */
async function waitForTmSection(report: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      // "TM 探测未完成" is the PLACEHOLDER, not a finished state — matching it
      // here would return before the refinement this helper exists to await.
      if (/TM 已配置|TM 不适用/.test(readFileSync(report, 'utf8'))) return
    } catch {
      // Not written yet.
    }
    await sleep(20)
  }
}

before(() => {
  ORIG_CWD = process.cwd()
  ROOT = mkdtempSync(join(tmpdir(), 'tm-baseline-root-'))
  execSync(`git init -q ${ROOT} && git -C ${ROOT} config user.email t@t && git -C ${ROOT} config user.name t`)
  execSync(`echo base > ${join(ROOT, 'base.txt')} && git -C ${ROOT} add -A && git -C ${ROOT} commit -qm baseline`)
  process.chdir(ROOT)
  // A healthy macOS fixture. `localsnapshot` deliberately throws: U-27 is a
  // read-only probe, so any attempt to take a snapshot is a bug — and the
  // unexpected-exec fallback makes that loud instead of silently tolerated.
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

// Runs after the suite reports (exit hook), so a failure message can still name
// its temp paths when it matters.
process.on('exit', () => {
  for (const dir of pendingCleanup) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // Best effort; these live in the OS temp dir.
    }
  }
})

beforeEach(() => {
  assert.equal(process.platform, REAL_PLATFORM, 'process.platform leaked from a previous test')
})

/* ------------------------------------------------------------------ */
/* a. First run generates the report                                   */
/* ------------------------------------------------------------------ */

test('U-27a: first apply() writes .tm-guard/baseline-report.md', () => {
  const ws = workspace()
  applyIn(ws, 'darwin')
  const report = reportOf(ws)
  assert.ok(existsSync(report), `baseline report not written: ${report}`)
  planCleanup(ws)
})

test('U-27a: the report carries all six section headings, in order', () => {
  const ws = workspace()
  applyIn(ws, 'darwin')
  const md = readFileSync(reportOf(ws), 'utf8')
  assert.ok(md.length > 500, 'report should be a real document, not a stub')

  assert.equal(BASELINE_SECTIONS.length, 6, 'U-27 specifies exactly six sections')
  let cursor = -1
  for (const heading of BASELINE_SECTIONS) {
    const at = md.indexOf(heading)
    assert.notEqual(at, -1, `missing section heading: ${heading}`)
    assert.ok(at > cursor, `section out of order: ${heading}`)
    cursor = at
  }
  planCleanup(ws)
})

test('U-27a: the report states the probe facts and the README risk list', async () => {
  const ws = workspace()
  applyIn(ws, 'darwin')
  // The file exists the instant apply() returns; the TM section is filled in by
  // the detached tmutil probe, so wait for that refinement before reading it.
  await waitForTmSection(reportOf(ws))
  const md = readFileSync(reportOf(ws), 'utf8')

  // (a) TM configured — the healthy fixture reports a destination.
  assert.match(md, /TM 已配置/)
  // (b) workspace protection stated, not implied.
  assert.match(md, /Workspace 受 TM 保护/)
  // (c) git baseline reachability + creation policy.
  assert.match(md, /git 可用/)
  assert.match(md, /requireGitBaseline/)
  assert.match(md, /惰性创建/, 'must say the baseline is created lazily, i.e. not by this probe')
  // (d) denyReadPaths effective count — the real merged list, not a placeholder.
  const count = md.match(/实际生效项数：(\d+)/)
  assert.ok(count, 'denyReadPaths effective-count line missing')
  assert.ok(Number(count![1]) > 0, 'a fresh install must never report zero deny-read paths')
  assert.match(md, /~\/\.ssh/, 'the default sensitive list should be enumerated')
  // (e) platform mode.
  assert.match(md, /full mode/)
  // (f) residual risks, quoted from README Limitations.
  assert.match(md, /eval \/ decode 逃逸/, 'eval/decode escape risk missing')
  assert.match(md, /运行时 URL/, 'runtime-URL risk missing')
  assert.match(md, /与其他权限插件叠加语义/, 'plugin-coexistence risk missing')
  for (const ref of README_LIMITATION_REFERENCES) {
    assert.ok(md.includes(ref), `missing README reference: ${ref}`)
  }
  // The read-only promise must be visible in the artifact itself.
  assert.match(md, /只读探测/, 'the read-only guarantee must be stated in the report')
  planCleanup(ws)
})

test('U-27a: first apply() logs the one-line pointer to the report', () => {
  const ws = workspace()
  const cap = logCapture()
  cap.open()
  try {
    applyIn(ws, 'darwin')
  } finally {
    cap.close()
  }
  assert.ok(existsSync(reportOf(ws)), 'report not written')
  const line = cap.logs.find((l) => l.includes('首次运行基线报告已生成'))
  assert.ok(line, `expected the first-run notice, got: ${JSON.stringify(cap.logs)}`)
  assert.match(line!, /baseline-report\.md/)
  assert.match(line!, /实际保护等级/)
  planCleanup(ws)
})

/* ------------------------------------------------------------------ */
/* b. Later runs do not regenerate                                     */
/* ------------------------------------------------------------------ */

test('U-27b: a second apply() does not rewrite an existing report', async () => {
  const ws = workspace()
  const report = reportOf(ws)
  applyIn(ws, 'darwin')
  assert.ok(existsSync(report), 'first apply did not generate the report')
  await sleep(30) // so a rewrite would land on a strictly later mtime
  const first = readFileSync(report, 'utf8')
  const firstMtime = statSync(report).mtimeMs

  applyIn(ws, 'darwin')
  assert.equal(readFileSync(report, 'utf8'), first, 'report bytes changed on re-apply')
  assert.equal(statSync(report).mtimeMs, firstMtime, 'report was rewritten on re-apply')
  planCleanup(ws)
})

test('U-27b: a second apply() prints no first-run notice', () => {
  const ws = workspace()
  applyIn(ws, 'darwin')
  assert.ok(existsSync(reportOf(ws)), 'first apply did not generate the report')

  const cap = logCapture()
  cap.open()
  try {
    applyIn(ws, 'darwin')
  } finally {
    cap.close()
  }
  assert.equal(
    cap.logs.filter((l) => l.includes('首次运行基线报告已生成')).length,
    0,
    `a second apply must not announce a first run: ${JSON.stringify(cap.logs)}`,
  )
  planCleanup(ws)
})

test('U-27b: deleting the report makes the NEXT apply a first run again', () => {
  const ws = workspace()
  const report = reportOf(ws)
  applyIn(ws, 'darwin')
  assert.ok(existsSync(report), 'first apply did not generate the report')

  rmSync(report)
  const cap = logCapture()
  cap.open()
  try {
    applyIn(ws, 'darwin')
  } finally {
    cap.close()
  }
  assert.ok(existsSync(report), 'report was not regenerated after deletion')
  assert.ok(
    cap.logs.some((l) => l.includes('首次运行基线报告已生成')),
    'regeneration after deletion should announce itself again',
  )
  planCleanup(ws)
})

test('U-27b: detection is per-workspace — two workspaces are two first runs', () => {
  const a = workspace()
  const b = workspace()
  applyIn(a, 'darwin')
  assert.ok(existsSync(reportOf(a)), 'no report in workspace A')
  assert.equal(existsSync(reportOf(b)), false, 'workspace B must not have a report yet')
  applyIn(b, 'darwin')
  assert.ok(existsSync(reportOf(b)), 'no report in workspace B after its own first run')
  planCleanup(a)
  planCleanup(b)
})

test('U-27b: an existing report is left byte-identical even if the facts changed', () => {
  // The report is a first-run SNAPSHOT, not a live view: if TM is reconfigured
  // afterwards the file must not silently start rendering half-old facts.
  // `tm_status` is the live answer; the report stays the historical one.
  const ws = workspace()
  applyIn(ws, 'darwin')
  const report = reportOf(ws)
  const first = readFileSync(report, 'utf8')

  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'destinationinfo') throw new Error('TM was turned off after the first run')
    if (a[0] === 'listlocalsnapshots') throw new Error('no snapshots anymore')
    if (a[0] === 'isexcluded') return { stdout: `[Excluded] ${a[1]}\n` }
    throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
  })
  try {
    applyIn(ws, 'darwin')
  } finally {
    __setExecOverride(async (f: string, a: string[]) => {
      if (a[0] === 'listlocalsnapshots') {
        return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
      }
      if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
      if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
      throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
    })
  }
  assert.equal(readFileSync(report, 'utf8'), first, 'an existing report must not be rewritten')
  planCleanup(ws)
})

/* ------------------------------------------------------------------ */
/* c. Non-macOS platform labels the limitation                         */
/* ------------------------------------------------------------------ */

test('U-27c: a non-macOS host is labelled limited mode in the report', () => {
  const ws = workspace()
  applyIn(ws, 'linux')
  const report = reportOf(ws)
  assert.ok(existsSync(report), 'baseline report not written on the non-macOS host')
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
  assert.match(md, /能力限制/, 'the missing TM must be framed as a capability limit, not a fault')
  planCleanup(ws)
})

test('U-27c: non-macOS probing never shells out to tmutil', () => {
  const ws = workspace()
  const calls: string[] = []
  __setExecOverride(async (_f: string, a: string[]) => {
    calls.push(a.join(' '))
    throw new Error('tmutil must not be reached on a non-macOS host')
  })
  try {
    applyIn(ws, 'linux')
  } finally {
    __setExecOverride(async (f: string, a: string[]) => {
      if (a[0] === 'listlocalsnapshots') {
        return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
      }
      if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
      if (a[0] === 'isexcluded') return { stdout: `[Included] ${a[1]}\n` }
      throw new Error(`unexpected exec: ${f} ${a.join(' ')}`)
    })
  }
  assert.ok(existsSync(reportOf(ws)), 'report not written')
  assert.deepEqual(calls, [], `no tmutil call may happen on linux: ${JSON.stringify(calls)}`)
  planCleanup(ws)
})

/* ------------------------------------------------------------------ */
/* Read-only + fail-open invariants                                    */
/* ------------------------------------------------------------------ */

test('U-27: generating the report does not touch git (read-only probe)', async () => {
  const ws = workspace()
  // The regression check below compares `git status` before/after, which only
  // means anything in a real repository — so make the workspace one, the way a
  // user's project would be. (The report itself must not depend on this.)
  execSync(`git init -q ${ws} && git -C ${ws} config user.email t@t && git -C ${ws} config user.name t`)
  writeFileSync(join(ws, 'base.txt'), 'base\n', 'utf8')
  execSync('git add -A && git commit -qm baseline', { cwd: ws })
  // The probe runs with cwd = ws, so pin that directory's git state.
  const headBefore = execSync('git rev-parse HEAD', { cwd: ws, encoding: 'utf8' }).trim()
  const statusBefore = execSync('git status --porcelain', { cwd: ws, encoding: 'utf8' })
  const gitCalls: string[] = []
  __setGitOverride(async (args: string[]) => {
    gitCalls.push(args.join(' '))
    return ''
  })
  try {
    applyIn(ws, 'darwin')
  } finally {
    __setGitOverride(null)
  }
  assert.ok(existsSync(reportOf(ws)), 'report not written')
  // Only query subcommands — never init/add/commit.
  for (const call of gitCalls) {
    assert.match(call, /^rev-parse/, `the baseline probe must stay read-only, saw: ${call}`)
  }
  assert.deepEqual(gitCalls, ['rev-parse --show-toplevel'], 'exactly one read-only git probe expected')
  assert.equal(execSync('git rev-parse HEAD', { cwd: ws, encoding: 'utf8' }).trim(), headBefore, 'HEAD moved')
  assert.equal(execSync('git status --porcelain', { cwd: ws, encoding: 'utf8' }), statusBefore, 'work tree changed')
  planCleanup(ws)
})

test('U-27: the probe writes nothing but the report into the workspace', () => {
  const ws = workspace()
  // Everything the gate writes lives in the cwd's `.tm-guard/`, so record it
  // first: the baseline probe must add exactly one file — the report — and no
  // snapshot, no reports/ entry, no state.json.
  const before = readdirSync(join(ws, '.tm-guard')).sort()
  applyIn(ws, 'darwin')
  assert.ok(existsSync(reportOf(ws)), 'report not written')
  assert.deepEqual(before, [], 'the workspace starts empty (audit.jsonl is created lazily)')
  assert.deepEqual(
    readdirSync(join(ws, '.tm-guard')).sort(),
    [BASELINE_REPORT_FILE],
    'the baseline probe must write nothing but the report',
  )
  planCleanup(ws)
})

test('U-27: an unwritable report path degrades to a warning, never a load failure', () => {
  const ws = workspace()
  // `.tm-guard` exists in every workspace(); replace it with a regular file so
  // the report has nowhere to go.
  rmSync(join(ws, '.tm-guard'), { recursive: true, force: true })
  writeFileSync(join(ws, '.tm-guard'), 'not a directory', 'utf8')

  const cap = logCapture()
  cap.open()
  try {
    assert.doesNotThrow(() => {
      applyIn(ws, 'darwin')
    }, 'apply() must survive an unwritable report path')
  } finally {
    cap.close()
  }
  // No first-run success notice, and the failure is reported rather than swallowed.
  assert.equal(cap.logs.filter((l) => l.includes('首次运行基线报告已生成')).length, 0)
  assert.ok(
    cap.warns.some((l) => l.includes('Baseline report skipped')),
    `expected a degradation warning, got: ${JSON.stringify(cap.warns)}`,
  )
  planCleanup(ws)
})

/* ------------------------------------------------------------------ */
/* Pure renderer + probe units (no apply, no tmutil)                   */
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
    tm: {
      probed: true,
      destinationConfigured: true,
      healthy: true,
      workspaceProtected: true,
      unprotectedPaths: [],
    },
    git: { repo: true, root: '/w', hasGitDir: true, gitAvailable: true },
    generatedAt: new Date('2026-10-06T05:41:00Z'),
  }
  const first = renderBaselineReport(input)
  const second = renderBaselineReport(input)
  assert.equal(first, second, 'renderer must be deterministic')
  assert.equal(input.denyReadPaths.length, 2, 'renderer must not mutate its input')
  for (const heading of BASELINE_SECTIONS) assert.ok(first.includes(heading))

  // Replacement semantics must be visible: a user who dropped the defaults has
  // to be able to see that from the report alone.
  const replaced = renderBaselineReport({
    ...input,
    denyReadPathsReplace: true,
    denyReadPaths: ['~/project'],
  })
  assert.match(replaced, /替换/)
  assert.match(replaced, /实际生效项数：1/)
  // An empty list is a fail-open opt-out and must be called out as one.
  const emptied = renderBaselineReport({ ...input, denyReadPaths: [] })
  assert.match(emptied, /实际生效项数：0/)
  assert.match(emptied, /清单为空/)

  // Unhealthy facts render as problems with a next step, never as a green light.
  const unhealthy = renderBaselineReport({
    ...input,
    tm: {
      probed: true,
      destinationConfigured: false,
      healthy: false,
      workspaceProtected: false,
      unprotectedPaths: ['/w'],
    },
  })
  assert.match(unhealthy, /UNHEALTHY/)
  assert.match(unhealthy, /下一步/)
  assert.match(unhealthy, /\/w/)
})

test('U-27: the report does not leak the maintainer home path', () => {
  // The report is written into the user's own workspace, so it is theirs to
  // keep — but the shipped *code* must stay free of maintainer paths (the pack
  // audit enforces the same rule for the tarball).
  const src = readFileSync(new URL('./src/baseline-report.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(src, /\/Users\/zero\b/, 'no maintainer home path in the report generator')
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
  // PATH without git: the probe must answer "not available" rather than crash
  // the plugin load — an installer-shaped failure deserves a finding, not a
  // stack trace at startup.
  const savedPath = process.env.PATH
  process.env.PATH = '/nonexistent-bin'
  try {
    const probe = probeGitBaseline(ROOT)
    assert.equal(probe.gitAvailable, false)
    assert.equal(probe.repo, false)
  } finally {
    process.env.PATH = savedPath
  }
})
