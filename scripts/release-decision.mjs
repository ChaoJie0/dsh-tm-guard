#!/usr/bin/env node
/**
 * Release-decision chain — `node scripts/release-decision.mjs`.
 *
 * When asked "is the current version releasable?", run the whole chain and emit
 * one GO / PENDING / NO-GO verdict with per-gate evidence. Read-only: it never
 * commits, pushes, tags, publishes, or mutates the tree.
 *
 * Verdict (exit code):
 *   0 = GO       — stage 0 pass + automatic gates green + L4/L5a/L5b evidence
 *                  bound to this HEAD and PASS. Still leaves push/tag/publish to
 *                  the user's terminal; this script does not release.
 *   1 = NO-GO    — a hard failure (automatic gate, stale/mismatched evidence,
 *                  version already on registry, CHANGELOG missing, gate script
 *                  untracked, evidence self-reports NO-GO/blocker).
 *   2 = PENDING  — automatic gates green but evidence missing / registry UNKNOWN
 *                  / first-push history unverified. Not a release, not a crash.
 *
 * Design: docs/release-decision-design.md (v2.1); dsh round2 VERDICT PASS.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const VERSION = pkg.version
const PKG_NAME = pkg.name

function run(cmd, args, opts = {}) {
  try {
    const out = execFileSync(cmd, args, {
      cwd: ROOT, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024, ...opts,
    })
    return { ok: true, out }
  } catch (e) {
    return { ok: false, out: (e.stdout || '') + (e.stderr || '') }
  }
}
function git(args) {
  const r = run('git', args)
  return r.ok ? r.out : ''
}

// ---- verdict accumulators -------------------------------------------------
const hardFail = []   // NO-GO reasons
const pending = []    // PENDING reasons
const rows = []       // display rows: {stage, name, status, detail}
function row(stage, name, status, detail) { rows.push({ stage, name, status, detail }) }

// ---- stage 0: prerequisites ------------------------------------------------
const HEAD = git(['rev-parse', 'HEAD']).trim()

// 0.0 gate scripts must be tracked (fresh clone / CI / L5-b must not miss them)
const REQUIRED_SCRIPTS = [
  'scripts/release-gate.mjs',
  'scripts/verify-hygiene.mjs',
  'scripts/verify-pack-audit.mjs',
  'scripts/verify-reproducible-build.mjs',
  'scripts/verify-peer-matrix.mjs',
  'scripts/release-decision.mjs',
]
const tracked = new Set(git(['ls-files']).split('\n').filter(Boolean))
const untrackedScripts = REQUIRED_SCRIPTS.filter((f) => !tracked.has(f))
if (untrackedScripts.length) {
  hardFail.push(`gate script(s) not committed to git: ${untrackedScripts.join(', ')} (commit them before release)`)
  row('0', 'gate scripts tracked', 'FAIL', `untracked: ${untrackedScripts.join(', ')}`)
} else {
  row('0', 'gate scripts tracked', 'PASS', `${REQUIRED_SCRIPTS.length} tracked`)
}

// 0.1 semver present
const semverRe = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/
if (!VERSION || !semverRe.test(VERSION)) {
  hardFail.push(`package.json version missing/invalid: ${VERSION}`)
  row('0', 'version semver', 'FAIL', String(VERSION))
} else {
  row('0', 'version semver', 'PASS', VERSION)
}

// 0.2 registry occupancy: only 404 = free; only 200 = taken; everything else UNKNOWN
async function registryStatus() {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), 8000)
  try {
    const res = await fetch(`https://registry.npmjs.org/${PKG_NAME}/${VERSION}`, { signal: ctrl.signal })
    return res.status
  } catch {
    return 0
  } finally { clearTimeout(t) }
}
const regStatus = await registryStatus()
if (regStatus === 404) {
  row('0', 'registry free', 'PASS', '404 not published')
} else if (regStatus === 200) {
  hardFail.push(`version ${VERSION} already exists on registry (200) — do not republish`)
  row('0', 'registry free', 'FAIL', `200 already published`)
} else {
  pending.push(`registry status ${regStatus || 'unreachable'} UNKNOWN — verify with npm view before release`)
  row('0', 'registry free', 'UNKNOWN', `http=${regStatus || '000'} verify manually`)
}

// 0.3 CHANGELOG anchored section, non-empty, matches package version
const changelogPath = join(ROOT, 'CHANGELOG.md')
const cl = existsSync(changelogPath) ? readFileSync(changelogPath, 'utf8') : ''
const anchor = new RegExp(`^##\\s*\\[${VERSION.replace(/\./g, '\\.')}\\](\\s|$)`, 'm')
let clSectionOk = false
if (anchor.test(cl)) {
  const idx = cl.search(anchor)
  // Drop this section's own title line, then slice up to the NEXT `## [` heading;
  // measure the target body itself (not the section below it) — B-1.
  const afterTitle = cl.slice(idx).replace(/^##[^\n]*\n/, '')
  const seg = afterTitle.split(/^##\s*\[/m)[0] || ''
  clSectionOk = seg.trim().length > 0
}
if (!cl || !anchor.test(cl)) {
  hardFail.push(`CHANGELOG has no anchored [${VERSION}] section`)
  row('0', 'CHANGELOG section', 'FAIL', `missing [${VERSION}]`)
} else if (!clSectionOk) {
  hardFail.push(`CHANGELOG [${VERSION}] section is empty`)
  row('0', 'CHANGELOG section', 'FAIL', 'empty')
} else {
  row('0', 'CHANGELOG section', 'PASS', `[${VERSION}] non-empty, matches package`)
}

// 0.4 HEAD + porcelain recorded
const porcelain = git(['status', '--porcelain=v1', '--untracked-files=normal']).trim()
row('0', 'HEAD / tree', 'INFO', `${HEAD.slice(0, 12)}${porcelain ? `, ${porcelain.split('\n').length} uncommitted` : ', clean'}`)

// 0.5 origin/main (first-push / shallow => history unverified)
const hasBaseline = run('git', ['rev-parse', '--verify', 'origin/main']).ok
if (!hasBaseline) {
  pending.push('no origin/main baseline (first push / shallow clone) — full history must be scanned on a complete clone')
  row('0', 'origin/main baseline', 'UNKNOWN', 'absent; verify full history manually')
} else {
  row('0', 'origin/main baseline', 'PASS', 'present')
}

// ---- stage 1: automatic gates (reuse verify:fast chain) ---------------------
const autoGates = [
  ['L0 unit tests', ['run', 'test', '--silent'], (o) => {
    const fail = Number((o.match(/# fail\s+(\d+)/) || [])[1] ?? NaN)
    const pass = Number((o.match(/# pass\s+(\d+)/) || [])[1] ?? NaN)
    return { ok: fail === 0 && Number.isFinite(fail), detail: `fail ${fail} / pass ${pass}` }
  }],
  ['L3 peer matrix', ['run', 'verify:peer', '--silent'], (o) => {
    const m = o.match(/peer matrix (\d+)\/(\d+)/)
    const f = Number((o.match(/FAIL:\s+(\d+)\s+expectation/) || [])[1] ?? 0)
    return { ok: f === 0 && Boolean(m), detail: m ? `${m[1]}/${m[2]} met` : `violated ${f}` }
  }],
  ['L1 reproducible build', ['run', 'verify:build', '--silent'], (o) => {
    const p = o.match(/PASS:\s+(\d+)\s+files byte-identical/)
    const f = Number((o.match(/FAIL:\s+(\d+)\s+file\(s\) differ/) || [])[1] ?? NaN)
    return { ok: Boolean(p) && !Number.isFinite(f), detail: p ? `${p[1]} identical` : `${Number.isFinite(f) ? f : '?'} differ` }
  }],
  ['L2 pack audit (L6-c + no hooks)', ['run', 'verify:pack', '--silent'], (o) => {
    const p = o.match(/PASS:\s+(\d+)\s+files/)
    const bad = /Content audit violations:|✗/.test(o)
    return { ok: Boolean(p) && !bad, detail: p ? `${p[1]} files, clean` : 'violations' }
  }],
  ['L6 tree + history hygiene', ['run', 'verify:hygiene', '--silent'], (o) => {
    const green = /PASS:.*clean/.test(o)
    const hard = /Hygiene violations:/.test(o)
    return { ok: green && !hard, detail: hard ? 'hard violations' : green ? 'clean' : 'unknown' }
  }],
]

for (const [name, [script, ...args], parse] of autoGates) {
  const r = run('npm', [script, ...args])
  const res = parse(r.out)
  if (!res.ok) {
    hardFail.push(`${name} failed: ${res.detail}`)
    row('1', name, 'FAIL', res.detail)
  } else {
    row('1', name, 'PASS', res.detail)
  }
}

// ---- stage 2: bound evidence identity gates -------------------------------
// Strip fenced code blocks before matching (NIT-b), so a quoted identity block
// inside a report cannot be mistaken for a real verdict.
function stripFence(text) {
  return text.replace(/```[\s\S]*?```/g, '')
}
function parseIdentity(text) {
  const body = stripFence(text)
  const map = {}
  for (const line of body.split('\n')) {
    const m = line.match(/^(GIT-HEAD|VERDICT|BLOCKERS|TGZ-SHA256|BUNDLE-VERSION):\s*(.*)$/)
    if (m) (map[m[1]] ||= []).push(m[2].trim())
  }
  // NIT-a: every key must appear exactly once outside fences; duplicates conflict
  for (const [k, vals] of Object.entries(map)) {
    if (vals.length > 1) return { conflict: `${k} appears ${vals.length} times` }
  }
  return {
    gitHead: map['GIT-HEAD']?.[0] ?? null,
    verdict: map['VERDICT']?.[0] ?? null,
    blockers: map['BLOCKERS']?.[0] ?? null,
    tgz: map['TGZ-SHA256']?.[0] ?? null,
    bundle: map['BUNDLE-VERSION']?.[0] ?? null,
  }
}

function findEvidence(pred) {
  const out = []
  const docs = join(ROOT, 'docs')
  if (!existsSync(docs)) return out
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name)
      if (e.isDirectory()) walk(p)
      else if (e.name.endsWith('.md') && pred(e.name.toLowerCase())) out.push(p)
    }
  }
  walk(docs)
  return out
}

// version tokens for filename discovery: 0.2.8, 028, 0.2.8 (raw)
const tokens = [VERSION, VERSION.replace(/\./g, '')]
const tokRe = new RegExp(tokens.join('|'), 'i')
// Each gate carries substantive-content markers (B-2): beyond the identity
// lines, the report body (fences stripped) must carry these evidence markers,
// otherwise a 5-line self-attestation could pass. Existence-only; replay is
// still anchored by GIT-HEAD.
const buckets = [
  {
    key: 'L4', label: 'L4 isolated live host smoke', re: /smoke|live-host/,
    need: { bundle: true, tgz: true },
    markers: [
      { re: /\[tm-guard\] Loaded/, label: 'load banner' },
      { re: /TM health check passed/, label: 'TM health check' },
      { re: /BLOCKED/, label: 'destructive command truly blocked' },
      { re: /3080/, label: 'production 3080 referenced' },
      { re: /unchanged|continuous|same pid/i, label: 'production pid unchanged across turn' },
    ],
  },
  {
    key: 'L5a', label: 'L5-a MainAgent walkthrough', re: /l5a|walkthrough/,
    need: { bundle: false, tgz: false },
    markers: [
      { re: /CHANGELOG/i, label: 'CHANGELOG change-by-change reconciliation' },
      { re: /truth table|truth-table|真值表|关键路径|walkthrough|走查/i, label: 'truth-table / key-path walkthrough' },
      { re: /L6[-_ ]?[abc]/i, label: 'L6-a/b/c completion record' },
    ],
  },
  {
    key: 'L5b', label: 'L5-b dsh independent review', re: /(^|[-_])l5[-_.]|review-l5/,
    need: { bundle: false, tgz: true, realTgz: true },
    markers: [
      { re: /byte-identical|bit-identical|逐字节|artifact|发布物|tarball/i, label: 'review covered the actual artifact vs git HEAD' },
    ],
  },
]

const adoptedPaths = []
const evidenceStatus = {}
for (const b of buckets) {
  const cands = findEvidence((name) => b.re.test(name) && tokRe.test(name))
  const parsed = cands.map((p) => ({ p, raw: readFileSync(p, 'utf8'), id: parseIdentity(readFileSync(p, 'utf8')) }))
  if (parsed.some((x) => x.id.conflict)) {
    hardFail.push(`${b.key} evidence has conflicting identity lines: ${parsed.find((x) => x.id.conflict).id.conflict}`)
    evidenceStatus[b.key] = 'NO-GO'
    row('2', b.label, 'FAIL', 'conflicting identity rows')
    continue
  }
  // Reports carrying a sha; reports without any identity line are legacy and ignored here.
  const withHead = parsed.filter((x) => x.id.gitHead)
  const valid = withHead.filter((x) => x.id.gitHead === HEAD)
  if (valid.length === 0) {
    if (withHead.length > 0) {
      // A report IS bound to a sha, just not this HEAD => stale, hard NO-GO.
      hardFail.push(`${b.key} evidence is stale: bound to ${withHead.map((x) => x.id.gitHead.slice(0, 12)).join(', ')} != HEAD ${HEAD.slice(0, 12)} — rerun this gate on current HEAD`)
      evidenceStatus[b.key] = 'NO-GO'
      row('2', b.label, 'FAIL', 'stale: bound to other HEAD, not current')
    } else {
      // No bound report at all (legacy reports lack identity lines) => missing, PENDING.
      pending.push(`${b.key} evidence missing — ${b.key === 'L4' ? 'run isolated host turn' : b.key === 'L5b' ? 'dispatch dsh against this commit hash' : 'complete L5-a walkthrough'}; legacy reports need re-signing on this HEAD`)
      evidenceStatus[b.key] = 'PENDING'
      row('2', b.label, '☐', 'missing (legacy report needs re-sign)')
    }
    continue
  }
  if (valid.length > 1) {
    hardFail.push(`${b.key} has ${valid.length} valid-bound reports (ambiguous) — converge to one`)
    evidenceStatus[b.key] = 'NO-GO'
    row('2', b.label, 'FAIL', 'ambiguous multiple valid reports')
    continue
  }
  const v = valid[0]
  const problems = []
  if (v.id.verdict !== 'PASS') problems.push(`VERDICT=${v.id.verdict}`)
  if (v.id.blockers !== '0') problems.push(`BLOCKERS=${v.id.blockers}`)
  if (b.need.bundle && v.id.bundle !== VERSION) problems.push(`BUNDLE-VERSION=${v.id.bundle}`)
  // NIT-1: L4/L5-b tgz — L5-b needs a real 64-hex sha; L4 accepts 64-hex or HEAD-rebuild.
  if (b.need.tgz && b.realTgz && !/^[0-9a-f]{64}$/.test(v.id.tgz || '')) problems.push(`L5-b needs real 64-hex TGZ-SHA256, got ${v.id.tgz}`)
  if (b.need.tgz && !b.realTgz && !/^[0-9a-f]{64}$/.test(v.id.tgz || '') && v.id.tgz !== 'HEAD-rebuild') problems.push(`L4 needs TGZ-SHA256 (64-hex) or HEAD-rebuild, got ${v.id.tgz}`)
  // B-2: substantive body markers on the fence-stripped text.
  const body = stripFence(v.raw)
  for (const m of b.markers) {
    if (!m.re.test(body)) problems.push(`missing evidence marker: ${m.label}`)
  }
  if (problems.length) {
    hardFail.push(`${b.key} evidence fails identity/content: ${problems.join('; ')}`)
    evidenceStatus[b.key] = 'NO-GO'
    row('2', b.label, 'FAIL', problems.join('; '))
  } else {
    evidenceStatus[b.key] = 'OK'
    adoptedPaths.push(v.p)
    row('2', b.label, 'PASS', `bound ${HEAD.slice(0, 12)} PASS/0`)
  }
}

// NIT-3: the three independent gates must resolve to three distinct files; one
// report must not impersonate both L5-a and L5-b (or any pair).
const dupPaths = adoptedPaths.filter((p, i) => adoptedPaths.indexOf(p) !== i)
if (dupPaths.length) {
  hardFail.push(`evidence file shared across independent gates: ${[...new Set(dupPaths)].join(', ')} — L4/L5-a/L5-b must be distinct reports`)
}

// ---- render ---------------------------------------------------------------
console.log('')
console.log(`RELEASE DECISION — ${PKG_NAME}@${VERSION}`)
console.log('===========================================')
for (const r of rows) {
  const icon = r.status === 'PASS' ? '✅' : r.status === 'FAIL' ? '✗' : r.status === 'UNKNOWN' ? '⚠' : r.status === '☐' ? '☐' : '•'
  console.log(`${icon} [${r.stage}] ${r.name}`)
  if (r.detail) console.log(`     ${r.detail}`)
}

console.log('')
// Priority: stale/NO-GO > registry UNKNOWN > missing PENDING (NIT-f)
if (hardFail.length) {
  console.error('✗ VERDICT: NO-GO')
  for (const f of hardFail) console.error(`  - ${f}`)
  process.exit(1)
}
if (pending.length) {
  console.log('◐ VERDICT: PENDING (automatic gates green; finish the following)')
  for (const p of pending) console.log(`  - ${p}`)
  console.log('')
  console.log('Not a release yet. Complete the items above, then re-run.')
  process.exit(2)
}
console.log('✅ VERDICT: GO — automatic gates green and L4/L5a/L5b bound to this HEAD.')
console.log('   Remaining steps are YOUR terminal: push main, tag+push, npm publish (no --ignore-scripts), gh release, post-publish verify.')
process.exit(0)
