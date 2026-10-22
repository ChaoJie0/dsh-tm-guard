#!/usr/bin/env node
/**
 * Release gate scorecard — `npm run release:gate`.
 *
 * Runs the deterministic automatic gates (L0 test, L3 peer, L1 reproducible
 * build, L2 pack audit, L6 hygiene) and prints one quantified scorecard.
 * Every automatic threshold is "violations = 0"; raw counts (pass, files,
 * warnings) are shown for context but are not release lines.
 *
 * Manual gates L4 (isolated live host smoke) and L5 (independent dsh review)
 * cannot be proven by a script. They are never auto-claimed: pass them only
 * with an explicit confirmation flag, otherwise the final verdict stays
 * MANUAL PENDING and the process exits non-zero.
 *
 * Exit codes:
 *   0 = RELEASE GO (automatic gates green AND L4/L5 confirmed)
 *   1 = NO-GO (an automatic gate failed)
 *   2 = AUTOMATIC GREEN, MANUAL PENDING (automatic gates green, L4/L5 not yet
 *       confirmed) — not a failure, but not a release either.
 *
 * Usage:
 *   node scripts/release-gate.mjs                 # automatic gates only
 *   node scripts/release-gate.mjs --confirm-l4 --confirm-l5
 */
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

function run(cmd, args) {
  try {
    const out = execFileSync(cmd, args, {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    })
    return { ok: true, out }
  } catch (e) {
    return { ok: false, out: (e.stdout || '') + (e.stderr || '') }
  }
}

// Each gate: label, threshold text, runner, parser -> { value, pass }.
const gates = []

function addGate(label, threshold, runner, parse) {
  gates.push({ label, threshold, runner, parse })
}

// L0 unit tests: TAP "# pass N" / "# fail M"; threshold fail = 0.
addGate('L0 unit tests', 'fail = 0', () => run('npm', ['run', 'test', '--silent']), (out) => {
  const fail = Number((out.match(/# fail\s+(\d+)/) || [])[1] ?? NaN)
  const pass = Number((out.match(/# pass\s+(\d+)/) || [])[1] ?? NaN)
  return { value: `fail ${fail} / pass ${pass}`, pass: fail === 0 && Number.isFinite(fail) }
})

// L3 peer matrix: "PASS: peer matrix N/N" or "FAIL: M expectation(s)".
addGate('L3 peer matrix', 'violated = 0', () => run('npm', ['run', 'verify:peer', '--silent']), (out) => {
  const m = out.match(/peer matrix (\d+)\/(\d+)/)
  const f = Number((out.match(/FAIL:\s+(\d+)\s+expectation/) || [])[1] ?? 0)
  const total = m ? Number(m[2]) : NaN
  const ok = f === 0 && Number.isFinite(total)
  return { value: m ? `${m[1]}/${m[2]} met` : `violated ${f}`, pass: ok }
})

// L1 reproducible build: "PASS: N files byte-identical" / "FAIL: M differ".
addGate('L1 reproducible build', 'differ = 0 files', () => run('npm', ['run', 'verify:build', '--silent']), (out) => {
  const pass = out.match(/PASS:\s+(\d+)\s+files byte-identical/)
  const fail = Number((out.match(/FAIL:\s+(\d+)\s+file\(s\) differ/) || [])[1] ?? NaN)
  return {
    value: pass ? `${pass[1]} files identical` : `${Number.isFinite(fail) ? fail : '?'} differ`,
    pass: Boolean(pass) && !Number.isFinite(fail),
  }
})

// L2 pack audit: "PASS: N files" / "Content audit violations".
addGate('L2 pack audit', 'leak = 0', () => run('npm', ['run', 'verify:pack', '--silent']), (out) => {
  const pass = out.match(/PASS:\s+(\d+)\s+files/)
  const leaked = /Content audit violations:|✗/.test(out)
  return { value: pass ? `${pass[1]} files, clean` : 'violations present', pass: Boolean(pass) && !leaked }
})

// L6 hygiene: "PASS: ... (W warning(s))" / "Hygiene violations".
addGate('L6 tree + history hygiene', 'hard violation = 0', () => run('npm', ['run', 'verify:hygiene', '--silent']), (out) => {
  const green = /PASS:.*clean/.test(out)
  const warn = Number((out.match(/\((\d+)\s+warning\(s\)/) || [])[1] ?? 0)
  const hard = /Hygiene violations:/.test(out)
  return { value: hard ? 'hard violations' : `clean (${warn} warn)`, pass: green && !hard }
})

// --- Manual gates (explicit confirmation only) ---
const flags = new Set(process.argv.slice(2))
const manual = [
  { key: 'L4', label: 'L4 isolated live host smoke (real macOS/APFS/TM/dsh)', confirmed: flags.has('--confirm-l4') },
  { key: 'L5', label: 'L5 independent dsh review (VERDICT PASS, 0 blockers)', confirmed: flags.has('--confirm-l5') },
]

if (!existsSync(join(ROOT, '.git'))) {
  console.error('✗ not a git checkout — release gate requires git')
  process.exit(1)
}

console.log('')
console.log('RELEASE GATE SCORECARD')
console.log('======================')
console.log('')

let autoFail = 0
for (const g of gates) {
  const { ok, out } = g.runner()
  const parsed = g.parse(out)
  const status = ok && parsed.pass ? 'PASS' : 'FAIL'
  if (status === 'FAIL') autoFail++
  console.log(`${status === 'PASS' ? '✅' : '✗'} ${g.label}`)
  console.log(`     threshold: ${g.threshold} | measured: ${parsed.value}`)
  if (status === 'FAIL') {
    const lines = out.trim().split('\n').map((s) => s.trim()).filter(Boolean)
    // Prefer real violation lines over non-blocking WARN tails. HOOKS is
    // anchored to the uppercase producer line so the benign "no install-time
    // lifecycle hooks ✅" note is not mistaken for a violation.
    const signal = lines.filter((l) =>
      /✗|FAIL|DIFFERS|\bDIFF\b|violation|LEAK|MISSING|EXTRA|differ from HEAD|working tree not clean/i.test(l) ||
      /^HOOKS\b/.test(l))
    const tail = (signal.length ? signal : lines).slice(-4)
    for (const line of tail) console.log(`       ${line.slice(0, 160)}`)
  }
}

console.log('')
console.log('Manual gates (script cannot self-certify):')
for (const m of manual) {
  console.log(`${m.confirmed ? '✅' : '☐'} ${m.key} ${m.label}${m.confirmed ? ' — confirmed' : ' — NOT confirmed'}`)
}

console.log('')
if (autoFail > 0) {
  console.error(`✗ NO-GO: ${autoFail} automatic gate(s) failed. Fix before release.`)
  process.exit(1)
}

const manualDone = manual.every((m) => m.confirmed)
if (!manualDone) {
  console.log('AUTOMATIC GATES GREEN, but MANUAL PENDING:')
  for (const m of manual) if (!m.confirmed) console.log(`  - confirm ${m.key} with --confirm-${m.key.toLowerCase()} after completing it`)
  console.log('')
  console.log('Not a release yet: complete L4/L5, then re-run with both flags.')
  process.exit(2)
}

console.log('✅ RELEASE GO: automatic gates green and L4/L5 confirmed.')
console.log('   Remaining manual steps (your terminal): commit/push, tag, publish.')
process.exit(0)
