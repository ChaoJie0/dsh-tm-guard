#!/usr/bin/env node
/**
 * Peer compatibility matrix — `npm run verify:peer`
 *
 * Verifies the dsh peer range declared in package.json against every dsh
 * version we MUST support and every version we MUST NOT support.
 *
 * Regression guard for the 0.1.1 incident: `>=0.1.0-rc.1 <0.2.0-0` excluded
 * the entire dsh 0.2.x line, silently breaking 2.0 users. Any future edit of
 * the peer range must keep this matrix green.
 *
 * Exit code: 0 = all expectations met; 1 = mismatch (fails the release gate).
 */
import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'

const require = createRequire(import.meta.url)
const semver = require('semver')

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const peerRange = pkg.peerDependencies['@deepseek-ai/dsh-tools']
const engineRange = (pkg.engines && pkg.engines.dsh) || null

// [version, mustSatisfy] — true = range MUST match, false = range MUST NOT match.
const MATRIX = [
  // 0.1.x line (legacy host)
  ['0.1.0-rc.1', true], // earliest supported (segment 1 lower bound)
  ['0.1.0',      true], // first shipped stable (2026-09-19, npm)
  ['0.1.1',      true], // shipped stable on the 0.1.x line (npm latest before 0.2.0)
  ['0.1.2-rc.1', true], // 0.1.x latest, real host used in dual-line smoke tests
  // 0.2.x line (current host)
  ['0.2.0-0',    true], // prerelease boundary of segment 3 (must be satisfied per npm semver rules)
  ['0.2.0-rc.2', true], // npm latest 0.2.x, production host
  ['0.2.0',      true], // stable 0.2.0
  ['0.2.9',      true], // upper 0.2.x boundary
  // must NOT match
  ['0.3.0',      false], // next major line
  ['1.0.0',      false],
  ['0.1.0-rc.0', false], // before earliest supported
  ['0.0.9',      false],
]

let failures = 0
const rows = []

for (const [version, mustSatisfy] of MATRIX) {
  if (!semver.valid(version)) {
    console.error(`✗ matrix entry invalid semver: ${version}`)
    failures++
    continue
  }
  const ok = semver.satisfies(version, peerRange, { includePrerelease: false })
  const pass = ok === mustSatisfy
  if (!pass) failures++
  rows.push({ version, mustSatisfy, ok, pass })
}

console.log('peerDependencies["@deepseek-ai/dsh-tools"] =', peerRange)
console.log('')
console.log(String.prototype.padEnd.call('dsh version', 16), 'must', 'actual', 'verdict')
console.log('-'.repeat(46))
for (const r of rows) {
  console.log(
    String.prototype.padEnd.call(r.version, 16),
    r.mustSatisfy ? 'PASS ' : 'FAIL ',
    r.ok ? 'match' : 'no   ',
    r.pass ? '  ✅' : '  ❌'
  )
}

// engines.dsh must be identical to the peer range (single source of truth).
if (engineRange !== peerRange) {
  console.error(`✗ engines.dsh (${engineRange}) differs from peer range (${peerRange})`)
  failures++
} else {
  console.log('')
  console.log('engines.dsh == peer range ✅ (single source of truth)')
}

console.log('')
if (failures === 0) {
  console.log(`PASS: peer matrix ${rows.length}/${rows.length} expectations met`)
  process.exit(0)
} else {
  console.error(`FAIL: ${failures} expectation(s) violated — do NOT release until fixed`)
  process.exit(1)
}
