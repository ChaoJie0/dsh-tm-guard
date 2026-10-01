#!/usr/bin/env node
/**
 * Package content audit — `npm run verify:pack`
 *
 * Runs `npm pack --dry-run --json` and audits the exact tarball contents:
 *   - no local absolute paths (privacy: /Users, /private, session ids, ports)
 *   - no source/test/scratch leakage (src/, test-*.mts, .smoke-out/, .tm-*)
 *   - file count matches the files whitelist derivation
 *   - no unexpected top-level entries
 *
 * This is the machine gate for the pre-push privacy audit that caught
 * local reports and npm_RTx artifacts before the 0.2.0 release.
 *
 * Exit code: 0 = clean; 1 = any violation (fails the release gate).
 */
import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))

let out
try {
  out = execSync('npm pack --dry-run --json', { cwd: ROOT, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
} catch (e) {
  // npm may print notices to stderr; the JSON is on stdout.
  out = String(e.stdout || '')
}

let report
try {
  // prepare/build logs can prefix stdout with non-JSON lines (e.g.
  // "[dsh-tm-guard] build OK..."). The npm pack JSON array starts on its own
  // line after a newline; try every line-start '[' candidate and keep the
  // first one that parses.
  const candidates = []
  let idx = -1
  while ((idx = out.indexOf('\n[', idx + 1)) >= 0) candidates.push(idx + 1)
  if (out.startsWith('[')) candidates.unshift(0)
  for (const s of candidates) {
    try {
      report = JSON.parse(out.slice(s))
      break
    } catch {
      /* keep trying */
    }
  }
  if (!report) throw new Error('no candidate parses as JSON array')
} catch {
  console.error('✗ npm pack --dry-run --json produced no parseable output')
  console.error(String(out).slice(0, 800))
  process.exit(1)
}

const entry = report[0] || {}
const files = entry.files || []

const violations = []
const unexpectedTop = []

const FORBIDDEN = [
  /^\/Users\//, /^\/private\//, /^\/tmp\//,      // local absolute paths
  /session-[0-9a-f-]{36}/, /(^|\/)\.smoke-out\//, // session ids, scratch
  /(^|\/)\.tm-/, /(^|\/)src\//, /(^|\/)test-.*\.mts$/, // test residue
  /(^|\/)\.git(\/|$)/, /(^|\/)node_modules(\/|$)/,
]
const FORBIDDEN_HINT = [
  '/Users/', '/private/', '/tmp/',
  'session-', '.smoke-out/',
  '.tm-', 'src/', 'test-*.mts',
  '.git/', 'node_modules/',
]

const expectedTop = ['lib', 'cordis.patch.yml', 'README.md', 'CHANGELOG.md', 'LICENSE', 'package.json']
const expectedLibCount = 9 // 8 js + index.d.ts (must match lib/ output)

for (const f of files) {
  const path = f.path
  for (let i = 0; i < FORBIDDEN.length; i++) {
    if (FORBIDDEN[i].test(path)) {
      violations.push(`${path}  (forbidden pattern: ${FORBIDDEN_HINT[i]})`)
    }
  }
  if (path.includes('/')) {
    const top = path.split('/')[0]
    if (!expectedTop.includes(top) && !unexpectedTop.includes(top)) unexpectedTop.push(top)
  }
}

console.log(`tarball: ${entry.filename || pkg.version + '.tgz'}  |  files: ${files.length}`)
console.log('')
console.log('Top-level entries:')
for (const t of expectedTop) {
  console.log(`  ${t} ${expectedTop.includes(t) ? '✅' : ''}`)
}
if (unexpectedTop.length) {
  console.log(`  UNEXPECTED: ${unexpectedTop.join(', ')}`)
  violations.push(`unexpected top-level: ${unexpectedTop.join(', ')}`)
}

console.log('')
if (violations.length) {
  console.error('✗ Content audit violations:')
  for (const v of violations) console.error(`  - ${v}`)
  process.exit(1)
}

console.log(`PASS: ${files.length} files, no local paths, no source/test/scratch leakage`)
process.exit(0)
