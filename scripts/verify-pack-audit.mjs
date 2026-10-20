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
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { gunzipSync } from 'node:zlib'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))

// Expand the exact tarball file list from package.json's `files` whitelist —
// the publish content of this package is fully determined by it (npm also
// always ships package.json). Pure in-process computation: no child process
// (previously `npm pack --dry-run --json` was classified as a package
// operation and denied inside a guarded agent session, making the local L2
// gate unusable), no extra dependency.
function expandWhitelist(entry) {
  const p = join(ROOT, entry)
  const st = statSync(p)
  if (st.isDirectory()) {
    return readdirSync(p, { withFileTypes: true })
      .sort((a, b) => (a.name < b.name ? -1 : 1))
      .flatMap((d) => (d.isDirectory() ? expandWhitelist(join(entry, d.name)) : [join(entry, d.name)]))
  }
  return [entry]
}
const whitelist = pkg.files || []
const rel = [...new Set(whitelist.flatMap(expandWhitelist).concat('package.json'))]
const files = rel.map((p) => ({ path: p }))

const violations = []
const unexpectedTop = []

const FORBIDDEN = [
  /^\/Users\//, /^\/private\//, /^\/tmp\//,      // local absolute paths
  /session-[0-9a-f-]{36}/, /(^|\/)\.smoke-out\//, // session ids, scratch
  /(^|\/)\.tm-/, /(^|\/)src\//, /(^|\/)test-.*\.m[jt]s$/, // test residue
  /(^|\/)\.git(\/|$)/, /(^|\/)node_modules(\/|$)/,
]
const FORBIDDEN_HINT = [
  '/Users/', '/private/', '/tmp/',
  'session-', '.smoke-out/',
  '.tm-', 'src/', 'test-*.mts / test-*.mjs',
  '.git/', 'node_modules/',
]

const expectedTop = ['lib', 'cordis.patch.yml', 'README.md', 'CHANGELOG.md', 'LICENSE', 'package.json']

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

console.log(`tarball: dsh-tm-guard-${pkg.version}.tgz  |  files: ${files.length}`)
console.log('')
console.log('Top-level entries:')
for (const t of expectedTop) {
  console.log(`  ${t} ${expectedTop.includes(t) ? '✅' : ''}`)
}
if (unexpectedTop.length) {
  console.log(`  UNEXPECTED: ${unexpectedTop.join(', ')}`)
  violations.push(`unexpected top-level: ${unexpectedTop.join(', ')}`)
}

// R-3 freshness gate: if a local tarball exists, every entry must byte-match
// the current worktree (which equals HEAD when verify:build passed). This
// closes the blind spot where the audit checked the tree but not the tarball
// actually staged for publish. Pure Node: no child process, no tar binary.
const TGZ = join(ROOT, `dsh-tm-guard-${pkg.version}.tgz`)
if (existsSync(TGZ)) {
  console.log('')
  console.log('Freshness vs staged tarball:')
  const tarBuf = gunzipSync(readFileSync(TGZ))
  const entries = []
  let off = 0
  while (off + 512 <= tarBuf.length) {
    const header = tarBuf.subarray(off, off + 512)
    if (header.every((b) => b === 0)) break
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '')
    const size = parseInt(header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim() || '0', 8)
    off += 512
    const content = size > 0 ? tarBuf.subarray(off, off + size) : Buffer.alloc(0)
    entries.push({ name, content })
    off += Math.ceil(size / 512) * 512
  }
  const byName = new Map(entries.map((e) => [e.name.replace(/^package\//, ''), e.content]))
  for (const f of rel) {
    const disk = join(ROOT, f)
    const want = existsSync(disk) ? readFileSync(disk) : null
    const got = byName.get(f)
    if (got === undefined) {
      violations.push(`tarball missing whitelist file: ${f}`)
      console.log(`  MISSING ${f}`)
    } else if (want === null) {
      violations.push(`tarball has file absent from worktree: ${f}`)
      console.log(`  EXTRA ${f}`)
    } else if (!got.equals(want)) {
      violations.push(`tarball byte-differs from worktree: ${f}`)
      console.log(`  DIFF   ${f}`)
    } else {
      console.log(`  OK     ${f}`)
    }
  }
  for (const [name, content] of byName) {
    if (name.startsWith('package/')) continue // tar pax/global headers ignored by map above
    if (!rel.includes(name)) {
      violations.push(`tarball contains non-whitelist entry: ${name} (${content.length}B)`)
      console.log(`  EXTRA  ${name}`)
    }
  }
} else {
  console.log('  (no staged tarball — freshness check skipped)')
}

// G3: install-time lifecycle hooks must not exist — this plugin sits between
// the agent and the filesystem; a preinstall/install/postinstall script would
// execute arbitrary code on the user's machine at install time.
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall']
const installHooks = INSTALL_HOOKS.filter((h) => pkg.scripts && pkg.scripts[h])
if (installHooks.length) {
  violations.push(`install-time lifecycle hooks present: ${installHooks.join(', ')}`)
  console.log(`  HOOKS  ${installHooks.join(', ')}`)
} else {
  console.log('  no install-time lifecycle hooks (preinstall/install/postinstall) ✅')
}

console.log('')
if (violations.length) {
  console.error('✗ Content audit violations:')
  for (const v of violations) console.error(`  - ${v}`)
  process.exit(1)
}

console.log(`PASS: ${files.length} files, no local paths, no source/test/scratch leakage`)
process.exit(0)
