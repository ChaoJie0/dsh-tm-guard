#!/usr/bin/env node
/**
 * Post-publish verification — `npm run verify:postpublish`
 *
 * Run AFTER `npm publish`. Read-only against the registry and the local
 * worktree; it never publishes, tags, or mutates anything. It confirms the
 * version actually reachable on npm is the exact artifact that passed the
 * pre-publish gates:
 *
 *   A. registry metadata: name/version/main/types/license/peerDependencies match
 *   B. published tarball: required members present, no leakage, every shipped
 *      file byte-matches the local worktree (what you audited = what ships)
 *   C. entry point sanity: lib/index.js exports are present
 *
 * Exit code:
 *   0 = all checks PASS
 *   1 = a hard mismatch (wrong version/name, drift, leakage, missing member)
 *   2 = registry unreachable (UNKNOWN) — network only, re-run when online
 */
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import { gunzipSync } from 'node:zlib'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const NAME = pkg.name
const VERSION = pkg.version
const REGISTRY = 'https://registry.npmjs.org'

const failures = []
const unknowns = []
const ok = []

function fail(msg) { failures.push(msg) }
function unknown(msg) { unknowns.push(msg) }
function pass(msg) { ok.push(msg) }

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex')
}

// Expand package.json `files` whitelist into relative shipped paths (mirrors
// verify:pack-audit.mjs). package.json itself always ships.
function expand(entry) {
  const p = join(ROOT, entry)
  const st = statSync(p)
  if (st.isDirectory()) {
    return readdirSync(p, { withFileTypes: true })
      .sort((a, b) => (a.name < b.name ? -1 : 1))
      .flatMap((d) => (d.isDirectory() ? expand(join(entry, d.name)) : [join(entry, d.name)]))
  }
  return [entry]
}
const shipped = [...new Set([...(pkg.files || []).flatMap(expand), 'package.json'])]

async function fetchJson(url, timeoutMs = 12000) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } })
    return { status: res.status, body: await res.json() }
  } catch {
    return { status: 0, body: null }
  } finally {
    clearTimeout(t)
  }
}

async function fetchBuffer(url, timeoutMs = 30000) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(url, { signal: ctrl.signal })
    if (!res.ok) return { status: res.status, buf: null }
    return { status: res.status, buf: Buffer.from(await res.arrayBuffer()) }
  } catch {
    return { status: 0, buf: null }
  } finally {
    clearTimeout(t)
  }
}

// Minimal ustar member walk over a gzip tarball; returns [{name, content}].
function parseTar(tgz) {
  const tar = gunzipSync(tgz)
  const entries = []
  let off = 0
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512)
    if (header.every((b) => b === 0)) break
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '')
    const size = parseInt(header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim() || '0', 8)
    off += 512
    const content = size > 0 ? tar.subarray(off, off + size) : Buffer.alloc(0)
    entries.push({ name, content })
    off += Math.ceil(size / 512) * 512
  }
  return entries
}

console.log(`POST-PUBLISH CHECK — ${NAME}@${VERSION}`)
console.log('===========================================')

// ---- A. registry metadata ------------------------------------------------
let meta = null
{
  const { status, body } = await fetchJson(`${REGISTRY}/${NAME}/${VERSION}`)
  if (status === 0) {
    unknown('registry unreachable (network) — metadata check skipped')
  } else if (status === 404) {
    fail(`version ${VERSION} NOT found on registry — publish it before running this check`)
  } else if (status !== 200) {
    unknown(`registry returned HTTP ${status} — metadata check inconclusive`)
  } else {
    meta = body
    if (meta.name !== NAME) fail(`registry name ${meta.name} != local ${NAME}`)
    else pass(`registry name ${meta.name}`)
    if (meta.version !== VERSION) fail(`registry version ${meta.version} != local ${VERSION}`)
    else pass(`registry version ${meta.version}`)
    for (const field of ['main', 'types', 'license', 'type']) {
      const local = pkg[field]
      if (local == null) continue
      if (meta[field] !== local) fail(`registry ${field} ${JSON.stringify(meta[field])} != local ${JSON.stringify(local)}`)
      else pass(`metadata ${field} = ${meta[field]}`)
    }
    const localPeer = pkg.peerDependencies || {}
    const regPeer = meta.peerDependencies || {}
    for (const dep of Object.keys(localPeer)) {
      if (regPeer[dep] !== localPeer[dep]) fail(`peerDependency ${dep}: registry ${regPeer[dep]} != local ${localPeer[dep]}`)
      else pass(`peerDependency ${dep} ${regPeer[dep]}`)
    }
    for (const dep of Object.keys(regPeer)) {
      if (!(dep in localPeer)) fail(`registry has unexpected peerDependency ${dep}`)
    }
    if (!meta.dist?.tarball) fail('registry metadata has no dist.tarball URL')
    else pass(`tarball ${meta.dist.tarball.split('/').pop()}`)
  }
}

// ---- B. tarball members + byte match against local worktree --------------
if (meta?.dist?.tarball) {
  const { status, buf } = await fetchBuffer(meta.dist.tarball)
  if (status === 0 || buf == null) {
    unknown('tarball download failed (network) — content check skipped')
  } else {
    const entries = parseTar(buf)
    const byName = new Map(entries.map((e) => [e.name.replace(/^package\//, ''), e.content]))

    const REQUIRED = ['lib/index.js', 'cordis.patch.yml', 'README.md', 'CHANGELOG.md', 'LICENSE', 'package.json']
    for (const rel of REQUIRED) {
      if (!byName.has(rel)) fail(`tarball missing required member: ${rel}`)
      else pass(`member present: ${rel}`)
    }

    const FORBIDDEN = [/(^|\/)src\//, /(^|\/)test-.*\.m[jt]s$/, /(^|\/)\.git(\/|$)/, /(^|\/)node_modules(\/|$)/, /^\/Users\//, /^\/private\//, /^\/tmp\//]
    for (const name of byName.keys()) {
      for (const re of FORBIDDEN) {
        if (re.test(name)) fail(`tarball leaks forbidden entry: ${name} (${re.source})`)
      }
    }

    for (const rel of shipped) {
      const got = byName.get(rel)
      const localPath = join(ROOT, rel)
      if (got === undefined) {
        fail(`tarball missing whitelisted file: ${rel}`)
        continue
      }
      if (!existsSync(localPath)) {
        fail(`tarball has file absent from worktree: ${rel}`)
        continue
      }
      if (!got.equals(readFileSync(localPath))) {
        fail(`published ${rel} byte-differs from worktree (drift)`)
      }
    }
    const localSet = new Set(shipped)
    for (const name of byName.keys()) {
      if (!localSet.has(name)) fail(`tarball contains non-whitelist entry: ${name}`)
    }
    pass(`tarball parsed: ${entries.length} entries, ${(buf.length / 1024).toFixed(1)} KiB`)
  }
}

// ---- C. entry point sanity (static; no peer import to avoid false negatives)
{
  const entry = join(ROOT, 'lib/index.js')
  if (existsSync(entry)) {
    const text = readFileSync(entry, 'utf8')
    if (!/^export\s/m.test(text) && !/export\s*\{/m.test(text)) fail('lib/index.js exposes no exports')
    else pass('entry point exports present')
  } else {
    fail('lib/index.js missing locally')
  }
}

// ---- render ---------------------------------------------------------------
console.log('')
for (const m of ok) console.log(`✅ ${m}`)
for (const m of unknowns) console.log(`⚠️  ${m}`)
for (const m of failures) console.error(`✗ ${m}`)

console.log('')
if (failures.length) {
  console.error(`✗ POST-PUBLISH FAIL: ${failures.length} problem(s)`)
  process.exit(1)
}
if (unknowns.length) {
  console.log(`◐ POST-PUBLISH UNVERIFIED (${unknowns.length} network item) — re-run online; no hard mismatch`)
  process.exit(2)
}
console.log(`✅ POST-PUBLISH PASS: registry ${NAME}@${VERSION} matches audited worktree`)
process.exit(0)
