// O1 symlink-escape regression tests for canonicalTarget / isAutoInitSafe.
//
// The O1 blind spot (found on the live isolated host while releasing 0.2.10):
// a symlink ancestor pointing OUTSIDE the workspace, followed by one or more
// not-yet-existing components, fell back to the LEXICAL path in canonicalTarget
// when the parent could not be realpath'd — placing the write "inside" cwd.
// 0.2.9's missing-dir git init ENOENT accidentally denied it; the 0.2.10
// ancestor fallback changed it to allow + a git baseline created in the real
// external directory (git follows the symlink). Fix: resolveParentToReal walks
// up to the nearest existing ancestor, realpath's it, and re-appends the
// missing suffix (dangling links followed lexically); isAutoInitSafe now also
// refuses anchors whose realpath escapes the session cwd.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, symlinkSync, rmSync, realpathSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir, homedir } from 'node:os'
import { canonicalTarget, isAutoInitSafe } from './src/index.ts'

let ROOT = ''
let CWD = ''
let OUT = ''
let ROOT_REAL = ''
let CWD_REAL = ''
let OUT_REAL = ''
let HOME_DIR = '' // real /Users dir (no /private/var prefix) for isAutoInitSafe true-cases
let HOME = homedir()
const ORIG_CWD = process.cwd()

before(() => {
  ROOT = mkdtempSync(join(tmpdir(), 'tm-o1-'))
  CWD = join(ROOT, 'cwd')
  OUT = join(ROOT, 'outside')
  mkdirSync(CWD, { recursive: true })
  mkdirSync(OUT, { recursive: true })
  mkdirSync(join(CWD, 'sub'), { recursive: true })
  symlinkSync(OUT, join(CWD, 'elink'))                    // existing external link
  symlinkSync(join(ROOT, 'outside-x'), join(CWD, 'dlink')) // dangling link
  symlinkSync(join(CWD, 'sub'), join(CWD, 'ink'))         // internal link (target exists)
  HOME_DIR = mkdtempSync(join(HOME, '.tm-o1-'))
  mkdirSync(join(HOME_DIR, 'sub'), { recursive: true })
  process.chdir(CWD)
  // macOS /var -> /private/var: canonicalTarget returns realpath forms.
  ROOT_REAL = realpathSync(ROOT)
  CWD_REAL = realpathSync(CWD)
  OUT_REAL = realpathSync(OUT)
})

after(() => {
  process.chdir(ORIG_CWD)
  rmSync(ROOT, { recursive: true, force: true })
  if (HOME_DIR) rmSync(HOME_DIR, { recursive: true, force: true })
})

test('canonicalTarget: external symlink + missing component resolves outside (O1 fix)', () => {
  assert.equal(canonicalTarget('elink/newdir/f.txt'), join(OUT_REAL, 'newdir/f.txt'))
})

test('canonicalTarget: dangling symlink ancestor + missing component follows link target (O1 fix)', () => {
  // The dangling link's lexical target (link text) is returned; it must be
  // judged OUTSIDE the real cwd (the OS write follows the link out).
  const t = canonicalTarget('dlink/f.txt')
  assert.equal(t, join(ROOT, 'outside-x/f.txt'))
  assert.ok(!(t === CWD_REAL || t.startsWith(CWD_REAL + '/')))
})

test('canonicalTarget: existing parent + new file resolves the link (unchanged)', () => {
  assert.equal(canonicalTarget('elink/probe.txt'), join(OUT_REAL, 'probe.txt'))
})

test('canonicalTarget: plain missing directory stays lexical inside cwd (unchanged)', () => {
  assert.equal(canonicalTarget('fresh/f.txt'), join(CWD_REAL, 'fresh/f.txt'))
})

test('canonicalTarget: internal symlink + missing file stays inside (unchanged)', () => {
  assert.equal(canonicalTarget('ink/f.txt'), join(CWD_REAL, 'sub/f.txt'))
})

test('canonicalTarget: lexical .. before symlink still resolves outside (unchanged)', () => {
  assert.equal(canonicalTarget('sub/../elink/newdir/f.txt'), join(OUT_REAL, 'newdir/f.txt'))
})

test('canonicalTarget: bare external symlink resolves to its target (unchanged)', () => {
  assert.equal(canonicalTarget('elink'), OUT_REAL)
})

test('canonicalTarget: lexical escape outside cwd stays outside (unchanged)', () => {
  assert.equal(canonicalTarget('../outside/x'), join(ROOT_REAL, 'outside/x'))
})

test('canonicalTarget: existing file inside cwd resolves to realpath (unchanged)', () => {
  writeFileSync(join(CWD, 'real.txt'), 'x')
  assert.equal(canonicalTarget('real.txt'), realpathSync(join(CWD, 'real.txt')))
})

test('isAutoInitSafe: cwd itself is safe (unchanged, real /Users path)', () => {
  assert.equal(isAutoInitSafe(HOME_DIR, HOME_DIR), true)
})

test('isAutoInitSafe: inside-cwd anchor is safe (unchanged, real /Users path)', () => {
  assert.equal(isAutoInitSafe(join(HOME_DIR, 'sub'), HOME_DIR), true)
})

test('isAutoInitSafe: external-symlink anchor is REFUSED (O1 defense-in-depth)', () => {
  assert.equal(isAutoInitSafe(join(CWD, 'elink'), CWD_REAL), false)
})

test('isAutoInitSafe: anchor whose realpath is outside cwd is REFUSED (O1 defense-in-depth)', () => {
  assert.equal(isAutoInitSafe(OUT_REAL, CWD_REAL), false)
})

test('isAutoInitSafe: forbidden roots still refused (unchanged)', () => {
  assert.equal(isAutoInitSafe('/', HOME_DIR), false)
  assert.equal(isAutoInitSafe('/Users', HOME_DIR), false)
  assert.equal(isAutoInitSafe(HOME, HOME_DIR), false)
  assert.equal(isAutoInitSafe('/System', HOME_DIR), false)
  assert.equal(isAutoInitSafe('/System/Library', HOME_DIR), false)
})
