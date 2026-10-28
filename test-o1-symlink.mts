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
import { classifyBashCommand, decide } from './src/classifier.ts'
import { isPathProtected } from './src/tm.ts'

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
  // macOS /var -> /private/var: canonicalTarget returns realpath forms.
  ROOT_REAL = realpathSync(ROOT)
  CWD_REAL = realpathSync(CWD)
  OUT_REAL = realpathSync(OUT)
  // HOME_DIR must be a real path (no symlink prefix), NOT under $HOME (a
  // sandboxed/CI $HOME is often read-only → EPERM), and NOT under any
  // AUTO_INIT_FORBIDDEN_ROOT (/private, /System, …): /Users/Shared satisfies
  // all three (review-l5b-0.2.10d O3).
  HOME_DIR = mkdtempSync('/Users/Shared/.tm-o1-')
  mkdirSync(join(HOME_DIR, 'sub'), { recursive: true })
  process.chdir(CWD)
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

test('canonicalTarget: symlink then lexical .. resolves to dotdot-escape sentinel (B4)', () => {
  assert.equal(canonicalTarget('elink/../back.txt'), '/.tmguard-dotdot-escape')
})

test('canonicalTarget: symlink then .. then more components is denied (B4)', () => {
  assert.equal(canonicalTarget('elink/../sub/f.txt'), '/.tmguard-dotdot-escape')
})

test('canonicalTarget: internal symlink + .. is also fail-closed (B4, conservative)', () => {
  assert.equal(canonicalTarget('ink/../deep.txt'), '/.tmguard-dotdot-escape')
})

test('canonicalTarget: .. after non-symlink directory is untouched (B4 control)', () => {
  assert.equal(canonicalTarget('fresh/../x.txt'), join(CWD_REAL, 'x.txt'))
})

test('canonicalTarget: symlink without .. unaffected by B4 guard', () => {
  assert.equal(canonicalTarget('elink/newdir/f.txt'), join(OUT_REAL, 'newdir/f.txt'))
})

test('classifier: symlink + lexical .. target becomes dotdot-escape sentinel (B4)', () => {
  const r = classifyBashCommand('echo hi > elink/../back.txt')
  assert.ok(r.targetPaths.some((p) => p === '/.tmguard-dotdot-escape'))
})

test('classifier: symlink + .. + more components becomes sentinel (B4)', () => {
  const r = classifyBashCommand('mkdir -p elink/../kd && echo hi > elink/../kd/f.txt')
  assert.ok(r.targetPaths.includes('/.tmguard-dotdot-escape'))
})

test('classifier: plain .. without symlink stays resolved (B4 control)', () => {
  const r = classifyBashCommand('echo hi > fresh/../x.txt')
  assert.equal(r.targetPaths[0], join(CWD_REAL, 'x.txt'))
})

test('classifier: ABSOLUTE symlink+.. path becomes sentinel (B4, review-l5b blocker 1)', () => {
  // toAbsolute() must run the B4 guard on absolute paths too — the raw
  // `elink/../` must not survive collapse when written as an absolute target.
  const r = classifyBashCommand(`echo hi > ${CWD_REAL}/elink/../abs.txt`)
  assert.ok(r.targetPaths.includes('/.tmguard-dotdot-escape'), `got ${JSON.stringify(r.targetPaths)}`)
})

test('classifier: TILDE (~) symlink+.. path becomes sentinel (B4, review-l5b blocker 2)', () => {
  // expandHome must be followed by the guard, not shortcut past it.
  const savedHome = process.env.HOME
  try {
    process.env.HOME = ROOT
    symlinkSync(OUT, join(ROOT, 'hl'))
    const r = classifyBashCommand('echo hi > ~/hl/../tilde.txt')
    assert.ok(r.targetPaths.includes('/.tmguard-dotdot-escape'), `got ${JSON.stringify(r.targetPaths)}`)
  } finally {
    process.env.HOME = savedHome
  }
})

test('classifier: $HOME symlink+.. path becomes sentinel (B4, review-l5b blocker 2)', () => {
  const savedHome = process.env.HOME
  try {
    process.env.HOME = ROOT
    symlinkSync(OUT, join(ROOT, 'hl2'))
    const r = classifyBashCommand('echo hi > $HOME/hl2/../dollar.txt')
    assert.ok(r.targetPaths.includes('/.tmguard-dotdot-escape'), `got ${JSON.stringify(r.targetPaths)}`)
  } finally {
    process.env.HOME = savedHome
  }
})

test('decide: sentinel target is forced deny even when pathsProtected=true (review-l5b O1)', () => {
  const c = {
    category: 'file_write' as const,
    reason: 'test',
    targetPaths: ['/.tmguard-dotdot-escape'],
  }
  const d = decide(c, true)
  assert.equal(d.allow, false)
  assert.match(d.reason, /forced deny/)
})

// review-l5b-0.2.10d B5-1: bare-letter `tar xf a.tar -C link/../dir` produced
// NO write target (zero-target file_write allowed via cwd coverage) and the OS
// landed extracted members outside the workspace. `-C DIR` is now extracted as
// a write target in every form (separate, glued, `--directory[=]`), and bare
// action clusters are parsed like short-option clusters.

function tarHasSentinel(cmd: string): boolean {
  const r = classifyBashCommand(cmd)
  assert.ok(r.targetPaths.includes('/.tmguard-dotdot-escape'),
    `${cmd} → got ${JSON.stringify(r.targetPaths)}`)
  return true
}

test('classifier: tar xf -C link/../dir (bare cluster) is sentinel (B5-1)', () => {
  tarHasSentinel('tar xf a.tar -C elink/../ex')
})

test('classifier: tar --directory separated form is sentinel (B5-1)', () => {
  tarHasSentinel('tar xf a.tar --directory elink/../ex')
})

test('classifier: tar --directory= glued form is sentinel (B5-1)', () => {
  tarHasSentinel('tar xf a.tar --directory=elink/../ex')
})

test('classifier: tar xpf -C form is sentinel (B5-1)', () => {
  tarHasSentinel('tar xpf a.tar -C elink/../ex')
})

test('classifier: tar -xf -C form is sentinel (B5-1)', () => {
  tarHasSentinel('tar -xf a.tar -C elink/../ex')
})

test('classifier: tar -C before -xf (reordered) is sentinel (B5-1)', () => {
  tarHasSentinel('tar -C elink/../ex -xf a.tar')
})

test('classifier: tar glued -Celink/../dir is sentinel (B5-1)', () => {
  tarHasSentinel('tar -Celink/../ex -xf a.tar')
})

test('classifier: tar create mode with -C link/../dir is sentinel (B5-1)', () => {
  tarHasSentinel('tar -C elink/../ex -cf out.tar .')
})

test('classifier: tar xf -C plain dir stays inside (B5-1 control)', () => {
  const r = classifyBashCommand('tar xf a.tar -C freshdir')
  assert.ok(!r.targetPaths.includes('/.tmguard-dotdot-escape'))
  assert.ok(r.targetPaths.some((p) => p.includes('freshdir')))
})

test('classifier: tar list -tf with -C writes nothing (B5-1 control)', () => {
  const r = classifyBashCommand('tar tf a.tar -C elink/../ex')
  assert.ok(!r.targetPaths.includes('/.tmguard-dotdot-escape'))
  assert.ok(!r.targetPaths.some((p) => p.includes('elink')))
})

test('classifier: plain filename not mistaken for bare cluster (B5-1 control)', () => {
  const r = classifyBashCommand('tar xf backup.tar')
  assert.ok(!r.targetPaths.includes('/.tmguard-dotdot-escape'))
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

// ---- B-regression cases (dsh adversarial round, 0.2.10) ----

test('canonicalTarget: >40-hop dangling parent chain returns cap sentinel (B1 fix)', () => {
  // hc/l1 -> l2 -> ... -> l41 (each link exists) -> dangling absolute target;
  // the parent-side chain must hit the hop cap and fail closed, not collapse
  // back to an in-cwd lexical path.
  const hc = join(CWD, 'hc41')
  mkdirSync(hc, { recursive: true })
  let prev = ''
  for (let i = 1; i <= 41; i++) {
    const name = `l${i}`
    const target = i < 41 ? `l${i + 1}` : join(ROOT, 'far-ghost')
    symlinkSync(target, join(hc, name))
    prev = name
  }
  const t = canonicalTarget(join('hc41', 'l1', 'new', 'f.txt'))
  assert.equal(t, '/.tmguard-symlink-cap')
  assert.ok(!(t === CWD_REAL || t.startsWith(CWD_REAL + '/')))
})

test('canonicalTarget: in-cwd symlink cycle returns loop sentinel (B2 fix)', () => {
  // ca -> cb, cb -> ca: the kernel rejects any write through the cycle with
  // ELOOP, so canonicalTarget must fail closed instead of returning an
  // in-cwd path that the gate would allow.
  symlinkSync('cb', join(CWD, 'ca'))
  symlinkSync('ca', join(CWD, 'cb'))
  const t = canonicalTarget(join('ca', 'f.txt'))
  assert.equal(t, '/.tmguard-symlink-loop')
  assert.ok(!(t === CWD_REAL || t.startsWith(CWD_REAL + '/')))
})

test('canonicalTarget: cycle terminal inside the basename chain is also a loop sentinel (B2 fix)', () => {
  // cx -> cy, cy -> cx; the target is the link itself plus a missing component.
  symlinkSync('cy', join(CWD, 'cx'))
  symlinkSync('cx', join(CWD, 'cy'))
  const t = canonicalTarget(join('cx', 'new', 'f.txt'))
  assert.equal(t, '/.tmguard-symlink-loop')
})

test('isPathProtected canonical re-check: escaped realpath is NOT covered by lexical cwd prefix (B3 premise)', async () => {
  // A symlink-escaped landing point (realpath outside cwd) must not match a
  // lexical protected prefix of the cwd itself; only an explicitly configured
  // real (TM-protected) prefix keeps allowing.
  assert.equal(await isPathProtected(join(HOME_DIR, 'out', 'new', 'x.txt'), [CWD]), false)
  assert.equal(await isPathProtected(join(HOME_DIR, 'out', 'new', 'x.txt'), [join(HOME_DIR, 'out')]), true)
  assert.equal(await isPathProtected(join(CWD, 'ok.txt'), [CWD]), true)
})
