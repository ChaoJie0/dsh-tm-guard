// Regression tests for the three security findings from the independent dsh
// review (M1 dd if= bypass, M2 write-side `..` escape, M3 glued --flag=value
// bypass) plus the S1 tool-arg key-name gap. Red before the fix, green after.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand, classifyToolCall, normalizeForMatch } from './src/classifier.ts'
import { isPathProtected, __setExecOverride } from './src/tm.ts'

const DENY_READ = ['~/.ssh', '~/.aws', '~/Library/Keychains']

// ---------- M1: dd if= is a read path ----------
test('M1: dd if=<sensitive> is denied (read side extracted)', () => {
  const c = classifyBashCommand('dd if=~/.ssh/id_rsa of=/tmp/stolen.key', DENY_READ)
  assert.equal(c.forceDeny, true, 'dd if=~/.ssh must be force-denied')
  const c2 = classifyBashCommand('dd if=/Users/zero/.aws/credentials of=/tmp/k', DENY_READ)
  assert.equal(c2.forceDeny, true)
})

test('M1: dd with non-sensitive input stays usable', () => {
  const c = classifyBashCommand('dd if=/etc/hosts of=/tmp/copy bs=1k', DENY_READ)
  assert.ok(!c.forceDeny, 'dd with non-sensitive I/O must not be force-denied')
  assert.equal(c.category, 'file_write')
})

// ---------- M3: glued --flag=value carries a path ----------
test('M3: --flag=<sensitive> is denied (read side)', () => {
  for (const cmd of [
    'grep --file=~/.ssh/id_rsa /tmp/a',
    'grep --regexp=~/.ssh/id_rsa /tmp/a',
    'sort --files0-from=~/.ssh/list /tmp/a',
    'diff --from-file=~/.ssh/id_rsa /tmp/a',
  ]) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.equal(c.forceDeny, true, `${cmd} must be denied`)
  }
})

test('M3: --flag=<sensitive> is denied (write side)', () => {
  const c = classifyBashCommand('sort --output=~/.ssh/x /tmp/a', DENY_READ)
  assert.equal(c.forceDeny, true)
})

test('M3: --flag=<non-sensitive> does not false-positive', () => {
  const c = classifyBashCommand('grep --file=/etc/hosts /tmp/a', DENY_READ)
  assert.ok(!c.forceDeny, 'non-sensitive file must not be force-denied')
  const c2 = classifyBashCommand('sort --output=/tmp/x /tmp/a', DENY_READ)
  assert.ok(!c2.forceDeny, 'non-sensitive output must not be force-denied')
})

// ---------- M2: write-side path normalization ----------
test('M2: isPathProtected resolves `..` escapes to false', async () => {
  __setExecOverride(async () => ({ stdout: '[Included]\n' }))
  try {
    const prefixes = ['/Users/zero/projects/myapp']
    assert.equal(await isPathProtected('/Users/zero/projects/myapp/a.ts', prefixes), true)
    assert.equal(await isPathProtected('/Users/zero/projects/myapp/../secrets.txt', prefixes), false)
    assert.equal(await isPathProtected('/Users/zero/projects/myapp/../../.zshrc', prefixes), false)
    // // and case normalize to a protected prefix
    assert.equal(await isPathProtected('//Users//zero//projects//myapp//a.ts', prefixes), true)
    assert.equal(await isPathProtected('/Users/ZERO/Projects/MyApp/A.TS', prefixes), true)
    // sibling prefix must NOT match
    assert.equal(await isPathProtected('/Users/zero/projects/myapp-evil/a.ts', prefixes), false)
  } finally { __setExecOverride(null) }
})

test('M2: normalizeForMatch resolves segments deterministically', () => {
  assert.equal(normalizeForMatch('/a/b/../c'), '/a/c')
  assert.equal(normalizeForMatch('/a//b/./c/'), '/a/b/c')
  assert.equal(normalizeForMatch('/Users/X/SSH'), '/users/x/ssh')
})

// ---------- S1: tool arg key names ----------
test('S1: classifyToolCall sees filePath / paths[] / pattern keys', () => {
  for (const [name, args] of [
    ['fs_read_file', { filePath: '/Users/zero/.ssh/id_rsa' }],
    ['read_multiple_files', { paths: ['/Users/zero/.ssh/id_rsa'] }],
    ['read_files', { paths: ['/a.txt', '/Users/zero/.aws/credentials'] }],
    ['glob', { pattern: '/Users/zero/.ssh/*' }],
  ] as const) {
    const c = classifyToolCall(name, args, DENY_READ)
    assert.equal(c.forceDeny, true, `${name} ${JSON.stringify(args)} must be denied`)
  }
})

test('S1: non-sensitive multi-path args stay allowed', () => {
  const c = classifyToolCall('read_multiple_files', { paths: ['/tmp/a', '/tmp/b'] }, DENY_READ)
  assert.ok(!c.forceDeny)
})

// ---------- R1/R2: regressions introduced by the fix batch ----------
test('R1: read-typed glued flags do NOT become write targets (no in-scope false deny)', () => {
  // tar --files-from is a READ input; with the generic write-side glue
  // extraction it landed in targetPaths and denied legitimate in-scope writes
  // whenever the input list lives outside the protected prefix.
  const c = classifyBashCommand('tar --files-from=/etc/list -C /tmp/out .', DENY_READ)
  // The essential regression: a read-typed input outside the protected scope
  // must NOT turn an in-scope write into a deny.
  assert.ok(!c.forceDeny, 'tar --files-from (read input) must not force-deny the write')
  const c2 = classifyBashCommand('diff --from-file=/etc/hosts /tmp/a', DENY_READ)
  assert.ok(!c2.forceDeny, 'diff --from-file (read-typed) must not be force-denied')
})

test('R1: write-typed glued flags still caught', () => {
  for (const cmd of ['sort --output=~/.ssh/x /tmp/a', 'sort -o=/Users/zero/.ssh/x /tmp/a']) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.ok(c.forceDeny || c.targetPaths.some((p) => p.includes('/.ssh/')), `${cmd} must keep write path visible`)
  }
})

test('R2: relative protectedPrefix "." resolves to cwd, not the whole disk', async () => {
  __setExecOverride(async () => ({ stdout: '[Included]\n' }))
  try {
    // With the raw normalizeForMatch(".") → "/" bug, every absolute path was
    // "protected" — the writable scope silently became the whole disk.
    const dot = await isPathProtected('/etc/passwd', ['.'])
    assert.equal(dot, false)
    const rel = await isPathProtected('a.txt', ['src']) // "src" relative → cwd/src
    // cwd is the project dir; ./src may not exist as prefix for 'a.txt'
    assert.equal(rel, false)
  } finally { __setExecOverride(null) }
})
