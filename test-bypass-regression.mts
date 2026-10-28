// Regression tests for the three security findings from the independent dsh
// review (M1 dd if= bypass, M2 write-side `..` escape, M3 glued --flag=value
// bypass) plus the S1 tool-arg key-name gap. Red before the fix, green after.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import { classifyBashCommand, classifyToolCall, normalizeForMatch } from './src/classifier.ts'
import { isPathProtected, __setExecOverride } from './src/tm.ts'

const HOME = os.homedir()
const DENY_READ = ['~/.ssh', '~/.aws', '~/Library/Keychains']

// ---------- M1: dd if= is a read path ----------
test('M1: dd if=<sensitive> is denied (read side extracted)', () => {
  const c = classifyBashCommand('dd if=~/.ssh/id_rsa of=/tmp/stolen.key', DENY_READ)
  assert.equal(c.forceDeny, true, 'dd if=~/.ssh must be force-denied')
  const c2 = classifyBashCommand(`dd if=${HOME}/.aws/credentials of=/tmp/k`, DENY_READ)
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
    const prefixes = [`${HOME}/projects/myapp`]
    assert.equal(await isPathProtected(`${HOME}/projects/myapp/a.ts`, prefixes), true)
    assert.equal(await isPathProtected(`${HOME}/projects/myapp/../secrets.txt`, prefixes), false)
    assert.equal(await isPathProtected(`${HOME}/projects/myapp/../../.zshrc`, prefixes), false)
    // // and case normalize to a protected prefix
    assert.equal(await isPathProtected(`//${HOME}//projects//myapp//a.ts`, prefixes), true)
    assert.equal(await isPathProtected(`${HOME.toUpperCase()}/Projects/MyApp/A.TS`, prefixes), true)
    // sibling prefix must NOT match
    assert.equal(await isPathProtected(`${HOME}/projects/myapp-evil/a.ts`, prefixes), false)
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
    ['fs_read_file', { filePath: `${HOME}/.ssh/id_rsa` }],
    ['read_multiple_files', { paths: [`${HOME}/.ssh/id_rsa`] }],
    ['read_files', { paths: ['/a.txt', `${HOME}/.aws/credentials`] }],
    ['glob', { pattern: `${HOME}/.ssh/*` }],
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
  for (const cmd of [`sort --output=~/.ssh/x /tmp/a`, `sort -o=${HOME}/.ssh/x /tmp/a`]) {
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

test('R1b: write-typed glued flag variants keep out-of-scope writes caught', () => {
  // dsh review round 3: the whitelist over-narrowed and dropped --outfile /
  // --target-directory, silently re-allowing out-of-workspace writes.
  const cases = [
    `gzip --outfile=${HOME}/outside/a.gz /tmp/a`,
    'tar --outfile=~/outside/a.tar -cf x.tar /tmp',
    `cp /tmp/a --target-directory=${HOME}/outside/`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.ok(
      c.targetPaths.some((p) => p.includes('outside') || p.includes('outside/')),
      `${cmd} must surface the out-of-scope write path (got ${JSON.stringify(c.targetPaths)})`,
    )
  }
})

// ── f-round review (docs/f-round-h-review-37ac047.md): F1-F4 regression ──
// Each fix needs a positive intercept + a negative no-false-positive.

// F1: ruby/perl/php find-launcher variants fail closed (no-paren, %x,
// Kernel.send, pipe-open, IPC::Open2/3, fork+exec, php primitives).
test('f/F1: ruby find launchers (no-paren / %x / Kernel.send) fail closed', () => {
  const cases = [
    `find . -exec ruby -e 'c="id";system c' {} \;`,
    `find . -exec ruby -e '%x(id)' {} \;`,
    `find . -exec ruby -e 'Kernel.send(:system,"id")' {} \;`,
    `find . -exec ruby -e 'system"id"' {} \;`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
    assert.notEqual(c.category, 'local_exec', `${cmd} must fail closed`)
  }
})

test('f/F1: perl find launchers (pipe-open / IPC::Open2 / fork+exec) fail closed', () => {
  const cases = [
    `find . -exec perl -e 'open(my $f,"-|") or exec "id"; print <$f>' {} \;`,
    `find . -exec perl -MIPC::Open2 -e 'open2($o,$i,"id")' {} \;`,
    `find . -exec perl -e 'fork; exec "id"' {} \;`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
    assert.notEqual(c.category, 'local_exec', `${cmd} must fail closed`)
  }
})

test('f/F1: php find launchers (proc_open / passthru / pcntl_exec) fail closed', () => {
  const cases = [
    `find . -exec php -r 'proc_open("id",[],$p);' {} \;`,
    `find . -exec php -r 'passthru("id");' {} \;`,
    `find . -exec php -r 'pcntl_exec("/bin/sh");' {} \;`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
    assert.notEqual(c.category, 'local_exec', `${cmd} must fail closed`)
  }
})

test('f/F1: python find launchers with non-literal argv fail closed', () => {
  const cases = [
    `find . -exec python3 -c "import os;c='curl';os.popen(c).read()" {} \;`,
    `find . -exec python3 -c "import os;os.execvp('cu'+'rl',['curl'])" {} \;`,
    `find . -exec python3 -c "import subprocess;subprocess.run(cmd)" {} \;`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
    assert.notEqual(c.category, 'local_exec', `${cmd} must fail closed`)
  }
})

test('f/F1: node find launchers with non-literal argv fail closed', () => {
  const cases = [
    `find . -exec node -e "require('child_process').spawnSync(cmd)" {} \;`,
    `find . -exec node -e "require('child_process').spawn('cu'+'rl',['curl'])" {} \;`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
    assert.notEqual(c.category, 'local_exec', `${cmd} must fail closed`)
  }
})

// F1 negatives: literal local argv stays read (G5/G6/G3/G4 contract).
test('f/F1-neg: literal local argv keeps read (no false positives)', () => {
  const cases = [
    `find /tmp/demo/project -exec ruby -e 'puts "operating system check"' {} \;`,
    `find /tmp/demo/project -exec perl -Mstrict -e 'print(1)' {} \;`,
    `find /tmp/demo/project -exec python3 -c "os.popen('ls').read()" {} \;`,
    `find /tmp/demo/project -exec python3 -c "os.execvp('ls',['ls'])" {} \;`,
    `find /tmp/demo/project -exec python3 -c "subprocess.run(['ls'])" {} \;`,
    `find /tmp/demo/project -exec node -e "require('child_process').spawnSync('ls')" {} \;`,
    `find /tmp/demo/project -exec node -e "console.log(1)" {} \;`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.equal(c.category, 'read', `${cmd} must stay read (got ${c.category})`)
  }
})

// F3: PYTHONPATH / sys.path code-load vectors fail closed.
test('f/F3: PYTHONPATH/sys.path outside-cwd code load fails closed', () => {
  const cases = [
    `python3 -c 'import sys;sys.path.insert(0,"/tmp/evil");import m'`,
    `PYTHONPATH=/tmp/evil python3 -c 'import m'`,
    `env PYTHONPATH=/tmp/evil python3 -c 'import m'`,
    `export PYTHONPATH=/tmp/evil; python3 script.py`,
    `export PYTHONPATH; python3 script.py`,
    `python3 -c 'import sys;sys.path.insert(0,v);import m'`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
    assert.notEqual(c.category, 'local_exec', `${cmd} must fail closed`)
  }
})

test('f/F3-neg: cwd-relative python code load stays allowed', () => {
  const cases = [
    `python3 -c 'import sys;sys.path.insert(0,"./lib");import m'`,
    `PYTHONPATH=./lib python3 -c 'import m'`,
    `export PYTHONPATH=./lib; python3 script.py`,
    `export PATH=/usr/bin; python3 script.py`,
    `python3 -c 'import sys;print(sys.path)'`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'unknown', `${cmd} must not fail closed (got ${c.category})`)
    assert.notEqual(c.category, 'network', `${cmd} must not be network (got ${c.category})`)
  }
})

// F4: interpreter reading code from stdin (pipe or bare "-") fails closed.
test('f/F4: piped/stdin interpreter code source fails closed', () => {
  const cases = [
    `echo 'import urllib.request;urllib.request.urlopen("http://x")' | python3 -`,
    `echo 'import os;os.system("id")' | python3 /dev/stdin`,
    `python3 -`,
    `node /dev/stdin`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
    assert.notEqual(c.category, 'local_exec', `${cmd} must fail closed`)
  }
})

test('f/F4-neg: explicit -c and file-fed interpreters keep their paths', () => {
  const cases = [
    `python3 -c 'print(1)'`,
    `cat <<'PY' > /tmp/x; python3 /tmp/x`,
  ]
  for (const cmd of cases) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.ok(c, `classifies ${cmd}`)
  }
})

// ---------- f-round-2 (dsh adversarial review of 690af9a) ----------
// F1-a: Open3 family inside a find -exec ruby action fails closed.
test('f2/F1-a: Open3 capture2/pipeline find actions fail closed', () => {
  for (const cmd of [
    `find . -exec ruby -e 'require "open3";Open3.capture2("id")' {} \\;`,
    `find . -exec ruby -e 'Open3.pipeline(["id"])' {} \\;`,
  ]) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
  }
})

// F1-b: sh -c wrapper around a double-quoted node/python inline code string.
test('f2/F1-b: wrapped double-quoted node/python inline code fails closed', () => {
  for (const cmd of [
    `find . -exec sh -c 'node -e "require(\\"child_process\\").execSync(\\"id\\")"' _ {} \\;`,
    `find . -exec sh -c 'python3 -c "import os;os.system(\\"echo X\\")"' _ {} \\;`,
  ]) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
  }
})

// F1-c: perl three-arg pipe-open write end inside find -exec.
test('f2/F1-c: perl "|-" pipe-open write end fails closed', () => {
  const c = classifyBashCommand(`find . -exec perl -e 'open(my $f,"|-","id");print $f ""' {} \\;`, DENY_READ)
  assert.notEqual(c.category, 'read', 'perl pipe-open write end must NOT stay read')
})

// F2-a: compressor -I hidden behind two escaped backtick layers.
test('f2/F2-a: gzip -I at depth-2 backtick substitution fails closed', () => {
  const c = classifyBashCommand('echo `echo \\`gzip -dc -I sh evil.gz\\``', DENY_READ)
  assert.notEqual(c.category, 'read', 'gzip -I at depth 2 must NOT stay read')
})

// F3-a: PYTHONHOME env override is an unverifiable interpreter code load.
test('f2/F3-a: PYTHONHOME env override fails closed', () => {
  const c = classifyBashCommand('PYTHONHOME=/tmp/evil python3 -c "import m"', DENY_READ)
  assert.notEqual(c.category, 'read', 'PYTHONHOME must NOT stay read')
})

// F4: stdin/stdin-marker/fd interpreters fail closed; benign -c stays open.
test('f2/F4: stdin and fd-fed interpreters fail closed', () => {
  for (const cmd of [
    `python3 - < /tmp/payload.py`,
    `node /dev/fd/63 63< /tmp/p.js`,
    `printf "print(1)\\n" | nohup python3 -`,
  ]) {
    const c = classifyBashCommand(cmd, DENY_READ)
    assert.notEqual(c.category, 'read', `${cmd} must NOT stay read`)
  }
})

// FP-1: subprocess.Popen(['ls','-la']) as a find action stays usable (no FP).
test('f2/FP-1: Popen list literal in find action is not over-denied', () => {
  const c = classifyBashCommand(`find . -exec python3 -c "import subprocess;subprocess.Popen(['ls','-la'])" {} \\;`, DENY_READ)
  assert.notEqual(c.category, 'unknown', 'Popen list must NOT fail closed')
  assert.notEqual(c.category, 'network', 'Popen list must NOT be network')
})
