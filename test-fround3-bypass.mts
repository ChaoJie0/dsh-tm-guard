// f-round-3 regression: the 6 remaining items from the dsh adversarial review
// of af859d2 (B1 send-var, B2 spawnSync escaped-argv, B3 node heredoc,
// B5 importlib alias, B6 subshell paren, FP-4 spec_from_file_location rel)
// plus the already-closed f-round-2 family so a regression cannot reopen them.
// Red before the round-3 fixes, green after.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand } from './src/classifier.ts'
import { scanCommandForEgress } from './src/scan-scripts.ts'

async function gate(cmd: string): Promise<{ deny: boolean; cls: any; e: any }> {
  const cls = classifyBashCommand(cmd)
  const e = await scanCommandForEgress(cmd)
  const deny =
    cls.forceDeny ||
    cls.category === 'network' ||
    cls.category === 'unknown' ||
    (cls.category === 'file_write' && cls.allow === false) ||
    e.hits.length > 0 ||
    e.unverifiable === true
  return { deny, cls, e }
}

async function expect(cmd: string, wantDeny: boolean, msg: string) {
  const r = await gate(cmd)
  assert.equal(r.deny, wantDeny, `${msg} (${r.cls.category}, deny=${r.deny})`)
}

// ---------- B1: Open3 family incl. dynamic dispatch on a variable ----------
test('B1: Open3 alias / :: / send / method / interp all fail closed', async () => {
  const cases: [string, boolean][] = [
    [`find . -exec ruby -e 'require "open3";o=Open3;o.capture2("echo X")' {} \\;`, true],
    [`find . -exec ruby -e 'require "open3";i,o=Open3::popen2("echo X")' {} \\;`, true],
    [`find . -exec ruby -e 'require "open3";Open3.send(:capture2,"echo X")' {} \\;`, true],
    [`find . -exec ruby -e 'require "open3";m="capture2";Open3.send(m,"echo X")' {} \\;`, true],
    [`find . -exec ruby -e 'require "open3";Open3.method("capture2").call("echo X")' {} \\;`, true],
    [`find . -exec ruby -e 'require "open3";Open3.public_send("popen#{2}","echo X")' {} \\;`, true],
  ]
  for (const [cmd, want] of cases) await expect(cmd, want, 'B1')
})

// ---------- B2: node spawnSync with network argv, incl. escaped quotes ----------
test('B2: node spawnSync network argv fails closed; literal argv stays read', async () => {
  await expect(`find . -exec sh -c 'node -e "require(\\"child_process\\").spawnSync(\\"curl\\",[\\"http://x\\"])"' _ {} \\;`, true, 'B2 escaped curl')
  await expect(`find . -exec node -e 'require("child_process").spawnSync("curl",["http://x"])' {} \\;`, true, 'B2 direct curl')
  await expect(`find . -exec sh -c 'node -e "require(\\"child_process\\").spawnSync(\\"ls\\")"' _ {} \\;`, false, 'B2 literal ls stays read')
})

// ---------- B3: heredoc stdin interpreters execute arbitrary code ----------
test('B3: heredoc bodies (ruby/python/node/perl/tab/quoted/wrapper) fail closed', async () => {
  const cases: [string, boolean][] = [
    [`find . -name fd -exec ruby - {} \\; <<'RB'\nsystem("echo X")\nRB`, true],
    [`find . -name fd -exec python3 - {} \\; <<'PY'\nimport os;os.system("echo X")\nPY`, true],
    [`find . -name fd -exec node - {} \\; <<'JS'\nrequire("child_process").execSync("echo X")\nJS`, true],
    [`find . -name fd -exec perl - {} \\; <<'PL'\nsystem("echo X");\nPL`, true],
    [`find . -name fd -exec ruby - {} \\; <<-'RB'\n\tsystem("echo X")\n\tRB`, true],
    [`find . -name fd -exec ruby - {} \\; <<RB\nsystem("echo X")\nRB`, true],
    [`find . -name fd -exec sh -c 'ruby -' {} \\; <<'RB'\nsystem("echo X")\nRB`, true],
    [`find . -name fd -exec cat {} \\; <<'EOF'\nhello world\nEOF`, false],
  ]
  for (const [cmd, want] of cases) await expect(cmd, want, 'B3')
})

// ---------- B4: PYTHONHOME / PYTHONPATH overrides ----------
test('B4: PYTHONHOME/PYTHONPATH absolute/~/.. fails closed; relative stays read', async () => {
  const cases: [string, boolean][] = [
    [`PYTHONHOME=~/nonexist python3 -c 'pass'`, true],
    [`cd fd && PYTHONHOME=../hrel2 python3 -c 'pass'`, true],
    [`python3 - <<'PY'\nimport os\nos.environ["PYTHONHOME"]="/tmp/evil"\nPY`, true],
    [`PYTHONPATH=~/evil python3 -c 'pass'`, true],
    [`PYTHONPATH=./lib python3 -c 'pass'`, false],
  ]
  for (const [cmd, want] of cases) await expect(cmd, want, 'B4')
})

// ---------- B5: sys.path mutations + importlib alias ----------
test('B5: sys.path setitem/getattr/importlib-alias absolute fails closed; relative stays read', async () => {
  const cases: [string, boolean][] = [
    [`python3 -c 'import sys;sys.path.__setitem__(0,"/tmp/evilpath2");import m'`, true],
    [`python3 -c 'import sys;getattr(sys.path,"insert")(0,"/tmp/evilpath2");import m'`, true],
    [`python3 -c 'from importlib.util import spec_from_file_location as s;s("m","/tmp/none.py")'`, true],
    [`python3 -c 'import sys;sys.path.__setitem__(0,"./lib");import x'`, false],
    [`python3 -c 'import sys;sys.path.insert(0,"./lib");import x'`, false],
  ]
  for (const [cmd, want] of cases) await expect(cmd, want, 'B5')
})

// ---------- B6: wrapper prefixes incl. subshell paren ----------
test('B6: nohup/command/time/env/paren-wrapped stdin interpreters fail closed', async () => {
  const cases: [string, boolean][] = [
    [`echo 1 | nohup python3 -`, true],
    [`echo 1 | command python3 -`, true],
    [`echo 1 | time python3 -`, true],
    [`echo 1 | env python3 -`, true],
    [`echo 1 | env -i python3 -`, true],
    [`echo 1 | nohup nohup python3 -`, true],
    [`echo 1 | X=1 nohup python3 -`, true],
    [`echo 1 | (python3 -)`, true],
    [`echo 1 | nohup node /dev/stdin`, true],
    [`echo 1 | python3 -c 'print(1)'`, false],
  ]
  for (const [cmd, want] of cases) await expect(cmd, want, 'B6')
})

// ---------- FP-3/FP-4/FP-5 benign surfaces stay allowed ----------
test('FP-3/4/5: relative addsitedir/spec/module_from_spec and ruby puts stay read', async () => {
  const cases: [string, boolean][] = [
    [`python3 -c 'import site;site.addsitedir("./lib");import x'`, false],
    [`python3 -c 'import importlib.util as u;u.spec_from_file_location("m","./m.py")'`, false],
    [`python3 -c 'import importlib.util as u;u.module_from_spec(u.spec_from_file_location("m","./m.py"))'`, false],
    [`ruby -e 'puts "operating system check"'`, false],
  ]
  for (const [cmd, want] of cases) await expect(cmd, want, 'FP')
})
