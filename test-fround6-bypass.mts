// f-round-6 regression: dsh NO-GO on 4ff753c — B-F5-1 (executor-prefix
// wrappers env/nice/nohup/time/stdbuf defeat find interp/heredoc detection),
// B-F5-2 (argv0 relays env/find/xargs/busybox + flag reordering `--norc -c`,
// merged `-xc`, `sh -s`, non-literal argv0), B-F5-3 (python shell=truthy,
// getattr dispatch, bare from-imports, find-inline alias calls) and B-N1-b
// residue (template keys, computed destructuring, comma-operator bindings,
// method binding on the find -e face). Red before this round, green after.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand } from './src/classifier.ts'
import { scanCommandForEgress } from './src/scan-scripts.ts'

async function gate(cmd: string) {
  const cls = classifyBashCommand(cmd)
  const e = await scanCommandForEgress(cmd)
  return {
    deny:
      cls.forceDeny ||
      cls.category === 'network' ||
      cls.category === 'unknown' ||
      (cls.category === 'file_write' && cls.allow === false) ||
      e.hits.length > 0 ||
      e.unverifiable === true,
    cat: cls.category,
  }
}

const H = "find . -exec node -e 'CODE' {} \\;"
const P = "find . -exec python3 -c 'CODE' {} \\;"
const HH = "find . -exec node - {} \\; <<'JS'\nCODE\nJS"
const PH = "find . -exec python3 - {} \\; <<'PY'\nCODE\nPY"

test('f-round-6 B-F5-1: executor-prefix wrappers denied on find heredoc + inline', async () => {
  const cases: Array<[string, string]> = [
    [`find . -exec env node - {} \\; <<'JS'\nrequire("child_process").spawnSync("sh",["-c","echo ENVNODE > /tmp/x"])\nJS`, 'env node heredoc'],
    [`find . -exec /usr/bin/env node - {} \\; <<'JS'\nrequire("child_process").spawnSync("sh",["-c","echo X > /tmp/x"])\nJS`, 'abs env node heredoc'],
    [`find . -exec env env node - {} \\; <<'JS'\nrequire("child_process").spawnSync("sh",["-c","echo X > /tmp/x"])\nJS`, 'env env node heredoc'],
    [`find . -exec nice node - {} \\; <<'JS'\nrequire("child_process").spawnSync("sh",["-c","echo NICE > /tmp/x"])\nJS`, 'nice node heredoc'],
    [`find . -exec nohup node - {} \\; <<'JS'\nrequire("child_process").spawnSync("sh",["-c","echo X > /tmp/x"])\nJS`, 'nohup node heredoc'],
    [`find . -exec env python3 - {} \\; <<'PY'\nimport subprocess\nsubprocess.run(["/bin/sh","-c","echo X > /tmp/x"])\nPY`, 'env python heredoc'],
    [`find . -exec nice node -e 'require("child_process").spawnSync("sh",["-c","echo NICE_E > /tmp/x"])' {} \\;`, 'nice node -e'],
    [`find . -exec nohup node -e 'require("child_process").spawnSync("sh",["-c","echo X > /tmp/x"])' {} \\;`, 'nohup node -e'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F5-1 ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-6 B-F5-2: argv0 relays + flag reordering + non-literal argv0 denied', async () => {
  const cases: Array<[string, string]> = [
    [H.replace('CODE', 'require("child_process").spawnSync("env",["sh","-c","echo ENV_RELAY > /tmp/x"])'), 'argv0=env relay'],
    [H.replace('CODE', 'require("child_process").spawnSync("find",[".","-exec","sh","-c","echo X > /tmp/x",";"])'), 'argv0=find relay'],
    [H.replace('CODE', 'require("child_process").spawnSync("bash",["--norc","-c","echo NORC > /tmp/x"])'), 'bash --norc -c'],
    [H.replace('CODE', 'require("child_process").spawnSync("sh",["-xc","echo XC > /tmp/x"])'), 'sh -xc merged'],
    [H.replace('CODE', 'require("child_process").spawnSync("sh",["-s"])'), 'sh -s stdin script'],
    [H.replace('CODE', 'const s="sh";require("child_process").spawnSync(s,["-c","echo VARV0 > /tmp/x"])'), 'argv0 variable'],
    [H.replace('CODE', 'require("child_process").spawnSync("s"+"h",["-c","echo CONCAT > /tmp/x"])'), 'argv0 concat'],
    [H.replace('CODE', 'require("child_process").spawnSync("/bin/"+"sh",["-c","echo X > /tmp/x"])'), 'argv0 path concat'],
    [H.replace('CODE', 'require("child_process").spawnSync("busybox",["sh","-c","echo X > /tmp/x"])'), 'busybox relay'],
    [HH.replace('CODE', 'require("child_process").spawnSync("env",["sh","-c","echo X > /tmp/x"])'), 'heredoc argv0=env'],
    [PH.replace('CODE', 'import subprocess\nx="sh"\nsubprocess.run([x,"-c","echo X > /tmp/x"])'), 'python argv0 var'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F5-2 ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-6 B-F5-3: python shell=truthy / getattr / bare from-import / alias denied', async () => {
  const cases: Array<[string, string]> = [
    [PH.replace('CODE', 'import subprocess\nsubprocess.run("echo X > /tmp/x",shell=1)'), 'heredoc shell=1'],
    [PH.replace('CODE', 'import subprocess\nx=True\nsubprocess.run("echo X > /tmp/x",shell=x)'), 'heredoc shell=truthy var'],
    [PH.replace('CODE', 'import os\ngetattr(os,"system")("echo X > /tmp/x")'), 'heredoc getattr os.system'],
    [PH.replace('CODE', 'from os import system\nsystem("echo X > /tmp/x")'), 'heredoc bare from os import system'],
    [PH.replace('CODE', 'from subprocess import run\nrun(["/bin/sh","-c","echo X > /tmp/x"])'), 'heredoc bare from subprocess import run'],
    [P.replace('CODE', 'import subprocess as s\ns.run(["/bin/sh","-c","echo X > /tmp/x"])'), 'find -c alias s.run'],
    [P.replace('CODE', 'import os\ngetattr(os,"system")("echo X > /tmp/x")'), 'find -c getattr'],
    [H.replace('CODE', 'require("child_process")[`execSync`]("sh",["-c","echo X > /tmp/x"])'), 'template-key execSync'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F5-3 ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-6 B-N1-b residue: template keys / computed destructure / comma / method bind denied', async () => {
  const cases: Array<[string, string]> = [
    [HH.replace('CODE', 'require("child_process")[`execSync`]("sh",["-c","echo TPLKEY > /tmp/x"])'), 'heredoc template key'],
    [H.replace('CODE', 'const {["exec"+"Sync"]:e}=require("child_process");e("sh",["-c","echo DESTRUCT > /tmp/x"])'), 'find -e computed destructure'],
    [H.replace('CODE', 'const cp=require("child_process"),r=cp.execSync;r("sh",["-c","echo COMMA > /tmp/x"])'), 'find -e comma operator'],
    [H.replace('CODE', 'const r=require("child_process").execSync;r("sh",["-c","echo BIND > /tmp/x"])'), 'find -e method binding'],
    [HH.replace('CODE', 'const r=require("child_process").execSync;r("sh",["-c","echo X > /tmp/x"])'), 'heredoc method binding'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-N1-b ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-6 stdin-delivery family: here-string / pipe / file-redirect feeding find interp denied, scanned heredoc stays allowed', async () => {
  const cases: Array<[string, string]> = [
    [`find . -exec node - {} \\; <<< 'require("child_process").spawnSync("sh",["-c","id"])'`, 'here-string node -'],
    [`find . -exec bash -s {} \\; <<< 'id'`, 'bash -s here-string'],
    [`find . -exec sh -s {} \\; <<< 'id'`, 'sh -s here-string'],
    [`find . -exec python3 - {} \\; <<< 'code'`, 'python - here-string'],
    [`printf 'require("child_process").spawnSync("sh",["-c","id"])' | find . -maxdepth 1 -exec node - {} \\;`, 'pipe into find node -'],
    [`find . -maxdepth 1 -exec node - {} \\; < code.js`, 'file redirect into find node -'],
    [`find . -exec node - {} \\; </dev/stdin`, 'dev/stdin into find node -'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `stdin-family ${name} must DENY (got ${r.cat})`)
  }
  const benign: Array<[string, string]> = [
    [`find . -exec node - {} \\; <<'JS'\nrequire("child_process").spawnSync("ls",["-la"])\nJS`, 'scanned benign heredoc node'],
    [`find . -exec python3 - {} \\; <<'PY'\nprint(1)\nPY`, 'scanned benign heredoc python'],
    [`find . -exec sh -c 'ls -la' {} \\;`, 'sh -c ls'],
  ]
  for (const [c, name] of benign) {
    const r = await gate(c)
    assert.equal(r.deny, false, `${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-6 benign contract: read-only binaries + pure prints stay allowed', async () => {
  const cases: Array<[string, string]> = [
    [H.replace('CODE', 'require("child_process").spawnSync("ls",["-la"])'), 'node spawnSync ls'],
    [H.replace('CODE', 'require("child_process").spawnSync("git",["status"])'), 'node spawnSync git status'],
    [H.replace('CODE', 'require("child_process").spawnSync("cat",["a.txt"])'), 'node spawnSync cat'],
    [P.replace('CODE', 'import subprocess\nsubprocess.run(["ls","-la"])'), 'python run ls'],
    [P.replace('CODE', 'print(1)'), 'python print'],
    [PH.replace('CODE', 'import subprocess\nsubprocess.run(["ls","-la"])'), 'heredoc python run ls'],
    [PH.replace('CODE', 'import subprocess\nsubprocess.run("echo hi",shell=False)'), 'heredoc shell=False safe'],
    [HH.replace('CODE', 'require("child_process").spawnSync("ls",["-la"])'), 'heredoc node ls'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, false, `${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-7 B-F7-1: child_process rename/dynamic-key/bind dispatch denied (heredoc + find inline)', async () => {
  const cases: Array<[string, string]> = [
    [HH.replace('CODE', 'const {spawnSync:ss}=require("child_process");ss("sh",["-c","echo X > /tmp/x"])'), 'heredoc rename spawnSync:ss'],
    [H.replace('CODE', 'const {execFile:ef}=require("child_process");ef("sh",["-c","echo X > /tmp/x"])'), 'find -e rename execFile:ef'],
    [H.replace('CODE', 'var m="spawnSync";require("child_process")[m]("sh",["-c","echo X > /tmp/x"])'), 'find -e var key'],
    [H.replace('CODE', 'require("child_process")["spawn"+"Sync"]("sh",["-c","echo X > /tmp/x"])'), 'find -e concat key'],
    [HH.replace('CODE', 'const k="Sync";const cp=require("child_process");cp[`spawn${k}`]("sh",["-c","echo X > /tmp/x"])'), 'heredoc template expr key'],
    [H.replace('CODE', 'const cp=require("child_process");const f=cp["spawnSync"];f("sh",["-c","echo X > /tmp/x"])'), 'find -e bind f=cp[key]'],
    [HH.replace('CODE', 'const cp=require("child_process");const f=cp.execSync;f("sh",["-c","echo X > /tmp/x"])'), 'heredoc bind f=cp.execSync'],
    [H.replace('CODE', 'const {spawnSync}=require("child_process");spawnSync("sh",["-c","echo X > /tmp/x"])'), 'find -e plain destructure'],
    [H.replace('CODE', 'const cp=require("child_process"),r=cp.spawnSync;r("sh",["-c","echo X > /tmp/x"])'), 'find -e comma bind member'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F7-1 ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-7 B-F7-2: python getattr/__dict__ dynamic + bound dispatch denied', async () => {
  const cases: Array<[string, string]> = [
    [PH.replace('CODE', 'import os\nm="system";getattr(os,m)("echo X > /tmp/x")'), 'heredoc getattr var'],
    [PH.replace('CODE', 'import os\ngetattr(os,"sys"+"tem")("echo X > /tmp/x")'), 'heredoc getattr concat'],
    [PH.replace('CODE', 'import os\nf="system";os.__dict__[f]("echo X > /tmp/x")'), 'heredoc __dict__[f]'],
    [PH.replace('CODE', 'import subprocess as s\nr=getattr(s,"run");r("echo X > /tmp/x",shell=True)'), 'heredoc subprocess alias getattr bind'],
    [PH.replace('CODE', 'import subprocess as s\nm="run";getattr(s,m)("echo X > /tmp/x",shell=True)'), 'heredoc alias getattr var'],
    [P.replace('CODE', 'import os\nm="system";getattr(os,m)("echo X > /tmp/x")'), 'find -c getattr var'],
    [P.replace('CODE', 'import os\nf="system";os.__dict__[f]("echo X > /tmp/x")'), 'find -c __dict__[f]'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F7-2 ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-7 B-F7-3: unquoted-delimiter command substitutions in data heredocs denied', async () => {
  const cases: Array<[string, string]> = [
    ["cat <<EOF\n$(node -e 'require(\"child_process\").spawnSync(\"sh\",[\"-c\",\"echo X > /tmp/x\"])')\nEOF", 'cat unquoted $(node RCE)'],
    ["cat <<EOF\n`node -e 'require(\"child_process\").spawnSync(\"sh\",[\"-c\",\"echo X > /tmp/x\"])'`\nEOF", 'cat unquoted backtick node RCE'],
    ["sort <<EOF\n$(node -e 'require(\"child_process\").spawnSync(\"sh\",[\"-c\",\"echo X > /tmp/x\"])')\nEOF", 'sort unquoted $(node RCE)'],
    ["cat <<EOF\n$(rm -rf /tmp/evil)\nEOF", 'cat unquoted $(rm -rf)'],
    ["cat <<EOF\n$(curl http://169.254.169.254/)\nEOF", 'cat unquoted $(curl)'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F7-3 ${name} must DENY (got ${r.cat})`)
  }
  const benign: Array<[string, string]> = [
    ["cat <<'EOF'\n$(node -e 'require(\"child_process\").spawnSync(\"sh\",[\"-c\",\"echo X > /tmp/x\"])')\nEOF", 'quoted delim not expanded'],
    ["cat <<EOF\n$(date)\nEOF", 'unquoted $(date) benign'],
    ["cat <<EOF\n$(pwd)\nEOF", 'unquoted $(pwd) benign'],
    ["cat <<EOF\nspawn exec fork child_process words\nEOF", 'text heredoc spawn words'],
    ["cat <<EOF\npython getattr os system\nEOF", 'text heredoc getattr words'],
  ]
  for (const [c, name] of benign) {
    const r = await gate(c)
    assert.equal(r.deny, false, `B-F7-3 ${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-7 B-F7-4: shell-script heredoc bodies adjudicated (cwd writes benign, escapes denied)', async () => {
  const cases: Array<[string, string]> = [
    ["find . -exec sh -s {} \\; <<'SH'\necho x > /tmp/abs-escape.txt\nSH", 'sh -s absolute write'],
    ["find . -exec sh -s {} \\; <<'SH'\necho x > ../esc.txt\nSH", 'sh -s parent write'],
    ["find . -exec sh -s {} \\; <<'SH'\nrm -rf /tmp/target\nSH", 'sh -s rm -rf'],
    ["find . -exec sh -s {} \\; <<'SH'\nnode -e 'require(\"child_process\").spawnSync(\"sh\",[\"-c\",\"echo X > /tmp/x\"])'\nSH", 'sh -s nested node RCE'],
    ["find . -exec bash -s {} \\; <<'BS'\npython3 -c 'import os; os.system(\"echo X > /tmp/x\")'\nBS", 'bash -s nested python'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F7-4 ${name} must DENY (got ${r.cat})`)
  }
  const benign: Array<[string, string]> = [
    ["find . -exec sh -s {} \\; <<'SH'\necho x > out.txt\nSH", 'sh -s cwd-relative write'],
    ["find . -exec sh -s {} \\; <<'SH'\nid\nSH", 'sh -s benign id'],
  ]
  for (const [c, name] of benign) {
    const r = await gate(c)
    assert.equal(r.deny, false, `B-F7-4 ${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-7 B-F7-5: commands after heredoc terminator adjudicated', async () => {
  const cases: Array<[string, string]> = [
    ["head <<EOF\nx\nEOF\nnode -e 'require(\"child_process\").spawnSync(\"sh\",[\"-c\",\"echo X > /tmp/x\"])'", 'after-HD newline node RCE'],
    ["cat <<EOF\nx\nEOF\npython3 -c 'import os; os.system(\"echo X > /tmp/x\")'", 'after-HD newline python RCE'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F7-5 ${name} must DENY (got ${r.cat})`)
  }
  const benign: Array<[string, string]> = [
    ["head <<EOF\nx\nEOF\necho done", 'after-HD benign echo'],
  ]
  for (const [c, name] of benign) {
    const r = await gate(c)
    assert.equal(r.deny, false, `B-F7-5 ${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-7 benign contract: string/comment mentions stay allowed', async () => {
  const cases: Array<[string, string]> = [
    ["node - <<'JS'\n// spawn exec fork are words in a comment\nconsole.log('hi')\nJS", 'node comment mention'],
    ["node - <<'JS'\nconst s = \"spawn exec child_process\";\nconsole.log(s)\nJS", 'node string mention'],
    ["find . -exec node -e 'const s=\"spawn exec\";console.log(s)' {} \\;", 'find -e string mention'],
    ["python3 - <<'PY'\ns=\"getattr(os,\\\"system\\\")\"\nprint(s)\nPY", 'python string getattr escaped'],
    ["node - <<'JS'\nconsole.log('hi')\nJS", 'node benign ls'],
    ["python3 - <<'PY'\nprint(1)\nPY", 'python benign print'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, false, `${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-8 B-F8-1: eval/vm/Function/Reflect nets on find inline + heredoc faces', async () => {
  const cases: Array<[string, string]> = [
    [H.replace('CODE', 'eval("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline eval'],
    [H.replace('CODE', '(0,eval)("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline indirect eval'],
    [H.replace('CODE', 'Function("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")()'), 'inline Function ctor'],
    [H.replace('CODE', 'new Function("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")()'), 'inline new Function'],
    [H.replace('CODE', 'require("vm").runInThisContext("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline vm.runInThisContext'],
    [H.replace('CODE', 'const cp=require("child_process");Reflect.get(cp,"spawnSync")("sh",["-c","echo X > /tmp/x"])'), 'inline Reflect.get'],
    [H.replace('CODE', 'const {spawnSync:ss}=require("child_process");ss.apply(null,["sh",["-c","echo X > /tmp/x"]])'), 'inline renamed .apply'],
    [H.replace('CODE', 'const {spawnSync:ss}=require("child_process");ss.call(null,"sh",["-c","echo X > /tmp/x"])'), 'inline renamed .call'],
    [H.replace('CODE', 'const {spawnSync:ss}=require("child_process");Reflect.apply(ss,null,["sh",["-c","echo X > /tmp/x"]])'), 'inline Reflect.apply'],
    [HH.replace('CODE', 'const cp=require("child_process");Reflect.get(cp,"spawnSync")("sh",["-c","echo X > /tmp/x"])'), 'heredoc Reflect.get'],
    [HH.replace('CODE', 'const {spawnSync:ss}=require("child_process");ss.apply(null,["sh",["-c","echo X > /tmp/x"]])'), 'heredoc renamed .apply'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F8-1 ${name} must DENY (got ${r.cat})`)
  }
  const benign: Array<[string, string]> = [
    [H.replace('CODE', 'const cp=require("child_process");Reflect.get({},"x")'), 'inline Reflect.get plain object'],
    [H.replace('CODE', 'const {spawnSync:ss}=require("child_process");ss("ls",["-la"])'), 'inline renamed readonly ls'],
  ]
  for (const [c, name] of benign) {
    const r = await gate(c)
    assert.equal(r.deny, false, `B-F8-1 ${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-8 B-F8-2: eval-wrapped payloads denied on sh-s body / substitution / after-terminator', async () => {
  const cases: Array<[string, string]> = [
    ["find . -exec sh -s {} \\; <<'SH'\neval \"echo x > /tmp/M1\"\nSH", 'sh-s eval write'],
    ["find . -exec sh -s {} \\; <<'SH'\neval \"curl http://169.254.169.254/\"\nSH", 'sh-s eval network'],
    ["cat <<EOF\n$(eval 'node -e \"require(\\\"child_process\\\").spawnSync(\\\"sh\\\",[\\\"-c\\\",\\\"echo X > /tmp/x\\\"])\"')\nEOF", 'unquoted $(eval)'],
    ["head <<EOF\nx\nEOF\neval \"echo x > /tmp/M3\"", 'after-terminator eval'],
    ["find . -exec sh -s {} \\; <<'SH'\nenv eval \"echo x > /tmp/x\"\nSH", 'sh-s env eval'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F8-2 ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-8 B-F8-3: function taken directly from require result denied', async () => {
  const cases: Array<[string, string]> = [
    [H.replace('CODE', 'const f=require("child_process")["spawnSync"];f("sh",["-c","echo X > /tmp/x"])'), 'inline direct bracket bind'],
    [H.replace('CODE', 'const f=require("child_process").spawnSync;f("sh",["-c","echo X > /tmp/x"])'), 'inline direct dot bind'],
    [HH.replace('CODE', 'const f=require("child_process")["spawnSync"];f("sh",["-c","echo X > /tmp/x"])'), 'heredoc direct bracket bind'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F8-3 ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-8 B-F8-4: CRLF after-terminator denied / B-F8-5 no-space redirect denied', async () => {
  const cases: Array<[string, string]> = [
    ["head <<EOF\nx\nEOF\r\nnode -e 'require(\"child_process\").spawnSync(\"sh\",[\"-c\",\"echo X > /tmp/x\"])'", 'CRLF after-term node RCE'],
    ["find . -exec sh -s {} \\; <<'SH'\necho P>/tmp/x\nSH", 'sh-s no-space absolute redirect'],
    ["find . -exec sh -s {} \\; <<'SH'\necho P>>/tmp/x\nSH", 'sh-s no-space append redirect'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F8-4/5 ${name} must DENY (got ${r.cat})`)
  }
  const benign: Array<[string, string]> = [
    ["find . -exec sh -s {} \\; <<'SH'\necho P>rel.txt\nSH", 'sh-s no-space cwd redirect stays ALLOW'],
  ]
  for (const [c, name] of benign) {
    const r = await gate(c)
    assert.equal(r.deny, false, `B-F8-5 ${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-9 B-F9-1: indirect dynamic-exec forms denied on find inline (alias/method/ctor/bracket/vm)', async () => {
  // NOTE: CODE must stay single-quote-free — the outer find -e template wraps
  // it in single quotes and an inner quote would truncate extraction. All
  // indirect forms below use double-quoted payload strings.
  const cases: Array<[string, string]> = [
    [H.replace('CODE', 'eval.call(null,"require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline eval.call'],
    [H.replace('CODE', 'eval.apply(null,["require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])"])'), 'inline eval.apply'],
    [H.replace('CODE', 'var e=eval;e("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline eval alias'],
    [H.replace('CODE', '(0,eval)("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline indirect eval comma'],
    [H.replace('CODE', 'Function.call(null,"return require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")()'), 'inline Function.call'],
    [H.replace('CODE', '[].constructor.constructor("return require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")()'), 'inline ctor chain'],
    [H.replace('CODE', '(function(){}).constructor("return require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")()'), 'inline fn ctor single-link'],
    [H.replace('CODE', 'var v=require("vm");v.runInThisContext("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline vm alias'],
    [H.replace('CODE', 'new (require("vm").Script)("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])").runInThisContext()'), 'inline vm Script new'],
    [H.replace('CODE', 'globalThis["eva"+"l"]("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline bracket concat eval'],
    [H.replace('CODE', 'Reflect.get(globalThis,"eval")("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])")'), 'inline Reflect.get global eval'],
    [H.replace('CODE', 'setTimeout("require(\\"child_process\\").spawnSync(\\"sh\\",[\\"-c\\",\\"echo X > /tmp/x\\"])",1)'), 'inline string-arg timer'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F9-1 ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-9 B-F9-2: Reflect.apply/get dynamic-member dispatch denied, read-only argv stays ALLOW', async () => {
  const deny: Array<[string, string]> = [
    [H.replace('CODE', 'const cp=require("child_process");var v="spawnSync";Reflect.apply(cp[v],cp,["sh",["-c","echo X > /tmp/x"]])'), 'inline reflect.apply dynamic member'],
    [H.replace('CODE', 'const cp=require("child_process");Reflect.apply(cp["sp"+"awnSync"],cp,["sh",["-c","echo X > /tmp/x"]])'), 'inline reflect.apply concat key'],
    [H.replace('CODE', 'const cp=require("child_process");Reflect.get(cp,"sp"+"awnSync")("sh",["-c","echo X > /tmp/x"])'), 'inline reflect.get concat key'],
    [HH.replace('CODE', 'const cp=require("child_process");var v="spawnSync";Reflect.apply(cp[v],cp,["sh",["-c","echo X > /tmp/x"]])'), 'heredoc reflect.apply dynamic member'],
    [HH.replace('CODE', 'const cp=require("child_process");cp.spawnSync.apply(cp,["sh",["-c","echo X > /tmp/x"]])'), 'heredoc cp.spawnSync.apply'],
    [HH.replace('CODE', 'const cp=require("child_process");cp.spawnSync.call(cp,"sh",["-c","echo X > /tmp/x"])'), 'heredoc cp.spawnSync.call'],
    [H.replace('CODE', 'const cp=require("child_process");var f=Reflect.get(cp,"spawnSync");f("sh",["-c","echo X > /tmp/x"])'), 'inline Reflect.get bound then invoked'],
    // heredoc face: any require("child_process") body stays fail-closed via the
    // pre-existing F6_CP_MODULE_RE gate regardless of argv (read-only included).
    [HH.replace('CODE', 'const cp=require("child_process");cp.spawnSync.apply(cp,["ls",["-la"]])'), 'heredoc cp.spawnSync.apply readonly fails closed'],
  ]
  for (const [c, name] of deny) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F9-2 ${name} must DENY (got ${r.cat})`)
  }
  const allow: Array<[string, string]> = [
    [H.replace('CODE', 'const {spawnSync:ss}=require("child_process");ss.apply(null,["ls",["-la"]])'), 'inline renamed .apply readonly'],
    [H.replace('CODE', 'const {spawnSync:ss}=require("child_process");ss.call(null,"ls",["-la"])'), 'inline renamed .call readonly'],
    [H.replace('CODE', 'const cp=require("child_process");Reflect.apply(cp["spawnSync"],cp,["ls",["-la"]])'), 'inline Reflect.apply literal readonly'],
    [H.replace('CODE', 'const {spawnSync:ss}=require("child_process");Reflect.apply(ss,null,["ls",["-la"]])'), 'inline Reflect.apply fvar readonly'],
    [H.replace('CODE', 'const cp=require("child_process");Reflect.get(cp,"spawnSync")("ls",["-la"])'), 'inline Reflect.get literal readonly'],
    [H.replace('CODE', 'var o={x:1};Reflect.get(o,"x")'), 'inline plain object Reflect.get'],
    [H.replace('CODE', 'console.log("eval.call(1)")'), 'inline string eval mention'],
  ]
  for (const [c, name] of allow) {
    const r = await gate(c)
    assert.equal(r.deny, false, `B-F9-2 ${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-10 B-F10-1/2/3: dsh review cba2a07 blockers closed — dynamic cp dispatch data-flow, alias closure, heredoc f8 net', async () => {
  const SHC = `["sh",["-c","echo X > /tmp/x"]]`
  const CP = `require("child_process").spawnSync("sh",["-c","echo X > /tmp/x"])`
  const FS = `require("fs").writeFileSync("/tmp/f10-e","pwn")`
  const deny: Array<[string, string]> = [
    // B-F10-1: dynamic member read bound to a var, invoked via any shape (FE+HD)
    [H.replace('CODE', `const cp=require("child_process");var f=Reflect.get(cp,"sp"+"awnSync");Reflect.apply(f,cp,${SHC})`), 'inline reflect.get concat -> var -> Reflect.apply'],
    [HH.replace('CODE', `const cp=require("child_process");var f=Reflect.get(cp,"sp"+"awnSync");Reflect.apply(f,cp,${SHC})`), 'heredoc reflect.get concat -> var -> Reflect.apply'],
    [H.replace('CODE', `const cp=require("child_process");Reflect.get(cp,"sp"+"awnSync").apply(cp,${SHC})`), 'inline reflect.get concat .apply'],
    [HH.replace('CODE', `const cp=require("child_process");Reflect.get(cp,"sp"+"awnSync").apply(cp,${SHC})`), 'heredoc reflect.get concat .apply'],
    [H.replace('CODE', `const cp=require("child_process");Reflect.get(cp,"sp"+"awnSync").call(cp,"sh",["-c","echo X > /tmp/x"])`), 'inline reflect.get concat .call'],
    [HH.replace('CODE', `const cp=require("child_process");Reflect.get(cp,"sp"+"awnSync").call(cp,"sh",["-c","echo X > /tmp/x"])`), 'heredoc reflect.get concat .call'],
    [H.replace('CODE', `const cp=require("child_process");var f=cp["sp"+"awnSync"];f("sh",["-c","echo X > /tmp/x"])`), 'inline bracket-concat key -> var -> call'],
    [HH.replace('CODE', `const cp=require("child_process");var f=cp["sp"+"awnSync"];f("sh",["-c","echo X > /tmp/x"])`), 'heredoc bracket-concat key -> var -> call'],
    [H.replace('CODE', `Reflect.apply(require("child_process")["sp"+"awnSync"],null,${SHC})`), 'inline Reflect.apply(require()[concat])'],
    [HH.replace('CODE', `Reflect.apply(require("child_process")["sp"+"awnSync"],null,${SHC})`), 'heredoc Reflect.apply(require()[concat])'],
    [H.replace('CODE', `const cp=require("child_process");var k="spawnSync";var f=cp[k];Reflect.apply(f,cp,${SHC})`), 'inline var k -> cp[k] -> Reflect.apply'],
    [HH.replace('CODE', `const cp=require("child_process");var k="spawnSync";var f=cp[k];Reflect.apply(f,cp,${SHC})`), 'heredoc var k -> cp[k] -> Reflect.apply'],
    // B-F10-2: alias closure + Reflect/ctor/proto/global-key forms (FE)
    [H.replace('CODE', `var e1=eval;var e2=e1;e2("${CP}")`), 'inline eval two-hop alias'],
    [H.replace('CODE', `var C=[].constructor.constructor;C("${CP}")()`), 'inline ctor-chain alias'],
    [H.replace('CODE', `Reflect.construct(Function,["${CP}"])()`), 'inline Reflect.construct(Function)'],
    [H.replace('CODE', `var k="eva";globalThis[k+"l"]("${CP}")`), 'inline variable bracket key'],
    [H.replace('CODE', `Reflect.apply(eval,null,["${CP}"])`), 'inline Reflect.apply(eval)'],
    [H.replace('CODE', `Reflect.apply(Function,null,["${CP}"])()`), 'inline Reflect.apply(Function)'],
    [H.replace('CODE', `Reflect.get(Reflect.getPrototypeOf(()=>0),"constructor")("${CP}")()`), 'inline proto-chain ctor'],
    [H.replace('CODE', `var F1=Function;var F2=F1;F2("${CP}")()`), 'inline Function two-hop alias'],
    // B-F10-3: heredoc node body dynamic-exec strings, fs payload (no cp marker)
    [HH.replace('CODE', `eval.call(null,"${FS}")`), 'heredoc eval.call fs'],
    [HH.replace('CODE', `var e1=eval;var e2=e1;e2("${FS}")`), 'heredoc eval two-hop alias fs'],
    [HH.replace('CODE', `var F1=Function;var F2=F1;F2("${FS}")()`), 'heredoc Function two-hop alias fs'],
    [HH.replace('CODE', `var C=[].constructor.constructor;C("${FS}")()`), 'heredoc ctor alias fs'],
    [HH.replace('CODE', `var v=require("vm");var s=new v.Script("${FS}");s.runInThisContext()`), 'heredoc vm Script alias member fs'],
    [HH.replace('CODE', `var k="eva";globalThis[k+"l"]("${FS}")`), 'heredoc variable bracket key fs'],
    [HH.replace('CODE', `Reflect.construct(Function,["${FS}"])()`), 'heredoc Reflect.construct fs'],
  ]
  for (const [c, name] of deny) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F10 ${name} must DENY (got ${r.cat})`)
  }
  // control: claimed-closed shapes must STILL deny (probe-sanity guard)
  const denyCtrl: Array<[string, string]> = [
    [H.replace('CODE', `eval("${CP}")`), 'direct eval denied-control'],
    [H.replace('CODE', `var e=eval;e("${CP}")`), 'single-hop eval alias denied-control'],
    [H.replace('CODE', `const cp=require("child_process");Reflect.apply(cp["sp"+"awnSync"],cp,${SHC})`), 'Reflect.apply(cp[concat]) denied-control'],
  ]
  for (const [c, name] of denyCtrl) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-F10 ${name} must DENY (got ${r.cat})`)
  }
  const allow: Array<[string, string]> = [
    // read-only / benign shapes that must NOT flip
    [H.replace('CODE', `const {spawnSync:ss}=require("child_process");ss.apply(null,["ls",["-la"]])`), 'inline renamed .apply readonly stays ALLOW'],
  ]
  for (const [c, name] of allow) {
    const r = await gate(c)
    assert.equal(r.deny, false, `B-F10 ${name} must stay ALLOW (got ${r.cat})`)
  }
})
