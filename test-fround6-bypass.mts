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
