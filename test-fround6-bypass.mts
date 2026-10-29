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
