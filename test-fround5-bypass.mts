// f-round-5 regression: dsh NO-GO on 87f4070 — B-N1-a (literal-argv
// spawn/execFile whose argv[0] is a shell/interpreter with -c/-e/-E/-r is a
// full RCE, riding read), B-N1-b (find heredoc exec-family alias/dynamic
// residue — no transitive closure, .call/.apply, concat keys, require(n),
// method binding, template commands), N-N1-c (python os/subprocess aliases in
// find bodies) and M-N3-a (find -exec sh -c cwd-local writes hard-denied by
// the absolutized-target escape check). Red before this round, green after.
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

test('f-round-5 B-N1-a: shell/interpreter argv[0] RCE denied on find surfaces', async () => {
  const cases: Array<[string, string]> = [
    [`find . -exec node - {} \\; <<'JS'\nrequire("child_process").spawnSync("sh",["-c","echo SHC_PWNED > /tmp/shc-pwn.txt"])\nJS`, 'find node heredoc spawnSync sh -c'],
    [`find . -exec node -e 'require("child_process").spawnSync("sh",["-c","echo FIND_NODE_E_PWN > /tmp/findnodee-pwn.txt"])' {} \\;`, 'find node -e spawnSync sh -c'],
    [`find . -exec python3 - {} \\; <<'PY'\nimport subprocess\nsubprocess.run(["/bin/sh","-c","echo X > /tmp/x"])\nPY`, 'find py heredoc run sh -c'],
    [`find . -exec node -e 'require("child_process").execFile("bash",["-c","echo X > /tmp/x"])' {} \\;`, 'find node -e execFile bash -c'],
    [`find . -exec ruby - {} \\; <<'RB'\nsystem("echo X > /tmp/x")\nRB`, 'find ruby heredoc system (existing B3)'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-N1-a ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-5 B-N1-b: exec-family alias/dynamic forms denied inside find bodies', async () => {
  const cases: Array<[string, string]> = [
    [`find . -exec node - {} \\; <<'JS'\nconst q=require("child_process");q.execSync("echo X")\nJS`, 'module alias'],
    [`find . -exec node - {} \\; <<'JS'\nconst q=require("child_process");const r=q;r.execSync("echo X")\nJS`, 'two-hop alias'],
    [`find . -exec node - {} \\; <<'JS'\nconst cp=require("child_process");cp.execSync.call(null,"echo X")\nJS`, '.call dispatch'],
    [`find . -exec node - {} \\; <<'JS'\nrequire("child_process")["exec"+"Sync"]("echo X")\nJS`, 'concat member key'],
    [`find . -exec node - {} \\; <<'JS'\nconst n=require("child_process");require(n).execSync("echo X")\nJS`, 'variable module id'],
    [`find . -exec node - {} \\; <<'JS'\nconst r=require("child_process").execSync;r("echo X")\nJS`, 'method binding'],
    [`find . -exec node - {} \\; <<'JS'\nrequire("child_process").execSync(\`echo \${x}\`)\nJS`, 'template command string'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `B-N1-b ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-5 N-N1-c: python os/subprocess aliases denied inside find bodies', async () => {
  const cases: Array<[string, string]> = [
    [`find . -exec python3 - {} \\; <<'PY'\nimport subprocess as s\ns.run(["echo X"],shell=True)\nPY`, 'subprocess module alias'],
    [`find . -exec python3 - {} \\; <<'PY'\no=os\no.system("echo X")\nPY`, 'os module alias'],
  ]
  for (const [c, name] of cases) {
    const r = await gate(c)
    assert.equal(r.deny, true, `N-N1-c ${name} must DENY (got ${r.cat})`)
  }
})

test('f-round-5 M-N3-a: cwd-local writes inside find -exec sh -c are NOT hard-denied', async () => {
  const allowed: Array<[string, string]> = [
    [`find . -exec sh -c 'mkdir -p newdir' _ {} \\;`, 'mkdir'],
    [`find . -exec sh -c 'echo x | tee local.txt' _ {} \\;`, 'tee'],
    [`find . -exec sh -c 'cp /etc/hostname local-copy.txt' _ {} \\;`, 'cp to cwd target'],
    [`find . -exec sh -c 'touch local-touch.txt' _ {} \\;`, 'touch'],
  ]
  for (const [c, name] of allowed) {
    const r = await gate(c)
    assert.equal(r.deny, false, `M-N3-a ${name} must NOT hard-deny (got ${r.cat})`)
  }
  const escaping: Array<[string, string]> = [
    [`find . -exec sh -c 'echo X > /tmp/esc.txt' _ {} \\;`, 'absolute'],
    [`find . -exec sh -c 'echo X > ../esc.txt' _ {} \\;`, 'parent traversal'],
    [`find . -exec sh -c 'echo X > ~/esc.txt' _ {} \\;`, 'home'],
  ]
  for (const [c, name] of escaping) {
    const r = await gate(c)
    assert.equal(r.deny, true, `M-N3-a ${name} escape must still DENY (got ${r.cat})`)
  }
})

test('f-round-5 benign contract preserved', async () => {
  const allowed: Array<[string, string]> = [
    [`find . -exec sh -c 'node -e "require(\\"child_process\\").spawnSync(\\"ls\\")"' _ {} \\;`, 'B2 find-wrapped spawnSync ls'],
    [`find . -exec sh -c 'echo $(basename /etc/hostname)' _ {} \\;`, 'find sh read-only substitution'],
    [`find . -exec sh -c 'git log' _ {} \\;`, 'find sh git log'],
    [`find . -exec sh -c 'echo X' _ {} \\;`, 'find sh echo'],
    [`find . -exec sh -c 'python3 -c "print(1)"' _ {} \\;`, 'find sh python print'],
  ]
  for (const [c, name] of allowed) {
    const r = await gate(c)
    assert.equal(r.deny, false, `benign ${name} must ALLOW (got ${r.cat})`)
  }
})
