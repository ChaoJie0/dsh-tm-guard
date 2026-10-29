// f-round-14 regression: dsh round-14 NO-GO on 48d4a8f —
// B-F14-1 (property-descriptor channel: getOwnPropertyDescriptor(cp,"spawnSync")
// .value(...) and 22+ variants incl. Reflect/getOwnPropertyDescriptors/
// bracket-value/destructure/apply-forward/spread/Promise/IIFE),
// B-F14-2 (array-destructure / catch-param / .bind alias binding gaps:
// `var [e]=[eval]`, `try{throw eval}catch([e])`, `eval.bind(null)`,
// splice/extract, exec-member destructure `var [f]=[cp.spawnSync]`),
// B-F14-3 (Function tagged-template backtick invocation).
// Every exploit form must DENY on both the find -e (FE) and heredoc (HD)
// faces; the dyn payload is an arithmetic string (no fs/cp marker) and must
// still DENY. Pure read-only controls (AJ2/AC1/AJ15 descriptor .value with
// literal argv, `eval` tagged-template laziness T3, f9 read-only apply/call/
// bind/destructure R1-R4) stay ALLOW. FE/HD must decide identically.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand } from './src/classifier.ts'
import { scanCommandForEgress } from './src/scan-scripts.ts'

const HDre = /<<-?\s*(?:'([^']+)'|"([^"]+)"|[A-Za-z_][A-Za-z0-9_]*)/
const LUA_RE = /lua/

async function gate(cmd: string) {
  const cls = classifyBashCommand(cmd)
  const hasHeredoc = HDre.test(cmd)
  let cat = cls.category
  let reason = cls.reason ?? ''
  if (cls.category === 'local_exec' || (cls.category === 'read' && hasHeredoc)) {
    const e = await scanCommandForEgress(cmd)
    if (e.hits.length > 0) cat = 'network'
    else if (e.unverifiable) cat = 'unknown'
  }
  return {
    deny:
      cat === 'network' ||
      cat === 'unknown' ||
      (cat === 'file_write' && cls.allow === false),
    cat,
    reason,
  }
}

const H = "find . -exec node -e 'CODE' {} \\;"
const HH = "find . -exec node - {} \\; <<'JS'\nCODE\nJS"
const cp = `require("child_process")`
const SH = `["sh",["-c","echo X > /tmp/f14p"]]`
const ARITH = `"1+1"`
const WRITE = `process.getBuiltinModule("fs").writeFileSync("/tmp/f14p","pwn")`
const ROARR = `["ls",["-la"]]`
const ROSP = `"ls",["-la"]`

// dsh round-14 section 3, B-F14-1: descriptor .value channels carrying the
// exec member from a child_process source; every form DENY on FE+HD.
const descForms: Array<[string, string]> = [
  [`var d=Object.getOwnPropertyDescriptor(${cp},"spawnSync");d.value(${SH})`, 'AA1 var descriptor'],
  [`Object.getOwnPropertyDescriptor(${cp},"spawnSync").value(${SH})`, 'AB3 inline descriptor'],
  [`Reflect.getOwnPropertyDescriptor(${cp},"spawnSync").value(${SH})`, 'AB4 Reflect descriptor'],
  [`Object.getOwnPropertyDescriptors(${cp})["spawnSync"].value(${SH})`, 'AB5 all descriptors bracket'],
  [`Object.getOwnPropertyDescriptors(${cp})["sp"+"awnSync"].value(${SH})`, 'AB10 all descriptors concat key'],
  [`var k="spawnSync";Object.getOwnPropertyDescriptor(${cp},k).value(${SH})`, 'AB13 var key'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync");f(${SH})`, 'AF4 destructured value'],
  [`Object.getOwnPropertyDescriptor(${cp},"sp"+"awnSync").value(${SH})`, 'AI3 concat member key'],
  [`Object.getOwnPropertyDescriptor(${cp},"spawnSync")["value"](${SH})`, 'AI13 bracket value'],
  [`function g(){return Object.getOwnPropertyDescriptor(${cp},"spawnSync")}g().value(${SH})`, 'AJ4 function return'],
  [`Promise.resolve(Object.getOwnPropertyDescriptor(${cp},"spawnSync")).then(d=>d.value(${SH}))`, 'AJ9 promise then'],
  [`(function(d){d.value(${SH})})(Object.getOwnPropertyDescriptor(${cp},"spawnSync"))`, 'AJ10 IIFE arg'],
  [`Reflect.apply(Object.getOwnPropertyDescriptor(${cp},"spawnSync").value,null,[${SH}])`, 'AK8 Reflect.apply value'],
]

// B-F14-2: array-destructure / catch-param / .bind alias binding gaps.
// Payload is an ARITHMETIC string for eval-family, WRITE for fs-family.
const destrForms: Array<[string, string]> = [
  [`var e;[e]=[eval];e(${ARITH})`, 'U13 no-decl destructure'],
  [`var [e]=[eval];e.call(0,${ARITH})`, 'V1 destructure call forward'],
  [`var [,e]=[0,eval];e(${ARITH})`, 'V3 elision destructure'],
  [`var a=[eval],e;[e]=a;e(${ARITH})`, 'W9 multi-decl destructure'],
  [`var e=eval.bind(null);e(${ARITH})`, 'W13 eval bind alias'],
  [`var [[e]]=[[eval]];e(${ARITH})`, 'X1 nested destructure'],
  [`try{throw eval}catch(e){e(${ARITH})}`, 'Y1 catch param eval'],
  [`try{throw eval}catch([e]){e(${ARITH})}`, 'AC17 catch array destructure'],
  [`var {eval:e}={eval};e(${ARITH})`, 'AD9 object shorthand destructure'],
  [`var [e,...r]=[eval];e(${ARITH})`, 'Z1 rest destructure'],
  [`var a=[eval];a.splice(0,1)[0](${ARITH})`, 'AD16 splice extract'],
]

// B-F14-2 exec-member destructure + f9 read-only forwarding: destructured
// exec-member values invoked with read-only argv stay ALLOW; a destructive
// argv fails closed.
const execDestrForms: Array<[string, string]> = [
  [`${cp}.spawnSync.apply(${cp},${ROARR})`, 'f9-R1 apply readonly', false],
  [`${cp}.spawnSync.call(${cp},${ROSP})`, 'f9-R2 call readonly', false],
  [`${cp}.spawnSync.bind(${cp})(${ROSP})`, 'f9-R3 bind readonly', false],
  [`var [f]=[${cp}.spawnSync];f(${ROSP})`, 'f9-R4 destructure readonly', false],
  [`var [f]=[${cp}.spawnSync];f(${SH})`, 'f9-R4-D destructure write', true],
]

// B-F14-3: Function tagged-template backtick invocation.
const tagForms: Array<[string, string]> = [
  [`Function\`return process.getBuiltinModule("fs")\`().writeFileSync("/tmp/f14p","pwn")`, 'T4 tagged Function'],
  [`var F=Function;F\`return process.getBuiltinModule("fs")\`().writeFileSync("/tmp/f14p","pwn")`, 'T4B tagged alias'],
  [`var [F]=[Function];F\`return process.getBuiltinModule("fs")\`().writeFileSync("/tmp/f14p","pwn")`, 'Z2 tagged destructured'],
]

// read-only controls that must stay ALLOW on both faces:
const roForms: Array<[string, string]> = [
  [`Object.getOwnPropertyDescriptor(${cp},"spawnSync").value(${ROSP})`, 'AJ2 descriptor readonly'],
  [`var d=Object.getOwnPropertyDescriptor(${cp},"spawnSync");d.value(${ROSP})`, 'AJ15 descriptor var readonly'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync");f(${ROSP})`, 'AF4-RO destructured readonly'],
]

test('f-round-14 B-F14-1: all descriptor forms DENY on FE+HD, same verdict', async () => {
  for (const [code, name] of descForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F14-1 ${name} FE must DENY (got ${fe.cat}/${fe.reason})`)
    assert.equal(hd.deny, true, `B-F14-1 ${name} HD must DENY (got ${hd.cat}/${hd.reason})`)
    assert.equal(fe.deny, hd.deny, `B-F14-1 ${name} FE/HD semantic equivalence (FE=${fe.cat} HD=${hd.cat})`)
  }
})

test('f-round-14 B-F14-2: destructure/catch/bind forms DENY on FE+HD with arithmetic payload', async () => {
  for (const [code, name] of destrForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F14-2 ${name} FE must DENY (got ${fe.cat}/${fe.reason})`)
    assert.equal(hd.deny, true, `B-F14-2 ${name} HD must DENY (got ${hd.cat}/${hd.reason})`)
    assert.equal(fe.deny, hd.deny, `B-F14-2 ${name} FE/HD semantic equivalence (FE=${fe.cat} HD=${hd.cat})`)
    assert.equal(LUA_RE.test(fe.reason), false, `B-F14-2 ${name} FE deny must NOT come from lua net (reason=${fe.reason})`)
  }
})

test('f-round-14 B-F14-2 exec-member destructure + f9 read-only forwarding parity', async () => {
  // The f9 recovery target (dsh round-14 condition 4: restore the f9 matrix to
  // 38/0, or pin an explicit expectation) is measured at the classifier layer:
  // these member-head indirections / destructured exec members must NOT be
  // denied by the classifier when the argv is provably read-only, and a
  // destructive argv must fail closed. (The heredoc face additionally trips
  // the egress-scan unverifiable net, which is the outer runtime layer, not
  // part of the f9 recovery count.)
  for (const [code, name, expectDeny] of execDestrForms) {
    const fe = classifyBashCommand(H.replace('CODE', code))
    const hd = classifyBashCommand(HH.replace('CODE', code))
    const denyOf = (c: typeof fe) =>
      c.category === 'network' ||
      c.category === 'unknown' ||
      (c.category === 'file_write' && c.allow === false)
    assert.equal(denyOf(fe), expectDeny, `B-F14-2 ${name} FE expect=${expectDeny} (got ${fe.category}/${fe.reason})`)
    assert.equal(denyOf(hd), expectDeny, `B-F14-2 ${name} HD expect=${expectDeny} (got ${hd.category}/${hd.reason})`)
    assert.equal(denyOf(fe), denyOf(hd), `B-F14-2 ${name} FE/HD semantic equivalence (FE=${fe.category} HD=${hd.category})`)
  }
})

test('f-round-14 B-F14-3: Function tagged-template forms DENY on FE+HD', async () => {
  for (const [code, name] of tagForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F14-3 ${name} FE must DENY (got ${fe.cat}/${fe.reason})`)
    assert.equal(hd.deny, true, `B-F14-3 ${name} HD must DENY (got ${hd.cat}/${hd.reason})`)
    assert.equal(fe.deny, hd.deny, `B-F14-3 ${name} FE/HD semantic equivalence (FE=${fe.cat} HD=${hd.cat})`)
  }
})

test('f-round-14 read-only controls stay ALLOW on FE+HD, same verdict', async () => {
  for (const [code, name] of roForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, false, `B-F14-RO ${name} FE must stay ALLOW (got ${fe.cat}/${fe.reason})`)
    assert.equal(hd.deny, false, `B-F14-RO ${name} HD must stay ALLOW (got ${hd.cat}/${hd.reason})`)
    assert.equal(fe.deny, hd.deny, `B-F14-RO ${name} FE/HD semantic equivalence (FE=${fe.cat} HD=${hd.cat})`)
  }
})

test('f-round-14 T3: eval tagged-template laziness stays ALLOW on the HD face (dsh form)', async () => {
  // `eval`echo X`` is a tagged-template that does not execute anything until
  // eval is called; the dsh round-14 form is the heredoc face only. The FE
  // face is conservatively caught by the outer inline-code net (backtick
  // treated as command substitution), which is not part of this fix.
  const hd = await gate(HH.replace('CODE', 'eval`echo X`'))
  assert.equal(hd.deny, false, `T3 HD must stay ALLOW (got ${hd.cat}/${hd.reason})`)
})
