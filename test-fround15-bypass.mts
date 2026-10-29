// f-round-15 regression: dsh round-15 NO-GO on a0ad7ca —
// B-F15-1 descVal taint seeding & propagation (descriptor .value bindings
//   through destructure/alias/container/timer/Reflect/globalThis and computed
//   keys are executable and must DENY when args are not provably read-only),
// B-F15-2 eval/Function through .bind/.call/optional-member/array-member/
//   bound-backtick invocation chains,
// B-F15-3 catch/throw across blocks and destructure-RHS function return /
//   IIFE / await sources,
// B-F15-4 residual AD9/Y3 shapes + RODV2 semantic read-only layer
//   (recursive literal argv with `>`/`>>`/`$(` is NOT read-only) + over-broad
//   capture recovery (AC1/AJ15 descriptor .value with literal read-only argv).
// Expect: 33 exploit forms DENY + 10 read-only controls ALLOW on both the
// find -e (FE) and heredoc (HD) faces.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand } from './src/classifier.ts'
import { scanCommandForEgress } from './src/scan-scripts.ts'

const HDre = /<<-?\s*(?:'([^']+)'|"([^"]+)"|[A-Za-z_][A-Za-z0-9_]*)/

async function gate(cmd: string) {
  const cls = classifyBashCommand(cmd)
  const hasHeredoc = HDre.test(cmd)
  let cat = cls.category
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
  }
}

const H = "find . -exec node -e 'CODE' {} \\;"
const HH = "find . -exec node - {} \\; <<'JS'\nCODE\nJS"
const cp = `require("child_process")`
const SH = `["sh",["-c","echo X > /tmp/f15p"]]`
const RO = `["ls",["-la"]]`
const ARITH = `"1+1"`

// B-F15-1: descriptor .value bindings — descVal taint seed + propagation
// through alias / array container / globalThis / timer / Reflect / nested
// destructure / computed key / try-catch-wrap; every form carries a
// non-read-only argv (SH) and must DENY.
const descForms: Array<[string, string]> = [
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f.call(null,${SH})`, 'D116 call-forward'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); Reflect.apply(f,null,[${SH}])`, 'D117 reflect.apply'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f.apply(null,[${SH}])`, 'D201 apply-forward'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f.bind(null)(${SH})`, 'D202 bind-forward'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); var g=f; g(${SH})`, 'D204 re-alias'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); [f][0](${SH})`, 'D231 inline container'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); var a=[f]; a[0](${SH})`, 'D232 named container'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); globalThis.zz=f; globalThis.zz(${SH})`, 'D233 globalThis'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); setTimeout(f,0,${SH})`, 'D234 timer defer'],
  [`var {spawnSync:{value:f}}=Object.getOwnPropertyDescriptors(${cp}); f.call(null,${SH})`, 'D312 all-descriptors nested'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(process.getBuiltinModule("child_process"),"spawnSync"); f.call(null,${SH})`, 'D315 builtin-module'],
  [`var {value:f=null}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); Reflect.apply(f,null,[${SH}])`, 'D328 default-value reflect'],
  [`var {["value"]:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f.call(null,${SH})`, 'D410 computed-key destructure'],
  [`var {value:f,writable:w}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f.call(null,${SH})`, 'D514 multi-key destructure'],
  [`try{var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync")}catch(x){} f.call(null,${SH})`, 'D517 try-catch wrap'],
]

// B-F15-2/B-F15-3: eval/Function chain invocation and cross-block catch/throw,
// destructure RHS function return / IIFE / await sources.
const evalForms: Array<[string, string]> = [
  ['var [e]=[eval]; e?.call?.(0,"1+1")', 'B307 optional call'],
  ['var a=[eval]; a[0].call(0,"1+1")', 'B309 array member'],
  ['eval.bind(null).call(null,"1+1")', 'B314 bound eval'],
  ['Function.bind(null)`return 2`()', 'B315 bound backtick'],
  ['try{try{throw eval}finally{0}}catch(e){e("1+1")}', 'B108 finally block'],
  ['try{{throw eval}}catch(e){e("1+1")}', 'B201 nested block'],
  ['function t(){throw eval} try{t()}catch(e){e("1+1")}', 'B136 function throw'],
  ['try{throw globalThis.eval}catch(e){e("1+1")}', 'B208 globalThis.eval throw'],
  ['function f(){return[eval]} var [e]=f(); e("1+1")', 'B228 function return'],
  ['var [e]=(()=>[eval])(); e("1+1")', 'B229 IIFE return'],
  ['(async function(){var [e]=await [eval]; e("1+1")})()', 'B247 await source'],
  ['var b="eval"; [globalThis[b]][0]("1+1")', 'B138 computed globalThis'],
  ['var n="eva",m="l";[globalThis[n+m]][0]("1+1")', 'B241 concat computed'],
]

// B-F15-4: residual shapes from earlier rounds re-pinned.
const residualForms: Array<[string, string]> = [
  [`Promise.reject(${cp}).catch(x=>x["sp"+"awnSync"]?.(SH))`, 'AD9 catch concat member'],
  ['var [,...F]=[0,Function]; F[0]("return 2")()', 'Y3 rest destructure'],
  ['var a=[eval]; a[0]("1+1")', 'V3 container call'],
  ['var {value:[e]=[eval]}={value:undefined}; e("1+1")', 'AG7 nested default'],
  [`var z="echo X"; var [f]=[${cp}.spawnSync]; f("sh",["-c",z])`, 'RODV2 non-readonly var argv'],
]

// Read-only controls must stay ALLOW: descriptor .value with literal
// read-only argv (gate layer, both faces).
const roForms: Array<[string, string]> = [
  [`Object.getOwnPropertyDescriptor(${cp},"spawnSync").value(${RO})`, 'AJ2 dot value'],
  [`Object.getOwnPropertyDescriptor(${cp},"spawnSync")["value"](${RO})`, 'AC1 bracket value'],
  [`var d=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); d["value"](${RO})`, 'AC1D alias bracket'],
  [`var d=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); d.value(${RO})`, 'AJ15 alias dot'],
  [`var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f(${RO})`, 'AF4RO destructure RO'],
]

// f9 read-only exec-member forwarding (classifier layer; the heredoc face
// additionally trips the outer egress-scan unverifiable net, which is a
// runtime-layer conservatism documented in f-round-14, not a classifier deny).
const fwdForms: Array<[string, string]> = [
  [`${cp}.spawnSync.apply(${cp},${RO})`, 'R1 apply RO'],
  [`${cp}.spawnSync.call(${cp},"ls",["-la"])`, 'R2 call RO'],
  [`${cp}.spawnSync.bind(${cp})("ls",["-la"])`, 'R3 bind RO'],
  [`var [f]=[${cp}.spawnSync]; f("ls",["-la"])`, 'R4 destructure RO'],
]

test('f-round-15 descriptor-value bindings DENY on FE+HD (B-F15-1)', async () => {
  for (const [code, name] of descForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F15-1 ${name} FE must DENY (got ${fe.cat})`)
    assert.equal(hd.deny, true, `B-F15-1 ${name} HD must DENY (got ${hd.cat})`)
  }
})

test('f-round-15 eval/Function chain + catch/throw forms DENY on FE+HD (B-F15-2/3)', async () => {
  for (const [code, name] of evalForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F15-2/3 ${name} FE must DENY (got ${fe.cat})`)
    assert.equal(hd.deny, true, `B-F15-2/3 ${name} HD must DENY (got ${hd.cat})`)
  }
})

test('f-round-15 residual + RODV2 forms DENY on FE+HD (B-F15-4)', async () => {
  for (const [code, name] of residualForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F15-4 ${name} FE must DENY (got ${fe.cat})`)
    assert.equal(hd.deny, true, `B-F15-4 ${name} HD must DENY (got ${hd.cat})`)
  }
})

test('f-round-15 read-only controls stay ALLOW on FE+HD', async () => {
  for (const [code, name] of roForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, false, `B-F15-RO ${name} FE must stay ALLOW (got ${fe.cat})`)
    assert.equal(hd.deny, false, `B-F15-RO ${name} HD must stay ALLOW (got ${hd.cat})`)
  }
})

test('f-round-15 f9 read-only exec-member forwarding stays ALLOW at classifier layer', () => {
  // The heredoc face additionally trips the outer egress-scan unverifiable net
  // (documented runtime-layer conservatism since f-round-14); measure the
  // classifier verdict only, same as the f9 recovery parity test.
  for (const [code, name] of fwdForms) {
    const fe = classifyBashCommand(H.replace('CODE', code))
    const hd = classifyBashCommand(HH.replace('CODE', code))
    const denyOf = (c: typeof fe) =>
      c.category === 'network' ||
      c.category === 'unknown' ||
      (c.category === 'file_write' && c.allow === false)
    assert.equal(denyOf(fe), false, `B-F15-FWD ${name} FE must stay ALLOW (got ${fe.category}/${fe.reason})`)
    assert.equal(denyOf(hd), false, `B-F15-FWD ${name} HD must stay ALLOW (got ${hd.category}/${hd.reason})`)
  }
})

test('f-round-15 T3: eval tagged-template laziness stays ALLOW on the HD face (dsh form)', async () => {
  const hd = await gate(HH.replace('CODE', 'eval`echo X`'))
  assert.equal(hd.deny, false, `T3 HD must stay ALLOW (got ${hd.cat})`)
})
