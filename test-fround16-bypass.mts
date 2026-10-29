// f-round-16 regression: dsh round-16 NO-GO on c90e54e (docs/f-round-i-review-c90e54e.md) —
// B-F16-1 descVal/dyn taint not propagated through value-flow containers
//   (function return / Promise.then / thenable / Map / array extraction /
//   ternary/nullish/|| heads / container injection forwarders),
// B-F16-2 gate crash fail-open (capDeny/capRO TDZ) + timer-family coverage,
// B-F16-3 catch/throw source shapes HD-only gap (variable / subscript /
//   ternary / computed globalThis key / nested catch patterns),
// B-F16-4 eval/Function indirect heads HD-only gap (ternary/nullish heads,
//   [eval].at(0), array-stored Function tagged-template + call),
// B-F16-5 RODV2 read-only verdict reversal on variable argv,
// B-F16-6 residual D2-28 ({value:f=0} default value) / D3-20 (g=f.bind(null) g()).
// Expect: exploit forms DENY on FE+HD; read-only controls stay ALLOW.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand } from './src/classifier.ts'
import { scanCommandForEgress } from './src/scan-scripts.ts'

const HDre = /<<-?\s*(?:'([^']+)'|"([^"]+)"|[A-Za-z_][A-Za-z0-9_]*)/
const W = 'process.getBuiltinModule("fs").writeFileSync("/tmp/f16p","pwn")'
const cp = `require("child_process")`
const SH = `["sh",["-c","echo X > /tmp/f16p"]]`
const RO = `["ls",["-la"]]`
const desc = `var {value:f}=Object.getOwnPropertyDescriptor(${cp},"spawnSync");`

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

// B-F16-6: default-value destructure must not truncate the binding seed;
// bind-return inherits descVal taint and a bind-returned call is a call.
const d28: Array<[string, string]> = [
  [`var {value:f=0}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f(${SH})`, 'D2-28 default-value descVal'],
  [`var {value:f=null}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f(${SH})`, 'D2-28b default-null'],
  [`var {value:f=undefined}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f(${SH})`, 'D2-28c default-undefined'],
  [`var {value:f=()=>{}}=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); f(${SH})`, 'D2-28d default-arrow'],
  [`${desc} var g=f.bind(null); g(${SH})`, 'D3-20 bind-then-call'],
  [`${desc} var g=f.bind(this); g(${SH})`, 'D3-20b bind-this'],
]

// B-F16-3: catch/throw source shapes — variable, subscript, ternary,
// computed globalThis key, nested catch patterns (object / rest / elision).
const c3: Array<[string, string]> = [
  [`var v=eval; try{throw v}catch(e){ e(${W}) }`, 'B16-3 throw-var'],
  [`try{throw [eval][0]}catch(e){ e(${W}) }`, 'B16-3 throw-subscript'],
  [`try{throw true?eval:0}catch(e){ e(${W}) }`, 'B16-3 throw-ternary'],
  [`try{throw globalThis["eval"]}catch(e){ e(${W}) }`, 'B16-3 throw-bracket'],
  [`var a="ev",b="al"; try{throw globalThis[a+b]}catch(e){ e(${W}) }`, 'B16-3 throw-concat-key'],
  [`try{throw [[eval]]}catch([[e]]){ e(${W}) }`, 'B16-3 catch-nested-array'],
  [`try{throw [eval,...[1]]}catch([e,...r]){ e(${W}) }`, 'B16-3 catch-rest'],
  [`try{throw [0,eval]}catch([,e]){ e(${W}) }`, 'B16-3 catch-elision'],
  [`try{throw {eval}}catch({eval:e}){ e(${W}) }`, 'B16-3 catch-obj-rename'],
  [`try{throw {x:{eval}}}catch({x:{eval:e}}){ e(${W}) }`, 'B16-3 catch-nested-obj'],
  [`try{throw {a:1,val:eval}}catch({val:e}){ e(${W}) }`, 'B16-3 catch-obj-omit'],
  [`var v=Function; try{throw v}catch(e){ e(${W}) }`, 'B16-3 throw-fn-var'],
]

// B-F16-4: eval/Function indirect heads — parenthesized ternary/nullish/||,
// array-extraction chains, array-stored Function tagged-template + call.
const c4: Array<[string, string]> = [
  ['(1?eval:0)("1+1")', 'B16-4 ternary-head'],
  ['(eval??0)("1+1")', 'B16-4 nullish-head'],
  ['(0||eval)("1+1")', 'B16-4 or-head'],
  ['[eval].at(0)("1+1")', 'B16-4 at-head'],
  ['[eval].find(()=>true)("1+1")', 'B16-4 find-head'],
  ['[eval].shift()("1+1")', 'B16-4 shift-head'],
  ['[eval].pop()("1+1")', 'B16-4 pop-head'],
  [`var b="eval";[globalThis[b]][0](${W})`, 'B16-4 gt-computed'],
  [`var b="Func",c="tion";[globalThis[b+c]][0](${W})`, 'B16-4 gt-concat'],
  ['var a=[Function];a[0]`return 2`()', 'B16-4 array-tag-call'],
  ['var a=[Function];(a)[0]`return 2`()', 'B16-4 paren-array-tag-call'],
  ['(Function)`return 2`()', 'B16-4 paren-tag-call'],
]

// B-F16-1: value-flow containers — the taint name reaches a call through a
// container operator or forwarder.
const c1: Array<[string, string]> = [
  [`${desc} (function(){return f})()(${SH})`, 'B16-1 fn-return'],
  [`${desc} (()=>f)()(${SH})`, 'B16-1 arrow-return'],
  [`${desc} (0||f)(${SH})`, 'B16-1 or-head-taint'],
  [`${desc} (0??f)(${SH})`, 'B16-1 nullish-taint'],
  [`${desc} (true?f:0)(${SH})`, 'B16-1 ternary-taint'],
  [`${desc} [f].pop()(${SH})`, 'B16-1 pop-taint'],
  [`${desc} [f].shift()(${SH})`, 'B16-1 shift-taint'],
  [`${desc} [f].at(0)(${SH})`, 'B16-1 at-taint'],
  [`${desc} [f].values().next().value(${SH})`, 'B16-1 values-next'],
  [`${desc} [f].find(()=>true)(${SH})`, 'B16-1 find-taint'],
  [`${desc} [f].flatMap(x=>x)(${SH})`, 'B16-1 flatmap-taint'],
  [`${desc} Array.from([f])[0](${SH})`, 'B16-1 from-taint'],
  [`${desc} new Map().set(7,f).get(7)(${SH})`, 'B16-1 map-set-get'],
  [`${desc} new WeakMap().set({},f).get({})(${SH})`, 'B16-1 weakmap-set'],
  [`${desc} Promise.resolve(f).then(g=>g(${SH}))`, 'B16-1 promise-then'],
  [`${desc} Promise.resolve().then(()=>f)(${SH})`, 'B16-1 promise-return'],
  [`${desc} setTimeout(f,0,${SH})`, 'B16-1 timer-f'],
  [`${desc} var g=f.bind(null); setTimeout(g,0,${SH})`, 'B16-1 timer-bind'],
  [`${desc} process.nextTick(f,${SH})`, 'B16-1 nexttick-f'],
  [`${desc} var h=f; h.apply(null,[${SH}])`, 'B16-1 alias-apply'],
  [`${desc} Function.prototype.call.call(f,null,${SH})`, 'B16-1 call-borrow'],
  [`${desc} Reflect.apply(f,null,[${SH}])`, 'B16-1 reflect-apply'],
]

// Read-only controls must stay ALLOW (descriptor .value literal RO argv, eval
// tagged-template laziness). f9 RO exec-member forwarding (R1-R4) is asserted
// at the classifier layer — the heredoc face additionally trips the outer
// egress-scan unverifiable net, a documented runtime-layer conservatism.
const ro: Array<[string, string]> = [
  [`Object.getOwnPropertyDescriptor(${cp},"spawnSync").value(${RO})`, 'AJ2 dot value'],
  [`Object.getOwnPropertyDescriptor(${cp},"spawnSync")["value"](${RO})`, 'AC1 bracket value'],
  [`var d=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); d["value"](${RO})`, 'AC1D alias bracket'],
  [`var d=Object.getOwnPropertyDescriptor(${cp},"spawnSync"); d.value(${RO})`, 'AJ15 alias dot'],
  [`${desc} f(${RO})`, 'AF4RO destructure RO'],
]
// T3: eval tagged-template laziness is asserted on the HD face only — the FE
// face additionally trips the outer find-inline nets (documented since B-F14-3).
const t3 = 'eval`echo X`'
const roFwd: Array<[string, string]> = [
  [`${cp}.spawnSync.apply(${cp},${RO})`, 'R1 apply RO'],
  [`${cp}.spawnSync.call(${cp},"ls",["-la"])`, 'R2 call RO'],
  [`${cp}.spawnSync.bind(${cp})("ls",["-la"])`, 'R3 bind RO'],
  [`var [f]=[${cp}.spawnSync]; f("ls",["-la"])`, 'R4 destructure RO'],
]

test('f-round-16 B-F16-6 default-value/bind-return DENY on FE+HD', async () => {
  for (const [code, name] of d28) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F16-6 ${name} FE must DENY (got ${fe.cat})`)
    assert.equal(hd.deny, true, `B-F16-6 ${name} HD must DENY (got ${hd.cat})`)
  }
})

test('f-round-16 B-F16-3 catch/throw source shapes DENY on FE+HD', async () => {
  for (const [code, name] of c3) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F16-3 ${name} FE must DENY (got ${fe.cat})`)
    assert.equal(hd.deny, true, `B-F16-3 ${name} HD must DENY (got ${hd.cat})`)
  }
})

test('f-round-16 B-F16-4 eval/Function indirect heads DENY on FE+HD', async () => {
  for (const [code, name] of c4) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F16-4 ${name} FE must DENY (got ${fe.cat})`)
    assert.equal(hd.deny, true, `B-F16-4 ${name} HD must DENY (got ${hd.cat})`)
  }
})

test('f-round-16 B-F16-1 value-flow containers DENY on FE+HD', async () => {
  for (const [code, name] of c1) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F16-1 ${name} FE must DENY (got ${fe.cat})`)
    assert.equal(hd.deny, true, `B-F16-1 ${name} HD must DENY (got ${hd.cat})`)
  }
})

test('f-round-16 read-only controls stay ALLOW on FE+HD', async () => {
  for (const [code, name] of ro) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, false, `B-F16-RO ${name} FE must stay ALLOW (got ${fe.cat})`)
    assert.equal(hd.deny, false, `B-F16-RO ${name} HD must stay ALLOW (got ${hd.cat})`)
  }
  const hdT3 = await gate(HH.replace('CODE', t3))
  assert.equal(hdT3.deny, false, `T3 HD must stay ALLOW (got ${hdT3.cat})`)
})

test('f-round-16 f9 read-only exec-member forwarding stays ALLOW at classifier layer', () => {
  for (const [code, name] of roFwd) {
    const fe = classifyBashCommand(H.replace('CODE', code))
    const hd = classifyBashCommand(HH.replace('CODE', code))
    const denyOf = (c: typeof fe) =>
      c.category === 'network' ||
      c.category === 'unknown' ||
      (c.category === 'file_write' && c.allow === false)
    assert.equal(denyOf(fe), false, `B-F16-FWD ${name} FE must stay ALLOW (got ${fe.category}/${fe.reason})`)
    assert.equal(denyOf(hd), false, `B-F16-FWD ${name} HD must stay ALLOW (got ${hd.category}/${hd.reason})`)
  }
})
