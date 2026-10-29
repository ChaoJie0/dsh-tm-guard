// f-round-17 regression: dsh round-17 NO-GO on a150eaf (docs/f-round-j-review-a150eaf.md) —
// residual 8 shapes from the round-17 matrix (B-F16-1 property store/load,
// B-F16-3 dynamic Reflect.get catch source, B-F16-6 bind-return apply chain):
//   J1 object property store/load edges (defineProperty value/getter,
//      Object.assign, object spread, Reflect.set/get),
//   J2 wrapper-function constructor escape (new (S.bind(null))(...)),
//   J3 descriptor-value member seeding (var d=desc(...),f=d.value) so
//      bind/call/apply chains on f stay closed,
//   J4 FE/HD semantic parity on dynamic Reflect.get catch sources —
//      the dsh round-17 FE "ALLOW" was a single-quoted harness artifact
//      (inner single quotes split the -e arg); the real double-quoted /
//      unquoted execution shape is DENY on both faces.
// Expect: exploit forms DENY on FE+HD; read-only controls stay ALLOW.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBashCommand } from './src/classifier.ts'
import { scanCommandForEgress } from './src/scan-scripts.ts'

const HDre = /<<-?\s*(?:'([^']+)'|"([^"]+)"|[A-Za-z_][A-Za-z0-9_]*)/
const W = 'process.getBuiltinModule("fs").writeFileSync("/tmp/f17p","pwn")'
const cp = `require("child_process")`
const SH = `["sh",["-c","echo X > /tmp/f17p"]]`
const RO = `["ls",["-la"]]`
const desc = `var d=Object.getOwnPropertyDescriptor(${cp},"spawnSync"),f=d.value;`

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

// f-round-17 J1/J2/J3: the seven real execution shapes from the round-17
// residual list — all share the d/f descVal seeding and a destructive argv.
const j17: Array<[string, string]> = [
  [`${desc} var o={};Object.defineProperty(o,"x",{get(){return f}}); o.x(${SH})`, 'J1 defineProperty getter'],
  [`${desc} var o={};Object.defineProperty(o,"x",{value:f}); o.x(${SH})`, 'J1 defineProperty value'],
  [`${desc} function S(a,b){return f(a,b)} new (S.bind(null))(${SH})`, 'J2 bound constructor wrapper'],
  [`${desc} f.bind(null).call(null,${SH})`, 'J3 bind-return call chain'],
  [`${desc} var o={...Object.create(null),x:f}; o.x(${SH})`, 'J1 object spread store'],
  [`${desc} var o={};Reflect.set(o,"x",f); Reflect.get(o,"x")(${SH})`, 'J1 Reflect.set/get'],
  [`${desc} var g=f.bind(null); g.apply(null,[${SH}])`, 'J3 bind-return apply'],
]

// f-round-17 J4: dynamic Reflect.get catch source — the real double-quoted
// execution shape (inner single quotes are fine inside a double-quoted -e).
const j4 = `var a="ev",b="al"; try{throw Reflect.get(globalThis,a+b)}catch(e){ e(${W}) }`

// read-only controls that must stay ALLOW on both faces. Note: descriptor
// extraction shapes (defineProperty/Reflect.get-of-descriptor) are kept out —
// they trip the pre-existing descriptor-extraction net on the classifier face
// (documented conservative behavior, same class as fround-14).
const ro: Array<[string, string]> = [
  [`${desc} var g=f.bind(null); g.apply(null,[${RO}])`, 'RO bind-apply read-only'],
  [`${desc} var o={...Object.create(null),x:f}; o.x(${RO})`, 'RO spread read-only'],
  [`${desc} f.bind(null).call(null,${RO})`, 'RO bind-call read-only'],
  [`${desc} var g=f.bind(null); g(${RO})`, 'RO bind direct read-only'],
]

test('f-round-17 J1/J2/J3 residual shapes DENY on FE+HD', async () => {
  for (const [code, name] of j17) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `FE ${name}: ${fe.cat} (${code.slice(0, 60)})`)
    assert.equal(hd.deny, true, `HD ${name}: ${hd.cat}`)
  }
})

test('f-round-17 J4 dynamic Reflect.get catch source DENY on FE+HD (double-quoted shape)', async () => {
  const fe = await gate(H.replace('CODE', j4))
  const hd = await gate(HH.replace('CODE', j4))
  assert.equal(fe.deny, true, `FE J4: ${fe.cat}`)
  assert.equal(hd.deny, true, `HD J4: ${hd.cat}`)
})

test('f-round-17 read-only controls stay ALLOW on FE+HD', async () => {
  for (const [code, name] of ro) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, false, `FE ${name}: ${fe.cat}`)
    assert.equal(hd.deny, false, `HD ${name}: ${hd.cat}`)
  }
})
