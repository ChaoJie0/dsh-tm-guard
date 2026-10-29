// f-round-13 regression: dsh round-13 NO-GO on 9de0292 —
// B-F13-1 (child_process/module-source VALUE-PASSING channels: params,
// callbacks, defaults, generators, Map/Proxy, ternary/cond-head/return
// assignment, array extraction, optional-call) and B-F13-2 (eval/Function/
// globalThis dynamic sources through the same channels).
// Every dsh round-13 form must DENY on both the find -e (FE) and heredoc
// (HD) faces; the FE deny must come from f8/f6JsDanger itself, so the
// B-F13-2 payload is an arithmetic string (no fs/cp marker) and must still
// DENY. Semantic-equivalence asserts FE/HD decide identically. B-F13-3
// read-only forward controls (R1-R4) stay ALLOW.
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
const SH = `["sh",["-c","echo X > /tmp/f13p"]]`
const ARITH = `"1+1"`

// dsh round-13 section 3, B-F13-1: value-passing channels carrying the
// module source; every form DENY on FE+HD.
const cpForms: Array<[string, string]> = [
  [`(function(x){x["sp"+"awnSync"](${SH})})(require("child_process"))`, 'I1 IIFE param'],
  [`((x)=>x["sp"+"awnSync"](${SH}))(require("child_process"))`, 'I2 arrow param'],
  [`Promise.resolve(require("child_process")).then(x=>x["sp"+"awnSync"](${SH}))`, 'I3 promise then'],
  [`var f;if(f=require("child_process"))f["sp"+"awnSync"](${SH})`, 'I4 cond-head assign'],
  [`[require("child_process")].forEach(x=>x["sp"+"awnSync"](${SH}))`, 'I6 forEach'],
  [`[require("child_process")].map(x=>x["sp"+"awnSync"](${SH}))[0]`, 'I7 map extract'],
  [`function g(x){f=x};g(require("child_process"));f["sp"+"awnSync"](${SH})`, 'I11 callback closure'],
  [`var f=(function(x){return x})(require("child_process"));f["sp"+"awnSync"](${SH})`, 'I12 identity IIFE'],
  [`Object.assign(o,require("child_process"));o["sp"+"awnSync"](${SH})`, 'I14 object assign'],
  [`new (function(x){this.x=x})(require("child_process")).x["sp"+"awnSync"](${SH})`, 'I16 ctor this'],
  [`((x)=>{x["sp"+"awnSync"](${SH})})(require("child_process"))`, 'J7 arrow block'],
  [`var f=[require("child_process")].shift();f["sp"+"awnSync"](${SH})`, 'J10 shift extract'],
  [`[0,require("child_process")].pop()["sp"+"awnSync"](${SH})`, 'L6 pop extract'],
  [`(function(x){x("/")("child_process")["sp"+"awnSync"](${SH})})(require("module").createRequire)`, 'K1 createRequire param'],
  [`(function(r){r("child_process")["sp"+"awnSync"](${SH})})(require)`, 'K2 require param'],
  [`[cp].forEach(function(x){x["sp"+"awnSync"](${SH})})`, 'K3 function-expr callback'],
  [`[require("child_process")].reduce((a,b)=>b)["sp"+"awnSync"](${SH})`, 'K6 reduce extract'],
  [`new Proxy(require("child_process"),{})["sp"+"awnSync"](${SH})`, 'K8 proxy wrap'],
  [`var cp=true?require("child_process"):0;cp["sp"+"awnSync"](${SH})`, 'K10 ternary rhs'],
  [`var cp=require("child_process");cp?.["sp"+"awnSync"]?.(${SH})`, 'K12 optional chain'],
  [`function g(){return f=require("child_process")}g()["sp"+"awnSync"](${SH})`, 'K16 return assign'],
  [`function*g(){yield require("child_process")}g().next().value["sp"+"awnSync"](${SH})`, 'O3 generator yield'],
  [`function g(x=require("child_process")){x["sp"+"awnSync"](${SH})}g()`, 'O5 default param'],
  [`async function g(){var cr=await Promise.resolve(require("module").createRequire);cr("/")("child_process")["sp"+"awnSync"](${SH})}g()`, 'O9 async createRequire'],
  [`var o={m(x){x["sp"+"awnSync"](${SH})}};o.m(require("child_process"))`, 'O12 method arg'],
  [`var f=require("child_process")?.["sp"+"awnSync"];f?.(${SH})`, 'P12 opt get + opt call'],
  [`[].forEach.call([cp],function(x){x["sp"+"awnSync"](${SH})})`, 'Q4 forEach.call'],
  [`var m=process.getBuiltinModule("module");var cr=m.createRequire("/");var cp=cr("child_process");cp["sp"+"awnSync"](${SH})`, 'Q6C gbm createRequire'],
  [`new Map([["c",require("child_process")]]).get("c")["sp"+"awnSync"](${SH})`, 'S7 map get'],
]

// dsh round-13 section 3, B-F13-2: eval/Function/globalThis dynamic sources
// through the same channels. Payload is an ARITHMETIC string (no fs/cp
// marker) — FE must still DENY via f8/f6JsDanger, NOT via lua/fs nets.
const dynForms: Array<[string, string]> = [
  [`((x)=>x(${ARITH}))(eval)`, 'I9 arrow param eval'],
  [`var e;if(e=eval)e(${ARITH})`, 'I10 cond-head eval'],
  [`var e=(function(x){return x})(eval);e(${ARITH})`, 'I13 identity IIFE eval'],
  [`[eval].reduce((a,b)=>b)(${ARITH})`, 'I15 reduce eval'],
  [`function g(x){x(${ARITH})}g(eval)`, 'K7 param eval'],
  [`Promise.resolve(eval).then(x=>x(${ARITH}))`, 'K4 promise then eval'],
  [`var e=true?eval:0;e(${ARITH})`, 'K9 ternary rhs eval'],
  [`var e=(0,eval);e(${ARITH})`, 'K11 indirect eval comma'],
  [`Object.values({a:1,b:eval})[1](${ARITH})`, 'L7 object values eval'],
  [`globalThis[Object.getOwnPropertyNames(globalThis).find(n=>n=="Function")](${ARITH})()`, 'L8 globalThis Function'],
  [`var n=["Func","tion"].join("");globalThis[n](${ARITH})()`, 'L10 join key Function'],
  [`function g(x=eval){x(${ARITH})}g()`, 'O6 default param eval'],
  [`var o={m(x){x(${ARITH})}};o.m(eval)`, 'O11 method arg eval'],
  [`[[eval]].flat()[0](${ARITH})`, 'P6 flat extract eval'],
  [`var e=eval;e?.(${ARITH})`, 'Q3 optional call eval'],
  [`function*g(){yield eval}g().next().value(${ARITH})`, 'Q7 generator yield eval'],
  [`[eval].reduce((a,b)=>b)(${ARITH})`, 'Q10 reduce eval alt'],
  [`var g=()=>eval;g()(${ARITH})`, 'R10 arrow return eval'],
  [`new Map([["e",eval]]).get("e")(${ARITH})`, 'S6 map get eval'],
  [`Promise.all([eval]).then(([e])=>e(${ARITH}))`, 'S11 promise all eval'],
]

// B-F13-3 read-only forwarding controls: real execution is read-only, must
// stay ALLOW on both faces (dsh round-13 report section 3 / condition 4).
const roForms: Array<[string, string]> = [
  [`function g(x){x.spawnSync("ls",["-la"])}g(require("child_process"))`, 'R1 param forward readonly'],
  [`require("child_process").then(x=>x.spawnSync("ls",["-la"]))`, 'R2 then forward readonly'],
  [`new Proxy(require("child_process"),{}).spawnSync("ls",["-la"])`, 'R3 proxy forward readonly'],
  [`console.log("eval(1)")`, 'R4 string eval mention'],
]

test('f-round-13 B-F13-1: all cp value-passing forms DENY on FE+HD, same verdict', async () => {
  for (const [code, name] of cpForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F13-1 ${name} FE must DENY (got ${fe.cat}/${fe.reason})`)
    assert.equal(hd.deny, true, `B-F13-1 ${name} HD must DENY (got ${hd.cat})`)
    assert.equal(fe.deny, hd.deny, `B-F13-1 ${name} FE/HD semantic equivalence (FE=${fe.cat} HD=${hd.cat})`)
  }
})

test('f-round-13 B-F13-2: all dyn forms DENY on FE+HD with arithmetic payload, verdict from f8/f6', async () => {
  for (const [code, name] of dynForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, true, `B-F13-2 ${name} FE must DENY (got ${fe.cat}/${fe.reason})`)
    assert.equal(hd.deny, true, `B-F13-2 ${name} HD must DENY (got ${hd.cat})`)
    assert.equal(fe.deny, hd.deny, `B-F13-2 ${name} FE/HD semantic equivalence (FE=${fe.cat} HD=${hd.cat})`)
    assert.equal(LUA_RE.test(fe.reason), false, `B-F13-2 ${name} FE deny must NOT come from lua net (reason=${fe.reason})`)
  }
})

test('f-round-13 B-F13-3: read-only forwarding stays ALLOW on FE+HD', async () => {
  for (const [code, name] of roForms) {
    const fe = await gate(H.replace('CODE', code))
    const hd = await gate(HH.replace('CODE', code))
    assert.equal(fe.deny, false, `B-F13-3 ${name} FE must stay ALLOW (got ${fe.cat})`)
    assert.equal(hd.deny, false, `B-F13-3 ${name} HD must stay ALLOW (got ${hd.cat})`)
    assert.equal(fe.deny, hd.deny, `B-F13-3 ${name} FE/HD semantic equivalence (FE=${fe.cat} HD=${hd.cat})`)
  }
})
