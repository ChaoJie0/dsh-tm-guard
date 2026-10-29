// f-round-12 regression: dsh round-12 NO-GO on 185986c —
// B-F12-1 (28 child_process arbitrary-command forms: F5/Reflect lexical
// fragility, require/createRequire source aliasing, container/binding
// variants, scan-call boundary) and B-F12-2 (14 HD dynamic-exec forms).
// Every form must DENY on both the find -e (FE) and heredoc (HD) faces;
// read-only literal controls (RO1-5/RO9) must stay ALLOW; the RO6-8
// dynamic-key readonly tradeoff is accepted and pinned to DENY.
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
const SHC = `["sh",["-c","echo X > /tmp/f12-pwn"]]`
const FS = `process.getBuiltinModule("fs").writeFileSync("/tmp/f12-z","pwn")`

test('f-round-12 B-F12-1/B-F12-2: all dsh round-12 forms DENY on FE+HD', async () => {
  const cases: Array<[string, string]> = [
    // class A: F5/Reflect lexical fragility
    [`Reflect.get (Reflect.get({c:require("child_process")},"c"),"sp"+"awnSync")("sh",["-c","echo X > /tmp/x"])`, 'N2 get-space'],
    [`var R=Reflect;R.get(R.get({c:require("child_process")},"c"),"sp"+"awnSync")("sh",["-c","echo X > /tmp/x"])`, 'N3 reflect alias'],
    [`var R={g:Reflect.get};R.g(R.g({c:require("child_process")},"c"),"sp"+"awnSync")("sh",["-c","echo X > /tmp/x"])`, 'N4 member-object alias'],
    [`Reflect.get (Reflect.get ({c:require("child_process")},"c"),"sp"+"awnSync")("sh",["-c","echo X > /tmp/x"])`, 'M5 double-space'],
    [`var A=Reflect.apply,G=Reflect.get;A(G({c:require("child_process")},"c")["sp"+"awnSync"],null,${SHC})`, 'M6 apply+get alias'],
    [`Reflect.apply (Reflect.get ({c:require("child_process")},"c")["sp"+"awnSync"],null,${SHC})`, 'V1 apply-space'],
    [`var R=Reflect,A=R.apply,G=R.get;A(G({c:require("child_process")},"c")["sp"+"awnSync"],null,${SHC})`, 'V2 alias chain apply'],
    [`var c={c:require("child_process")};var f=Reflect.get(c,"c");f["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'X1 literal-get then dyn-call'],
    [`var f=Reflect.get({c:require("child_process")},"c");f["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'X3 get-then-dyn-call'],
    // class B: require/createRequire source aliasing
    [`var cr=require("module").createRequire;cr("/")("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'N6 createRequire alias'],
    [`var cr=require("module").createRequire;cr.call(require("module"),"/")("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'M1 cr.call forward'],
    [`var m=process.getBuiltinModule("module");m.createRequire("/")("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'N7 gbm alias'],
    [`var n="child_process";require("module").createRequire("/")(n)["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'N8 module-name var'],
    [`require("module").createRequire("/")("child"+"_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'N10 module-name concat'],
    [`var rq=require("module");rq.createRequire("/")("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'N19 module alias createRequire'],
    [`var rm=require("module");rm["createRequire"]("/")("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'Y3 bracket createRequire'],
    [`var cr=require("module").createRequire;cr.bind(null)("/")("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'V3 cr.bind forward'],
    [`Reflect.apply(require("module").createRequire,null,["/"])("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'V4 cr via Reflect.apply'],
    [`var cr=require("module").createRequire;cr.apply(null,["/"])("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'Y2 cr.apply forward'],
    [`var cr=require("module").createRequire;cr(require("url").pathToFileURL("/x.js"))("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'M2 cr pathToFileURL'],
    [`var k=require.resolve("child_process");require(k)["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'M12 require.resolve indirect'],
    [`var r=require;r("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'N20 require alias'],
    [`var o={r:require};o.r("child_process")["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'M3 require member-object'],
    [`Reflect.apply(require,null,["child_process"])["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'M4 require via Reflect.apply'],
    // class C: container/binding variants
    [`var cp=require("child_process");Object.getOwnPropertyDescriptor(cp,"spawnSync").value("sh",["-c","echo X > /tmp/x"])`, 'V10 prop-descriptor value'],
    [`var cp=require("child_process");var o={...cp};o["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'V11 object spread'],
    [`var cp=require("child_process");var f;({spawnSync:f}=cp);f("sh",["-c","echo X > /tmp/x"])`, 'V12 rename destructure no-decl'],
    [`var a,b;a=b=require("child_process");a["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'Y9 chain assignment'],
    [`var [cp]=[require("child_process")];cp["sp"+"awnSync"]("sh",["-c","echo X > /tmp/x"])`, 'Y10 array destructure'],
    // B-F12-2: HD dynamic-exec residual (fs payload)
    [`var a=eval,b=a,c=b;c(${FS})`, 'Z1 comma multi-hop'],
    [`var g=globalThis;g["ev"+"al"](${FS})`, 'Z4 global alias concat'],
    [`globalThis["Func"+"tion"](${FS})()`, 'Z6 globalThis body concat'],
    [`var p=Reflect.getPrototypeOf;Reflect.get(p(function(){}),"constructor")(${FS})()`, 'Z10 proto alias'],
    [`var a=[eval];a[0](${FS})`, 'M10 array container eval'],
    [`var F=globalThis[["Function"].join("")];F(${FS})()`, 'M11 join key Function'],
    [`var a=eval,b=a,c=b;c.call(null,${FS})`, 'M15 comma multi-hop .call'],
    [`var a=eval;var b=a,c=b;c(${FS})`, 'Y4 semi+comma multi-hop'],
    [`var arr=[Function];arr[0](${FS})()`, 'Y5 array container Function'],
    [`(function(){return eval})()(${FS})`, 'Y7 return forward eval'],
    [`var E=eval;Function.prototype.call.call(E,null,${FS})`, 'Y14 call.call forward'],
    [`var e=eval;e/*x*/(${FS})`, 'V7 comment separator'],
    [`([].constructor)["con"+"structor"](${FS})()`, 'V8 bracket concat ctor'],
    [`globalThis[["eval"].join("")](${FS})`, 'V9 join key eval'],
  ]
  for (const [code, name] of cases) {
    for (const [face, tmpl] of [['FE', H], ['HD', HH]] as const) {
      const r = await gate(tmpl.replace('CODE', code))
      assert.equal(r.deny, true, `B-F12 ${name} ${face} must DENY (got ${r.cat})`)
    }
  }
})

test('f-round-12 RO: read-only literal controls stay ALLOW', async () => {
  const cases: Array<[string, string]> = [
    [`const {spawnSync:ss}=require("child_process");ss.apply(null,["ls",["-la"]])`, 'RO1 destructure apply readonly'],
    [`const {spawnSync:ss}=require("child_process");ss.call(null,"ls",["-la"])`, 'RO2 destructure call readonly'],
    [`const cp=require("child_process");Reflect.get(cp,"spawnSync")("ls",["-la"])`, 'RO3 reflect.get literal readonly'],
    [`const cp=require("child_process");Reflect.apply(cp["spawnSync"],cp,["ls",["-la"]])`, 'RO4 reflect.apply literal readonly'],
    [`const cp=require("child_process");cp["spawnSync"]("ls",["-la"])`, 'RO5 literal bracket readonly'],
    [`const cp=require("child_process");cp.spawnSync("ls",["-la"])`, 'RO9 dot literal readonly'],
  ]
  for (const [code, name] of cases) {
    const r = await gate(H.replace('CODE', code))
    assert.equal(r.deny, false, `RO ${name} must stay ALLOW (got ${r.cat})`)
  }
})

test('f-round-12 RO6-8: dynamic-key readonly tradeoff pinned to DENY', async () => {
  const cases: Array<[string, string]> = [
    [`const cp=require("child_process");var f=cp["sp"+"awnSync"];(f.apply)(cp,["ls",["-la"]])`, 'RO6 paren method dyn-key readonly'],
    [`const cp=require("child_process");var f=cp["sp"+"awnSync"];f["call"](cp,"ls",["-la"])`, 'RO7 string-member dyn-key readonly'],
    [`const cp=require("child_process");var f=cp["sp"+"awnSync"];f?.("ls",["-la"])`, 'RO8 optional dyn-key readonly'],
  ]
  for (const [code, name] of cases) {
    const r = await gate(H.replace('CODE', code))
    assert.equal(r.deny, true, `RO ${name} tradeoff pinned DENY (got ${r.cat})`)
  }
})
