// U-25 — autoApprove risk made explicit.
//
// autoApprove=true means the plugin answers DSH approval prompts on the user's
// behalf. That is a consequential, invisible-by-default behaviour, so apply()
// must announce it at startup, and must additionally call out the one
// combination that leaves no backstop at all: failClosed=false (writes are no
// longer blocked when the rollback net is missing) + autoApprove=true (the
// human prompt that would have caught it is auto-answered).
//
// console.warn is captured by temporarily replacing it — the plugin writes
// straight to the global console, so a spy on the method is the only seam.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { apply } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'

const README = readFileSync(new URL('./README.md', import.meta.url), 'utf8')

/** Run apply() with console.warn captured; returns every warned line. */
function warningsFrom(config?: Record<string, unknown>): string[] {
  const captured: string[] = []
  const original = console.warn
  const originalLog = console.log
  console.warn = (...args: unknown[]) => { captured.push(args.map(String).join(' ')) }
  // apply() also console.log()s the load banner; keep the test output clean.
  console.log = () => {}
  try {
    apply(
      {
        on() { return this as any },
        tools: { register() {} },
        systemPrompt: { section() {} },
        inject() {},
      } as any,
      config as any,
    )
  } finally {
    console.warn = original
    console.log = originalLog
  }
  return captured
}

const warns = (lines: string[]) => lines.filter((l) => l.includes('[tm-guard]')).join('\n')

before(() => {
  // Healthy TM keeps the failure paths quiet so only the warnings under test
  // can appear.
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
    throw new Error(`unexpected ${f} ${a.join(' ')}`)
  })
})
after(() => __setExecOverride(null))

test('U-25: default config (autoApprove=true) warns that approvals are auto-answered', () => {
  const lines = warningsFrom({ protectedPaths: [process.cwd()] })
  const text = warns(lines)
  assert.match(text, /autoApprove=true/, `no autoApprove declaration in warnings:\n${text}`)
  assert.match(text, /自动应答/, 'warning must state that approvals are answered automatically')
  assert.match(text, /prepend/, 'warning must mention the prepend-ordering dependency')
  assert.match(text, /README/, 'warning must point at the README')
})

test('U-25: the autoApprove warning links to a real README anchor', () => {
  const lines = warningsFrom({ protectedPaths: [process.cwd()] })
  const line = lines.find((l) => l.includes('autoApprove=true'))!
  const anchor = line.match(/#([a-z0-9-]+)/)?.[1]
  assert.ok(anchor, `warning should carry a README anchor, got: ${line}`)
  // GitHub lowercases headings and strips punctuation: the anchor must exist
  // as a heading in README.md, else the "详见 README" pointer is a dead link.
  const headings = [...README.matchAll(/^#{2,4}\s+(.+)$/gm)].map((m) =>
    m[1].toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-'),
  )
  assert.ok(headings.includes(anchor), `anchor #${anchor} not found in README headings: ${headings.join(', ')}`)
})

test('U-25: autoApprove=false does NOT print the auto-approve declaration', () => {
  const lines = warningsFrom({ protectedPaths: [process.cwd()], autoApprove: false })
  const text = warns(lines)
  assert.doesNotMatch(text, /将自动应答 dsh approval 询问/, `unexpected autoApprove warning:\n${text}`)
})

test('U-25: failClosed=false + autoApprove=true warns about the high-risk combination', () => {
  const lines = warningsFrom({ protectedPaths: [process.cwd()], failClosed: false, autoApprove: true })
  const text = warns(lines)
  assert.match(text, /failClosed=false/, `no linkage warning:\n${text}`)
  assert.match(text, /autoApprove=true/, 'linkage warning must name both config values')
  assert.match(text, /高风险|风险/, 'linkage warning must flag the risk explicitly')
  // Both warnings are expected: the declaration AND the combination warning.
  assert.match(text, /prepend/, 'the standalone autoApprove declaration should still be emitted')
})

test('U-25: failClosed=false alone does not trigger the combination warning', () => {
  const lines = warningsFrom({ protectedPaths: [process.cwd()], failClosed: false, autoApprove: false })
  const text = warns(lines)
  assert.doesNotMatch(text, /高风险组合/, `unexpected combination warning:\n${text}`)
})

test('U-25: failClosed defaults to true, so the risky pair is not the default', () => {
  const lines = warningsFrom(undefined)
  const text = warns(lines)
  assert.match(text, /autoApprove=true/, 'the declaration should still fire on a bare apply()')
  assert.doesNotMatch(text, /高风险组合/, 'failClosed defaults true — the risky pair must not warn by default')
})

test('U-25: warning is emitted once per apply(), not per tool call', () => {
  const lines = warningsFrom({ protectedPaths: [process.cwd()] })
  const declarations = lines.filter((l) => l.includes('将自动应答 dsh approval 询问'))
  assert.equal(declarations.length, 1, `expected exactly one declaration, got ${declarations.length}`)
})

test('U-25: non-boolean autoApprove falls back to the default true (and warns)', () => {
  // normalizeBool: a hand-edited `autoApprove: "yes"` is not a boolean, so the
  // safe-by-default merge applies and the declaration must still be printed.
  const lines = warningsFrom({ protectedPaths: [process.cwd()], autoApprove: 'yes' })
  assert.match(warns(lines), /autoApprove=true/, 'string value should degrade to the boolean default')
})
