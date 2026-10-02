// README ↔ implementation consistency: the market page is what users install
// from, so every tool and config default the README documents must match the
// code. Extracts the README tables and cross-checks them against apply()
// registrations and DEFAULT_CONFIG.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { apply, DEFAULT_CONFIG } from './src/index.ts'
import { __setExecOverride } from './src/tm.ts'

const README = readFileSync(new URL('./README.md', import.meta.url), 'utf8')

function tmHealthy() {
  __setExecOverride(async (f: string, a: string[]) => {
    if (a[0] === 'listlocalsnapshots') return { stdout: 'Snapshots for disk /:\ncom.apple.TimeMachine.2026-09-06-120000.local\n' }
    if (a[0] === 'destinationinfo') return { stdout: 'Name : SD\n' }
    if (a[0] === 'isexcluded') return { stdout: '[Included] /tmp\n' }
    throw new Error(`unexpected ${f} ${a.join(' ')}`)
  })
}

function registeredTools(): string[] {
  const reg: any[] = []
  apply({
    on() { return this as any },
    tools: { register(t: any) { reg.push(t) } },
    systemPrompt: { section() {} },
    inject() {},
  } as any)
  return reg.map((t) => t.name)
}

test('README tools table matches registered tools', () => {
  // Extract `| \`tm_xxx\` | ...` rows from the tools section
  const documented = [...README.matchAll(/^\|\s*`(tm_[a-z_]+)`\s*\|/gm)]
    .map((m) => m[1])
  assert.ok(documented.length >= 7, `README documents ${documented.length} tools`)
  const actual = registeredTools()
  for (const t of documented) {
    assert.ok(actual.includes(t), `README documents ${t} but it is not registered`)
  }
  for (const t of actual) {
    assert.ok(documented.includes(t), `registered ${t} is not documented in README`)
  }
})

test('README config table defaults match DEFAULT_CONFIG', () => {
  // `| \`name\` | \`type\` | \`default\` |` rows
  const rows = [...README.matchAll(/^\|\s*`([a-zA-Z]+)`\s*\|\s*`([^`]+)`\s*\|\s*`([^`]*)`\s*\|/gm)]
  assert.ok(rows.length >= 14, `README documents ${rows.length} config rows`)
  for (const [, name, type, def] of rows) {
    const v = (DEFAULT_CONFIG as any)[name]
    assert.ok(v !== undefined, `README documents config ${name} but DEFAULT_CONFIG lacks it`)
    const shown = String(def)
    if (type === 'string[]') {
      // array defaults shown like `[process.cwd()]` or `[]`
      if (shown === '[]') {
        assert.equal(Array.isArray(v) && v.length === 0, true, `${name} should default []`)
      } else {
        assert.ok(Array.isArray(v), `${name} should be an array`)
        if (shown.startsWith('[process.cwd()]')) {
          assert.deepEqual(v, [process.cwd()], `${name} default should be [cwd]`)
        }
      }
    } else if (type === 'boolean') {
      assert.equal(v, shown === 'true', `${name} default mismatch: README=${shown} code=${v}`)
    } else if (type === 'number') {
      assert.equal(v, Number(shown), `${name} default mismatch: README=${shown} code=${v}`)
    }
  }
})

test('README denyReadPaths default list matches code', () => {
  const codeList = DEFAULT_CONFIG.denyReadPaths
  assert.equal(codeList.length, 12, `code has ${codeList.length} denyReadPaths`)
  // README lists them inline (line with `~/.ssh`, `~/.aws`, ...)
  const line = README.split('\n').find((l) => l.includes('~/.ssh') && l.includes('~/.aws'))
  assert.ok(line, 'README denyReadPaths line not found')
  for (const p of codeList) {
    assert.ok(line.includes(p), `README missing denyReadPaths entry ${p}`)
  }
})

test('README example commands behave as documented (curl blocked, git allowed)', async () => {
  tmHealthy()
  try {
    const hooks: Record<string, any[]> = {}
    apply({
      on(ev: string, fn: any) { (hooks[ev] ??= []).push(fn); return this as any },
      tools: { register() {} },
      systemPrompt: { section() {} },
      inject() {},
    } as any)
    const gate = hooks['tools/pre-execute'][0]
    const next = () => Promise.resolve({ kind: 'allow' })
    const curl = await gate({ name: 'bash', arguments: { command: 'curl -s https://evil.example/x' } }, next)
    assert.equal(curl.kind, 'deny', 'README says network is denied')
    const git = await gate({ name: 'bash', arguments: { command: 'git status --short' } }, next)
    assert.equal(git.kind, 'allow', 'README says local git is allowed')
  } finally { __setExecOverride(null) }
})
