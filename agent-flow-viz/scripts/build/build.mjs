#!/usr/bin/env node
/**
 * Zero-dependency build for dsh-agent-flow-viz.
 *
 * Uses Node's built-in strip-types transform (Node >= 22.6 / 20.19):
 *   src/*.ts  ->  lib/*.js  (types stripped, ESM preserved)
 * Relative specifiers are rewritten so the emitted graph resolves at runtime.
 * The dsh Host itself loads TypeScript directly, so building is only needed
 * for plain-`node` use and for the published npm package.
 */
import {
  readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..', '..')
const srcDir = join(root, 'src')
const outDir = join(root, 'lib')

const { stripTypeScriptTypes } = await import('node:module')

rmSync(outDir, { recursive: true, force: true })
mkdirSync(outDir, { recursive: true })

const files = readdirSync(srcDir).filter((f) => f.endsWith('.ts'))
const bases = new Set(files.map((f) => f.replace(/\.ts$/, '')))

for (const file of files) {
  const source = readFileSync(join(srcDir, file), 'utf8')
  const js = stripTypeScriptTypes(source, { mode: 'strip', sourceMap: false })
  const rewritten = js.replace(
    /(from\s*['"]|import\s*['"])(\.\.?\/[^'"]+)(['"])/g,
    (m, pre, spec, post) => {
      let base = spec
      if (base.endsWith('.ts')) base = base.slice(0, -3) + '.js'
      else if (!/\.(js|json|wasm|mjs|cjs)$/.test(base)) {
        const clean = base.replace(/\/$/, '')
        if (bases.has(clean.split('/').pop())) base = clean + '.js'
      }
      return pre + base + post
    },
  )
  writeFileSync(join(outDir, file.replace(/\.ts$/, '.js')), rewritten, 'utf8')
}

const dts = `// Type declarations for dsh-agent-flow-viz (hand-maintained).
import type { Context } from '@deepseek-ai/cordis'

export interface AgentFlowVizConfig {
  port: number
  verbose: boolean
  ignoreTools: string[]
}

export declare const name: 'agent-flow-viz'
export declare const inject: string[]
export declare function apply(
  ctx: Context,
  rawConfig?: Partial<AgentFlowVizConfig>,
): void
export type { Context }
`
writeFileSync(join(outDir, 'index.d.ts'), dts, 'utf8')
console.log(`[dsh-agent-flow-viz] build OK: ${files.length} modules -> lib/`)
