#!/usr/bin/env node
/**
 * Zero-dependency build for dsh-tm-guard.
 *
 * The runtime target (dsh Host) is Node ≥ 20 with TypeScript-aware loading,
 * and the published package must work WITHOUT a TypeScript toolchain on the
 * consumer machine. This script produces lib/ using only Node's built-in
 * module strip-types transform:
 *
 *   - every src/*.ts is transpiled to lib/*.js (types stripped, ESM preserved)
 *   - local relative imports are rewritten:
 *       './tm.ts'        -> './tm.js'
 *       './classifier'   -> './classifier.js'  (extensionless, as used in src)
 *   - a hand-maintained lib/index.d.ts re-exports the public surface, so
 *     consumers importing the package get typings without shipping a .d.ts
 *     generator. (Node strip-types does not emit declarations.)
 *
 * `node --experimental-strip-types` is used for transpilation only; the
 * emitted lib is plain ESM JavaScript runnable by ordinary `node lib/index.js`
 * on Node >= 20.19 / 22.6+ (strip-types era) and under dsh's own loader.
 */

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  readdirSync,
  rmSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..', '..')
const srcDir = join(root, 'src')
const outDir = join(root, 'lib')

/** Type-only syntax that strip-types leaves behind must also be removed from
 *  value positions; we rely on Node's stripTypeScriptTypes for the full job. */
const { stripTypeScriptTypes } = await import('node:module').then(
  (m) => m,
  async () => {
    // Older Node: dynamically resolve the API name; fail with a clear message.
    throw new Error(
      'Node >= 22.6 (or 20.19 LTS) is required to build dsh-tm-guard (stripTypeScriptTypes). Current: ' +
        process.version,
    )
  },
)

rmSync(outDir, { recursive: true, force: true })
mkdirSync(outDir, { recursive: true })

const files = readdirSync(srcDir).filter((f) => f.endsWith('.ts'))
const jsBases = new Set(files.map((f) => f.replace(/\.ts$/, '')))

for (const file of files) {
  const source = readFileSync(join(srcDir, file), 'utf8')

  // Node 26's API only supports mode:'strip' (type-only syntax removal);
  // the codebase is already ESM JS with type annotations, so strip is enough.
  const js = stripTypeScriptTypes(source, {
    mode: 'strip',
    sourceMap: false,
  })

  // Rewrite relative specifiers so the emitted .js graph resolves at runtime
  // (Node ESM requires explicit extensions; src mixes .ts and extensionless).
  const rewritten = js.replace(
    /(from\s*['"]|import\s*['"])(\.\.?\/[^'"]+)(['"])/g,
    (match, pre, spec, post) => {
      // Leave node: and package imports untouched (regex only matches ./ ../).
      let base = spec
      if (base.endsWith('.ts')) {
        base = base.slice(0, -3) + '.js'
      } else if (!/\.(js|json|wasm|mjs|cjs)$/.test(base)) {
        // Extensionless relative import — append .js if it points at a local
        // module file in this package.
        const cleanBase = base.replace(/\/$/, '')
        const leaf = cleanBase.split('/').pop()
        if (jsBases.has(leaf)) base = cleanBase + '.js'
      }
      return pre + base + post
    },
  )

  const outName = file.replace(/\.ts$/, '.js')
  writeFileSync(join(outDir, outName), rewritten, 'utf8')
}

// --- Public type surface ---------------------------------------------------
// strip-types emits no declarations. Ship a thin hand-written declaration
// entry re-exporting the types consumers need. The public entry is
// `apply(ctx, config?)`; config/tool types are internal but exported for
// profile authors. Keep this in sync when the public surface changes.
const dts = `// Type declarations for dsh-tm-guard.
// Generated/hand-maintained by scripts/build/build.mjs (Node strip-types does
// not emit .d.ts). The runtime entry is lib/index.js.
import type { Context } from '@deepseek-ai/cordis'

export interface TmGuardConfig {
  protectedPaths: string[]
  snapshotCooldownSeconds: number
  denyNetwork: boolean
  denySystem: boolean
  denyReadPaths: string[]
  extraAllowTools: string[]
  extraDenyTools: string[]
  verbose: boolean
  requireTaskSnapshot: boolean
  failClosed: boolean
  failClosedBlockReads: boolean
  turnReports: boolean
  blockingBackupBeforeWrite: boolean
  requireGitBaseline: boolean
  autoApprove: boolean
}

export declare const name: 'tm-guard'
export declare const inject: string[]
export declare function apply(
  ctx: Context,
  rawConfig?: Partial<TmGuardConfig>,
): void
export type { Context }
`
writeFileSync(join(outDir, 'index.d.ts'), dts, 'utf8')

console.log(`[dsh-tm-guard] build OK: ${files.length} modules -> lib/`)
