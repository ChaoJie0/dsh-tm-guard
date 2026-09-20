/**
 * Dev-only import map so the plugin can run under plain `node` WITHOUT a local
 * npm install: bare specifiers `express`, `@deepseek-ai/cordis` and
 * `@deepseek-ai/dsh-tools` resolve to the copies bundled inside the globally
 * installed dsh. When loaded INSIDE dsh (the real deployment) these packages
 * are already resolvable and this file is not used.
 *
 * Usage:
 *   node --import ./scripts/resolve-dsh.mjs scripts/run-server.mjs
 *
 * Override discovery with DSH_NODE_MODULES (a folder containing @deepseek-ai/dsh).
 */
import { register } from 'node:module'
import { pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const dshPkg = require.resolve('@deepseek-ai/dsh/package.json', {
  paths: [process.env.DSH_NODE_MODULES || '/opt/homebrew/lib/node_modules'],
})
const root = new URL('node_modules/', pathToFileURL(dshPkg)).pathname

const map = {
  express: root + 'express/index.js',
  '@deepseek-ai/cordis': root + '@deepseek-ai/cordis/lib/index.js',
  '@deepseek-ai/dsh-tools': root + '@deepseek-ai/dsh-tools/lib/index.js',
}

const hook = `
  const map = ${JSON.stringify(map)};
  export async function resolve(spec, ctx, next) {
    if (map[spec]) return next(map[spec], ctx);
    return next(spec, ctx);
  }
`
register(pathToFileURL('data:text/javascript,' + encodeURIComponent(hook)))
