/**
 * Dev-only import map so the plugin can run under plain `node` WITHOUT a local
 * npm install: bare specifiers `express`, `@deepseek-ai/cordis` and
 * `@deepseek-ai/dsh-tools` resolve to the copies bundled inside the globally
 * installed dsh. When loaded INSIDE dsh (the real deployment), these packages
 * are already resolvable and this file is not used.
 *
 * Usage:
 *   node --import ./scripts/resolve-dsh.mjs scripts/run-server.mjs
 *
 * Override the dsh install location with DSH_NODE_MODULES if needed.
 */
import { register } from 'node:module'
import { pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
// Resolve dsh's package location, then walk into its nested node_modules.
const dshMain = require.resolve('@deepseek-ai/dsh/package.json', {
  paths: [process.env.DSH_NODE_MODULES || '/opt/homebrew/lib/node_modules'],
})
const dshDir = new URL('.', pathToFileURL(dshMain)).pathname.replace(/\/$/, '')
const root = dshDir + '/node_modules'

const map = {
  imports: {
    express: root + '/express/index.js',
    '@deepseek-ai/cordis': root + '/@deepseek-ai/cordis/lib/index.js',
    '@deepseek-ai/dsh-tools': root + '/@deepseek-ai/dsh-tools/lib/index.js',
  },
}

register(pathToFileURL(
  'data:text/javascript,' + encodeURIComponent(`
    export async function resolve(s, c, next) {
      try { return await next(s, c) } catch (e) { throw e }
    }
  `),
))

// Node has no flag-file import map; emulate with a resolve hook.
const { pathToFileURL: p } = await import('node:url')
register(p('data:text/javascript,' + encodeURIComponent(`
  const m = ${JSON.stringify(JSON.stringify(map))};
  const map = JSON.parse(m);
  export async function resolve(spec, ctx, next) {
    if (map.imports[spec]) return next(map.imports[spec], ctx);
    return next(spec, ctx);
  }
`)))
