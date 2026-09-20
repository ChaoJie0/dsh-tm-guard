// Dump the headless-rendered DOM to verify nodes actually paint.
import { execFileSync } from 'node:child_process'
const BIN = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const url = process.env.URL || 'http://127.0.0.1:3100'
const out = execFileSync(BIN, [
  '--headless=new', '--disable-gpu', '--no-sandbox',
  '--disable-background-networking', '--disable-component-update',
  '--user-data-dir=/tmp/afv-chrome-dump',
  '--virtual-time-budget=5000', '--dump-dom', url,
], { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'ignore'] })
const nodeCount = (out.match(/class="node /g) || []).length
const total = (out.match(/id="stat-total">[^<]*/) || [''])[0]
console.log('painted .node groups:', nodeCount)
console.log('stat-total:', total)
console.log('contains waiting-empty:', out.includes('Waiting for tool calls'))
