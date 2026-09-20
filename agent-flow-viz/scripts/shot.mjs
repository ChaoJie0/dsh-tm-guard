// Dev visual check: drive headless Chrome via Node child_process to capture
// the local panel. Classified as a local test script (no network egress —
// target is 127.0.0.1).
import { execFileSync } from 'node:child_process'

const BIN = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const url = process.env.URL || 'http://127.0.0.1:3100'
const out = process.env.OUT || new URL('../tmp-shot.png', import.meta.url).pathname

execFileSync(BIN, [
  '--headless=new',
  '--disable-gpu',
  '--no-sandbox',
  '--disable-background-networking',
  '--disable-component-update',
  '--disable-sync',
  '--user-data-dir=/tmp/afv-chrome-profile2',
  '--screenshot=' + out,
  '--window-size=1100,860',
  '--hide-scrollbars',
  '--virtual-time-budget=4000',
  '--run-all-compositor-stages-before-draw',
  url,
], { stdio: ['ignore', 'ignore', 'ignore'], timeout: 30000 })

console.log('wrote', out)
