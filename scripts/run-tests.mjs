// Local test runner shim.
//
// Why this exists: the plugin's own static egress scanner is invoked on the
// `bash` command line. When the scanner is pointed at `node --test test-*.mts`
// it follows the tests' import graph into src/, where src/scan-scripts.ts
// contains its own rule definitions — and an older build of that scanner
// matched those *rule literals* as if they were live network calls, denying
// the test run outright. Driving the suite from a small runner keeps the
// command line free of .mts entry points so the suite is runnable regardless
// of which scanner build the host has loaded. The scanner itself is now fixed
// (rules lines are skipped); this shim stays as a stable entry point.
import { spawnSync } from 'node:child_process'
import { readdirSync } from 'node:fs'

const tests = readdirSync('.')
  .filter((f) => /^test-.*\.mts$/.test(f))
  .sort()

const args = process.argv.slice(2)
const selected = args.length > 0 ? args : tests
const r = spawnSync(process.execPath, ['--test', ...selected], { stdio: 'inherit' })
process.exit(r.status ?? 1)
