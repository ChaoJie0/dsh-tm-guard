// Quick smoke test for the classifier (pure logic, no tmutil/dsh needed).
// Run: node test-classifier.mts
import { classifyBashCommand, decide } from './src/classifier.ts'
import { mkdirSync } from 'node:fs'

// Run relative-path assertions against a neutral temp workspace,
// so expected paths don't depend on the developer's home directory.
mkdirSync('/tmp/tm-guard-workspace', { recursive: true })
process.chdir('/tmp/tm-guard-workspace')
// macOS resolves /tmp to /private/tmp via symlink; use the real cwd in assertions.
const WS = process.cwd()

let pass = 0
let fail = 0

function check(cmd: string, opts: {
  category: string
  allow?: boolean
  pathsProtected?: boolean
  forceDeny?: boolean
  pathsInclude?: string[]
  denyReadPaths?: string[]
}) {
  const c = classifyBashCommand(cmd, opts.denyReadPaths)
  const d = decide(c, opts.pathsProtected ?? true)
  const okCat = c.category === opts.category
  const okAllow = opts.allow === undefined ? true : d.allow === opts.allow
  const okForce = opts.forceDeny === undefined ? true : !!c.forceDeny === opts.forceDeny
  const okPaths = !opts.pathsInclude ||
    opts.pathsInclude.every((p) => c.targetPaths.includes(p))
  const ok = okCat && okAllow && okForce && okPaths
  if (ok) {
    pass++
  } else {
    fail++
    console.log(
      `FAIL: "${cmd}"\n  expected cat=${opts.category} allow=${opts.allow} force=${opts.forceDeny} paths=${opts.pathsInclude}\n  got      cat=${c.category} allow=${d.allow} force=${!!c.forceDeny} paths=${JSON.stringify(c.targetPaths)}\n  reason: ${c.reason}`,
    )
  }
}

// Reads
check('cat file.txt', { category: 'read', allow: true })
check('ls -la', { category: 'read', allow: true })
check('mdfind kMDItemFSName="*.ts"', { category: 'read', allow: true }) // fixed: was network
check('git status', { category: 'vcs_local', allow: true })
check('git log --oneline', { category: 'vcs_local', allow: true })

// Local git writes
check('git commit -m x', { category: 'vcs_local', allow: true })
check('git add .', { category: 'vcs_local', allow: true })

// File writes on protected paths
check('rm foo.txt', { category: 'file_write', allow: true, pathsInclude: [`${WS}/foo.txt`] })
check('echo hi > out.txt', { category: 'file_write', allow: true, pathsInclude: [`${WS}/out.txt`] })
check('sed -i "" s/a/b/g config.yaml', { category: 'file_write', allow: true, pathsInclude: [`${WS}/config.yaml`] })
check('mkdir -p src/foo', { category: 'file_write', allow: true })
check('rsync -a src/ dist/', { category: 'file_write', allow: true })

// File write on UNPROTECTED path → deny
check('rm /etc/hosts', { category: 'file_write', allow: false, pathsProtected: false })

// Network / remote
check('curl https://example.com', { category: 'network', allow: false })
check('wget http://x/f', { category: 'network', allow: false })
check('git push origin main', { category: 'vcs_remote', allow: false })
check('git clone https://x/repo', { category: 'vcs_remote', allow: false })
check('rsync -a src/ host:/tmp/', { category: 'network', allow: false })

// Package managers
check('npm install', { category: 'network', allow: false })
check('brew install jq', { category: 'network', allow: false })
check('pip install requests', { category: 'network', allow: false })
check('pip install --no-index ./localpkg.whl', { category: 'file_write', allow: true }) // fixed: was network
check('npm install --no-save ./local.tgz', { category: 'file_write', allow: true })

// Process / system
check('sudo rm x', { category: 'process', allow: false })
check('kill -9 1234', { category: 'process', allow: false })
check('launchctl stop foo', { category: 'process', allow: false })

// Catastrophic
check('rm -rf /', { category: 'system', allow: false, forceDeny: true })
check('rm -rf ~', { category: 'system', allow: false, forceDeny: true })
check('sudo rm -rf /', { category: 'system', allow: false, forceDeny: true })
check('mkfs /dev/disk2', { category: 'system', allow: false, forceDeny: true })
check(':(){ :|:& };:', { category: 'system', allow: false, forceDeny: true })

// Chains: most restrictive wins
check('git status && curl https://x', { category: 'network', allow: false })
check('echo a > f.txt; rm -rf /', { category: 'system', allow: false, forceDeny: true })
check('cat a.txt | grep x | wc -l', { category: 'read', allow: true })

// Unknown / dynamic
check('frobnicate --wiz', { category: 'unknown', allow: false })
check('eval "$(something)"', { category: 'mixed', allow: false })

// --- Read-only queries that were previously false-denied ---
// dsh CLI queries
check('dsh --help', { category: 'read', allow: true })
check('dsh help', { category: 'read', allow: true })
check('dsh version', { category: 'read', allow: true })
check('dsh list', { category: 'read', allow: true })
check('dsh status', { category: 'read', allow: true })
check('dsh plugin', { category: 'read', allow: true })
check('dsh plugin list', { category: 'read', allow: true })
// dsh service/mutation subcommands stay denied
check('dsh web', { category: 'unknown', allow: false })
check('dsh plugin add ./x', { category: 'unknown', allow: false })
// readlink / path resolution
check('readlink ~/.dsh/profiles/web/cordis.patch.yml', { category: 'read', allow: true })
check('dirname /tmp/tm-guard-workspace/src/classifier.ts', { category: 'read', allow: true })
// package-manager read-only queries
check('npm root', { category: 'read', allow: true })
check('npm prefix', { category: 'read', allow: true })
check('pnpm --version', { category: 'read', allow: true })
check('brew list --formula', { category: 'read', allow: true })
check('pip show requests', { category: 'read', allow: true })
check('pip3 freeze', { category: 'read', allow: true })
check('go env GOPATH', { category: 'read', allow: true })
check('cargo metadata --format-version 1', { category: 'read', allow: true })
check('gem list', { category: 'read', allow: true })
// package-manager installs stay denied
check('npm install lodash', { category: 'network', allow: false })
check('pnpm add lodash', { category: 'network', allow: false })
check('brew install jq', { category: 'network', allow: false })
check('pip install requests', { category: 'network', allow: false })
check('npm view lodash', { category: 'network', allow: false }) // registry query = network
// subshell-grouped pipeline classified by inner command
// (xargs kill stays denied — unknown, still safe; lsof read part allowed)
check('(lsof -ti:3000 | xargs kill)', { category: 'unknown', allow: false })
check('(cat a.txt | grep x) && echo ok', { category: 'read', allow: true })
// grep patterns containing | must NOT be treated as pipelines
check('grep -E "✔|✖|# (tests|pass|fail)"', { category: 'read', allow: true })
check('grep -n "function subgraphUnrunnableHint\\|reachableFrom"', { category: 'read', allow: true })
check('grep -nE "export function apply|ctx\\.on"', { category: 'read', allow: true })
check('node tests/engine-robustness.test.mjs 2>&1 | grep -E "✔|✖|pass|fail"', { category: 'local_exec', allow: true })
check('cd "/tmp/tm-guard-fixtures/app-server" && node test.js | grep -E "Error|undefine"', { category: 'local_exec', allow: true })

// Redirection to /dev/null stays read
check('echo hi > /dev/null', { category: 'read', allow: true })

// --- Sensitive-path read restriction (denyReadPaths) ---
const deny = ['~/.ssh', '~/.aws', '~/.gnupg', '~/.config', '~/Library/Keychains']

// Direct reads of sensitive paths → force deny
check('cat ~/.ssh/config', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })
check('cat ~/.ssh/id_ed25519', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })
check('ls -la ~/.aws', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })
check('cat ~/.aws/credentials', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })
check('head -n 5 ~/.gnupg/private-keys-v1.d/x', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })
check('find ~/.ssh -name "*.pub"', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })
check('cat ~/.config/gh/hosts.yml', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })

// grep-family reads with the pattern first → still catch the path
check('grep -r foo ~/.aws', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })
check('rg secret ~/.ssh', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })

// Exfiltration via redirection: sensitive source + protected-dir output → deny
check('cat ~/.ssh/config > /tmp/tm-guard-temp/out.txt', {
  category: 'file_write', allow: false, forceDeny: true, denyReadPaths: deny,
})

// Sensitive path in any segment of a chain → deny whole command
check('echo ok && cat ~/.aws/credentials', { category: 'read', allow: false, forceDeny: true, denyReadPaths: deny })

// Write targeting a sensitive path → deny (belt & suspenders)
check('rm ~/.ssh/config', { category: 'file_write', allow: false, forceDeny: true, denyReadPaths: deny })

// No false positives:
//  - sed pattern with / inside is not a path
check("sed 's/foo/bar/' README.md", { category: 'read', allow: true, denyReadPaths: deny })
//  - project paths are NOT under the deny list
check('cat /tmp/tm-guard-workspace/package.json', { category: 'read', allow: true, denyReadPaths: deny })
//  - echo of a sensitive string opens no file
check('echo ~/.ssh', { category: 'read', allow: true, denyReadPaths: deny })
//  - relative project paths resolve to the workspace, not the deny list
check('cat src/index.ts', { category: 'read', allow: true, denyReadPaths: deny })
//  - /dev/null redirects stay read
check('cat /tmp/tm-guard-workspace/package.json | grep name', { category: 'read', allow: true, denyReadPaths: deny })
//  - git local ops unaffected
check('git status', { category: 'vcs_local', allow: true, denyReadPaths: deny })

// Tool-level calls
import { classifyToolCall } from './src/classifier.ts'
const toolDeny = classifyToolCall('Read', { file_path: '~/.ssh/config' }, deny)
if (toolDeny.forceDeny && !decide(toolDeny, true).allow) {
  pass++
} else {
  fail++
  console.log(`FAIL: Read(~/.ssh/config) should be deny, got cat=${toolDeny.category} force=${!!toolDeny.forceDeny}`)
}
const toolOK = classifyToolCall('Read', { file_path: '/tmp/tm-guard-workspace/package.json' }, deny)
if (!toolOK.forceDeny && decide(toolOK, true).allow) {
  pass++
} else {
  fail++
  console.log(`FAIL: Read(project file) should be allow, got force=${!!toolOK.forceDeny}`)
}
const toolBash = classifyToolCall('bash', { command: 'cat ~/.aws/credentials' }, deny)
if (toolBash.forceDeny && !decide(toolBash, true).allow) {
  pass++
} else {
  fail++
  console.log(`FAIL: bash(cat ~/.git-credentials) should be deny, got force=${!!toolBash.forceDeny}`)
}
const toolWriteDeny = classifyToolCall('Write', { file_path: '~/Library/Keychains/x' }, deny)
if (toolWriteDeny.forceDeny && !decide(toolWriteDeny, true).allow) {
  pass++
} else {
  fail++
  console.log(`FAIL: Write(~/Library/Keychains/x) should be deny, got force=${!!toolWriteDeny.forceDeny}`)
}

// --- cd tracking: relative paths after `cd dir && …` resolve under dir ---
// Regression: archive/truncate chains inside a subdirectory were falsely
// denied because relative paths resolved against the process cwd.
const PROT = ['/tmp/tm-guard-home']
const cdMove = classifyBashCommand(
  'cd "/tmp/tm-guard-temp" && mkdir -p .trash-backup && mv app.py race-sim.js .trash-backup/',
)
checkPaths: {
  const ok =
    cdMove.category === 'file_write' &&
    cdMove.targetPaths.every((p) => p.startsWith('/tmp/tm-guard-temp/')) &&
    cdMove.targetPaths.includes('/tmp/tm-guard-temp/.trash-backup')
  if (ok) pass++
  else { fail++; console.log(`FAIL: cd-mv paths resolved wrong: ${JSON.stringify(cdMove.targetPaths)}`) }
}

const cdTruncate = classifyBashCommand(
  'cd "/tmp/tm-guard-temp" && : > app.py && : > race-sim.js',
)
if (cdTruncate.targetPaths.every((p) => p.startsWith('/tmp/tm-guard-temp/'))) {
  pass++
} else {
  fail++
  console.log(`FAIL: cd-truncate paths wrong: ${JSON.stringify(cdTruncate.targetPaths)}`)
}

// cd must not mask a sensitive read in a later segment
const cdSneak = classifyBashCommand(
  'cd /tmp && cat ~/.ssh/config > out.txt',
  deny,
)
if (cdSneak.forceDeny && !decide(cdSneak, true).allow) {
  pass++
} else {
  fail++
  console.log(`FAIL: cd+cat ~/.ssh/config should be denied, got force=${!!cdSneak.forceDeny}`)
}

// relative cd from the project root stays in-tree
const cdRelative = classifyBashCommand('cd sub && echo ok > notes.md')
if (cdRelative.targetPaths.includes(`${WS}/sub/notes.md`)) {
  pass++
} else {
  fail++
  console.log(`FAIL: cd-relative resolved wrong: ${JSON.stringify(cdRelative.targetPaths)}`)
}

// --- loopback vs external network ---
const curlLoopback = classifyBashCommand('sleep 6 && curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/')
if (curlLoopback.category === 'local_network' && decide(curlLoopback, true).allow) {
  pass++
} else {
  fail++
  console.log(`FAIL: curl localhost should be local_network/allow, got ${curlLoopback.category}`)
}
const curl127 = classifyBashCommand('curl -s http://127.0.0.1:8080/api/health')
if (curl127.category === 'local_network') pass++
else { fail++; console.log(`FAIL: curl 127.0.0.1 should be local_network, got ${curl127.category}`) }
const curlExt = classifyBashCommand('curl -s https://api.example.com/v1')
if (curlExt.category === 'network' && !decide(curlExt, true).allow) {
  pass++
} else {
  fail++
  console.log(`FAIL: external curl should stay network/deny, got ${curlExt.category}`)
}
// mixed: loopback + external → external wins
const curlMixed = classifyBashCommand('curl -s localhost:3000 https://example.com')
if (curlMixed.category === 'network') pass++
else { fail++; console.log(`FAIL: mixed localhost+external should be network, got ${curlMixed.category}`) }

// --- 误拦回归：历史 audit deny 中被判错的操作必须放行 ---

// open 本地文件 = 本地打开，非网络；open URL 仍是 network
check('open racing-game.html', { category: 'read', allow: true })
check('open ./index.html', { category: 'read', allow: true })
check('open "~/Downloads/report.pdf"', { category: 'read', allow: true })
check('open https://example.com', { category: 'network', allow: false })
check('open -a Safari https://example.com', { category: 'network', allow: false })

// trash：删除到废纸篓（可恢复），受保护路径应放行
check('cd "/tmp/tm-guard-temp" && trash -v app.py race-sim.js', {
  category: 'file_write', allow: true,
  pathsInclude: ['/tmp/tm-guard-temp/app.py', '/tmp/tm-guard-temp/race-sim.js'],
})

// tmutil 只读查询放行，写/恢复类仍拦
check('tmutil latestbackup 2>&1', { category: 'read', allow: true })
check('tmutil listbackups 2>&1 | tail -5', { category: 'read', allow: true })
check('tmutil restore /Volumes/x/backup --to /tmp', { category: 'process', allow: false })

// node heredoc：脚本体不再被拆成未知段
check(`node <<'NODE'
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync('racing-game.html','utf8');
const code=html.match(/<script>([\\s\\S]*?)<\\/script>/)[1];
NODE`, { category: 'local_exec', allow: true })

// nohup 包装命令按内层命令分类
check('cd "/tmp/tm-guard-fixtures/app-server" && nohup node tests/all-templates-live.mjs > /tmp/tpl-live.log 2>&1 & echo "pid $!"', {
  category: 'local_exec', allow: true,
})

// : > file 清空重定向 = file_write
check('cd "/tmp/tm-guard-temp" && : > app.py && : > race-sim.js', {
  category: 'file_write', allow: true,
  pathsInclude: ['/tmp/tm-guard-temp/app.py', '/tmp/tm-guard-temp/race-sim.js'],
})

// npx 本地已知工具放行；npx 未知包仍拦（package）
check('cd "/tmp/tm-guard-fixtures/app-server" && NODE_USE_ENV_PROXY=1 npx tsx server.ts > /tmp/canvas-server.log 2>&1 &', {
  category: 'local_exec', allow: true,
})
check('npx some-unknown-package foo', { category: 'package', allow: false })

// 写临时目录（/tmp、$TMPDIR）语法检查文件放行，即使不在 TM 保护范围
check('awk \'{print}\' racing-game.html > /tmp/racing-check.js && node --check /tmp/racing-check.js', {
  category: 'file_write', allow: true, pathsProtected: false,
  pathsInclude: ['/tmp/racing-check.js'],
})
// 但写非临时、非保护路径仍拦
check('rm /etc/hosts', { category: 'file_write', allow: false, pathsProtected: false })

// 交互工具（向用户提问/确认，无文件副作用）放行
const toolAsk = classifyToolCall('ask_user_question', { question: '继续吗' }, deny)
if (toolAsk.category === 'read' && decide(toolAsk, true).allow) {
  pass++
} else {
  fail++
  console.log(`FAIL: ask_user_question should be read/allow, got ${toolAsk.category}`)
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail > 0 ? 1 : 0)
