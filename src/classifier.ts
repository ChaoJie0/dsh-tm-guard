/**
 * Operation classifier — determines whether a dsh tool call is
 * Time-Machine-rollback-able (allow) or not (deny).
 *
 * Classification philosophy:
 *   - READ operations     → always allow (no side effects), UNLESS the read
 *                           targets a denyReadPaths sensitive prefix
 *   - FILE_WRITE on protected paths → allow (TM can roll back)
 *   - NETWORK / external  → deny (cannot roll back remote state)
 *   - SYSTEM / process mgmt → deny (side effects beyond filesystem)
 *   - PACKAGE managers    → deny (network + global state)
 *   - VCS remote ops      → deny (git push / pull / clone = network)
 *   - VCS local ops       → allow (files only)
 *   - UNKNOWN / ambiguous → deny (conservative for zero-intervention)
 */

import { resolve } from 'node:path'

export type OpCategory =
  | 'read'
  | 'file_write'
  | 'local_exec'
  | 'network'
  | 'local_network'
  | 'process'
  | 'system'
  | 'package'
  | 'vcs_local'
  | 'vcs_remote'
  | 'mixed'
  | 'unknown'

export interface ClassifyResult {
  category: OpCategory
  /** Human-readable reason for the classification */
  reason: string
  /** For file_write: the target paths extracted from args/command */
  targetPaths: string[]
  /** True when the operation should be blocked regardless of TM status */
  forceDeny?: boolean
  /**
   * True for local VCS operations that actually mutate state (commit, reset,
   * checkout, clean, merge, …) as opposed to read-only ones (status, log, diff).
   * Such ops need a restore point in strict mode, just like file writes.
   */
  mutates?: boolean
}

/* ------------------------------------------------------------------ */
/* Command word lists                                                  */
/* ------------------------------------------------------------------ */

const READ_COMMANDS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'nl', 'od', 'xxd',
  'ls', 'dir', 'vdir', 'tree', 'find', 'fd', 'rg', 'grep', 'egrep',
  'fgrep', 'ag', 'ack', 'wc', 'stat', 'file', 'which', 'where',
  'whoami', 'id', 'pwd', 'echo', 'printf', 'true', 'false', 'sleep', 'test',
  'expr', 'date', 'cal', 'uname', 'hostname', 'sw_vers', 'env',
  'printenv', 'set', 'declare', 'typeset', 'readonly', 'help',
  'man', 'apropos', 'whatis', 'info', 'tty', 'users', 'w', 'who',
  'uptime', 'top', 'ps', 'lsof', 'fs_usage', 'netstat', 'ifconfig',
  'ipconfig', 'route', 'arp', 'ndp', 'system_profiler', 'sysctl',
  'defaults read', 'plutil', 'xattr', 'lsattr',
  'du', 'df', 'mount', 'diskutil list', 'brew list', 'brew info',
  'npm list', 'npm ls', 'pip list', 'gem list', 'git status',
  'git log', 'git diff', 'git show', 'git branch', 'git tag',
  'git stash list', 'git reflog', 'git blame', 'git grep',
  'svn status', 'svn log', 'svn diff', 'svn info',
  'mdfind', // Spotlight search — local, read-only
  'code', 'cursor', // editors launched in background = read-ish
  'jq', 'yq', // filters; redirect handled separately
  'sed', 'awk', 'perl', // filters without -i; redirect handled separately
  'sort', 'uniq', 'cut', 'paste', 'join', 'comm', 'tr', 'col',
  'expand', 'unexpand', 'fold', 'fmt', 'pr', 'rev', 'tac',
  'split', 'csplit', 'shuf',
  // Path/identity resolution and checksums — pure reads
  'readlink', 'realpath', 'dirname', 'basename',
  'shasum', 'md5', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum',
  'checksum', 'sum', 'cksum', 'strings', 'filepath',
])

const FILE_WRITE_COMMANDS = new Set([
  'mkdir', 'rmdir', 'touch', 'rm', 'mv', 'cp', 'ln', 'link',
  'unlink', 'rename', 'chmod', 'chown', 'chgrp', 'chflags',
  'setfattr', 'truncate', 'dd', 'mknod', 'mkfifo', 'install',
  'trash', // delete-to-trash: recoverable, treated like a write (TM-rollback-able)
  'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', 'bunzip2',
  'xz', 'unxz', 'zstd', 'unzstd', '7z', 'rar', 'unrar',
  'patch', 'diff', 'ed', 'ex', 'vi', 'vim', 'nvim', 'nano',
  'pico', 'emacs', 'code --wait', 'sed -i', 'perl -i', 'ruby -i',
  'tee', '>file', '>>append', 'clobber',
  'defaults write', 'defaults delete', 'plutil -replace',
  'xattr -w', 'xattr -d', 'xattr -c',
  'git add', 'git commit', 'git rm', 'git mv', 'git checkout',
  'git reset', 'git restore', 'git clean', 'git stash',
  'git merge', 'git rebase', 'git cherry-pick', 'git revert',
  'git tag -a', 'git branch -D', 'git worktree',
  // Local-only package installs are handled as special cases in the
  // network block below (rsync / npm --no-save / pip --no-index).
])

const NETWORK_COMMANDS = new Set([
  // Bare 'git' routes every git invocation through the git subcommand
  // dispatch below (local subs → vcs_local, remote/unknown → vcs_remote).
  'git',
  'curl', 'wget', 'httpie', 'http', 'https', 'fetch',
  'ssh', 'scp', 'sftp', 'rsync', // rsync with remote = network
  'nc', 'netcat', 'ncat', 'telnet', 'ftp', 'ftps',
  'ping', 'ping6', 'traceroute', 'tracepath', 'mtr',
  'dig', 'nslookup', 'host', 'whois', 'drill',
  'aria2c', 'axel', 'youtube-dl', 'yt-dlp',
  'git clone', 'git push', 'git pull', 'git fetch', 'git ls-remote',
  'git remote', 'git submodule update', 'git submodule init',
  'svn checkout', 'svn co', 'svn update', 'svn up', 'svn commit',
  'svn ci', 'svn import', 'svn switch', 'svn merge',
  'npm install', 'npm i', 'npm update', 'npm uninstall', 'npm rm',
  'npm publish', 'npm cache', 'npm audit', 'npm view', 'npm search',
  'yarn', 'yarn add', 'yarn remove', 'yarn upgrade', 'yarn install',
  'pnpm add', 'pnpm install', 'pnpm remove', 'pnpm update',
  'pip install', 'pip3 install', 'pip uninstall', 'pip download',
  'gem install', 'gem uninstall', 'gem update', 'bundle install',
  'cargo install', 'cargo add', 'cargo remove', 'cargo update',
  'go get', 'go install', 'go mod download', 'go mod tidy',
  'brew install', 'brew uninstall', 'brew remove', 'brew update',
  'brew upgrade', 'brew tap', 'brew untap', 'brew fetch',
  'port install', 'port uninstall', 'port selfupdate',
  'nix-env', 'nix-shell', 'nix profile',
  'docker pull', 'docker push', 'docker login', 'docker logout',
  'kubectl', 'helm', 'terraform', 'ansible', 'aws', 'gcloud',
  'az', 's3cmd', 'rclone', 'restic', 'borg',
  // NOTE: 'open' is intentionally NOT here anymore — it is handled in
  // classifySingleCommand: opening a local file/dir is a read, only URL
  // opens count as network egress.
])

/**
 * Local code execution / build / test / lint tools. These run LOCAL code whose
 * effects stay on the local filesystem (rollback-able via the git baseline) —
 * package INSTALLATION / fetching is NOT here (those stay in the network sets).
 */
const LOCAL_EXEC_COMMANDS = new Set([
  // Language interpreters / runners
  'python', 'python3', 'python2', 'node', 'nodejs', 'deno', 'bun',
  'ruby', 'php', 'lua', 'luajit', 'tclsh', 'wish', 'rscript', 'julia',
  'java', 'javac', 'kotlin', 'kotlinc', 'scala', 'groovy', 'dotnet', 'mono',
  'swift', 'rustc', 'ghc', 'runhaskell', 'runghc', 'elixir', 'escript',
  // Build / task runners
  'make', 'cmake', 'ninja', 'bazel', 'bazelisk', 'rake', 'rake',
  // Test runners
  'pytest', 'py.test', 'tox', 'nosetests', 'jest', 'mocha', 'vitest',
  'karma', 'jasmine', 'rspec', 'ctest',
  // Linters / formatters / type-checkers (local, read/write local files)
  'tsc', 'eslint', 'prettier', 'stylelint', 'rubocop', 'flake8', 'pylint',
  // Local document extraction (read-only, writes a local .txt/.json output)
  'pdftotext', 'pdfinfo',
  'black', 'ruff', 'mypy', 'pyright', 'shellcheck', 'hadolint', 'biome',
  'oxlint', 'standard', 'gofmt', 'goimports', 'golangci-lint', 'rustfmt',
  // Local servers / CLIs that only touch local files
  'flask', 'uvicorn', 'gunicorn',
])

/** Package-manager subcommands that are LOCAL (build/test) vs network (install/fetch). */
const LOCAL_PKG_SUBCOMMANDS: Record<string, Set<string>> = {
  npm: new Set(['test', 'run', 'run-script', 't']),
  pnpm: new Set(['test', 'run']),
  yarn: new Set(['test', 'run']),
  cargo: new Set(['test', 'build', 'run', 'check', 'clippy', 'fmt', 'doc', 'bench', 'fix']),
  go: new Set(['test', 'build', 'run', 'vet', 'fmt', 'doc']),
  mix: new Set(['test', 'compile', 'run']),
  dotnet: new Set(['test', 'build', 'run']),
  bundle: new Set(['exec']),
}

const PROCESS_COMMANDS = new Set([
  'kill', 'killall', 'pkill', 'xkill', 'skill', 'slay',
  'launchctl', 'launchctl load', 'launchctl unload',
  'launchctl start', 'launchctl stop', 'launchctl kickstart',
  'osascript', 'applescript', 'say', 'afplay', 'afconvert',
  'screencapture', 'sips', 'qlmanage', 'diskutil',
  'hdiutil', 'drutil', 'asr', 'softwareupdate',
  'tmutil', // Time Machine itself - system-level
  'sudo', 'su', 'doas', 'pkexec',
])

const SYSTEM_COMMANDS = new Set([
  'shutdown', 'reboot', 'halt', 'poweroff', 'restart',
  'systemsetup', 'nvram', 'csrutil', 'bless', 'fdisk',
  'gpt', 'newfs', 'fsck', 'mount', 'umount',
  'diskutil eraseDisk', 'diskutil partitionDisk', 'diskutil reformat',
  'dd if=/dev', 'dd if=/dev/zero', 'dd if=/dev/random',
  'rm -rf /', 'rm -rf /*', 'rm -rf ~', 'rm -rf $HOME',
  'rm -rf /System', 'rm -rf /Library', 'rm -rf /usr',
  'chmod -R 777 /', 'chown -R',
  'defaults write NSGlobalDomain', // system-wide defaults
  'pmset', 'energy saver',
])

/* ------------------------------------------------------------------ */
/* Catastrophic patterns — always deny, even if file_write             */
/* ------------------------------------------------------------------ */

const CATASTROPHIC_PATTERNS = [
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|-rf\s+|-\w*f\w*r\w*\s+)\/(\s|$)/,
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|-rf\s+|-\w*f\w*r\w*\s+)\$?HOME(\s|$)/,
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|-rf\s+|-\w*f\w*r\w*\s+)~(\s|$)/,
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|-rf\s+|-\w*f\w*r\w*\s+)\*(\s|$)/,
  /\bdd\s+if=\/dev\/(zero|random|urandom)\s+of=\/dev\//,
  /\bmkfs\b/,
  /\bformat\s+\/dev\//,
  /\bchmod\s+-R\s+777\s+\/(\s|$)/,
  /\bchown\s+-R\s+\S+\s+\/(\s|$)/,
  /:\s*\(\s*\)\s*\{[^}]*\|[^}]*&[^}]*\}/, // fork bomb: :(){ :|:& };:
  /\b>\s*\/dev\/sd[a-z]/,
  /\bshutdown\b/,
  /\breboot\b/,
  /\bhalt\b/,
]

/* ------------------------------------------------------------------ */
/* Path extraction from commands                                       */
/* ------------------------------------------------------------------ */

/**
 * Split a command into tokens on whitespace, respecting shell quotes so that
 * paths containing spaces (e.g. "/Users/me/My Projects/f.txt") stay intact.
 * Surrounding quotes are stripped; an explicit empty pair ("" or '') yields
 * an empty-string token (matters for `sed -i ''`).
 */
function tokenize(command: string): string[] {
  const tokens: string[] = []
  let cur = ''
  let has = false
  let quote: string | null = null
  const push = () => {
    if (has) {
      tokens.push(cur)
      cur = ''
      has = false
    }
  }
  for (const ch of command) {
    if (quote) {
      if (ch === quote) {
        quote = null
        has = true
      } else {
        cur += ch
        has = true
      }
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      has = true
      continue
    }
    if (/\s/.test(ch)) {
      push()
      continue
    }
    cur += ch
    has = true
  }
  push()
  return tokens
}

/**
 * Extract file paths that a command might modify.
 * Best-effort heuristic; quote-aware so spaced paths survive.
 */
function extractWritePaths(command: string): string[] {
  const paths: string[] = []
  const tokens = tokenize(command)
  const cmd = (tokens[0] ?? '').toLowerCase()

  // Redirection targets: > file, >> file, 1> file, &> file (and glued forms
  // like >file / 2>>file). The next token is the target.
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    if (/^(?:\d?>>?|&>>?)$/.test(t)) {
      if (tokens[i + 1] !== undefined) paths.push(tokens[i + 1])
      i++
      continue
    }
    const glued = t.match(/^(?:\d?>>?|&>>?)(.+)$/)
    if (glued && glued[1]) paths.push(glued[1])
  }

  if (['rm', 'mv', 'cp', 'touch', 'mkdir', 'rmdir', 'chmod', 'chown',
       'truncate', 'dd', 'install', 'ln', 'unlink', 'trash'].includes(cmd)) {
    for (let i = 1; i < tokens.length; i++) {
      const tok = tokens[i]
      if (tok.startsWith('-')) {
        if (tok.startsWith('of=')) paths.push(tok.slice(3)) // dd of=path
        continue
      }
      // Skip leading env assignments (FOO=bar); the rest are paths.
      if (tok.length > 0 && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
        paths.push(tok)
      }
    }
  }

  // tee output file: first non-flag argument.
  if (cmd === 'tee') {
    for (let i = 1; i < tokens.length; i++) {
      if (!tokens[i].startsWith('-')) {
        paths.push(tokens[i])
        break
      }
    }
  }

  // sed -i / perl -i / ruby -i in-place edits: after the -i flag there is an
  // optional backup-suffix token (macOS passes ''), then the script, then the
  // target files.
  if (cmd === 'sed' || cmd === 'perl' || cmd === 'ruby') {
    const idx = tokens.findIndex((t) => t === '-i' || /^-i\S/.test(t))
    if (idx >= 0) {
      let j = idx + 1
      if (tokens[idx] === '-i' && tokens[j] === '') j++ // macOS: -i '' suffix
      j++ // skip the script expression itself
      for (; j < tokens.length; j++) {
        if (tokens[j] && !tokens[j].startsWith('-')) paths.push(tokens[j])
      }
    }
  }

  return paths.filter(
    (p) => p.length > 0 && p !== '/dev/null' && p !== '/dev/stdout',
  )
}

/* ------------------------------------------------------------------ */
/* Sensitive-path read restriction (denyReadPaths)                     */
/* ------------------------------------------------------------------ */

function expandHome(p: string): string {
  if (p === '~') return process.env.HOME ?? p
  if (p.startsWith('~/')) return `${process.env.HOME ?? ''}${p.slice(1)}`
  return p
}

/** Absolute-ize a possibly-relative path for deny-prefix matching. */
function toAbsolute(path: string, baseDir: string = process.cwd()): string {
  if (path.startsWith('/')) return path
  if (path.startsWith('~')) return expandHome(path)
  return resolve(baseDir, path)
}

// Loopback hosts that count as local development targets, not external egress.
const LOOPBACK = /\[::1\]|127\.0\.0\.1|localhost|0\.0\.0\.0/i

/**
 * True when every network target in a command resolves to loopback.
 * Matches bare `curl localhost:3000` and URL forms; a single external URL or
 * host anywhere in the command makes it a real network command again.
 */
function isLoopbackOnly(rest: string): boolean {
  if (!LOOPBACK.test(rest)) return false
  // Any explicit http(s) URL to a non-loopback host → external.
  const urls = rest.match(/https?:\/\/[^\s"'`]+/gi) ?? []
  for (const u of urls) {
    const host = u.replace(/^https?:\/\//i, '').split(/[:\/?#]/)[0]
    if (host && !LOOPBACK.test(host)) return false
  }
  return true
}

/**
 * True when a curl command is a strict read-only download: GET to http(s)
 * URLs only, output written to a local file (-o/--output/-O/--remote-name),
 * and no request body, upload, custom method, auth/credential header,
 * TLS-bypass, proxy or referer flag. Anything else must remain network/deny.
 */
function isReadonlyCurlDownload(rest: string): boolean {
  const s = rest
  // Must target at least one http(s) URL.
  if (!/https?:\/\/[^\s"'`]+/.test(s)) return false
  // Must write output to a local file (not stdout, not piped).
  const hasOutput =
    /\s-o\s+\S+/.test(s) || /\s--output\s+\S+/.test(s) ||
    /\s--output=\S+/.test(s) || /\s-o\S+/.test(s) ||
    /\s-O\b/.test(s) || /\s--remote-name\b/.test(s)
  if (!hasOutput) return false
  // Any of these flags makes it not a read-only download.
  const blocked: RegExp[] = [
    /\s-X\s*\S?/, /\s--request\b/,
    /\s-d\b/, /\s--data\b/, /\s--data-raw\b/, /\s--data-binary\b/, /\s--data-urlencode\b/,
    /\s-T\b/, /\s--upload-file\b/,
    /\s-F\b/, /\s--form\b/,
    /\s-H\b/, /\s--header\b/,
    /\s-u\b/, /\s--user\b/, /\s--basic\b/, /\s--digest\b/, /\s--anyauth\b/, /\s--bearer\b/,
    /\s-k\b/, /\s--insecure\b/,
    /\s--proxy\b/, /\s-e\b/, /\s--referer\b/,
    /\s--post\d*\b/, /\s--head\b/,
  ]
  for (const re of blocked) if (re.test(s)) return false
  return true
}

/**
 * Extract file paths a READ command might open (best-effort, quote-aware).
 * Excludes pure string-printing commands (echo/printf) that open no files,
 * and skips the pattern/program argument of grep/sed/awk/perl so that
 * `sed 's/foo/bar/' file` does not treat the script as a path.
 */
function extractReadPaths(command: string): string[] {
  const paths: string[] = []
  const tokens = tokenize(command)
  if (tokens.length === 0) return paths
  const cmd = tokens[0].toLowerCase()
  if (['echo', 'printf'].includes(cmd)) return []

  // Input redirection: < file
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    if (/^(?:\d?<)$/.test(t)) {
      if (tokens[i + 1]) paths.push(tokens[i + 1])
      i++
      continue
    }
  }

  // grep/sed/awk/perl: the first non-flag token is a pattern/program, not a
  // path (unless it already looks like an absolute/~/ path).
  const patternFirst = new Set([
    'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'sed', 'awk', 'perl',
  ])
  const skipPattern = patternFirst.has(cmd)
  let skipped = false

  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i]
    if (!tok) continue
    if (tok.startsWith('-')) continue
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) continue
    // Glued input redirect: cat <~/.ssh/config
    const lt = tok.match(/^(?:\d?<)(.+)$/)
    if (lt) {
      paths.push(lt[1])
      continue
    }
    if (skipPattern && !skipped && !tok.startsWith('/') && !tok.startsWith('~')) {
      skipped = true
      continue
    }
    // Path-like: absolute, home-relative, or contains a directory separator.
    if (tok.startsWith('/') || tok.startsWith('~') || tok.includes('/')) {
      paths.push(tok)
    }
  }
  return [...new Set(paths)]
}

/** Return the first path that falls under a denyReadPaths prefix, or null. */
function denyHitFor(paths: string[], denyReadPaths: string[]): string | null {
  if (denyReadPaths.length === 0) return null
  const prefixes = denyReadPaths.map((p) => expandHome(p).replace(/\/+$/, ''))
  for (const p of paths) {
    const abs = toAbsolute(p)
    for (const pref of prefixes) {
      if (abs === pref || abs.startsWith(pref + '/')) return p
    }
  }
  return null
}

/* ------------------------------------------------------------------ */
/* Bash command classification                                         */
/* ------------------------------------------------------------------ */

/**
 * Match catastrophic patterns (rm -rf /, fork bombs, mkfs, …).
 * These are denied regardless of anything else.
 */
function matchCatastrophic(command: string): ClassifyResult | null {
  for (const pattern of CATASTROPHIC_PATTERNS) {
    if (pattern.test(command)) {
      return {
        category: 'system',
        reason: `Matched catastrophic pattern: ${pattern.source}`,
        targetPaths: [],
        forceDeny: true,
      }
    }
  }
  return null
}

/**
 * Detect whether a command writes to a file via shell redirection.
 * Ignores redirections to /dev/null and stderr-only redirections.
 */
function hasOutputRedirect(command: string): boolean {
  // Match >, >>, 1>, 1>>, &>, &>> but not 2> (stderr only)
  // and not when the target is /dev/null
  const re = /(?:^|[\s;|&])(?:\d?>>?|&>>?)\s*([^\s;|&]+)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(command)) !== null) {
    const target = m[1].replace(/^['"]|['"]$/g, '')
    if (target !== '/dev/null' && target !== '/dev/stderr') {
      return true
    }
  }
  return false
}

/**
 * Classify a single shell command (no pipes/chains).
 */
/**
 * Split a command on pipes that are OUTSIDE quotes and NOT backslash-escaped.
 * Used for pipelines hidden inside paren groups — naive `split('|')` would
 * shred grep patterns like `grep -E "a|b"` or `grep -n "x\|y"` into bogus
 * segments and false-deny perfectly reasonable read commands.
 */
function splitPipeRespectQuotes(command: string): string[] {
  const parts: string[] = []
  let cur = ''
  let inSingle = false
  let inDouble = false
  let inBacktick = false
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]
    if (ch === "'" && !inDouble && !inBacktick) { inSingle = !inSingle; cur += ch; continue }
    if (ch === '"' && !inSingle && !inBacktick) { inDouble = !inDouble; cur += ch; continue }
    if (ch === '`' && !inSingle && !inDouble) { inBacktick = !inBacktick; cur += ch; continue }
    if (ch === '|' && !inSingle && !inDouble && !inBacktick) {
      if (i > 0 && command[i - 1] === '\\') { cur += ch; continue } // \| is literal
      if (cur.trim()) parts.push(cur.trim())
      cur = ''
      continue
    }
    cur += ch
  }
  if (cur.trim()) parts.push(cur.trim())
  return parts
}

function classifySingleCommand(command: string): ClassifyResult {
  let trimmed = command.trim()
  // Strip one or more leading '(' (subshell groups) so `(lsof -ti:3000 | xargs …)`
  // is classified by its inner command, not rejected as unknown "(lsof …".
  while (trimmed.startsWith('(')) trimmed = trimmed.slice(1).trim()
  if (trimmed.endsWith(')')) trimmed = trimmed.slice(0, -1).trim()
  if (!trimmed) {
    return { category: 'read', reason: 'Empty command', targetPaths: [] }
  }

  // Command wrappers whose inner command decides the classification
  // (`nohup node x &` is a background launch of a local command — local).
  if (/^nohup\s+/i.test(trimmed)) {
    const inner = trimmed.replace(/^nohup\s+/i, '').trim()
    if (!inner || /^-\w/.test(inner)) {
      return { category: 'read', reason: 'nohup help/flag', targetPaths: [] }
    }
    return classifySingleCommand(inner)
  }

  // Check catastrophic patterns first
  const catastrophic = matchCatastrophic(trimmed)
  if (catastrophic) return catastrophic

  // A pipeline hidden inside a paren group becomes visible after stripping;
  // classify each command and keep the most restrictive result. Splitting is
  // quote- and escape-aware so grep patterns keep their "|" intact.
  const pipeParts = splitPipeRespectQuotes(trimmed)
  if (pipeParts.length > 1) {
    const sub = pipeParts.map((p) => classifySingleCommand(p.trim()))
    const localPriority: OpCategory[] = [
      'system', 'network', 'vcs_remote', 'package', 'process',
      'mixed', 'unknown', 'file_write', 'vcs_local', 'local_exec', 'local_network', 'read',
    ]
    let worst = sub[0]
    for (const r of sub) {
      if (r.forceDeny) return r
      if (localPriority.indexOf(r.category) < localPriority.indexOf(worst.category)) {
        worst = r
      }
    }
    return {
      category: worst.category,
      reason: `${sub.length} pipeline commands; most restrictive: ${worst.reason}`,
      targetPaths: worst.targetPaths,
      forceDeny: worst.forceDeny,
      mutates: sub.some((r) => r.mutates),
    }
  }

  // Extract the base command (first word, handling leading env vars)
  let cmdPart = trimmed
  // Strip leading environment variable assignments: FOO=bar cmd
  while (/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/.test(cmdPart)) {
    cmdPart = cmdPart.replace(/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/, '')
  }
  // Normalize: strip a leading path (e.g. /usr/bin/python3 -> python3) and env.
  const rawFirst = cmdPart.split(/\s+/)[0]?.toLowerCase() ?? ''
  const firstWord = rawFirst.split('/').pop() ?? rawFirst
  const rest = cmdPart.slice(cmdPart.split(/\s+/)[0]?.length ?? 0).trim()

  // Check subcommands (git, svn, brew, npm, etc.)
  const fullCmd = `${firstWord} ${rest.split(/\s+/)[0]?.toLowerCase() ?? ''}`.trim()

  // System commands check
  if (SYSTEM_COMMANDS.has(firstWord) || SYSTEM_COMMANDS.has(fullCmd)) {
    return {
      category: 'system',
      reason: `System-level command: ${fullCmd}`,
      targetPaths: extractWritePaths(trimmed),
      forceDeny: true,
    }
  }

  // tmutil read-only queries (backup listings, exclusion lists, checksums)
  // are harmless local reads; management subcommands fall through to the
  // process set below and stay denied.
  if (firstWord === 'tmutil') {
    const sub = rest.split(/\s+/)[0]?.toLowerCase() ?? ''
    const readOnly = new Set([
      'latestbackup', 'listbackups', 'listexclusions', 'listlocalsnapshots',
      'listlocalsnapshotdates', 'listdestinations', 'listtargetmachineinfo',
      'calculatemd5', 'compare', 'version', 'help', '--help', '-h',
    ])
    if (readOnly.has(sub)) {
      return {
        category: 'read',
        reason: `tmutil read-only query: tmutil ${sub}`,
        targetPaths: [],
      }
    }
  }

  // Process commands
  if (PROCESS_COMMANDS.has(firstWord) || PROCESS_COMMANDS.has(fullCmd)) {
    return {
      category: 'process',
      reason: `Process/system management command: ${fullCmd}`,
      targetPaths: [],
    }
  }

  // Local code execution / build / test / lint — local effects, rollback-able.
  // Checked BEFORE the network/package blocks so package-manager LOCAL
  // subcommands (npm test, cargo test, go run…) are allowed while install/fetch
  // (which hit the network) stay blocked.
  const subCmd = rest.split(/\s+/)[0]?.toLowerCase() ?? ''
  if (LOCAL_EXEC_COMMANDS.has(firstWord) || LOCAL_EXEC_COMMANDS.has(fullCmd)) {
    return {
      category: 'local_exec',
      reason: `Local execution/build/test: ${fullCmd}`,
      targetPaths: extractWritePaths(trimmed),
    }
  }
  const localPkgSubs = LOCAL_PKG_SUBCOMMANDS[firstWord]
  if (localPkgSubs && localPkgSubs.has(subCmd)) {
    return {
      category: 'local_exec',
      reason: `Local package-manager task: ${fullCmd}`,
      targetPaths: extractWritePaths(trimmed),
    }
  }

  // `open` with a local file/dir is a plain local read; only URL opens are
  // network egress. `open -a App URL` and `open URL` stay network.
  if (firstWord === 'open') {
    const target = rest.replace(/^-a\s+\S+\s*/i, '').trim()
    if (/:\/\//.test(target)) {
      return {
        category: 'network',
        reason: `open URL: ${target.slice(0, 80)}`,
        targetPaths: [],
      }
    }
    return {
      category: 'read',
      reason: `open local path: ${target || '(default)'}`,
      targetPaths: extractReadPaths(trimmed),
    }
  }

  // Network commands — but check for local-only variants
  if (NETWORK_COMMANDS.has(firstWord) || NETWORK_COMMANDS.has(fullCmd)) {
    // curl read-only download: GET to http(s) with output written to a local
    // file (-o/-O). Everything else (POST bodies, uploads, auth headers,
    // TLS-verification bypass, custom requests, referer) stays network/deny.
    // Loopback-only targets are local dev probes FIRST — even with -o/-O, so
    // `curl -o /dev/null http://localhost:3000/...` classifies as local_network
    // rather than file_write.
    if (firstWord === 'curl') {
      if (isLoopbackOnly(rest)) {
        return {
          category: 'local_network',
          reason: `Local network (loopback only): ${fullCmd}`,
          targetPaths: [],
        }
      }
      if (isReadonlyCurlDownload(rest)) {
        return {
          category: 'file_write',
          reason: `Read-only curl download: ${fullCmd}`,
          targetPaths: extractWritePaths(trimmed),
          mutates: false,
        }
      }
    }
    // git local operations
    if (firstWord === 'git') {
      const sub = rest.split(/\s+/)[0]?.toLowerCase() ?? ''
      const localGitSubs = new Set([
        'status', 'log', 'diff', 'show', 'branch', 'tag', 'stash',
        'add', 'commit', 'rm', 'mv', 'checkout', 'reset', 'restore',
        'clean', 'merge', 'rebase', 'cherry-pick', 'revert', 'blame',
        'grep', 'reflog', 'worktree', 'config', 'init', 'gc',
        'fsck', 'repack', 'prune', 'notes', 'replace', 'mktag',
        'verify-commit', 'verify-tag', 'shortlog', 'describe',
        'archive', 'bundle', 'cat-file', 'hash-object', 'ls-files',
        'ls-tree', 'read-tree', 'write-tree', 'commit-tree',
        'update-index', 'update-ref', 'symbolic-ref', 'rev-parse',
        'rev-list', 'for-each-ref', 'show-ref', 'name-rev',
        'merge-base', 'merge-file', 'merge-index', 'merge-octopus',
        'merge-one-file', 'merge-ours', 'merge-recursive', 'merge-subtree',
        'mergetool', 'difftool', 'apply', 'mailinfo', 'mailsplit',
        'imap-send', 'send-email', 'request-pull', 'format-patch',
      ])
      if (localGitSubs.has(sub)) {
        // State-changing local git ops need a restore point in strict mode;
        // read-only ones (status/log/diff/show/…) do not.
        const mutatingGitSubs = new Set([
          'add', 'commit', 'rm', 'mv', 'checkout', 'reset', 'restore',
          'clean', 'merge', 'rebase', 'cherry-pick', 'revert', 'stash',
          'worktree', 'apply', 'update-ref', 'symbolic-ref', 'gc', 'prune',
          'bundle', 'replace',
        ])
        return {
          category: 'vcs_local',
          reason: `Local git operation: git ${sub}`,
          targetPaths: extractWritePaths(trimmed),
          mutates: mutatingGitSubs.has(sub),
        }
      }
      // git remote operations
      return {
        category: 'vcs_remote',
        reason: `Remote git operation: git ${sub}`,
        targetPaths: [],
      }
    }

    // rsync: local only if no remote host specifier.
    // Remote forms: user@host:path, host::path (daemon), host:path (rsh, no user).
    if (firstWord === 'rsync' &&
        !/(?:^|\s)[\w.-]+@[\w.-]+:|(?:^|\s)[\w.-]+::|(?:^|\s)[\w][\w.-]*:[^\s]/.test(rest)) {
      return {
        category: 'file_write',
        reason: 'Local rsync (no remote host)',
        targetPaths: extractWritePaths(trimmed),
      }
    }

    // npm/pip with local-only flags (no registry access)
    if (firstWord === 'npm' && rest.includes('--no-save') && rest.includes('install')) {
      return {
        category: 'file_write',
        reason: 'npm install --no-save (local only)',
        targetPaths: extractWritePaths(trimmed),
      }
    }
    if ((firstWord === 'pip' || firstWord === 'pip3') &&
        rest.includes('--no-index') && rest.includes('install')) {
      return {
        category: 'file_write',
        reason: `${firstWord} install --no-index (local only)`,
        targetPaths: extractWritePaths(trimmed),
      }
    }

    // Loopback-only network targets (localhost / 127.0.0.1 / [::1] /
    // 0.0.0.0) are local development probes, not external egress — classify
    // as local_network so denyNetwork still blocks real network commands.
    if (isLoopbackOnly(rest)) {
      return {
        category: 'local_network',
        reason: `Local network (loopback only): ${fullCmd}`,
        targetPaths: [],
      }
    }

    return {
      category: 'network',
      reason: `Network/external command: ${fullCmd}`,
      targetPaths: [],
    }
  }

  // npx: runs a locally-installed binary, or fetches one from the registry.
  // Known local dev tools (tsx, vitest, tsc, …) are local execution; anything
  // else risks a network fetch, so it stays conservative (package).
  if (firstWord === 'npx') {
    let pkg = rest.trim()
    let prev: string
    do {
      prev = pkg
      pkg = pkg.replace(/^(?:--yes|-y|--no-install|--no|--package=\S+|-p=\S+|-p\s+\S+)\s*/i, '').trim()
    } while (pkg !== prev)
    const pkgName = pkg.split(/\s+/)[0]?.toLowerCase() ?? ''
    const knownLocal = new Set([
      'tsx', 'ts-node', 'ts-node-esm', 'tsc', 'vitest', 'vite', 'next', 'nuxt',
      'eslint', 'prettier', 'jest', 'mocha', 'nyc', 'playwright', 'cypress',
      'webpack', 'rollup', 'esbuild', 'svgo', 'rimraf', 'concurrently',
      'nodemon', 'husky', 'prisma', 'sequelize-cli', 'nx', 'turbo', 'storybook',
      'parcel', 'babel', 'babel-node', 'expo', 'react-native', 'tsup',
      'unbuild', 'typedoc', 'knip', 'depcheck', 'syncpack',
    ])
    if (knownLocal.has(pkgName)) {
      return {
        category: 'local_exec',
        reason: `npx local tool: ${pkgName}`,
        targetPaths: extractWritePaths(trimmed),
      }
    }
    return {
      category: 'package',
      reason: `npx package: ${pkgName || '(unknown)'}`,
      targetPaths: [],
    }
  }

  // Package managers — but read-only QUERIES (no registry access, no global
  // state) are harmless and should not be denied: npm root / pnpm --version /
  // brew list / pip show / go env / cargo metadata, etc.
  if (['brew', 'npm', 'yarn', 'pnpm', 'pip', 'pip3', 'gem', 'cargo',
       'go', 'port', 'nix-env', 'nix-shell'].includes(firstWord)) {
    const pkgReadOnlySubs = new Set([
      '--version', '-v', '--help', '-h', 'version', 'root', 'prefix', 'bin',
      'list', 'ls', 'show', 'info', 'explain', 'which', 'freeze', 'check',
      'leaves', 'deps', 'uses', 'installed', 'metadata', 'env', 'doc',
      'why', 'tree', 'outdated', // outdated reports versions locally
    ])
    const sub = rest.split(/\s+/)[0]?.toLowerCase() ?? ''
    if (pkgReadOnlySubs.has(sub)) {
      return {
        category: 'read',
        reason: `Package-manager read-only query: ${fullCmd}`,
        targetPaths: [],
      }
    }
    return {
      category: 'package',
      reason: `Package manager: ${fullCmd}`,
      targetPaths: [],
    }
  }

  // File write commands
  if (FILE_WRITE_COMMANDS.has(firstWord) || FILE_WRITE_COMMANDS.has(fullCmd)) {
    // tee always writes to at least one file
    if (firstWord === 'tee') {
      return {
        category: 'file_write',
        reason: 'tee writes to file',
        targetPaths: extractWritePaths(trimmed),
      }
    }

    return {
      category: 'file_write',
      reason: `File modification command: ${fullCmd}`,
      targetPaths: extractWritePaths(trimmed),
    }
  }

  // Read commands
  if (READ_COMMANDS.has(firstWord) || READ_COMMANDS.has(fullCmd)) {
    // Any read-family command with output redirection to a real file
    // becomes a file write (echo >, sed >, sort >, etc.)
    if (hasOutputRedirect(trimmed)) {
      return {
        category: 'file_write',
        reason: `${firstWord} with output redirection`,
        targetPaths: extractWritePaths(trimmed),
      }
    }
    return {
      category: 'read',
      reason: `Read-only command: ${fullCmd}`,
      targetPaths: [],
    }
  }

  // `:` is the no-op builtin; with an output redirection it truncates a file,
  // which is a write that must pass the TM protection check.
  if (firstWord === ':') {
    if (hasOutputRedirect(trimmed)) {
      return {
        category: 'file_write',
        reason: ': with output redirection (truncate)',
        targetPaths: extractWritePaths(trimmed),
      }
    }
    return {
      category: 'read',
      reason: 'Shell builtin: :',
      targetPaths: [],
    }
  }

  // Check for shell builtins that write
  if (['cd', 'pushd', 'popd', 'dirs', 'source', '.', 'export',
       'unset', 'alias', 'unalias', 'function', 'eval', 'exec',
       'exit', 'return', 'break', 'continue', 'shift', 'times',
       'trap', 'ulimit', 'umask', 'wait', 'jobs', 'fg', 'bg',
       'disown', 'suspend', 'logout', 'history', 'fc', 'bind',
       'enable', 'builtin', 'command', 'type', 'hash', 'help',
       'let', 'local', 'declare', 'typeset', 'readonly', 'getopts',
       'read', 'mapfile', 'readarray', 'select', 'case', 'if',
       'while', 'until', 'for', 'do', 'done', 'then', 'else',
       'elif', 'fi', 'esac', 'function', 'time', 'coproc'].includes(firstWord)) {
    // eval/exec could be dangerous
    if (['eval', 'exec'].includes(firstWord)) {
      return {
        category: 'mixed',
        reason: `Shell builtin with dynamic execution: ${firstWord}`,
        targetPaths: [],
      }
    }
    // read with redirect could write? No, read reads.
    return {
      category: 'read',
      reason: `Shell builtin: ${firstWord}`,
      targetPaths: [],
    }
  }

  // dsh CLI read-only queries (help/version/status/list/catalog/…). These
  // only inspect local state; subcommands that manage services or mutate
  // config (web/plugin add/plugin remove) stay unknown → denied.
  if (firstWord === 'dsh') {
    const dshReadOnly = new Set([
      'help', '--help', '-h', 'version', '--version', 'list', 'ls',
      'status', 'ps', 'sessions', 'catalog', 'models', 'doctor', 'whoami',
    ])
    const sub = rest.split(/\s+/)[0]?.toLowerCase() ?? ''
    if (dshReadOnly.has(sub)) {
      return {
        category: 'read',
        reason: `dsh read-only query: ${fullCmd}`,
        targetPaths: [],
      }
    }
    if (sub === 'plugin') {
      const rest2 = rest.replace(/^plugin\s*/i, '').trim()
      if (!rest2 || /^(list|ls|info|show|--help|-h)$/.test(rest2)) {
        return {
          category: 'read',
          reason: `dsh plugin query: ${fullCmd}`,
          targetPaths: [],
        }
      }
    }
    return {
      category: 'unknown',
      reason: `Unknown dsh subcommand: ${fullCmd}`,
      targetPaths: [],
    }
  }

  // Unknown command — conservative deny
  return {
    category: 'unknown',
    reason: `Unknown command: ${fullCmd}`,
    targetPaths: extractWritePaths(trimmed),
  }
}

/* ------------------------------------------------------------------ */
/* Full command string classification (handles pipes, chains)          */
/* ------------------------------------------------------------------ */

/**
 * Replace heredoc bodies (`<<EOF … EOF`) with a single `<<heredoc` marker so
 * script bodies are not split into bogus segments by `;`, `|` or `&&` inside
 * them (a heredoc fed to `node`/`python`/`bash` is local script code, not a
 * chain of separate shell commands). Matches `<<DELIM`, `<<'DELIM'`,
 * `<<"DELIM"`, `<<\DELIM` and `<<-DELIM`; the terminator must be alone on its
 * line. Bodies whose terminator is never found are left untouched (not a
 * valid heredoc), and arithmetic shifts like `$((x << 2))` don't match the
 * delimiter shape, so they are safe too.
 */
function stripHeredocs(command: string): string {
  const re = /<<-?\s*(?:'[^']*'|"[^"]*"|\\?[A-Za-z_][A-Za-z0-9_]*)/g
  const ranges: { start: number; end: number }[] = []
  let m: RegExpExecArray | null
  while ((m = re.exec(command)) !== null) {
    const delim = m[0]
      .replace(/^<<-?\s*/, '')
      .replace(/^['"]|['"]$/g, '')
      .replace(/^\\/, '')
    if (!delim) continue
    const esc = delim.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const termRe = new RegExp(`\\n[ \\t]*${esc}(?=\\n|$)`)
    const bodyStart = m.index + m[0].length
    const rest = command.slice(bodyStart)
    const tm = rest.match(termRe)
    if (!tm) continue
    ranges.push({ start: m.index, end: bodyStart + tm.index + tm[0].length })
    re.lastIndex = bodyStart + tm.index + tm[0].length
  }
  if (ranges.length === 0) return command
  let out = ''
  let last = 0
  for (const r of ranges) {
    out += command.slice(last, r.start) + '<<heredoc'
    last = r.end
  }
  out += command.slice(last)
  return out
}

/**
 * Split a command string into segments at ;, &&, ||, and pipes.
 * Returns the list of individual commands.
 */
function splitCommandSegments(command: string): string[] {
  const segments: string[] = []
  let current = ''
  let inSingleQuote = false
  let inDoubleQuote = false
  let inBacktick = false
  let parenDepth = 0

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]
    const next = command[i + 1]

    if (ch === "'" && !inDoubleQuote && !inBacktick) {
      inSingleQuote = !inSingleQuote
      current += ch
      continue
    }
    if (ch === '"' && !inSingleQuote && !inBacktick) {
      inDoubleQuote = !inDoubleQuote
      current += ch
      continue
    }
    if (ch === '`' && !inSingleQuote && !inDoubleQuote) {
      inBacktick = !inBacktick
      current += ch
      continue
    }

    if (!inSingleQuote && !inDoubleQuote && !inBacktick) {
      if (ch === '(') { parenDepth++; current += ch; continue }
      if (ch === ')') { parenDepth--; current += ch; continue }

      if (parenDepth === 0) {
        if (ch === ';') {
          if (current.trim()) segments.push(current.trim())
          current = ''
          continue
        }
        if (ch === '&' && next === '&') {
          if (current.trim()) segments.push(current.trim())
          current = ''
          i++
          continue
        }
        if (ch === '|' && next === '|') {
          if (current.trim()) segments.push(current.trim())
          current = ''
          i++
          continue
        }
        if (ch === '|') {
          // Pipe — classify the whole pipe, but track segments
          if (current.trim()) segments.push(current.trim())
          current = ''
          continue
        }
      }
    }

    current += ch
  }
  if (current.trim()) segments.push(current.trim())
  return segments
}

/**
 * Classify a full shell command string (may contain pipes, &&, ||, ;).
 * Returns the MOST RESTRICTIVE classification among all segments.
 *
 * @param denyReadPaths  Sensitive path prefixes (~-prefixed or absolute).
 *   Any operation referencing a path under one of these prefixes is denied,
 *   covering both direct reads (`cat ~/.ssh/config`) and reads smuggled
 *   through redirection (`cat ~/.ssh/config > project/out.txt`).
 */
export function classifyBashCommand(
  command: string,
  denyReadPaths: string[] = [],
): ClassifyResult {
  // Catastrophic patterns are checked on the WHOLE command before splitting —
  // fork bombs and similar span ; and | characters, so per-segment checks
  // would let them slip through. This also covers `rm -rf /` smuggled inside
  // a heredoc body.
  const catastrophic = matchCatastrophic(command)
  if (catastrophic) return catastrophic

  // Heredoc bodies are local script code — collapse them into one marker so
  // the ; / | / && inside them don't create false unknown segments.
  command = stripHeredocs(command)

  const segments = splitCommandSegments(command)

  if (segments.length === 0) {
    return { category: 'read', reason: 'Empty command', targetPaths: [] }
  }

  const results = segments.map(classifySingleCommand)

  // Track `cd` across segments so relative paths after `cd dir && …` resolve
  // under `dir` instead of the process cwd (prevents false denials for
  // archive/move/truncate chains inside a subdirectory). The extracted paths
  // are re-resolved per segment against the directory in effect there.
  const cdPattern = /^cd\s+(?:--\s+)?(?:"([^"]*)"|'([^']*)'|(\S+))/i
  let baseDir = process.cwd()
  const resolvedReads: string[] = []
  const resolvedWrites: string[] = []
  for (let i = 0; i < segments.length; i++) {
    const s = segments[i]
    const cd = s.match(cdPattern)
    if (cd) {
      const target = cd[1] ?? cd[2] ?? cd[3]
      baseDir = resolve(
        target.startsWith('/')
          ? target
          : target.startsWith('~')
            ? expandHome(target)
            : resolve(baseDir, target),
      )
      continue
    }
    const dir = baseDir
    for (const p of extractWritePaths(s)) {
      resolvedWrites.push(toAbsolute(p, dir))
    }
    for (const p of extractReadPaths(s)) {
      resolvedReads.push(toAbsolute(p, dir))
    }
  }

  // Priority order for "most restrictive"
  const priority: OpCategory[] = [
    'system', 'network', 'vcs_remote', 'package', 'process',
    'mixed', 'unknown', 'file_write', 'vcs_local', 'local_exec', 'local_network', 'read',
  ]

  let worst: ClassifyResult = results[0]
  for (const r of results) {
    if (r.forceDeny) return r
    if (priority.indexOf(r.category) < priority.indexOf(worst.category)) {
      worst = r
    }
  }

  // Sensitive-path restriction: ANY extracted path (read or write target)
  // under a denyReadPaths prefix blocks the whole command. Extraction runs
  // per segment (not on the whole string) so that an `echo`/`printf` prefix
  // cannot mask a sensitive read later in a chain.
  const deniedPath = denyHitFor(
    [...resolvedReads, ...resolvedWrites],
    denyReadPaths,
  )
  if (deniedPath) {
    return {
      category: worst.category === 'file_write' ? 'file_write' : 'read',
      reason: `Sensitive path access blocked (denyReadPaths): ${deniedPath}`,
      targetPaths: [deniedPath],
      forceDeny: true,
    }
  }

  // Merge target paths from all file-write segments (cd-resolved, absolute)
  const allPaths = resolvedWrites

  return {
    category: worst.category,
    reason:
      results.length > 1
        ? `${results.length} command segments; most restrictive: ${worst.reason}`
        : worst.reason,
    targetPaths: [...new Set(allPaths)],
    forceDeny: worst.forceDeny,
    mutates: results.some((r) => r.mutates),
  }
}

/* ------------------------------------------------------------------ */
/* Tool-level classification (for dsh built-in tools)                  */
/* ------------------------------------------------------------------ */

/**
 * Classify a dsh tool call by tool name and arguments.
 *
 * @param toolName - registered tool name (e.g. 'bash', 'fs_write_file')
 * @param args     - tool arguments object
 * @param denyReadPaths - sensitive path prefixes; reads/writes referencing
 *   them are force-denied (see classifyBashCommand)
 */
export function classifyToolCall(
  toolName: string,
  args: Record<string, unknown>,
  denyReadPaths: string[] = [],
): ClassifyResult {
  const name = toolName.toLowerCase()

  // --- Bash / shell tools ---
  if (name === 'bash' || name === 'shell' || name === 'sh' ||
      name === 'run_command' || name === 'exec' || name === 'terminal') {
    const cmd =
      (args.command as string) ??
      (args.input as string) ??
      (args.cmd as string) ??
      (args.code as string) ??
      ''
    return classifyBashCommand(cmd, denyReadPaths)
  }

  const pathArg =
    (args.path as string) ??
    (args.file_path as string) ??
    (args.file as string) ??
    (args.target as string) ??
    (args.destination as string) ??
    ''

  // --- Filesystem tools ---
  if (name.includes('write') || name.includes('edit') ||
      name.includes('delete') || name.includes('remove') ||
      name.includes('create') || name.includes('mkdir') ||
      name.includes('move') || name.includes('rename') ||
      name.includes('copy') || name.includes('chmod') ||
      name.includes('chown') || name.includes('touch') ||
      name.includes('append') || name.includes('overwrite')) {
    const hit = denyHitFor(pathArg ? [pathArg] : [], denyReadPaths)
    if (hit) {
      return {
        category: 'file_write',
        reason: `Sensitive path access blocked (denyReadPaths): ${hit}`,
        targetPaths: [hit],
        forceDeny: true,
      }
    }
    return {
      category: 'file_write',
      reason: `Filesystem write tool: ${toolName}`,
      targetPaths: pathArg ? [pathArg] : [],
    }
  }

  if (name.includes('read') || name.includes('cat') ||
      name.includes('view') || name.includes('list') ||
      name.includes('ls') || name.includes('stat') ||
      name.includes('grep') || name.includes('find') ||
      name.includes('search') || name.includes('glob') ||
      name.includes('head') || name.includes('tail') ||
      name.includes('diff')) {
    const hit = denyHitFor(pathArg ? [pathArg] : [], denyReadPaths)
    if (hit) {
      return {
        category: 'read',
        reason: `Sensitive path access blocked (denyReadPaths): ${hit}`,
        targetPaths: [hit],
        forceDeny: true,
      }
    }
    return {
      category: 'read',
      reason: `Filesystem read tool: ${toolName}`,
      targetPaths: pathArg ? [pathArg] : [],
    }
  }

  // --- Web / network tools ---
  if (name.includes('web') || name.includes('http') ||
      name.includes('fetch') || name.includes('request') ||
      name.includes('curl') || name.includes('download') ||
      name.includes('upload') || name.includes('api') ||
      name.includes('get_url') || name.includes('scrape')) {
    return {
      category: 'network',
      reason: `Network tool: ${toolName}`,
      targetPaths: [],
    }
  }

  // --- Subagent tools ---
  if (name.includes('subagent') || name.includes('delegate') ||
      name.includes('spawn') || name.includes('fork')) {
    return {
      category: 'mixed',
      reason: `Subagent tool: ${toolName} (cannot verify child operations)`,
      targetPaths: [],
    }
  }

  // --- Todo / planning tools (no side effects outside session) ---
  if (name.includes('todo') || name.includes('task') ||
      name.includes('plan') || name.includes('goal')) {
    return {
      category: 'read',
      reason: `Session-internal tool: ${toolName}`,
      targetPaths: [],
    }
  }

  // --- Interactive tools (asking the user a question / confirmation) ---
  // No filesystem or network side effects; dsh's autoApprove already gates
  // the approval waterfall, so blocking these only prevents the agent from
  // surfacing a question it is allowed to ask.
  if (name.includes('ask_user') || name.includes('user_question') ||
      name.includes('prompt_user') || name === 'confirm') {
    return {
      category: 'read',
      reason: `Interactive tool: ${toolName}`,
      targetPaths: [],
    }
  }

  // --- Our own TM tools (always allowed) ---
  if (name.startsWith('tm_')) {
    return {
      category: 'read',
      reason: `TM-Guard internal tool: ${toolName}`,
      targetPaths: [],
    }
  }

  // --- Unknown tools ---
  return {
    category: 'unknown',
    reason: `Unknown tool: ${toolName}`,
    targetPaths: [],
  }
}

/* ------------------------------------------------------------------ */
/* Final decision                                                      */
/* ------------------------------------------------------------------ */

export interface GateDecision {
  allow: boolean
  reason: string
  category: OpCategory
  /** When allow=true and this is a write op, whether to snapshot first */
  shouldSnapshot: boolean
}

/** macOS temp-dir prefixes — disposable scratch, exempt from the
 *  TM-protection requirement (the files are transient by nature). */
const TEMP_PREFIXES = [
  '/tmp', '/private/tmp', '/var/tmp', '/var/folders',
]

function isTempPath(abs: string): boolean {
  if (!abs.startsWith('/')) abs = toAbsolute(abs)
  return TEMP_PREFIXES.some(
    (p) => abs === p || abs.startsWith(p + '/'),
  )
}

/**
 * Make the final allow/deny decision based on classification and
 * path protection status.
 */
export function decide(
  classification: ClassifyResult,
  pathsProtected: boolean,
): GateDecision {
  const { category, reason, forceDeny } = classification

  if (forceDeny) {
    return {
      allow: false,
      reason: `BLOCKED (${category}, forced deny): ${reason}`,
      category,
      shouldSnapshot: false,
    }
  }

  switch (category) {
    case 'read':
    case 'vcs_local':
    case 'local_exec':
    case 'local_network':
      return {
        allow: true,
        reason: `Allowed (${category}): ${reason}`,
        category,
        shouldSnapshot: false,
      }

    case 'file_write':
      if (pathsProtected) {
        return {
          allow: true,
          reason: `Allowed (file_write on TM-protected path): ${reason}`,
          category,
          shouldSnapshot: true,
        }
      }
      // Writes confined to disposable temp dirs (/tmp, $TMPDIR, /var/tmp)
      // are scratch — no TM snapshot needed, and blocking them only
      // false-denies syntax-check/temp files.
      if (classification.targetPaths.length > 0 &&
          classification.targetPaths.every((p) => isTempPath(p))) {
        return {
          allow: true,
          reason: `Allowed (file_write in temp dir): ${reason}`,
          category,
          shouldSnapshot: false,
        }
      }
      return {
        allow: false,
        reason: `BLOCKED (file_write on path NOT protected by Time Machine): ${reason}`,
        category,
        shouldSnapshot: false,
      }

    case 'network':
    case 'vcs_remote':
    case 'package':
    case 'process':
    case 'system':
      return {
        allow: false,
        reason: `BLOCKED (${category}, not TM-rollback-able): ${reason}`,
        category,
        shouldSnapshot: false,
      }

    case 'mixed':
    case 'unknown':
    default:
      return {
        allow: false,
        reason: `BLOCKED (${category}, cannot verify TM-rollback-ability): ${reason}`,
        category,
        shouldSnapshot: false,
      }
  }
}
