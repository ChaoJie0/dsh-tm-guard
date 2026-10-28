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
import { lstatSync } from 'node:fs'

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

/** Most-restrictive-first ranking for merging segment verdicts (B7). */
const PRIORITY: OpCategory[] = [
  'system', 'network', 'vcs_remote', 'package', 'process',
  'mixed', 'unknown', 'file_write', 'vcs_local', 'local_exec', 'local_network', 'read',
]

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
  'sed', // filters without -i; redirect handled separately
  'sort', 'uniq', 'cut', 'paste', 'join', 'comm', 'tr', 'col',
  'expand', 'unexpand', 'fold', 'fmt', 'pr', 'rev', 'tac',
  'split', 'csplit', 'shuf',
  // Path/identity resolution and checksums — pure reads
  'readlink', 'realpath', 'dirname', 'basename',
  'shasum', 'md5', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum',
  'checksum', 'sum', 'cksum', 'strings', 'filepath',
  // Read-only process / binary / metadata inspection (R1)
  'pgrep', // find processes by name/pattern — read-only query
  'otool', // inspect Mach-O binaries (linked libraries) — read-only
  'mdls', // Spotlight metadata queries — read-only
  'afinfo', // audio file metadata — read-only
])

const FILE_WRITE_COMMANDS = new Set([
  'mkdir', 'rmdir', 'touch', 'rm', 'mv', 'cp', 'ln', 'link',
  'unlink', 'rename', 'chmod', 'chown', 'chgrp', 'chflags',
  'setfattr', 'truncate', 'dd', 'mknod', 'mkfifo', 'install',
  'trash', // delete-to-trash: recoverable, treated like a write (TM-rollback-able)
  'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', 'bunzip2',
  'xz', 'unxz', 'zstd', 'unzstd', '7z', 'rar', 'unrar', 'cpio',
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
  'npm publish', 'npm cache', 'npm audit',
  // NOTE: 'npm view' / 'npm search' are NOT here — they are read-only
  // registry lookups handled as read by the package block below (R1).
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
  // Code-carrying hosts: perl/awk inline programs and script files are
  // statically scanned for risky primitives (B1/B3/B4/B6) instead of riding
  // read; a plain `awk '{print}'` / `perl -pe 's/x/y/'` stays clean and allows.
  'perl', 'awk',
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
  // Local media / document converters and inspectors (R1): writing is
  // decided by the OUTPUT path via extractWritePaths, so conversion within
  // protected roots is allowed while /tmp or other unprotected outputs are
  // denied. `-version`/`--help` probes fall under the read-only rule below.
  'ffmpeg', 'ffprobe',
  'avconvert', 'afconvert',
  'soffice', 'libreoffice', 'textutil',
  'qpdf', 'gs', 'mutool', 'magick', 'convert',
  'uv', // uv version/help/init are local; `uv run --with` still hits network via LOCAL_PKG_SUBCOMMANDS absence → package
  'swiftc',
])

// R10: versioned/pypy python interpreters — `python3.12 -c 'print(1)'` is a
// daily reality on macOS/Homebrew and must ride local_exec like `python3`,
// not fail closed as unverifiable. isPython mirrors the SAME names so the
// python `#` comment channel applies to them too. LOCAL_EXEC_COMMANDS keeps
// the exact literal set; this regex widens the accept for `pythonX.Y` /
// `pypyX` while the interpreter-with-inline-code nets below still classify
// the wrapped argv (a `python3.12 -c "os.system('id')"` still denies).
// R11-followup: ABI/build suffixes `m`/`t`/`d` and `-dbg` are real
// executable names (python3.12m, python3.12t free-threading, python3.12-dbg)
// — accepted here, still fail-closed for anything else (python3.12x,
// python3.12-config stay unknown).
const PY_INTERPRETER_RE =
  /^(?:python(?:\d+(?:\.\d+)*)?(?:[mtd]|-dbg)?|pypy(?:\d+(?:\.\d+)*)?(?:[mtd]|-dbg)?)$/

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
 * Archive "bytes -> interpreter" sinks (review-029-r1 F2 / f1f2 closeout).
 * A tar archive can be told to pipe every extracted member through a shell
 * (`--to-command=sh`), execute a command at each checkpoint
 * (`--checkpoint-action=exec=…`), run a remote shell hook
 * (`--rmt-command` / `--rsh-command`), or decompress through an arbitrary
 * program (`-I` / `--use-compress-program`); cpio's interactive rename (`-r`)
 * is the same family. These are B1-class primitives: untrusted archive bytes
 * reach an interpreter with zero checked write targets.
 *
 * review-029-f2b-closeout hardening:
 * - Normalise shell quoting AND backslash escapes first (`\=`, `--to-com""mand`)
 *   so injected quotes/escapes cannot break the substring match (the shell
 *   consumes them, GNU tar sees the real option).
 * - Scope long-option matching to a tar-family first word (tar/gtar/bsdtar);
 *   scope -I/--use-compress-program to tar only, and cpio rename detection to
 *   cpio only — never a generic -i sweep (that wrongly denied sed -i,
 *   perl -i and plain cpio -idmv extraction).
 * - cpio rename is checked on ORIGINAL-case tokens so `-R owner` (restore
 *   ownership) is not mistaken for `-r`.
 * Single source of truth: index.ts and test-hook.mts import this function.
 */
const ARCHIVE_COMPRESSORS = new Set([
  'gzip', 'gunzip', 'bzip2', 'bunzip2', 'xz', 'unxz',
  'zstd', 'unzstd', 'lz4', 'lzip', 'zcat', 'bzcat',
  'xzcat', 'zstdcat', 'lzop', 'pigz', 'pbzip2', 'pixz', 'cat',
])
// No-op / pass-through prefixes: the real program is the next token.
const PASSTHROUGH_PREFIXES = new Set([
  'env', 'command', 'nohup', 'time', 'nice', 'ionice', 'strace',
  'xargs', 'busybox', 'exec', 'builtin', 'sudo', 'doas',
])
// Options of a pass-through prefix that consume their own argument token
// (env -u FOO, --unset NAME, env -C dir). env -i takes no argument.
const OPT_TAKES_ARG: Record<string, ReadonlySet<string>> = {
  env: new Set(['-u', '--unset', '-C', '--chdir', '--directory']),
}
// Shells whose -c STRING form executes a command string.
const COMMAND_SHELLS = new Set([
  'sh', 'bash', 'dash', 'zsh', 'ksh', 'ash', 'csh', 'tcsh', 'fish',
])

function hasTarSink(tokens: string[], start: number): boolean {
  const rest = tokens.slice(start).map((t) => t.toLowerCase())
  const c = rest.join(' ')
  if (c.includes('--to-command')) return true
  const cpa = c.indexOf('--checkpoint-action')
  if (cpa !== -1) {
    const tail = c.slice(cpa)
    const val = tail.match(/^--checkpoint-action[=\s]+([^\s]+)/)
    if (val && val[1].includes('exec')) return true
  }
  if (c.includes('--rmt-command') || c.includes('--rsh-command')) return true
  for (let i = 0; i < rest.length; i++) {
    const tl = rest[i]
    if (tl === '-i' || tl === '--use-compress-program') {
      const v = rest[i + 1] ?? ''
      if (!ARCHIVE_COMPRESSORS.has(v)) return true
      i++
      continue
    }
    if (tl.startsWith('-i') && tl.length > 2 && !tl.startsWith('--')) {
      // Glued form: -Ish
      const v = tl.slice(2)
      if (!ARCHIVE_COMPRESSORS.has(v)) return true
    }
    if (tl.startsWith('--use-compress-program=')) {
      const v = tl.slice('--use-compress-program='.length)
      if (!ARCHIVE_COMPRESSORS.has(v)) return true
    }
  }
  return false
}

function hasCpioSink(tokens: string[], start: number): boolean {
  // Interactive rename (-r / --rename) is an exec-style sink; check on
  // ORIGINAL-case tokens so -R owner is not confused with -r.
  for (const t of tokens.slice(start)) {
    if (t === '--rename') return true
    if (t.startsWith('-') && !t.startsWith('--') && t.slice(1).includes('r')) return true
  }
  return false
}

/**
 * Split on shell control operators (`;`, `&&`, `||`, `|`, `&`, newline)
 * OUTSIDE quotes. A sink in any clause of a compound command must deny
 * (review-029-f2d GAP-C), so every clause is scanned independently.
 */
function splitCommandClauses(command: string): string[] {
  const clauses: string[] = []
  let cur = ''
  let quote: string | null = null
  const push = () => {
    if (cur.trim()) clauses.push(cur)
    cur = ''
  }
  for (let k = 0; k < command.length; k++) {
    const ch = command[k]
    if (quote) {
      if (ch === quote) quote = null
      cur += ch
      continue
    }
    if (ch === '\\') {
      // Escaped character: `\;` is a literal semicolon, not a separator
      // (review-029-f2e (5) — avoid over-splitting on escaped operators).
      if (k + 1 < command.length) {
        cur += ch + command[k + 1]
        k++
      } else {
        cur += ch
      }
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      cur += ch
      continue
    }
    if (ch === ';' || ch === '&' || ch === '|' || ch === '\n') {
      push()
      continue
    }
    cur += ch
  }
  push()
  return clauses
}

/**
 * Archive "bytes -> interpreter" sinks (review-029-r1 F2 / f1f2 closeout).
 * A tar archive can be told to pipe every extracted member through a shell
 * (`--to-command=sh`), execute a command at each checkpoint
 * (`--checkpoint-action=exec=…`), run a remote shell hook
 * (`--rmt-command` / `--rsh-command`), or decompress through an arbitrary
 * program (`-I` / `--use-compress-program`); cpio's interactive rename (`-r`)
 * is the same family. These are B1-class primitives: untrusted archive bytes
 * reach an interpreter with zero checked write targets.
 *
 * review-029-f2b/f2c closeout hardening:
 * - Normalise shell quoting AND backslash escapes first (`\=`, `--to-com""mand`)
 *   so injected quotes/escapes cannot break the match (the shell consumes
 *   them, tar sees the real option).
 * - Wrapper-aware program resolution instead of a bare first-word equality:
 *   skip pass-through prefixes (env/command/nohup/time/nice/ionice/strace/
 *   xargs/busybox/exec/builtin/sudo/doas) and their leading options, resolve
 *   the program by basename (`/usr/bin/tar`, `./tar`, `tar.exe`), and recurse
 *   into `sh -c "STRING"` command strings (the agent's common composite form).
 * - Only a resolved tar-family program is tested for tar sinks, only a
 *   resolved cpio for rename sinks — sed -i / perl -i / gzip -i are never
 *   swept by a generic -i match.
 *
 * review-029-f2d closeout hardening (GAP-A/B/C):
 * - Compound commands: scan every clause split on `;`/`&&`/`||`/`|`/`&`/
 *   newline outside quotes — a sink in the tail of a compound command no
 *   longer hides behind the leading clause.
 * - Shell startup options before `-c`: `bash -x -c "STRING"`, `sh -e -c`,
 *   `bash -xc`, `sh -o pipefail -c`, `bash --norc -c` — skip the shell's
 *   leading options (short clusters, `-o NAME`, long no-arg flags) until the
 *   `-c`/`-cSTRING` command string is reached, then recurse.
 * - Environment assignments (`FOO=1 tar …`, `env FOO=1 tar …`, `FOO=1 env
 *   tar …`) are skipped as non-program tokens, and option-with-argument
 *   flags of pass-through prefixes (`env -u FOO`, `env --unset NAME`,
 *   `env -C dir`) consume their argument token.
 * Single source of truth: index.ts and test-hook.mts import this function.
 */
export function hasArchiveExecSink(command: string): boolean {
  for (const clause of splitCommandClauses(command ?? '')) {
    if (hasSinkInClause(clause)) return true
  }
  return false
}

function hasSinkInClause(clause: string): boolean {
  // Shell consumes backslash escapes and quotes before the tool sees its
  // argv; strip both so the matcher sees the real option string.
  const norm = clause.replace(/\\/g, '').replace(/["']/g, '')
  const tokens = tokenize(norm)
  let i = 0
  let lastPrefix = ''
  while (i < tokens.length) {
    const t = tokens[i]
    if (PASSTHROUGH_PREFIXES.has(t)) {
      lastPrefix = t
      i++
      continue
    }
    if (t.startsWith('-')) {
      // Leading options of a pass-through prefix. Options that take an
      // argument consume the following token (env -u FOO, --unset NAME).
      if (lastPrefix && OPT_TAKES_ARG[lastPrefix]?.has(t)) i++
      i++
      continue
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
      // Environment assignment (FOO=1 tar …): not a program name.
      i++
      continue
    }
    if (COMMAND_SHELLS.has((t.split('/').pop() ?? t).toLowerCase())) {
      // shell [-opts] [-c STRING | script] executes a command string when a
      // -c form is present. Parse the startup options with getopts semantics
      // (review-029-f2f): within a short cluster, 'o' takes the REMAINDER of
      // the cluster as its option name (or the next token when it is last);
      // 'c' takes the remainder of the cluster as the glued command string.
      // A positional argument is tolerated (bash allows one) — keep scanning
      // for a later -c instead of bailing, so `-exop pipefail -c …` and
      // `+eo pipefail -c …` still reach the recursion.
      const shellName = (t.split('/').pop() ?? t).toLowerCase()
      let j = i + 1
      let posArgs = 0
      while (j < tokens.length) {
        const opt = tokens[j]
        if (opt === '-c') {
          const strIdx = j + 1
          if (strIdx < tokens.length) {
            const inner = tokens.slice(strIdx).join(' ')
            if (hasArchiveExecSink(inner)) return true
          }
          return false
        }
        if (opt === '--option' || opt === '--rcfile' || opt === '--init-file') {
          j += 2
          continue
        }
        if (opt.startsWith('--')) {
          // Other long option, no argument: --norc, --noprofile, ...
          j++
          continue
        }
        if (opt.startsWith('-') || opt.startsWith('+')) {
          const body = opt.slice(1)
          if (!body) {
            j++
            continue
          }
          let consumedNext = false
          for (let p = 0; p < body.length; p++) {
            const ch = body[p]
            if (ch === 'c') {
              // bash/zsh ignore remaining flags after 'c' in the cluster and
              // take the NEXT argv token as the command string. Fail-closed
              // by shell (review-029-f2h/f2i): a whitelist per shell is
              // unbounded, so only characters the shell definitively rejects
              // mark the cluster as never executing. bash/sh/dash accept
              // alphabetic flags only; zsh additionally accepts digits and a
              // single trailing '-'. Rejected clusters are at worst a safe
              // over-denial.
              const rest = body.slice(p + 1)
              let legal = true
              if (shellName === 'zsh') {
                for (let r = 0; r < rest.length; r++) {
                  const rc = rest[r]
                  const alpha = (rc >= 'a' && rc <= 'z') || (rc >= 'A' && rc <= 'Z')
                  const digit = rc >= '0' && rc <= '9'
                  if (alpha || digit) continue
                  if (rc === '-' && r === rest.length - 1) continue
                  legal = false
                  break
                }
              } else {
                for (const rc of rest) {
                  if (!(rc >= 'a' && rc <= 'z') && !(rc >= 'A' && rc <= 'Z')) {
                    legal = false
                    break
                  }
                }
              }
              if (!legal) return false
              const inner = tokens.slice(j + 1).join(' ')
              if (hasArchiveExecSink(inner)) return true
              return false
            }
            if (ch === 'o') {
              if (p + 1 < body.length) {
                // Option name is the remainder of the cluster (-op NAME:
                // NAME stays inline); do NOT consume the next token.
                break
              }
              // -o / +o at the end of the cluster consumes the next token.
              consumedNext = true
              break
            }
            // Other single-char option (x, e, v, ...): no argument.
          }
          if (consumedNext) {
            j += 2
            continue
          }
          j++
          continue
        }
        // Non-option token: bash tolerates a single positional argument
        // before -c; a second one means the command is not executed.
        posArgs++
        if (posArgs > 1) return false
        j++
        continue
      }
      return false
    }
    const base = (t.split('/').pop() ?? t).toLowerCase()
    if (base === 'tar' || base === 'gtar' || base === 'bsdtar' || base.endsWith('tar.exe')) {
      return hasTarSink(tokens, i)
    }
    if (base === 'cpio' || base.endsWith('cpio.exe')) {
      return hasCpioSink(tokens, i)
    }
    // F2-a: GNU gzip/xz/bzip2 accept `-I PROG` / `--use-compress-program=PROG`
    // (read from stdin, decompress THROUGH an arbitrary program) — the same
    // bytes->interpreter sink family as tar's -I. The classifier's own
    // compression rule knows this; hasArchiveExecSink must too, because the
    // deep substitution loop in index.ts re-runs ONLY hasArchiveExecSink +
    // egress on normalized bodies (gzip -I hidden behind ≥2 backtick layers
    // previously read->ALLOW).
    if (base === 'gzip' || base === 'gunzip' || base === 'xz' || base === 'unxz' ||
        base === 'bzip2' || base === 'bunzip2' || base === 'lz4' || base === 'lzma' ||
        base === 'unlzma' || base === 'lzop' ||
        ['gzip.exe', 'gunzip.exe', 'xz.exe', 'bzip2.exe', 'lz4.exe', 'lzma.exe', 'lzop.exe'].includes(base)) {
      const rest = tokens.slice(i).map((t) => t.toLowerCase())
      for (let k = 0; k < rest.length; k++) {
        const tl = rest[k]
        if (tl === '-i' || tl === '--use-compress-program') {
          const v = rest[k + 1] ?? ''
          if (!ARCHIVE_COMPRESSORS.has(v) && v !== '') return true
          k++
          continue
        }
        if (tl.startsWith('-i') && tl.length > 2 && !tl.startsWith('--')) {
          const v = tl.slice(2)
          if (!ARCHIVE_COMPRESSORS.has(v) && v !== '') return true
        }
        if (tl.startsWith('--use-compress-program=')) {
          const v = tl.slice('--use-compress-program='.length)
          if (!ARCHIVE_COMPRESSORS.has(v) && v !== '') return true
        }
      }
      return false
    }
    // A real non-archive command (sed, perl, gzip, ...): its -i is its own.
    return false
  }
  return false
}

/**
 * Pure-listing / print / dry-run archive operations that write nothing to
 * disk: `tar -t|--list|-O|--to-stdout`, `unzip -l|-p|-Z`, `7z l|i`,
 * `rsync -n|--dry-run` (including glued short clusters such as -an). These
 * are classified read so an unprotected system cwd (e.g. /usr/local) does
 * not deny a zero-write operation (review-029-f1f2 (c)).
 */
function isReadOnlyArchiveOp(cmd: string, command: string): boolean {
  const tokens = tokenize(command)
  if (cmd === 'tar') {
    for (const t of tokens) {
      if (t === '--list' || t === '--to-stdout' || t === '-t' || t === '-O') return true
      if (t.startsWith('-') && !t.startsWith('--') && t.length > 2 &&
          (t.slice(1).includes('t') || t.slice(1).includes('O'))) return true
    }
    return false
  }
  if (cmd === 'unzip') {
    return tokens.some((t) => t === '-l' || t === '--list' || t === '-p' || t === '-Z')
  }
  if (cmd === '7z' || cmd === '7zz' || cmd === '7za') {
    const sub = (tokens[1] ?? '').toLowerCase()
    return sub === 'l' || sub === 'i'
  }
  if (cmd === 'rsync') {
    const short = tokens.filter((t) => t.startsWith('-') && !t.startsWith('--') && t.length > 1)
    return tokens.some((t) => t === '--dry-run' || t === '-n') ||
      short.some((t) => t.slice(1).includes('n'))
  }
  return false
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
    const glued = t.match(/^(?:\d?>>?|&>>?)(?![&\d])(.+)$/)
    if (glued && glued[1]) paths.push(glued[1])
  }

  // Glued WRITE-typed option values: `--output=…`, `--out=…`, `-o=…`,
  // `--target=…`, `--dest=…`, `--destination=…` — the value is a write
  // target even for otherwise-read commands (sort --output=). Deliberately
  // NOT a generic path-like extraction: `--files-from=…` / `--from-file=…`
  // are READ inputs (their values belong in the read-side extraction) and
  // feeding them into the write path list would deny legitimate in-scope
  // writes whenever the input list lives outside the protected prefix.
  const WRITE_VALUE_FLAGS = new Set([
    '--output', '--out', '-o', '--target', '--dest', '--destination',
    '--outfile', '--output-file', '--target-directory', '--dest-dir',
    '--destination-directory', '--output-directory',
  ])
  for (const t of tokens) {
    if (!t.startsWith('-')) continue
    const eq = t.indexOf('=')
    if (eq <= 1) continue
    const flag = t.slice(0, eq)
    if (!WRITE_VALUE_FLAGS.has(flag)) continue
    const val = t.slice(eq + 1)
    if (val && (val.startsWith('/') || val.startsWith('~') || val.includes('/'))) {
      paths.push(val)
    }
  }

  // curl -o/--output SEPARATE values (`-o /tmp/x`): the download lands on a
  // local path, so it must be extracted or legitimate `curl -o /tmp/x`
  // downloads get blocked as unprotected writes (0.2.6 edge 2 fix side).
  // -O/--remote-name writes into cwd using the remote basename; there is no
  // explicit target token, so synthesize cwd for the rollback check.
  if (cmd === 'curl') {
    let hasRemoteName = false
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if (t === '-o' || t === '--output' || t === '--output-file' || t === '--outfile') {
        const v = tokens[i + 1]
        if (v && !v.startsWith('-') && !/^https?:\/\//.test(v)) {
          paths.push(v)
          i++
        }
        continue
      }
      if (t === '--remote-name' || t === '--remote-name-all') {
        hasRemoteName = true
        continue
      }
      // -O in a short cluster (-sO, -O, -sfLO). A lowercase `-o` anywhere
      // consumes the rest as a filename, so only the letters before it count.
      if (t.startsWith('-') && !t.startsWith('--')) {
        const oIdx = t.indexOf('o')
        const head = oIdx === -1 ? t.slice(1) : t.slice(1, oIdx)
        if (head.includes('O')) hasRemoteName = true
      }
    }
    if (hasRemoteName) paths.push(process.cwd())
  }

  if (['rm', 'mv', 'cp', 'touch', 'mkdir', 'rmdir', 'chmod', 'chown',
       'truncate', 'dd', 'install', 'ln', 'unlink', 'trash'].includes(cmd)) {
    for (let i = 1; i < tokens.length; i++) {
      const tok = tokens[i]
      // dd key=value operands: `of=` is the write target (and `if=` is the
      // read input, handled in extractReadPaths). These are NOT env
      // assignments — without this, `dd of=/tmp/x` was never extracted at all
      // (the generic skip treats `of=…` as FOO=bar).
      if (cmd === 'dd') {
        if (tok.startsWith('of=')) { paths.push(tok.slice(3)); continue }
        if (tok.startsWith('if=')) continue // read side, handled there
      }
      if (tok.startsWith('-')) {
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
  // target files. `-i` may ride inside a short cluster (`perl -pi`,
  // `ruby -pi`, `perl -ni`, `perl -pi.bak`) — B1 regression: without the
  // cluster match, `perl -pi -e 's/x/y/' /etc/hosts` was classified local_exec
  // with zero write targets and sailed through.
  if (cmd === 'sed' || cmd === 'perl' || cmd === 'ruby') {
    let idx = -1
    for (let k = 0; k < tokens.length; k++) {
      const t = tokens[k]
      if (t === '-i') { idx = k; break }
      if (t.startsWith('-') && !t.startsWith('--') && /^[a-zA-Z0-9]*i(?:\.\S+)?$/.test(t.slice(1))) {
        idx = k
        break
      }
    }
    if (idx >= 0) {
      let j = idx + 1
      if (tokens[idx] === '-i' && tokens[j] === '') j++ // macOS: -i '' suffix
      // Skip remaining flags AND -e/-E/-M script values so the trailing
      // non-flag tokens are the real target files (`perl -pi -e 's/x/y/'
      // /etc/hosts` → /etc/hosts, not the script text).
      while (j < tokens.length) {
        const t = tokens[j]
        // -e / -E / -M / -m take a value (script or module); a short cluster
        // ending in `e` (-pe, -ne) also carries the script value after it.
        if (t === '-E' || t === '-M' || t === '-m' || /^-[a-zA-Z]*e$/.test(t)) { j += 2; continue }
        if (t.startsWith('-')) { j++; continue }
        break
      }
      for (; j < tokens.length; j++) {
        if (tokens[j] && !tokens[j].startsWith('-')) paths.push(tokens[j])
      }
    }
  }

  // R1: media/document converter outputs — the trailing non-flag token is the
  // output file (ffmpeg -y -i IN.m4a -ar 16000 OUT.wav; avconvert), while the
  // `-i` INPUT marker must be skipped. `-f null -` probes write nothing.
  // soffice writes converted files into `--outdir DIR`. ffprobe is a pure
  // metadata probe (stdout only) and must NOT get an output extraction —
  // `ffprobe in.mov` would otherwise mis-flag its input as a write target
  // (review T3).
  if (cmd === 'ffmpeg' || cmd === 'avconvert' || cmd === 'afconvert') {
    // Help mode: no output file to extract (`ffmpeg -h long` must not yield
    // a phantom write target — review T3).
    if (tokens.some((t) => t === '-h' || t === '-help' || t === '--help')) return paths
    for (let i = 1; i < tokens.length; i++) {
      const tok = tokens[i]
      if (tok.startsWith('-')) continue
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) continue
      if (tokens[i - 1] === '-i') continue // ffmpeg input marker
      if (tok === '-') continue // stdout sink (`-f null -` probe)
      // Any token carrying a redirection (<, >, &) is not an output file —
      // covers `2>&1`, `2>/dev/null`, `>log` glued forms (review T3).
      if (/[<>]/.test(tok)) continue
      // Last non-flag token is the output; earlier bare tokens are inputs
      // that are not write targets.
      if (i === tokens.length - 1) paths.push(tok)
    }
  }
  if (cmd === 'soffice' || cmd === 'libreoffice') {
    for (let i = 1; i < tokens.length; i++) {
      if (tokens[i] === '--outdir' && tokens[i + 1]) {
        paths.push(tokens[i + 1])
        break
      }
    }
  }
  // pdftotext IN OUT: with an explicit output file the trailing non-flag
  // token is the write target; a bare `pdftotext -layout IN` writes to stdout
  // (only 1 non-flag token → nothing extracted).
  if (cmd === 'pdftotext') {
    const nonFlags = tokens.slice(1).filter(
      (t) => !t.startsWith('-') && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) &&
             !/^(?:\d*[<>]&?\d*|\d*[<>]{1,2}|&[<>])$/.test(t),
    )
    if (nonFlags.length >= 2) paths.push(nonFlags[nonFlags.length - 1])
  }
  // swiftc -o OUT: the compile output path decides write permission.
  if (cmd === 'swiftc' || cmd === 'rustc' || cmd === 'javac' || cmd === 'kotlinc') {
    for (let i = 1; i < tokens.length; i++) {
      if (tokens[i] === '-o' && tokens[i + 1]) {
        paths.push(tokens[i + 1])
        break
      }
    }
  }
  // R1 review N1: converters added to local_exec must expose their output
  // paths or writes to /etc & co. would sail through as local_exec.
  // - magick/convert/qpdf/mutool: positional output = trailing non-flag token
  //   (only when ≥2 non-flag tokens, so a bare input probe stays a read).
  // - gs: -sOutputFile=FILE and -o FILE.
  // - textutil: -output FILE (;-stdout form writes nothing).
  if (cmd === 'magick' || cmd === 'convert' || cmd === 'qpdf') {
    const nonFlags = tokens.slice(1).filter(
      (t) => !t.startsWith('-') && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) &&
             !/[<>]/.test(t) && !/^(?:\d*[<>]&?\d*|\d*[<>]{1,2}|&[<>])$/.test(t),
    )
    if (nonFlags.length >= 2) paths.push(nonFlags[nonFlags.length - 1])
  }
  // mutool: `mutool draw -o OUT in.pdf` — the -o value is the output; the
  // trailing positional is the INPUT. Positional fallback only when -o absent.
  if (cmd === 'mutool') {
    const oIdx = tokens.indexOf('-o')
    if (oIdx !== -1 && tokens[oIdx + 1]) {
      paths.push(tokens[oIdx + 1])
    } else {
      const nonFlags = tokens.slice(1).filter(
        (t) => !t.startsWith('-') && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) &&
               !/[<>]/.test(t) && !/^(?:\d*[<>]&?\d*|\d*[<>]{1,2}|&[<>])$/.test(t),
      )
      if (nonFlags.length >= 2) paths.push(nonFlags[nonFlags.length - 1])
    }
  }
  if (cmd === 'gs') {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      const eq = t.indexOf('=')
      if (t.startsWith('-sOutputFile=') && t.slice(t.indexOf('=') + 1)) {
        paths.push(t.slice(t.indexOf('=') + 1))
      }
      if (t === '-o' && tokens[i + 1]) {
        paths.push(tokens[i + 1])
        break
      }
      void eq
    }
  }
  if (cmd === 'textutil') {
    for (let i = 1; i < tokens.length; i++) {
      if (tokens[i] === '-output' && tokens[i + 1]) {
        paths.push(tokens[i + 1])
        break
      }
    }
  }

  // Archive / sync commands with implicit targets (review-029-r1 F1):
  // without extraction these were classified file_write with 0 targets, and
  // the zero-target protection branch could not enforce a workspace boundary,
  // so `tar -cf /out/…` / `rsync -a S/ OUT/` / `unzip -d OUT …` could write
  // outside the session with no baseline. Extract their real write targets so
  // they flow through the normal per-target boundary + git-baseline checks.
  if (cmd === 'tar') {
    let archivePath: string | undefined
    let changeDir: string | undefined
    let mode = 'create' // tar with no action letter creates an archive
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if (t === '-f' || t === '--file') {
        const v = tokens[i + 1]
        if (v && !v.startsWith('-')) { archivePath = v; i++ }
        continue
      }
      if (t.startsWith('--file=')) { archivePath = t.slice(7); continue }
      if (t === '-C' || t === '--directory') {
        const v = tokens[i + 1]
        if (v) { changeDir = v; i++ }
        continue
      }
      if (t.startsWith('--directory=')) { changeDir = t.slice(12); continue }
      if (t === '-x' || t === '--extract' || t === '--get' || t === '-t' ||
          t === '--list' || t === '-d' || t === '--diff' || t === '--compare') {
        mode = 'extract'
        continue
      }
      if (t === '-c' || t === '--create' || t === '-r' || t === '--append' ||
          t === '-u' || t === '--update') {
        mode = 'create'
        continue
      }
      if (t.startsWith('-') && !t.startsWith('--')) {
        // Short-option cluster: `-czf` contains the `f` marker whose value is
        // the next token; `-C` consumes the next token (or a glued value
        // `-Cdir`) as the directory. An action letter (x/c/t/d/r/u) re-marks
        // the mode.
        const letters = t.slice(1)
        if (letters.includes('C')) {
          const rest = letters.slice(letters.indexOf('C') + 1)
          if (rest) { changeDir = rest }
          else if (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) {
            changeDir = tokens[i + 1]
            i++
          }
        }
        if (letters.includes('x') || letters.includes('t') || letters.includes('d')) mode = 'extract'
        if (letters.includes('c') || letters.includes('r') || letters.includes('u')) mode = 'create'
        if (letters.includes('f') && i + 1 < tokens.length && !tokens[i + 1].startsWith('-') &&
            !letters.includes('C')) {
          archivePath = tokens[i + 1]
          i++
        }
        continue
      }
      // Bare action cluster (GNU/bsd tar traditional form): `tar xf a.tar`
      // carries no `-` before the action letters. Only treat a token as a
      // bare cluster when its FIRST letter is an action letter and the rest
      // are tar option letters — a plain file name like `backup` must not be
      // mistaken for one (review-l5b-0.2.10d B5-1).
      if (!t.startsWith('-') && !archivePath && /^[xctdru][xctdruzjJvhwKmMPWgf]*$/.test(t)) {
        const letters = t
        if (letters.includes('x') || letters.includes('t') || letters.includes('d')) mode = 'extract'
        if (letters.includes('c') || letters.includes('r') || letters.includes('u')) mode = 'create'
        if (letters.includes('f') && i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) {
          archivePath = tokens[i + 1]
          i++
        }
      }
    }
    // `-C DIR` is a real write directory in BOTH create and extract modes —
    // extract mode additionally lands extracted members there. Push it
    // unconditionally (unless pure listing, which writes nothing) so a
    // `tar xf a.tar -C link/../dir` target flows through toAbsolute()/the B4
    // sentinel and the per-target boundary instead of vanishing into a
    // zero-target allow (review-l5b-0.2.10d B5-1).
    if (changeDir) {
      const listing = tokens.some((t) => t === '-t' || t === '--list' ||
        (t.startsWith('-') && !t.startsWith('--') && t.slice(1).includes('t')) ||
        (t === '--to-stdout' || t === '-O') ||
        /^[xctdru][xctdruzjJvhwKmMPWgf]*$/.test(t) && t.includes('t'))
      if (!listing) {
        paths.push(changeDir)
        // create mode with -C also writes the archive file itself
        if (mode === 'create' && archivePath) paths.push(archivePath)
      }
    } else if (mode === 'extract') {
      if (!tokens.some((t) => t === '--to-stdout' || t === '-O')) {
        // Extraction lands in the session cwd; synthesize it so the boundary
        // check can approve only rollback-covered directories. Pure listing
        // (-t/--list) and member-to-stdout (-O/--to-stdout) write nothing and
        // must NOT synthesize a write target (review-029-f1f2 (c)).
        const listing = tokens.some((t) => t === '-t' || t === '--list' ||
          (t.startsWith('-') && !t.startsWith('--') && t.slice(1).includes('t')) ||
          (/^[xctdru][xctdruzjJvhwKmMPWgf]*$/.test(t) && t.includes('t')))
        if (!listing) paths.push(process.cwd())
      }
    } else if (archivePath) {
      paths.push(archivePath)
    }
  }
  if (cmd === 'unzip') {
    // -p / -Z / -l / -q -l print/scan/list modes write nothing to disk.
    if (tokens.some((t) => t === '-p' || t === '-Z' || t === '--pipe' ||
        t === '-l' || t === '--list')) {
      // no write target
    } else {
      let outDir: string | undefined
      for (let i = 1; i < tokens.length; i++) {
        if (tokens[i] === '-d' && tokens[i + 1]) { outDir = tokens[i + 1]; break }
      }
      paths.push(outDir ?? process.cwd())
    }
  }
  if (cmd === 'rsync') {
    // Local-only rsync (remote forms are classified network): the last
    // positional argument is the destination. `--dry-run`/`-n` (including a
    // glued short cluster such as -an) writes nothing.
    const short = tokens.filter((t) => t.startsWith('-') && !t.startsWith('--') && t.length > 1)
    const dryRun = tokens.some((t) => t === '--dry-run' || t === '-n') ||
      short.some((t) => t.slice(1).includes('n'))
    if (!dryRun) {
      const positionals = tokens.slice(1).filter(
        (t) => !t.startsWith('-') && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t),
      )
      if (positionals.length >= 2) {
        const dst = positionals[positionals.length - 1]
        if (!dst.includes(':') && !dst.includes('::')) paths.push(dst)
      }
    }
  }
  if (cmd === '7z' || cmd === '7zz' || cmd === '7za') {
    // Subcommand `x`/`e` extract (to -o<dir> or cwd); `a`/`u`/`d` operate on
    // the archive named as the first positional. `l` (list) and `i` (info)
    // write nothing.
    const sub = (tokens[1] ?? '').toLowerCase()
    if (sub === 'x' || sub === 'e') {
      const o = tokens.find((t) => t.startsWith('-o'))
      if (o && o.length > 2) paths.push(o.slice(2))
      else paths.push(process.cwd())
    } else if ((sub === 'a' || sub === 'u' || sub === 'd')) {
      const first = tokens.slice(2).find((t) => !t.startsWith('-'))
      if (first) paths.push(first)
    }
  }
  if (cmd === 'zip' || cmd === 'zipinfo' || cmd === 'unzip') {
    if (cmd === 'zip') {
      // `zip out.zip files…`: the first positional is the archive being
      // written; `-d`/`-x` are membership filters, not write targets.
      const first = tokens.slice(1).find((t) => !t.startsWith('-'))
      if (first) paths.push(first)
    }
  }

  // B7: zero-target / implicit-target writers whose options the extractor
  // missed — without extraction they classify as file_write with 0 targets and
  // sail through the cwd-rollback allowance into an unprotected path.
  // cpio: `-D DIR` / `--directory DIR` is where extracted members land.
  if (cmd === 'cpio') {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if ((t === '-D' || t === '--directory') && tokens[i + 1]) { paths.push(tokens[i + 1]); break }
      if (t.startsWith('--directory=')) { paths.push(t.slice(12)); break }
    }
  }
  // rar/unrar: `x`/`e` extract into cwd, or `-wDIR`/`-oDIR` when given.
  if (cmd === 'rar' || cmd === 'unrar') {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if (t.startsWith('-w') && t.length > 2) { paths.push(t.slice(2)); break }
      if (t.startsWith('-o') && t.length > 2 && t[2] !== '+' && t[2] !== '-' && t[2] !== 'p') {
        paths.push(t.slice(2))
        break
      }
    }
  }
  // zstd: `-o OUT` separate value (the glued `--output=` form is already
  // covered); without `-o` the input is compressed in place (f → f.zst).
  if (cmd === 'zstd' || cmd === 'unzstd') {
    let hasOut = false
    for (let i = 1; i < tokens.length; i++) {
      if (tokens[i] === '-o' && tokens[i + 1] && !tokens[i + 1].startsWith('-')) {
        paths.push(tokens[i + 1])
        hasOut = true
        break
      }
    }
    if (!hasOut) {
      const first = tokens.slice(1).find((t) => !t.startsWith('-'))
      if (first) paths.push(first)
    }
  }
  // gzip/bzip2/xz/lz4 compress or decompress IN PLACE: the input file is the
  // write target (`gzip /etc/hosts` rewrites it → /etc/hosts.gz). Decompress
  // to stdout (`-dc` / `-d -c`) writes no input file.
  if (cmd === 'gzip' || cmd === 'gunzip' || cmd === 'bzip2' || cmd === 'bunzip2' ||
      cmd === 'xz' || cmd === 'unxz' || cmd === 'lz4' || cmd === 'lzop') {
    const decompressStdout = tokens.some((t, i) =>
      (t === '-dc' || t === '-cd' || t === '--stdout' || t === '--to-stdout') ||
      (t === '-d' && tokens.some((u, j) => j !== i && (u === '-c' || u === '--stdout'))))
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if (t.startsWith('-')) continue
      if (t === '-') continue // stdout sink
      if (t === '<') { i++; continue } // stdin redirect: the next token is a read input, not a write target
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) continue
      if (decompressStdout) continue // input is read, output goes to stdout
      paths.push(t)
    }
  }
  // rar/unrar: `x <archive> [dest-dir]` extracts INTO dest-dir — the trailing
  // non-flag positional is the write destination (`rar x a.rar /srv/out`).
  if (cmd === 'rar' || cmd === 'unrar') {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if (t.startsWith('-')) continue
      if (t.endsWith('.rar') || t.endsWith('.zip') || t.endsWith('.7z')) continue
      paths.push(t)
      break
    }
  }
  // ed/ex/vim open a FILE for editing — the first non-flag positional is the
  // write target (`ed /etc/hosts` can rewrite /etc/hosts; `vim -c ':w /tmp/x'`
  // is separately handled by the editor-injection detector).
  if (cmd === 'ed' || cmd === 'ex' || cmd === 'vim' || cmd === 'vi' || cmd === 'nvim') {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if (t.startsWith('-')) continue
      if (t.startsWith('+') || t === '-') continue
      if (t === '--') continue
      paths.push(t)
      break
    }
  }
  // patch: `-d DIR` chdirs before applying hunks — writes land under DIR.
  if (cmd === 'patch') {
    for (let i = 1; i < tokens.length; i++) {
      if (tokens[i] === '-d' && tokens[i + 1]) { paths.push(tokens[i + 1]); break }
      if (tokens[i].startsWith('--directory=')) { paths.push(tokens[i].slice(12)); break }
    }
  }
  // find -exec <copy-verb> {} <target>: the trailing non-placeholder token is
  // the write destination (`find . -name x -exec cp {} /tmp/out \;`).
  // Deletion verbs keep their existing actionVerbDestructive handling.
  if (cmd === 'find' || cmd === 'fd') {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if (t !== '-exec' && t !== '-execdir' && t !== '-ok' && !t.startsWith('-exec')) continue
      const verb = tokens[i + 1]
      if (!verb || verb.startsWith('-')) continue
      if (!['cp', 'mv', 'tee', 'dd', 'install', 'ln'].includes(verb.toLowerCase())) continue
      for (let j = i + 2; j < tokens.length; j++) {
        const a = tokens[j]
        if (a === ';' || a === '+' || a === '{}') continue
        if (a.startsWith('-')) break
        let k = j
        while (k + 1 < tokens.length) {
          const nxt = tokens[k + 1]
          if (nxt === ';' || nxt === '+' || nxt === '{}') break
          if (nxt.startsWith('-')) break
          k++
        }
        paths.push(tokens[k])
        break
      }
    }
  }

  return paths.filter(
    (p) => p.length > 0 && p !== '/dev/null' && p !== '/dev/stdout',
  )
}

/* ------------------------------------------------------------------ */
/* Interpreter-wrapped argv extraction (R5)                             */
/* ------------------------------------------------------------------ */

/**
 * Pull the wrapped executable out of interpreter inline code so it is
 * classified on its own argv. Covers the bypass forms observed in the
 * production audit: python subprocess/os, node child_process, and
 * process.kill.
 *
 * N3 (review): array/list arguments are reassembled into a full command
 * string and re-classified — `['bash','-c','curl …']` must classify as the
 * inner curl, not as a safe `bash`.
 *
 * Returns null when no wrapped executable is visible (plain print/side-effect
 * code stays local_exec); the caller then checks DANGEROUS_CALL_PATTERNS and
 * fails closed to unknown when a dangerous call site cannot be verified.
 */
/**
 * Shared inline-code extraction (H4): strip environment-style flags that do
 * NOT carry code (--input-type=module/commonjs, --experimental-*, --no-*)
 * BEFORE matching `-c/-e/--eval CODE`. The old regex matched
 * `--input-type=module` as a code-carrying flag, so
 * `node --input-type=module -e "import('child_process')…"` took `-e` as the
 * code and the N2 gate never fired. Both call sites (extractWrappedCommand
 * and the N2 branch in classifyBashCommand) MUST use this same function.
 */
/**
 * Y1: string-aware comment masking (mini-lexer). The previous regex masks
 * (`(^|[^:\w])//…` and `#[^\n]*`) ran on RAW code and any string literal
 * containing `//` or `#` washed out the REST OF THE LINE — e.g.
 * `const s='//'; import {writeFileSync as w} from 'node:fs'; w('/etc/x','a')`
 * collapsed to `const s='//'` and the write sailed through as allow. A
 * comment mask is lexical by nature: strings (single/double/backtick +
 * python triple-quoted), JS regex literals, `//` and node block comments,
 * plus `#` (python, only at line-start / after whitespace) must be told
 * apart. The output keeps line structure (comments become spaces, not
 * newlines) so line-anchored nets see unchanged positions.
 */
function maskComments(code: string, isPython = false): string {
  const out: string[] = []
  let i = 0
  const n = code.length
  const REGEX_PRECEDERS = /[=({\[,;:!&|?+\-*%^~<>]/
  const KW_RE = /\b(?:return|case|typeof|instanceof|in|of|new|delete|void|do|else|yield|await)$/
  while (i < n) {
    const ch = code[i]
    const prev = i > 0 ? code[i - 1] : ''
    // 1) strings — content is APPENDED VERBATIM (the nets must still see
    // 'node:fs', 'fs', mode strings etc.; only comments get blanked).
    if (ch === '"' || ch === "'" || ch === '`') {
      if (ch !== '`' && code.startsWith(ch.repeat(3), i)) {
        const end = code.indexOf(ch.repeat(3), i + 3)
        const stop = end === -1 ? n : end + 3
        out.push(code.slice(i, stop))
        i = stop
        continue
      }
      let j = i + 1
      while (j < n) {
        if (code[j] === '\\') { j += 2; continue }
        if (code[j] === ch) break
        if (ch !== '`' && code[j] === '\n') break // unclosed single-line string
        j++
      }
      const stop = j < n ? j + 1 : n
      out.push(code.slice(i, stop))
      i = stop
      continue
    }
    // 2) JS regex literal — only when the preceding token admits an expression
    if (ch === '/' && i + 1 < n && code[i + 1] !== '/' && code[i + 1] !== '*' &&
      (i === 0 || REGEX_PRECEDERS.test(prev) || KW_RE.test(code.slice(0, i)))) {
      let j = i + 1
      let inClass = false
      while (j < n) {
        if (code[j] === '\\') { j += 2; continue }
        if (code[j] === '[') inClass = true
        else if (code[j] === ']') inClass = false
        else if (code[j] === '/' && !inClass) break
        j++
      }
      const stop = j < n ? j + 1 : n
      out.push(code.slice(i, stop))
      i = stop
      continue
    }
    // 3) node line comment `//` (preceded by non-`:`, non-identifier)
    if (ch === '/' && code[i + 1] === '/' && prev !== ':' && !/[A-Za-z0-9_$]/.test(prev)) {
      while (i < n && code[i] !== '\n') { out.push(' '); i++ }
      continue
    }
    // 4) node block comment `/* … */`
    if (ch === '/' && code[i + 1] === '*') {
      const end = code.indexOf('*/', i + 2)
      const stop = end === -1 ? n : end + 2
      for (; i < stop; i++) out.push(code[i] === '\n' ? '\n' : ' ')
      continue
    }
    // 5) python line comment `#` — in python any `#` outside a string starts
    // a comment (x=1#os.system('id') is legal python); in node `#` is a
    // private-field/shebang marker, so node keeps the whitespace/line-start
    // rule (round-9: no-space inline python comments were still denied).
    if (ch === '#' && (isPython || i === 0 || /\s/.test(prev))) {
      while (i < n && code[i] !== '\n') { out.push(' '); i++ }
      continue
    }
    out.push(ch)
    i++
  }
  return out.join('')
}

function extractInlineCode(rest: string): string {
  let s = rest.trim()
  // N4/J3: strip ALL leading node flags (--flag or --flag=value) before the
  // code-carrying flag. The whitelist of env flags (--input-type=, --no-*,
  // --experimental-*) missed `--experimental-default-type=module` (equals
  // form), reopening the H4 extraction hole via experimental flags. Only
  // leading flags are removed so a `--flag` inside the -e code string is
  // untouched. J3: --eval must NOT be stripped here — `--eval  CODE`
  // (space form) was consumed by the flag loop and the code never
  // extracted; the negative lookahead keeps --eval for the extract match.
  let prev = ''
  while (s !== prev) {
    prev = s
    s = s.replace(/^--(?!=?eval\b)[a-zA-Z-]+(?:=\S+)?\s+/, '')
  }
  const m = s.match(/^(?:-c|-e|--eval)\s*(?:=\s*)?(?:"([^"]*)"|'([^']*)'|(\S+))/)
  return m?.[1] ?? m?.[2] ?? m?.[3] ?? ''
}

function extractWrappedCommand(rest: string, isPython = false): { command: string; kind: 'exec' | 'kill'; shellString?: boolean } | null {
  // python3 -m MODULE … — module mode runs a real command (python3 -m pip
  // install x is package management, python3 -m http.server is a local server).
  const moduleM = rest.match(/^(?:-m|-m=|--module)\s*([A-Za-z0-9_.-]+)/)
  if (moduleM) {
    const mod = moduleM[1]
    if (mod === 'pip' || mod === 'pip3') {
      const args = rest.replace(/^(?:-m|-m=|--module)\s*[A-Za-z0-9_.-]+\s*/, '').trim()
      return { command: `pip3 ${args}`.trim(), kind: 'exec' }
    }
    if (mod === 'http.server' || mod === 'SimpleHTTPServer') {
      return { command: 'python3 http.server', kind: 'exec' }
    }
    return null
  }
  const code = maskComments(extractInlineCode(rest), isPython)
  if (!code) return null

  // Reassemble a python list literal into a shell-ish command string:
  // ['bash','-c','curl http://x'] → bash -c "curl http://x" (each element
  // re-quoted so tokenize keeps embedded spaces inside one token).
  const pyList = code.match(
    /(?:subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*\[\s*)((?:"[^"]*"|'[^']*')(?:\s*,\s*(?:"[^"]*"|'[^']*'))*)\s*\]/,
  )
  if (pyList) {
    const els = pyList[1].match(/["'][^"']*["']/g) ?? []
    // First element is the executable (bare); flags stay bare (a quoted -c
    // would not match the shell `-c` branch); the rest keep quotes so
    // embedded spaces survive tokenize:
    // ['bash','-c','curl http://x'] → bash -c "curl http://x"
    const joined = els.length > 0
      ? [els[0].slice(1, -1), ...els.slice(1).map((e) => {
          const raw = e.slice(1, -1)
          return raw.startsWith('-') ? raw : `"${raw}"`
        })].join(' ')
      : ''
    if (joined) return { command: joined, kind: 'exec' }
  }
  // node spawn/execFile with separate args array: spawn('rm',['-rf','/tmp/x'])
  const ndArgs = code.match(
    /(?:child_process\.)?(?:execFileSync|execFile|spawn|spawnSync)\s*\(\s*["']([^"']+)["']\s*,\s*\[\s*((?:"[^"]*"|'[^']*')(?:\s*,\s*(?:"[^"]*"|'[^']*'))*)\s*\]/,
  )
  if (ndArgs) {
    const els = ndArgs[2].match(/["'][^"']*["']/g) ?? []
    const joined = [ndArgs[1], ...els.map((e) => {
      const raw = e.slice(1, -1)
      return raw.startsWith('-') ? raw : `"${raw}"`
    })].join(' ')
    return { command: joined, kind: 'exec' }
  }
  // python: subprocess.run(['cmd', 'a']) first-element fallback /
  // os.system('cmd') / os.popen('cmd')
  const py = code.match(
    /(?:subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*\[\s*["']([^"']+)["']|os\.(?:system|popen)\s*\(\s*["']([^"']+)["'])/,
  )
  if (py) {
    const cmd = py[1] ?? py[2] ?? ''
    // H1: os.system/os.popen are shell-string execution primitives — the
    // string can hold ANY command and a benign-looking literal cannot be
    // proven safe against concatenation, so mark it shellString and let the
    // caller fail closed even when the inner string classifies local/read.
    const shellString = py[2] != null
    if (cmd) return { command: cmd, kind: 'exec', shellString }
  }
  // python requests/urllib direct network calls in inline code
  const net = code.match(/(?:requests\.(?:get|post|put|delete|head)\s*\(\s*["'](https?:\/\/[^"']+)["']|urllib\.request\.urlopen\s*\(\s*["'](https?:\/\/[^"']+)["'])/)
  if (net) {
    const url = net[1] ?? net[2] ?? ''
    if (url) return { command: `curl ${url}`, kind: 'exec' }
  }
  // node: child_process.execSync('cmd') / exec('cmd') string forms
  const nd = code.match(
    /child_process\.(?:execSync|exec|execFileSync|execFile|spawn|spawnSync)\s*\(\s*["']([^"']+)["']/,
  )
  if (nd) {
    const cmd = nd[1] ?? ''
    if (cmd) return { command: cmd, kind: 'exec' }
  }
  if (/\bprocess\.kill\s*\(/.test(code)) return { command: 'kill', kind: 'kill' }
  return null
}

/**
 * N2 fail-closed gate (review M1/M2 rewrite).
 *
 * The previous regex list had symmetric holes and overreach at once:
 * aliased/indirect call forms (`process['kill'](`, `const f=fetch; f(URL)`,
 * `getattr(s,'run')(...)`, `import subprocess as s; s.run(...)`) sailed
 * through, while plain read-only stdlib calls (`os.getcwd()`,
 * `shutil.which()`, `pathlib.Path('.').exists()`) were denied. This rewrite
 * flips the semantics:
 *
 *  1. When a HIGH-RISK module/capability (subprocess/os/shutil/pathlib/
 *     requests/urllib + node child_process/process/fetch/require) enters the
 *     code block in ANY form (import x as / from x import / require() /
 *     destructure / bare identifier), the block is treated as untrusted:
 *     every call that the extractor did NOT successfully verify is
 *     fail-closed unknown.
 *  2. Provably read-only member calls (os.getcwd, os.path.join, shutil.which,
 *     pathlib.Path(...).exists, process.env, fs.readFileSync, console.log...)
 *     are stripped FIRST so normal agent behavior is not denied (M2).
 *  3. Dynamic/indirect shapes (subscript `m['run'](`, getattr, module alias
 *     member calls, aliased const = fetch/requests..., dangerous from-import
 *     aliases, bare dangerous names, dynamic import/require) all deny.
 */
function hasUnverifiableDanger(code: string, isPython = false): boolean {
  // K3/Y1: mask comments BEFORE any net runs with the string-aware lexer —
  // a `# open('/etc/x','w')` or `// p.write_text('a')` comment must not trip
  // the write nets, and a `'//'`/`'#'`/URL string must NOT wash out the rest
  // of its line (the Y1 fail-open the regex masks introduced).
  code = maskComments(code, isPython)
  // H3b/F3: python may load code from sys.path — a mutation targeting an
  // absolute path or a variable is unverifiable (a pure relative literal
  // stays inside the session cwd and is allowed).
  if (isPython) {
    const sysThreat = pythonSysPathThreat(code)
    if (sysThreat) return true
  }
  // K1/J1-spill: constructor names — literal Path/PurePath plus aliases from
  // `from pathlib import Path as P` (used by the bound-writer net AND the
  // section-0 strict-chain net, so aliased P('/x').write_text( still denies).
  const ctorNames = new Set(['Path', 'PurePath'])
  for (const m of code.matchAll(
    /\bfrom\s+pathlib\s+import\s+(?:Path|PurePath)(?:\s+as\s+(\w+))?\b/g,
  )) {
    if (m[1]) ctorNames.add(m[1])
  }
  const ctorReStr = [...ctorNames].join('|')
  // X1: fs bound to a RENAMED variable (const f=require('fs'), import f from
  // 'node:fs', import * as f, fs/promises submodule) — collected here so the
  // section-0 open-write-mode net and the read-only strip both cover the
  // alias, exactly like the literal `fs.` surface.
  const fsVarAliases = [
    ...(code.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)/g) || []),
    ...(code.matchAll(/\bimport\s+(\w+)\s+from\s*['"](?:node:)?fs(?:\/promises)?['"]/g) || []),
    ...(code.matchAll(/\bimport\s*\*\s*as\s+(\w+)\s+from\s*['"](?:node:)?fs(?:\/promises)?['"]/g) || []),
  ].map((m) => m[1])
  const fsAliasesPart = fsVarAliases.length ? `|${fsVarAliases.join('|')}` : ''
  // Y3: builtins/io import-as aliases (import io as ii; ii.open('/etc/x','w'))
  // — the section-0 open-mode net only matched literal builtins./io./open.
  const biAliases = [
    ...(code.matchAll(/\bimport\s+(?:builtins|io)\s+as\s+(\w+)\b/g) || []),
  ].map((m) => m[1])
  const biAliasesPart = biAliases.length ? `|${biAliases.join('|')}` : ''
  // Round-9 blocker: `from io import open as op; op('/etc/x','w')` (NAME
  // rename, unlike the MODULE renames above) still sailed through — op is a
  // bare call, not a member. Collect from-import open aliases + module
  // aliases + two-hop rebinds (o2=op) into the BARE open nets below; the
  // mode/chain checks keep read-only uses allowed (op('/etc/hosts').read()).
  const openAliases = new Set<string>()
  for (const m of code.matchAll(
    /\bfrom\s+(?:io|builtins)\s+import\s+open(?:\s+as\s+(\w+))?\b/g,
  )) {
    if (m[1]) openAliases.add(m[1])
  }
  for (const m of code.matchAll(/\bimport\s+(?:builtins|io)\s+as\s+(\w+)\b/g)) {
    openAliases.add(m[1])
  }
  for (let i = 0; i < 3; i++) {
    for (const m of code.matchAll(/\b(?:const|let|var)?\s*(\w+)\s*=\s*(\w+)\b/g)) {
      if (openAliases.has(m[2])) openAliases.add(m[1])
    }
  }
  const openAliasesPart = [...openAliases].length ? `|${[...openAliases].join('|')}` : ''
  // 0) UNCONDITIONAL shapes — these are dangerous with or without any import
  // (H3): python builtin open() in a WRITE mode (w/a/x, optional b/+/t)
  // writes arbitrary paths, and Path-family write methods (Path('/etc/x')
  // .write_text(...), aliased P(...) from `from pathlib import Path as P`,
  // or an unimported call) write too. Read-mode open('/etc/hosts').read()
  // and Path(...).resolve()/exists() read-only calls stay allowed (the
  // read-only strip handles those). `[^;)]*` must swallow the path (string
  // or variable); a chr()-obfuscated argument can defeat it, but the literal
  // path is what the gate needs to catch.
  // NOTE: `(?<![\w.$])` on open means `obj.open('w')` (an unrelated object
  // method) is NOT caught (W1 mis-fire); explicit `builtins.open` / `io.open`
  // module-prefix forms ARE caught (real write channels).
  if (new RegExp(`(?<![\\w.$])\\b(?:open${openAliasesPart})\\s*\\([^)]*['"](?:[wax](?:[bt]\\+?|[bt])?|r(?:[bt])?\\+)[bt+]*['"]`).test(code)) return true
  if (new RegExp(`\\b(?:builtins|io${biAliasesPart})\\s*\\.\\s*open\\s*\\([^)]*['"](?:[wax](?:[bt]\\+?|[bt])?|r(?:[bt])?\\+)[bt+]*['"]`).test(code)) return true
  // K1: node fs.open/openSync — the SECOND argument is a mode string, same
  // charset as python open; write modes must deny (they were in the fs
  // read-only strip table, so fs.openSync('/etc/x','w') rode local_exec).
  // X1: the prefix also covers renamed bindings (f=require('fs'), import f
  // from 'node:fs') — their write-mode open must deny exactly like `fs.`.
  if (new RegExp(`\\b(?:fs${fsAliasesPart})\\.open(?:Sync)?\\s*\\([^)]*['"](?:[wax](?:[btx]\\+?|[btx])?|r(?:[bt])?\\+|rs\\+)[btx+]*['"]`).test(code)) return true
  if (/\b(?:require|import)\s*\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)\s*\.\s*open(?:Sync)?\s*\([^)]*['"](?:[wax](?:[btx]\+?|[btx])?|r(?:[bt])?\+|rs\+)[btx+]*['"]/.test(code)) return true
  // J2: open() strict chain with a write method — the no-mode form
  // (open('/etc/x').write('a')) has no mode literal at all, so the mode
  // scan above misses it; the .write call itself is the danger.
  if (new RegExp(`(?<![\\w.$])\\b(?:open${openAliasesPart})\\s*\\([^;)]*\\)\\s*\\.\\s*(?:write|truncate|writelines)\\s*\\(`).test(code)) return true
  if (new RegExp(`\\b(?:builtins|io${biAliasesPart})\\s*\\.\\s*open\\s*\\([^;)]*\\)\\s*\\.\\s*(?:write|truncate|writelines)\\s*\\(`).test(code)) return true
  // W2: the old ANY-identifier chain net (obj.writeFileSync( / Store()
  // .write_text() ) mis-denied unrelated classes — narrow it to Path-family
  // and open constructors only (aliased P(...) included via ctorNames).
  if (new RegExp(`\\b(?:${ctorReStr}|pathlib\\.\\w+|(?<![\\w.$])open)\\s*\\([^;)]*\\)\\s*\\.\\s*(?:write_text|write_bytes|unlink|mkdir|rmdir|rename|replace|touch|chmod|symlink_to|hardlink_to|open|write|truncate|writelines)\\s*\\(`).test(code)) return true

  // 0.5) N3/J2/W1: variables bound from a Path-family constructor or open()
  // get a write-method net. N3's original "constructor present → ANY
  // identifier's write call denies" was W1: it mis-fired on unrelated
  // classes/comments (the block is high-risk already, but an unrelated
  // obj.open('w') should stay local). Instead the BOUND names (+ one-hop
  // alias chains q=p, p already bound) are tracked and only their
  // write-method calls deny. Strict chains Path('x').write_text( are
  // unconditional in section 0; f=open('/etc/x','w'); f.write('a') — the
  // variable-held open — lands here. Runs BEFORE the high-risk check so
  // import-less blocks (f=open(...); f.write('a')) are covered too.
  const boundWriters = new Set<string>()
  const ctorRe = new RegExp(`\\b(?:const|let|var)?\\s*(\\w+)\\s*=\\s*(?:${ctorReStr}|\\w+\\.(?:Path|PurePath))\\s*\\(`, 'g')
  for (const m of code.matchAll(ctorRe)) boundWriters.add(m[1])
  for (const m of code.matchAll(
    /\b(?:const|let|var)?\s*(\w+)\s*=\s*open\s*\([^;)]*\)/g,
  )) boundWriters.add(m[1])
  for (const m of code.matchAll(/\bwith\s+open\s*\([^;)]*\)\s+as\s+(\w+)\b/g)) {
    boundWriters.add(m[1])
  }
  // one-hop alias chains (q = p): iterate a few rounds to chase re-binds.
  for (let i = 0; i < 3; i++) {
    for (const m of code.matchAll(
      /\b(?:const|let|var)?\s*(\w+)\s*=\s*(\w+)\b/g,
    )) {
      if (boundWriters.has(m[2])) boundWriters.add(m[1])
    }
  }
  if (boundWriters.size > 0) {
    for (const n of boundWriters) {
      if (new RegExp(`\\b${n}\\s*\\.\\s*(?:write_text|write_bytes|unlink|mkdir|rmdir|rename|replace|touch|chmod|symlink_to|hardlink_to|open|write|truncate|writelines)\\s*\\(`).test(code)) return true
    }
  }

  // 1) High-risk capability introduced into the block.
  const HIGH_RISK_IMPORT = [
    /\b(?:import|from)\s+(?:subprocess|os|shutil|pathlib|requests|urllib)\b/,
    /\brequire\(\s*['"](?:child_process|fs)['"]\s*\)/,
    /\bimport\(\s*['"](?:child_process|fs)['"]\s*\)/,
    /\bchild_process\b/,
    /\bprocess\b/,
    /\bfetch\b/,
    /\brequire\s*\(/,
    // H4: dynamic import() of ANY module is a capability injection point
    // (import('child_process').then(m=>m.execSync(...))); read-only imports
    // (import('path')) are stripped below by the symmetric import() list.
    /\bimport\s*\(/,
    // N2: ESM static named/default imports of fs / node:fs / node:child_process
    // (import {writeFileSync} from 'node:fs' — never seen by require()/import()
    // nets). child_process is also matched by \bchild_process\b; fs is not.
    // J4: source prefix covers fs/promises (import {cp} from 'node:fs/promises').
    /\bfrom\s*['"]node:(?:fs(?:\/promises)?|child_process)['"]/,
    /\bfrom\s*['"](?:fs(?:\/promises)?|child_process)['"]/,
  ]
  if (!HIGH_RISK_IMPORT.some((re) => re.test(code))) {
    // No high-risk module: keep only the bare dangerous-name net
    // (exec/eval/fetch/spawn...) for inline code without imports.
    // W2/K3: bare-name net must not catch MEMBER calls (Store().writeFileSync
    // ( — unrelated object methods mis-denied). (?<![\w.$]) keeps the net for
    // true bare calls; member forms are adjudicated by the module/binding
    // nets.
    return /(?<![\w.$])\b(?:execSync|execFileSync|spawnSync|spawn|Popen|check_call|check_output|urlopen|kill|system|popen|exec|eval|fetch|new\s+Function|runInNewContext|runInThisContext|writeFileSync|writeFile|appendFileSync|appendFile|rmSync|rm|unlinkSync|unlink|chmodSync|chmod|renameSync|rename|copyFileSync|copyFile|truncateSync|truncate|cp|mkdir|mkdirSync|rmdir|rmdirSync|symlink|symlinkSync|link|linkSync|chown|chownSync|createWriteStream|writeSync|fsyncSync|fsync|fdatasyncSync|fdatasync|futimesSync|futimes|fchmodSync|fchmod|fchownSync|fchown|ftruncateSync|ftruncate)\s*\(/.test(code)
  }

  // 2) Strip provably read-only member calls first (M2).
  const READONLY_MEMBERS = [
    // python os / os.path (read-only surface)
    '\\bos\\.(?:getcwd|listdir|scandir|stat|lstat|fstat|statvfs|access|getenv|getpid|getuid|getgid|geteuid|getegid|uname|environ|sep|name|path|linesep|devnull|curdir|pardir|altsep|extsep|pathsep|get_terminal_size|getloadavg|cpu_count|times|fwalk|walk)\\b',
    '\\bos\\.path\\.(?:join|basename|dirname|exists|isfile|isdir|islink|isabs|abspath|realpath|expanduser|expandvars|splitext|normpath|normcase|relpath|getsize|ismount|samefile|sameopenfile|samefile|commonpath|commonprefix|split|splitdrive|splitroot)\\b',
    '\\bshutil\\.(?:which|disk_usage|get_terminal_size|get_archive_formats|unpack_archive)\\b',
    // pathlib Path construction + read-only methods
    '\\bPath\\s*\\([^;\\n]*?\\)\\s*\\.\\s*(?:exists|is_file|is_dir|is_symlink|is_socket|is_fifo|is_block_device|is_char_device|stat|lstat|resolve|absolute|read_text|read_bytes|glob|rglob|iterdir|name|parent|parents|stem|suffix|suffixes|home|cwd|expanduser|joinpath|with_name|with_suffix|parts|anchor|drive|root|as_posix|as_uri|owner|group|match|samefile)\\b',
    '\\bpathlib\\.\\w+\\s*\\([^)]*\\)\\s*\\.\\s*(?:exists|is_file|is_dir|stat|lstat|resolve|absolute|read_text|read_bytes|glob|rglob|iterdir|name|parent|stem|suffix|home|cwd|expanduser|joinpath|parts|as_posix|samefile)\\b',
    // node process read-only surface
    '\\bprocess\\.(?:env|argv|cwd|pid|ppid|version|platform|arch|title|exitCode|stdin|stdout|stderr|execPath|execArgv|versions|release|uptime|hrtime|memoryUsage)\\b',
    '\\bconsole\\.\\w+\\s*\\(',
    // node fs read-only methods — inline chain (require('fs').readFileSync…)
    // AND variable-held forms (const fs=require('fs'); fs.existsSync(…)) (H7)
    // AND promises-namespace read-only members (N2 symmetric blind spot).
    // X1: the member prefix covers renamed bindings too, or f.readFileSync
    // (f=require('fs')) would be denied by the module-member net.
    '\\b(?:require|import)\\s*\\(\\s*[\'"](?:node:)?fs(?:\\/promises)?["\']\\s*\\)\\s*\\.\\s*(?:readFileSync|readFile|existsSync|statSync|lstatSync|readdirSync|readdir|realpathSync|realpath|readlinkSync|readlink|accessSync|access|fstatSync|openSync|open|createReadStream|watch|watchFile|unwatchFile|constants)\\b',
    `\\b(?:fs${fsAliasesPart})\\s*\\.\\s*(?:readFileSync|readFile|existsSync|statSync|lstatSync|readdirSync|readdir|realpathSync|realpath|readlinkSync|readlink|accessSync|access|fstatSync|openSync|open|createReadStream|watch|watchFile|unwatchFile|constants)\\b`,
    '\\bfs\\.promises\\.(?:readFile|readdir|stat|lstat|realpath|readlink|access|constants)\\b',
    // require('fs') bound to a variable is itself inert — the danger is in
    // the member call, which the fs read/write nets above/below adjudicate.
    '\\b(?:const|let|var)\\s+\\w+\\s*=\\s*require\\s*\\(\\s*[\'"](?:node:)?fs(?:\\/promises)?["\']\\s*\\)',
    // W4: fs destructuring with rename — {readFileSync: r} = require('fs') is
    // read-only too; strip it or r(...) gets denied while the non-renamed
    // destructure is allowed.
    '\\b(?:const|let|var)\\s*\\{\\s*(?:readFileSync|readFile|existsSync|statSync|lstatSync|readdirSync|readdir|realpathSync|realpath|readlinkSync|readlink|accessSync|access|fstatSync|openSync|open|createReadStream|watch|watchFile|unwatchFile|constants)\\s*(?::\\s*\\w+)?\\s*\\}\\s*=\\s*require\\s*\\(\\s*[\'"]fs[\'"]\\s*\\)',
    // read-only dotted import alias: import os.path as op — os.path has no
    // write surface; without stripping, the alias would land in the member
    // net and op.join(...) would mis-deny.
    '\\bimport\\s+os\\.path\\s+as\\s+\\w+\\b',
    // W3: two-level destructure {promises:{readdir}} = require('fs') — the
    // modern read API nests under promises.
    '\\b(?:const|let|var)\\s*\\{\\s*promises\\s*:\\s*\\{\\s*(?:readFile|readdir|stat|lstat|realpath|readlink|access|readFileSync|readdirSync|statSync|lstatSync|realpathSync|readlinkSync|accessSync)\\s*(?::\\s*\\w+)?\\s*\\}\\s*\\}\\s*=\\s*require\\s*\\(\\s*[\'"]fs[\'"]\\s*\\)',
    // node read-only stdlib requires. NOTE: networking modules (http/https/
    // net/tls/dns/worker_threads) are deliberately NOT here — require('http')
    // .request(...) would be stripped whole and ride local_exec. Symmetric
    // import() list for H4 so import('path') stays local while
    // import('http')/import('child_process') trip the dynamic-import net.
    '\\brequire\\s*\\(\\s*[\'"](?:path|util|url|os|events|stream|crypto|zlib|buffer|string_decoder|querystring|timers|assert|perf_hooks|async_hooks|cluster|domain|v8|vm|wasi|repl|readline|module|punycode|sys|trace_events|inspector)["\']\\s*\\)',
    '\\bimport\\s*\\(\\s*[\'"](?:path|util|url|os|events|stream|crypto|zlib|buffer|string_decoder|querystring|timers|assert|perf_hooks|async_hooks|cluster|domain|v8|vm|wasi|repl|readline|module|punycode|sys|trace_events|inspector)["\']\\s*\\)',
  ]
  const stripped = code.replace(new RegExp(READONLY_MEMBERS.join('|'), 'g'), '')

  // X2: unified dangerous-alias registry — fed by the N4 receivers, the d)
  // assignment net, ESM named-import aliases and dangerous from-imports;
  // the transitive closure + call check run at the END of the net section
  // so every alias source is in the set before re-binds are chased.
  const dangerAliases = new Set<string>()

  // 3) Unverified dangerous call shapes.
  // a) subscript member call: m['run']( / process['kill'](
  if (/\b\w+\s*\[\s*['"]\w+['"]\s*\]\s*\(/.test(stripped)) return true
  // b) dynamic getattr
  if (/\bgetattr\s*\(/.test(stripped)) return true
  // c) high-risk module member calls, incl. `import subprocess as s` aliases
  // and DOTTED python imports (`import urllib.request as u` — the .urlopen
  // member call was riding the bare-name net until the W2 lookbehind).
  const moduleAliases = [
    ...(stripped.matchAll(/\bimport\s+[\w.]+(?:\s+as\s+(\w+))?\b/g) || []),
  ].map((m) => m[1]).filter((x): x is string => !!x)
  // K1/W2-spill: fs bound to a RENAMED variable (const f=require('fs'),
  // import f from 'node:fs', import * as f) — the read-only strip removes
  // the binding itself, and with the bare-net lookbehind the member call
  // f.writeFileSync(...) must be adjudicated by the module member net.
  // fsVarAliases itself is collected at the top (section 0 + read-only strip
  // need it before the member net runs).
  const modNames = ['subprocess', 'os', 'shutil', 'pathlib', 'requests',
    'urllib', 'child_process', 'fs', ...moduleAliases, ...fsVarAliases]
  for (const mod of modNames) {
    if (new RegExp(`\\b${mod}\\s*\\.\\s*\\w+\\s*\\(`).test(stripped)) return true
  }
  // N2: fs.promises.<method>( two-hop member net — promises is the modern
  // node write API and the single-hop regex let writeFile/rm/unlink/
  // appendFile/chmod sail through.
  if (/\bfs\.promises\s*\.\s*\w+\s*\(/.test(stripped)) return true
  // N4/K2: destructuring / array-binding / optional-chain receivers of
  // high-risk capabilities. All alias registrations go into one set, then a
  // transitive-closure pass (same as boundWriters) chases two-hop re-binds
  // (const {fetch:f}=globalThis; const hh=f; hh(URL)) — the per-net immediate
  // check let hh through.
  for (const m of stripped.matchAll(
    /\b(?:const|let|var)\s*\{\s*(\w+)\s*(?::\s*(\w+))?\s*\}\s*=\s*(?:(?:globalThis|global|window)|require\([^)]*\))\b/g,
  )) {
    dangerAliases.add(m[2] || m[1])
  }
  // J3: nested destructuring {process:{kill:k}} — one more brace level than
  // the net above; the rename slips the one-level pattern.
  for (const m of stripped.matchAll(
    /\b(?:const|let|var)\s*\{\s*\w+\s*:\s*\{\s*\w+\s*(?::\s*(\w+))?\s*\}\s*\}\s*=\s*(?:(?:globalThis|global|window)|require\([^)]*\))\b/g,
  )) {
    dangerAliases.add(m[1])
  }
  // N4/J3: array binding with the target at ANY position (const [x,f]=
  // [1,globalThis.fetch] — the single-element net anchored [f]= and the
  // comma form [,f] slipped). Every name in the left bracket is checked.
  // K2: the right side may reach the capability through a ROOT variable
  // (const g=globalThis; const [f]=[g.fetch]) — roots = the literals plus
  // any identifier assigned from them.
  const rootNames = new Set(['globalThis', 'global', 'window'])
  for (const m of stripped.matchAll(
    /\b(?:const|let|var)\s*(\w+)\s*=\s*(?:globalThis|global|window)\b/g,
  )) rootNames.add(m[1])
  // Y3: root-name closure (const g=globalThis; const h=g; h.fetch(URL)) —
  // two hops through plain re-binds.
  for (let i = 0; i < 3; i++) {
    for (const m of stripped.matchAll(
      /\b(?:const|let|var)?\s*(\w+)\s*=\s*(\w+)\b/g,
    )) {
      if (rootNames.has(m[2])) rootNames.add(m[1])
    }
  }
  const rootRe = [...rootNames].join('|')
  for (const m of stripped.matchAll(
    new RegExp(`\\b(?:const|let|var)\\s*\\[\\s*([^\\]]*)\\s*\\]\\s*=\\s*\\[\\s*[^\\]]*\\b(?:${rootRe})\\s*\\.\\s*(?:fetch|process)\\b`, 'g'),
  )) {
    for (const name of (m[1].match(/\w+/g) ?? [])) dangerAliases.add(name)
  }
  // d) aliased assignment calls: const f = fetch; f(URL). The RHS may be a
  // member expression (globalThis.fetch, globalThis.process.kill, any dotted
  // chain) — a bare-identifier-only RHS candidate was the hole. N4 adds the
  // optional-chain form globalThis?.fetch; J3 adds multi-hop optional chains
  // (globalThis?.process?.kill), subscript receivers (globalThis['fetch'])
  // and .call/.apply borrow (f.call(globalThis, URL)).
  for (const m of stripped.matchAll(
    /\b(?:const|let|var)?\s*(\w+)\s*=\s*(?:(?:globalThis|global|window)\s*\.\s*)?(?:fetch|requests\.\w+|subprocess\.\w+|child_process\.\w+|process\.\w+|require\([^)]*\)|import\([^)]*\)|exec|eval|spawn|execSync|execFileSync|\w+(?:\?\.\w+|\.\w+)+|\w+\s*\[\s*[^\]\s]*['"]\w+['"][^\]\s]*\s*\])(?=[^$\w]|$)/g,
  )) {
    if (m[1]) dangerAliases.add(m[1])
  }
  // J3: .call/.apply borrow WITHOUT an assignment — globalThis.fetch.call(
  // globalThis, URL) rides a member expression, so no alias net ever sees
  // `f(`. High-risk receiver + call/apply.
  if (/\b(?:(?:globalThis|global|window)\s*\.\s*)?(?:fetch|requests\.\w+|subprocess\.\w+|child_process\.\w+|process\.\w+|require\([^)]*\)|import\([^)]*\))\s*\.\s*(?:call|apply)\s*\(/.test(stripped)) return true
  // e) dangerous from-import aliases: from shutil import rmtree as r; r(...)
  // H3.3/H6: constrain by SOURCE module — an import name from a high-risk
  // module (subprocess/os/shutil/pathlib/requests/urllib) is a dangerous
  // alias no matter how generic the name (chmod/remove from os, get from
  // requests). pathlib Path is handled by the write-method net above
  // (construction itself is read-only).
  const DANGEROUS_IMPORT_NAMES = new Set([
    'run', 'call', 'check_call', 'check_output', 'Popen', 'system', 'popen',
    'urlopen', 'exec', 'eval', 'spawn', 'execSync', 'execFileSync',
    'spawnSync', 'kill', 'rmtree', 'remove', 'unlink', 'unlinkSync',
    'chmod', 'chmodSync', 'writeFile', 'writeFileSync', 'appendFile',
    'appendFileSync', 'rename', 'renameSync', 'symlink', 'symlinkSync',
    'copyfile', 'move', 'shutil', 'rm', 'truncate', 'link', 'linkSync',
    'cp', 'mkdir', 'mkdirSync', 'rmdir', 'rmdirSync', 'chown', 'chownSync',
    'createWriteStream', 'writeSync', 'fsync', 'fsyncSync', 'fdatasync',
    'futimes', 'fchmod', 'fchmodSync', 'fchown', 'fchownSync', 'ftruncate',
  ])
  const HIGH_RISK_SOURCES = new Set(
    ['subprocess', 'os', 'shutil', 'pathlib', 'requests', 'urllib'],
  )
  // W3: names that are read-only no matter their source (from os import
  // getcwd; from shutil import which; from os.path import join — the same
  // operation as their dotted forms, which are allowed). Judge by ORIGINAL
  // name so `getcwd as g` still allows.
  const FROM_IMPORT_READONLY = new Set([
    'getcwd', 'getenv', 'listdir', 'scandir', 'stat', 'lstat', 'fstat',
    'statvfs', 'access', 'environ', 'getpid', 'getuid', 'getgid', 'geteuid',
    'getegid', 'uname', 'sep', 'name', 'path', 'linesep', 'devnull',
    'get_terminal_size', 'getloadavg', 'cpu_count', 'times', 'fwalk', 'walk',
    'which', 'disk_usage', 'get_archive_formats', 'unpack_archive',
    'join', 'basename', 'dirname', 'exists', 'isfile', 'isdir', 'islink',
    'isabs', 'abspath', 'realpath', 'expanduser', 'expandvars', 'splitext',
    'normpath', 'normcase', 'relpath', 'getsize', 'ismount', 'samefile',
    'sameopenfile', 'commonpath', 'commonprefix', 'split', 'splitdrive',
    'splitroot',
  ])
  // J1/K1/X2: ESM named imports with `as` aliases — import {writeFileSync as
  // w} from 'node:fs' renames the primitive, so the bare-name net (keyed on
  // ORIGINAL names) misses w(...). Policy flip (K1): a named import from
  // fs/child_process NOT on the read table is DANGEROUS (fail-closed, so
  // future write APIs can't silently sail through) — register the alias in
  // dangerAliases (X2) instead of inline-checking, so `const w2=w; w2(...)`
  // is caught by the transitive closure. open/openSync are TWO-SIDED: their
  // second arg is a MODE string, so judge by the mode argument — 'w'/'a'/
  // 'r+' deny, read modes and no-mode (default 'r') stay allowed (X1).
  const FS_READ_PRIMS = new Set([
    'readFileSync', 'readFile', 'existsSync', 'statSync', 'lstatSync',
    'readdirSync', 'readdir', 'realpathSync', 'realpath', 'readlinkSync',
    'readlink', 'accessSync', 'access', 'fstatSync', 'createReadStream',
    'watch', 'watchFile', 'unwatchFile', 'constants',
  ])
  const OPEN_MODE_RE =
    /['"](?:[wax](?:[btx]\+?|[btx])?|r(?:[bt])?\+|rs\+)[btx+]*['"]/
  for (const m of stripped.matchAll(
    /\bimport\s*\{\s*([^}]+)\s*\}\s*from\s*['"](?:node:)?(?:fs(?:\/promises)?|child_process)['"]/g,
  )) {
    for (const spec of m[1].split(',')) {
      const sm = spec.match(/\s*(\w+)(?:\s+as\s+(\w+))?\s*/)
      if (!sm) continue
      const orig = sm[1]
      const alias = sm[2] || sm[1]
      if (orig === 'open' || orig === 'openSync') {
        if (new RegExp(`\\b${alias}\\s*\\([^)]*${OPEN_MODE_RE.source}`).test(stripped)) return true
        continue // read-mode / no-mode open stays allowed
      }
      if (!FS_READ_PRIMS.has(orig)) dangerAliases.add(alias)
    }
  }
  for (const m of stripped.matchAll(
    /\bfrom\s+([\w.]+)\s+import\s+(\w+)(?:\s+as\s+(\w+))?\b/g,
  )) {
    const src = m[1]
    const orig = m[2]
    const alias = m[3] || m[2]
    // N1: source may be a dotted submodule (urllib.request) — judge by its
    // FIRST segment so `from urllib.request import urlopen as u` is covered
    // (the single-\w+ source group silently dropped the dotted source).
    const srcRoot = src.split('.')[0]
    if (src === 'pathlib' && (orig === 'Path' || orig === 'PurePath')) {
      continue // write-method net above adjudicates; construction is read-only
    }
    if (FROM_IMPORT_READONLY.has(orig)) continue
    // X2: register (not inline-check) so a re-bind one hop out is chased:
    // `from os import system as s; s2=s; s2('id')` must deny.
    if (HIGH_RISK_SOURCES.has(srcRoot) || DANGEROUS_IMPORT_NAMES.has(orig)) {
      dangerAliases.add(alias)
    }
  }
  // X2/K2: transitive closure + unified alias-call check — runs AFTER every
  // alias source (N4 receivers, d) assignments, from-imports, ESM named
  // imports) has registered, so two-hop re-binds of ANY source deny.
  // Y3: the call shape covers direct calls, (w)(…), [w][0](…), tagged
  // templates (e`id`) and .call/.apply borrows.
  for (let i = 0; i < 3; i++) {
    for (const m of stripped.matchAll(
      /\b(?:const|let|var)?\s*(\w+)\s*=\s*(\w+)\b/g,
    )) {
      if (dangerAliases.has(m[2])) dangerAliases.add(m[1])
    }
  }
  for (const n of dangerAliases) {
    if (new RegExp(
      `\\b${n}\\s*(?:\\.\\s*(?:call|apply))?\\s*\\(|\\(\\s*${n}\\s*\\)\\s*\\(|\\[\\s*${n}\\s*\\]\\s*\\[\\s*0\\s*\\]\\s*\\(|\\b${n}\\s*\``,
    ).test(stripped)) return true
  }
  // f) bare dangerous call names (any receiver). N2/J4: write-file primitives
  // (incl. promises-specific cp/mkdir/rmdir/symlink/link/chown) join the net
  // so ESM named imports (import {writeFileSync} from 'node:fs') and any
  // unverified write-file call deny.
  if (/(?<![\w.$])\b(?:execSync|execFileSync|spawnSync|spawn|Popen|check_call|check_output|urlopen|kill|system|popen|exec|eval|fetch|new\s+Function|runInNewContext|runInThisContext|writeFileSync|writeFile|appendFileSync|appendFile|rmSync|rm|unlinkSync|unlink|chmodSync|chmod|renameSync|rename|copyFileSync|copyFile|truncateSync|truncate|cp|mkdir|mkdirSync|rmdir|rmdirSync|symlink|symlinkSync|link|linkSync|chown|chownSync|createWriteStream|writeSync|fsyncSync|fsync|fdatasyncSync|fdatasync|futimesSync|futimes|fchmodSync|fchmod|fchownSync|fchown|ftruncateSync|ftruncate)\s*\(/.test(stripped)) return true
  // K2: root-variable member calls (const g=globalThis; g.fetch(URL)) —
  // root names act as a capability namespace, same as module aliases.
  for (const r of rootNames) {
    if (new RegExp(`\\b${r}\\s*\\.\\s*(?:fetch|process\\.\\w+|require\\s*\\(|import\\s*\\()`).test(stripped)) return true
  }
  // g) dynamic import/require
  if (/\b(?:require|import)\s*\(/.test(stripped)) return true

  return false
}

/* ------------------------------------------------------------------ */
/* Sensitive-path read restriction (denyReadPaths)                     */
/* ------------------------------------------------------------------ */

export function expandHome(p: string): string {
  let out = p
  if (out === '~') out = process.env.HOME ?? out
  else if (out.startsWith('~/')) out = `${process.env.HOME ?? ''}${out.slice(1)}`
  // $HOME / ${HOME} — expand for sensitive-read matching. Bash expands these
  // before opening the file, so `cat $HOME/.ssh/id_rsa` must be treated like
  // `cat ~/.ssh/id_rsa` (adversarial GAP fixed in 0.2.3).
  const home = process.env.HOME ?? ''
  out = out.replace(/\$HOME(?=\/|$)/g, home)
  out = out.replace(/\$\{HOME\}(?=\/|$)/g, home)
  return out
}

/**
 * B4 (review-l5b-0.2.10b): a lexical `..` that crosses a symlink component is
 * applied by the kernel to the link's REAL target, not to the lexical link
 * path. Any absolute-ization / lexical collapse of such a path would fold
 * `elink/../x` back inside the workspace and allow a write that the OS lands
 * outside it. Detect that pattern on the RAW path (before any collapse) and
 * fail closed. `baseDir` must be the directory the relative path is resolved
 * against (the `cd`-tracked base, not necessarily process.cwd()).
 */
export function hasDotdotAcrossSymlink(
  p: string,
  baseDir: string = process.cwd(),
): boolean {
  // NOTE: use plain string concatenation, not path.join/resolve — join()
  // normalises `..` away and the pattern below would never be seen.
  const abs = p.startsWith('/') ? p : baseDir + '/' + p
  // Fast path: no lexical `..` component means nothing can be crossed — most
  // paths have none, and this avoids per-component lstat on the hot path.
  if (!/\.\.(?:\/|$)/.test(abs)) return false
  const parts = abs.split('/')
  let prefix = ''
  const linkStack: boolean[] = []
  for (const part of parts) {
    if (part === '' || part === '.') continue
    if (part === '..') {
      if (linkStack.some(Boolean)) return true
      linkStack.pop()
      prefix = prefix.slice(0, prefix.lastIndexOf('/'))
      continue
    }
    prefix = prefix === '' ? '/' + part : prefix + '/' + part
    let isLink = false
    try {
      isLink = lstatSync(prefix).isSymbolicLink()
    } catch (e) {
      // ENOENT means the component does not exist (and cannot be a link);
      // any other error (EACCES etc.) is fail-closed: treat the component as
      // a link so a `..` after it is denied rather than silently collapsed.
      isLink = (e as NodeJS.ErrnoException).code !== 'ENOENT'
    }
    linkStack.push(isLink)
  }
  return false
}

/** Absolute-ize a possibly-relative path for deny-prefix matching. */
function toAbsolute(path: string, baseDir: string = process.cwd()): string {
  // B4 check runs FIRST, on every form, before any collapse/expansion can
  // happen: absolute paths, `~`, `$HOME` and plain relative paths all cross
  // the same raw-path guard. `expandHome` is applied first for `~`/`$HOME`
  // so the guard lstat's a real path (a literal `~/` prefix has no lstat
  // target of its own).
  if (path.startsWith('~')) {
    const e = expandHome(path)
    if (hasDotdotAcrossSymlink(e)) return '/.tmguard-dotdot-escape'
    return e
  }
  if (/^\$(?:HOME|\{HOME\})(\/|$)/.test(path)) {
    const e = expandHome(path)
    if (hasDotdotAcrossSymlink(e)) return '/.tmguard-dotdot-escape'
    return e
  }
  if (path.startsWith('/')) {
    if (hasDotdotAcrossSymlink(path)) return '/.tmguard-dotdot-escape'
    return path
  }
  if (hasDotdotAcrossSymlink(path, baseDir)) return '/.tmguard-dotdot-escape'
  return resolve(baseDir, path)
}

// Loopback hosts that count as local development targets, not external egress.
const LOOPBACK = /\[::1\]|::1(?=[:\s"'`]|$)|127\.0\.0\.1|localhost(?:\.[a-z]+)*|0\.0\.0\.0/i

/**
 * True when every network target in a command resolves to loopback.
 * Matches bare `curl localhost:3000` and URL forms; a single external URL or
 * host anywhere in the command makes it a real network command again.
 */
/**
 * Exact loopback-host check (R2 hardening, review N5). Rejects substring
 * masquerades: `localhost.evil.example.invalid`, `127.0.0.1.nip.io`,
 * `evillocalhost` must NOT be treated as loopback. Covers IPv6 literals
 * (bracketed or not, full ::1 expansion, IPv4-mapped ::ffff:127.0.0.1 /
 * ::ffff:7f00:1) and 127/8 IPv4 (dotted and shorthand 127.1).
 */
function isLoopbackHost(raw: string): boolean {
  const t = raw.toLowerCase().replace(/^\[|\]$/g, '')
  if (t === 'localhost' || t === 'localhost.localdomain') return true
  if (t.includes(':')) {
    if (t === '::1' || t === '0:0:0:0:0:0:0:1') return true
    const mapped = t.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (mapped) return isLoopbackHost(mapped[1])
    const hex = t.match(/^::ffff:([0-9a-f:]+)$/)
    if (hex) {
      // Hex groups may be compressed (7f00:1) — pad each group to 4 hex
      // digits before joining so the 32-bit value is right.
      const full = hex[1].split(':').map((g) => g.padStart(4, '0')).join('')
      const n = parseInt(full, 16)
      return ((n >>> 24) & 0xff) === 127
    }
    return false
  }
  const parts = t.split('.')
  if (parts.length >= 2 && parts.length <= 4 && parts.every((p) => /^\d+$/.test(p) && Number(p) <= 255)) {
    return parts[0] === '127'
  }
  return false
}

function isLoopbackOnly(rest: string): boolean {
  // No LOOPBACK prefilter: exact host checks below are the single source of
  // truth, and the prefilter's substring match would wrongly exclude valid
  // full-form IPv6 (0:0:0:0:0:0:0:1) while including masquerades.
  // Any explicit http(s) URL to a non-loopback host → external.
  const urls = rest.match(/https?:\/\/[^\s"'`]+/gi) ?? []
  if (urls.length === 0) {
    // Bare host:port / host forms (curl 127.0.0.1:8080) — exact-check the
    // first token's host, so `curl 127.0.0.1.evil.example.invalid` is not
    // exempted by substring matching.
    const bare = rest.trim().split(/\s+/)[0]?.split(/[\/?#]/)[0].replace(/:\d+$/, '') ?? ''
    return isLoopbackHost(bare)
  }
  for (const u of urls) {
    // Split on /?# so an IPv6 literal keeps its brackets, then drop :port.
    const host = u.replace(/^https?:\/\//i, '').split(/[\/?#]/)[0].replace(/:\d+$/, '')
    if (!isLoopbackHost(host)) return false
  }
  return true
}

/**
 * True when a curl command is a strict read-only download: a single GET to
 * one http(s) URL, output written to a local file (-o/--output/-O/
 * --remote-name), and no request body, upload, custom method,
 * auth/credential header, TLS-bypass, proxy, destination override or
 * referer flag. This is an ALLOWLIST of known-benign flags, not a
 * denylist: every unlisted flag or token denies, so an undiscovered option
 * (proxy short form, cookie/oauth2 credentials, TLS weakening,
 * --resolve/--connect-to, HEAD) cannot slip through. Anything else must
 * remain network/deny.
 */
// Strict-GET download allowlist. Only flags that provably cannot change the
// method, destination, credentials or TLS trust are permitted; every
// unlisted flag or token denies. This retires the whole "undiscovered flag
// allowed" class that a denylist had (proxy short form, cookie/oauth2
// credentials, TLS weakening, --resolve/--connect-to destination override,
// HEAD) and matches the plugin's default-deny stance.

// Short flags that take no value and are benign for a GET download.
const CURL_BENIGN_SHORT = new Set([
  's', // silent
  'S', // show-error
  'L', // follow redirects
  'f', // fail on HTTP error
  'g', // globoff (disable URL globbing)
  'q', // disable (do not read curlrc)
  'N', // no output buffering
  'v', // verbose
  '#', // progress bar
  '4', // IPv4 only
  '6', // IPv6 only
])
// Short flags that take a value (the value is consumed, not re-checked).
const CURL_VALUE_SHORT = new Set([
  'r', // range
  'm', // max-time
  'z', // time-cond
  'C', // continue-at (resume)
  'Y', // speed-limit
  'y', // speed-time
])
// Long flags that take no value and are benign.
const CURL_BENIGN_LONG = new Set([
  '--silent', '--show-error', '--location', '--fail', '--fail-early',
  '--fail-with-body', '--globoff', '--disable', '--no-buffer', '--verbose',
  '--progress-bar', '--ipv4', '--ipv6', '--compressed', '--tr-encoding',
  '--remote-name', '--remote-name-all', '--no-remote-name',
  '--no-progress-meter', '--no-clobber', '--retry-all-errors',
  '--retry-connrefused', '--help', '--version',
])
// Long flags that take a value (the value is consumed, not re-checked).
const CURL_VALUE_LONG = new Set([
  '--range', '--max-time', '--time-cond', '--continue-at',
  '--speed-limit', '--speed-time', '--limit-rate', '--connect-timeout',
  '--retry', '--retry-delay', '--retry-max-time', '--output',
  '--max-filesize',
])

// A -o/--output target that is not a real file: `-` (stdout), a /dev
// pseudo-device, or a value carrying shell metacharacters (a pipe, an
// operator/command substitution, or bash process substitution `>(sh)`).
// The response then reaches a shell (`curl -o - URL | sh`,
// `curl -o >(sh) URL`) instead of a rollbackable local file, so it must
// not be treated as a strict-GET download.
const NON_FILE_TARGET_CHARS = /[|&;<>()$`]/
function isNonFileOutput(value: string): boolean {
  if (value === '-') return true
  // Normalise a doubled/leading-slash prefix: POSIX treats `//dev/stdout`
  // as `/dev/stdout`, so it must still hit the pseudo-device test and be
  // classified as a non-file output rather than a rollbackable file.
  const norm = value.startsWith('//') ? value.replace(/^\/+/, '/') : value
  if (norm.startsWith('/dev/')) return true
  if (NON_FILE_TARGET_CHARS.test(value)) return true
  return false
}

function isReadonlyCurlDownload(rest: string): boolean {
  // Quote-strip BEFORE flag detection: `curl "-HX:y"` / `curl "--insecure"`
  // are shell syntax — curl receives the bare option. A leading quote would
  // make the token look like a non-option and hide the flag entirely.
  const tokens = rest
    .split(/\s+/)
    .map((t) => t.replace(/^['"]|['"]$/g, ''))
    .filter(Boolean)

  let urlCount = 0
  let outputCount = 0

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]

    // Long option: exact name match (no curl-style abbreviation, which could
    // otherwise be ambiguous). Value is either inline after `=` or the next
    // token, and is consumed without re-checking.
    if (tok.startsWith('--')) {
      const eq = tok.indexOf('=')
      const name = eq === -1 ? tok : tok.slice(0, eq)
      if (CURL_BENIGN_LONG.has(name)) {
        if (eq !== -1) return false
        // --remote-name / --remote-name-all are the long form of -O: the
        // response is written to a server-named local file, so they supply
        // the required output.
        if (name === '--remote-name' || name === '--remote-name-all') outputCount++
        continue
      }
      if (CURL_VALUE_LONG.has(name)) {
        let val: string
        if (eq !== -1) {
          val = tok.slice(eq + 1)
        } else {
          if (i + 1 >= tokens.length) return false
          val = tokens[i + 1]
          i++
        }
        if (name === '--output') {
          if (isNonFileOutput(val)) return false
          outputCount++
        }
        continue
      }
      return false
    }

    // Short option: walk the cluster letter by letter. A bare benign flag
    // (`-s`, `-sfL`) only advances; a value-taking flag (`-r`, `-m`)
    // consumes the rest of the token or the next token; `-o` consumes the
    // filename; `-O` takes no value. Any unlisted letter denies — this is
    // what catches `-x` (proxy), `-b`/`-c` (cookies), `-A` (UA),
    // `-E`/`-K` (cert/config), `-I` (HEAD), `-X`/`-d`/`-H` etc.
    if (tok.startsWith('-') && tok.length > 1) {
      const chars = tok.slice(1)
      let j = 0
      while (j < chars.length) {
        const ch = chars[j]
        if (ch === 'o') {
          let outFile: string
          if (j + 1 < chars.length) {
            outFile = chars.slice(j + 1)
          } else {
            if (i + 1 >= tokens.length) return false
            outFile = tokens[i + 1]
            i++
          }
          if (isNonFileOutput(outFile)) return false
          outputCount++
          j = chars.length
          break
        }
        if (ch === 'O') {
          outputCount++
          j++
          continue
        }
        if (CURL_BENIGN_SHORT.has(ch)) {
          j++
          continue
        }
        if (CURL_VALUE_SHORT.has(ch)) {
          if (j + 1 >= chars.length) {
            if (i + 1 >= tokens.length) return false
            i++
          }
          j = chars.length
          break
        }
        return false
      }
      continue
    }

    // Exactly one http(s) URL.
    if (/^https?:\/\/[^\s"'`]+/i.test(tok)) {
      urlCount++
      continue
    }

    // Any other bare token (a stray host, filename, scheme-less URL) denies.
    return false
  }

  return urlCount === 1 && outputCount >= 1
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
    // dd input file: `dd if=~/.ssh/id_rsa of=x` READS the key even though dd
    // is classified as a write command. `if=` is not an env assignment (which
    // the next check would otherwise skip): extract it as a read path.
    if (cmd === 'dd' && tok.startsWith('if=')) {
      paths.push(tok.slice(3))
      continue
    }
    if (tok.startsWith('-')) {
      // Glued long/short option: `--file=~/.ssh/id_rsa` / `-f=/x`. The value
      // after `=` may carry a path (grep -f, sort --output=, tar --files-from,
      // diff --from-file, …). Extract it when it looks path-like.
      const eq = tok.indexOf('=')
      if (eq > 1) {
        const val = tok.slice(eq + 1)
        if (val && (val.startsWith('/') || val.startsWith('~') || val.includes('/'))) {
          paths.push(val)
        }
      }
      continue
    }
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
/**
 * Normalize a path for sensitive-prefix matching:
 * - collapse `//` runs (shell/FS treat them as `/`)
 * - resolve `.` and `..` segments (shell resolves them before opening)
 * - lowercase (macOS default APFS is case-insensitive; `.SSH` == `.ssh`)
 * Keeps a leading `/`. Non-sensitive callers should not use this.
 *
 * Exported so the write-side protection (tm.isPathProtected) applies the same
 * normalization as the read side (denyHitFor).
 */
export function normalizeForMatch(p: string): string {
  const collapsed = p.replace(/\/{2,}/g, '/')
  const out: string[] = []
  for (const part of collapsed.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') {
      out.pop()
      continue
    }
    out.push(part)
  }
  return '/' + out.join('/').toLowerCase()
}

function denyHitFor(paths: string[], denyReadPaths: string[]): string | null {
  if (denyReadPaths.length === 0) return null
  const prefixes = denyReadPaths.map((p) => normalizeForMatch(expandHome(p)))
  for (const p of paths) {
    const abs = normalizeForMatch(toAbsolute(p))
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

/** PYTHONPATH/PYTHONSTARTUP assignment whose value contains an absolute path
 * (or a variable / substitution) makes a python interpreter load code from an
 * unverifiable location — fail closed. A pure relative literal ("./lib", "lib",
 * ".") stays inside the session cwd and is allowed. */
function taintedPathEnv(assignTok: string): string | null {
  const m = assignTok.match(/^(PYTHONPATH|PYTHONSTARTUP|PYTHONHOME)=(.+)$/)
  if (!m) return null
  const value = m[2]!
  if (value === '') return null
  if (/\$/.test(value) || /`/.test(value) || /["']/.test(value)) {
    return `unverifiable ${m[1]} value`
  }
  for (const seg of value.split(':')) {
    if (seg.startsWith('/')) {
      return `${m[1]} points outside cwd (${seg.slice(0, 40)})`
    }
  }
  return null
}

/** sys.path mutation (insert/append/extend/index-assign/plain assign) that
 * loads python code from an absolute path or a non-literal argument — the
 * injected module is unverifiable. A pure relative literal stays inside the
 * session cwd and is allowed. */
function pythonSysPathThreat(code: string): string | null {
  let m: RegExpExecArray | null
  const mut = /\bsys\s*\.\s*path\s*\.\s*(?:insert|append|extend)\s*\(([^)]*)\)/g
  while ((m = mut.exec(code))) {
    const args = m[1]!
    const pathArg = args.includes(',')
      ? args.slice(args.indexOf(',') + 1).trim()
      : args.trim()
    const lit = pathArg.match(/^['"]([^'"]*)['"]$/)
    if (!lit) return `sys.path mutation with non-literal argument: ${pathArg.slice(0, 40)}`
    const p = lit[1]!
    if (p.startsWith('/') || p.includes(':')) return `sys.path points outside cwd: ${p.slice(0, 40)}`
  }
  const assign = /\bsys\s*\.\s*path\s*(?:\[[^\]]*\]\s*)?=\s*['"]([^'"]*)['"]/g
  while ((m = assign.exec(code))) {
    if (m[1]!.startsWith('/')) return `sys.path assignment outside cwd: ${m[1]!.slice(0, 40)}`
  }
  if (/\bsys\s*\.\s*path\s*=\s*(?!['"])/.test(code)) {
    return 'sys.path assigned from a non-literal'
  }
  return null
}

function classifySingleCommand(command: string, denyReadPaths: string[] = []): ClassifyResult {
  let trimmed = command.trim()
  // Strip one or more leading '(' (subshell groups) so `(lsof -ti:3000 | xargs …)`
  // is classified by its inner command, not rejected as unknown "(lsof …".
  while (trimmed.startsWith('(')) trimmed = trimmed.slice(1).trim()
  if (trimmed.endsWith(')')) trimmed = trimmed.slice(0, -1).trim()
  if (!trimmed) {
    return { category: 'read', reason: 'Empty command', targetPaths: [] }
  }

  // R14 W1: bare leading env-assignment prefixes (`FOO=bar python3 -c "…"`)
  // are shell wrappers — strip them and classify the inner command so the
  // -c danger/sensitive scans still apply (previously firstWord was FOO=bar
  // and no branch matched the inner interpreter).
  if (/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/.test(trimmed)) {
    const envValues: string[] = []
    let inner = trimmed
    while (/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/.test(inner)) {
      const em = inner.match(/^[A-Za-z_][A-Za-z0-9_]*=(\S+)\s+/)
      if (em) {
        // H3b/F3: PYTHONPATH / PYTHONSTARTUP pointing outside cwd loads
        // interpreter code from an unverifiable location.
        const taint = taintedPathEnv(inner.match(/^[A-Za-z_][A-Za-z0-9_]*=\S+/)?.[0] ?? '')
        if (taint) {
          return {
            category: 'unknown',
            reason: `interpreter code load via env (${taint})`,
            targetPaths: [],
          }
        }
        envValues.push(em[1])
      }
      inner = inner.replace(/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/, '').trim()
    }
    if (inner && inner !== trimmed) {
      // H1: GNU compressors read external-program options from env
      // ($GZIP, $XZ_DEFAULTS, $BZIP2, $GZIP_OPT). If an env value smuggles
      // --use-compress-program / -I onto a compressor command, fail closed.
      const first = inner.split(/\s+/)[0] ?? ''
      if (/^(gzip|gunzip|xz|unxz|bzip2|bunzip2|lz4|lzma|unlzma|lzop)\b/.test(first) &&
          envValues.some((v) => /compress-program/i.test(v) || /(?:^|\s)-[a-z0-9]*I[A-Za-z0-9_.=]*/.test(v))) {
        return {
          category: 'unknown',
          reason: `compressor external program via env (unverifiable): ${trimmed}`,
          targetPaths: [],
          mutates: true,
        }
      }
      return classifySingleCommand(inner, denyReadPaths)
    }
  }

  // command / builtin / time are launch or keyword prefixes, not standalone read
  // commands: strip the prefix and classify the actual tail instead of letting a
  // network/install/delete command sail through as a bare read (L5-b fail-open).
  if (/^(command|builtin|time)\b/i.test(trimmed)) {
    let inner = trimmed.replace(/^(command|builtin|time)\b/i, '').trim()
    // command -v/-V NAME and --version are query builtins (which command?); read-only.
    if (/^-v\s+|^-V\s+|^--version\b/i.test(inner)) {
      return { category: 'read', reason: 'command/builtin query flag', targetPaths: [] }
    }
    inner = inner.replace(/^--\s+/, '')
    if (!inner) {
      return { category: 'read', reason: 'launch prefix with no command', targetPaths: [] }
    }
    return classifySingleCommand(inner, denyReadPaths)
  }

  // Normalize an absolute-path env launcher (/usr/bin/env, /bin/env, /usr/env)
  // to bare env so the env-unwrapper below applies instead of falling to read.
  {
    const firstTok = trimmed.split(/\s+/)[0] ?? ''
    if (firstTok.includes('/') && firstTok.split('/').pop() === 'env') {
      trimmed = trimmed.replace(firstTok, 'env')
    }
  }

  // Command wrappers whose inner command decides the classification
  // (`nohup node x &` is a background launch of a local command — local).
  if (/^nohup\s+/i.test(trimmed)) {
    const inner = trimmed.replace(/^nohup\s+/i, '').trim()
    if (!inner || /^-\w/.test(inner)) {
      return { category: 'read', reason: 'nohup help/flag', targetPaths: [] }
    }
    return classifySingleCommand(inner, denyReadPaths)
  }

  // `env CMD` runs CMD with an adjusted environment — classify the INNER
  // command. Previously `env` sat in READ_COMMANDS, so `env curl https://…`
  // (and `env uv --version`) sailed through as a read (R5 bypass #80/#81).
  // Zero-argument short flags (`-i`/`--ignore-environment`, `-0`/`--null`,
  // clusters like `-iv`) must NOT swallow the following interpreter as a phantom
  // option argument; only options that genuinely take a value consume the next
  // token (`-u NAME`, `-C DIR`, and their `--unset`/`--chdir` long forms).
  if (/^env\s+/i.test(trimmed)) {
    let inner = trimmed.replace(/^env\s+/i, '').trim()
    const ENV_ARG_SHORT = new Set(['-u', '-C'])
    const ENV_ZERO_LONG = new Set(['--ignore-environment', '--null', '--help', '--version'])
    let guard = 0
    while (guard++ < 60) {
      const tok = inner.split(/\s+/)[0] ?? ''
      if (!tok) break
      // VAR=value assignment prefix
      if (/^[A-Za-z_][A-Za-z0-9_]*=\S*$/.test(tok)) {
        // H3b/F3: env PYTHONPATH=/abs … loads interpreter code outside cwd.
        const taint = taintedPathEnv(tok)
        if (taint) {
          return {
            category: 'unknown',
            reason: `interpreter code load via env (${taint})`,
            targetPaths: [],
          }
        }
        inner = inner.slice(tok.length).trim()
        continue
      }
      // Long option: --flag, --flag=value; zero-arg/self-contained, else --opt NAME
      if (tok.startsWith('--')) {
        const eq = tok.split('=')[0]!
        if (ENV_ZERO_LONG.has(eq) || tok.includes('=')) {
          inner = inner.slice(tok.length).trim()
          continue
        }
        if (/^--(unset|chdir|split-string|default-signal|block-signal|encoding|files-from|debug)$/.test(eq)) {
          inner = inner.slice(tok.length).trim()
          const arg = inner.split(/\s+/)[0]
          if (arg) inner = inner.slice(arg.length).trim()
          continue
        }
        break
      }
      // Short option cluster (`-i`, `-0`, `-iv`); only -u/-C take a value.
      // A value-taking letter may carry its value attached (`-C/`, `-C/tmp`,
      // `-uX`, `-iC/`); the whole attached token strips so the surviving command
      // is re-classified instead of collapsing to a bare read.
      if (/^-[A-Za-z0-9]+$/.test(tok)) {
        if (ENV_ARG_SHORT.has(tok)) {
          inner = inner.slice(tok.length).trim()
          const arg = inner.split(/\s+/)[0]
          if (arg) inner = inner.slice(arg.length).trim()
          continue
        }
        inner = inner.slice(tok.length).trim()
        continue
      }
      if (/^-[A-Za-z0-9]*[Cu][^\s]*$/.test(tok)) {
        inner = inner.slice(tok.length).trim()
        continue
      }
      break
    }
    if (!inner) {
      return { category: 'read', reason: 'env (no command)', targetPaths: [] }
    }
    if (/^--?(help|version|ignore-environment|null)$/i.test(inner)) {
      return { category: 'read', reason: 'env help/flag', targetPaths: [] }
    }
    return classifySingleCommand(inner, denyReadPaths)
  }

  // Check catastrophic patterns first
  const catastrophic = matchCatastrophic(trimmed)
  if (catastrophic) return catastrophic

  const segPart = trimmed.replace(/\s*[;&]\s*$/, '')
  const segFirst = segPart.split(/\s+/)[0]?.toLowerCase() ?? ''

  // H3b/F3: `export PYTHONPATH=/abs …` / `export PYTHONPATH` (inherits the
  // caller's value) makes a later python interpreter load code from an
  // unverifiable path — fail closed even though the export segment itself is
  // side-effect-free.
  if (/^export\s+[A-Za-z_][A-Za-z0-9_]*(\s|=|$)/.test(segPart.trim())) {
    const em = segPart.trim().match(/^export\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(\S+))?/)
    if (em && (em[1] === 'PYTHONPATH' || em[1] === 'PYTHONSTARTUP' || em[1] === 'PYTHONHOME')) {
      if (em[2] === undefined) {
        return {
          category: 'unknown',
          reason: `export ${em[1]} inherits an unverifiable value`,
          targetPaths: [],
        }
      }
      const taint = taintedPathEnv(`${em[1]}=${em[2]}`)
      if (taint) {
        return {
          category: 'unknown',
          reason: `interpreter code load via env (${taint})`,
          targetPaths: [],
        }
      }
    }
  }

  // Pure assignment segments (`VAR=hello` / `VAR=$(ls)` arriving as their own
  // segment after `;`/`&&` splitting) have no side effects — read. Without
  // this, `VAR=x; cmd` mis-classified the assignment half as unknown (R1
  // tokenization fix, audit #9/#21/#65/#108). Only matches a single-token
  // segment, so `NODE_USE_ENV_PROXY=1 npx …` keeps its env-strip path.
  if (!/\s/.test(segPart.trim()) && /^[A-Za-z_][A-Za-z0-9_]*=/.test(segFirst)) {
    return { category: 'read', reason: `Variable assignment: ${segPart}`, targetPaths: [] }
  }

  // A pipeline hidden inside a paren group becomes visible after stripping;
  // classify each command and keep the most restrictive result. Splitting is
  // quote- and escape-aware so grep patterns keep their "|" intact.
  const pipeParts = splitPipeRespectQuotes(trimmed)
  if (pipeParts.length > 1) {
    // H3b/F4: a pipeline feeding an interpreter's stdin (`… | python3 -`,
    // `… | node /dev/stdin`) makes the interpreter read CODE from upstream —
    // the content is not on the command line. Fail closed for the pipeline.
    // F4-c: strip command wrappers (nohup/setsid/command/time/nice/env) first
    // so `… | nohup python3 -` cannot slip past the interpreter check.
    const stdinInterp = pipeParts.find((p) => {
      const stripped = p.trim().replace(
        /^(?:(?:nohup|setsid|command|time|nice)\s+|env\s+(?:-\w+\s+)*)/i, '')
      return /^(?:ruby|perl|php|python\d*|node|nodejs)\s+(?:\/dev\/(?:stdin|fd\/\d+)|-)\s*$/.test(stripped)
    })
    if (stdinInterp) {
      return {
        category: 'unknown',
        reason: `interpreter reads code from stdin pipeline (unverifiable): ${stdinInterp.trim().slice(0, 60)}`,
        targetPaths: [],
      }
    }
    const sub = pipeParts.map((p) => classifySingleCommand(p.trim(), denyReadPaths))
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
  const subCmd = rest.split(/\s+/)[0]?.toLowerCase() ?? ''

  // Check subcommands (git, svn, brew, npm, etc.)
  const fullCmd = `${firstWord} ${rest.split(/\s+/)[0]?.toLowerCase() ?? ''}`.trim()

  // System commands check.
  // `fullCmd` only captures the first two words (lowercased), so multi-word
  // entries like 'diskutil eraseDisk', 'chown -R' or 'defaults write
  // NSGlobalDomain' would never match — also prefix-match against the raw
  // command (entries with a space are complete command patterns).
  if (SYSTEM_COMMANDS.has(firstWord) || SYSTEM_COMMANDS.has(fullCmd) ||
      [...SYSTEM_COMMANDS].some((c) => c.includes(' ') && trimmed.startsWith(c))) {
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

  // Read-only subcommand rule (R1): `--version` / `--help` / `version` /
  // `help` probes of ANY command are read-only — `ffmpeg -version`,
  // `soffice --version`, `sips --help`, `avconvert --help`, `qpdf --version`.
  // Runs BEFORE the process/exec/network families so `sips --help` does not
  // stay a process command. Deliberately excludes `-v` (ambiguous). `-h` is
  // also ambiguous for some tools (ls -h = human-readable) but is unambiguously
  // help for the converter/registry family, so it is whitelisted there
  // (review T3: `ffmpeg -h long | head` must not be a file_write).
  const UNIQUE_H_HELP = new Set([
    'ffmpeg', 'ffprobe', 'avconvert', 'afconvert', 'soffice', 'libreoffice',
    'textutil', 'qpdf', 'gs', 'mutool', 'magick', 'convert', 'sips', 'uv',
    'swiftc', 'pdftotext', 'pdfinfo', 'otool', 'mdls', 'afinfo', 'pgrep',
  ])
  if (subCmd !== '' &&
      (/^(?:-{1,2}version|-{1,2}help|version|help)$/i.test(subCmd) ||
       (subCmd === '-h' && UNIQUE_H_HELP.has(firstWord)))) {
    return {
      category: 'read',
      reason: `Version/help probe: ${fullCmd}`,
      targetPaths: [],
    }
  }

/**
 * uv flags that take a value (strip the flag AND its value from a `uv run`
 * prefix). Everything else starting with `-` is treated as boolean and
 * consumed alone; `--name=value` consumes itself; `--` stops flag parsing.
 * Mirrors uv's real CLI so `uv run --no-sync python3 -c "…"` keeps
 * `python3` as the interpreter token (R13 blocker fix).
 */
const UV_VALUE_FLAGS = new Set([
  '--python', '-p', '--directory', '-d', '--project', '--script',
  '--with-requirements', '--index-url', '--extra-index-url', '--find-links',
  '--python-platform', '--python-version', '--group',
])

function stripUvRunFlags(s: string): string {
  const toks = s.split(/\s+/)
  let i = 0
  while (i < toks.length) {
    const t = toks[i]
    if (t === '--') {
      i++
      break
    }
    if (t.startsWith('-') && t.length > 1) {
      if (t.includes('=')) {
        i++ // --x=y consumes itself
        continue
      }
      if (UV_VALUE_FLAGS.has(t)) {
        i += 2 // flag + its value
        continue
      }
      i++ // boolean flag
      continue
    }
    break // first non-flag token (interpreter or script)
  }
  return toks.slice(i).join(' ')
}

  // uv is a Python/tool package manager: install/add/remove/sync/tool install
  // and `run --with` hit the network and must be denied; version/help/
  // list/show/python/cache/init and plain `uv run script.py` are local
  // (review N4 — previously every uv subcommand rode local_exec).
  if (firstWord === 'uv') {
    const uvSub = rest.split(/\s+/)[0]?.toLowerCase() ?? ''
    if (uvSub === 'install' || uvSub === 'add' || uvSub === 'remove' ||
        uvSub === 'sync' || uvSub === 'lock' || uvSub === 'build') {
      return {
        category: 'package',
        reason: `uv package operation: ${fullCmd}`,
        targetPaths: [],
      }
    }
    if (uvSub === 'pip' && /^pip\s+(?:install|download|sync|uninstall|compile)\b/.test(rest)) {
      return {
        category: 'package',
        reason: `uv pip network operation: ${fullCmd}`,
        targetPaths: [],
      }
    }
    if (uvSub === 'tool' && /^tool\s+(?:install|run|upgrade|uninstall)\b/.test(rest)) {
      return {
        category: 'package',
        reason: `uv tool ${rest.split(/\s+/)[1] ?? 'op'} (fetches packages): ${fullCmd}`,
        targetPaths: [],
      }
    }
    // H5: `uv python install <ver>` downloads a Python build,
    // `uv self update` pulls a new uv binary — both are network package ops.
    if (uvSub === 'python' && /^python\s+(?:install|uninstall|download)\b/.test(rest)) {
      return {
        category: 'package',
        reason: `uv python install/download: ${fullCmd}`,
        targetPaths: [],
      }
    }
    if (uvSub === 'self' && /^self\s+update\b/.test(rest)) {
      return {
        category: 'package',
        reason: `uv self update: ${fullCmd}`,
        targetPaths: [],
      }
    }
    if (uvSub === 'run' && rest.includes('--with')) {
      return {
        category: 'package',
        reason: `uv run --with (fetches deps): ${fullCmd}`,
        targetPaths: [],
      }
    }
    // R12-followup (allow-side gap found in final pre-release review):
    // `uv run python3 -c "import urllib.request; ...evil.example..."` rode
    // local_exec below — the wrapped interpreter's inline code never entered
    // the danger nets (`python3 -c` alone and `env python3 -c` both deny the
    // same code). Strip the uv wrapper and re-classify the interpreter
    // command, mirroring the bash -c recursion; local scripts
    // (`uv run script.py`) and version probes still fall through to local_exec.
    // R13: flag stripping must follow uv's real syntax — only known
    // value-taking flags consume a token (`--no-sync python3 -c ...` must
    // NOT eat `python3`), `--x=y` consumes itself, `--` stops flag parsing;
    // the recursion must forward denyReadPaths (else -c code reading a
    // sensitive path escapes forceDeny), and a name that merely LOOKS like
    // an interpreter (python3x/ipython3/…) fails closed instead of riding
    // local_exec.
    if (uvSub === 'run') {
      const afterRun = stripUvRunFlags(rest.replace(/^run\s+/, ''))
      const interp = afterRun.split(/\s+/)[0]?.toLowerCase().split('/').pop() ?? ''
      if (LOCAL_EXEC_COMMANDS.has(interp) || PY_INTERPRETER_RE.test(interp) ||
          ['bash', 'sh', 'zsh', 'dash'].includes(interp)) {
        const inner = classifyBashCommand(afterRun, denyReadPaths)
        if (inner.category !== 'local_exec') return inner
      } else if (/^(?:ipython|python|pypy|node)/.test(interp)) {
        return {
          category: 'unknown',
          reason: `Unknown interpreter after uv run: ${fullCmd}`,
          targetPaths: [],
        }
      }
    }
    return {
      category: 'local_exec',
      reason: `uv local task: ${fullCmd}`,
      targetPaths: extractWritePaths(trimmed),
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

  // Shell interpreters: `bash -c "CODE"` must classify the CODE string, not
  // ride on the interpreter; `bash -n` is a pure syntax check; running a
  // local script is local execution (outputs decided by path).
  if (['bash', 'sh', 'zsh', 'dash'].includes(firstWord)) {
    if (subCmd === '-c') {
      // R14 W1: escape-aware quote extraction so `bash -c "python3 -c \"…\""`
      // does not truncate at the inner \" (extractFlagArgument).
      const code = extractFlagArgument(' ' + rest, '-c')
      if (code) {
        // R13: forward denyReadPaths — `bash -c "cat ~/.ssh/id_rsa"` must
        // forceDeny under a sensitive dir, not lose the context here.
        const inner = classifyBashCommand(code, denyReadPaths)
        return inner
      }
      return {
        category: 'mixed',
        reason: `Shell -c without extractable code: ${fullCmd}`,
        targetPaths: [],
      }
    }
    if (subCmd === '-n') {
      return {
        category: 'read',
        reason: `Shell syntax check: ${fullCmd}`,
        targetPaths: [],
      }
    }
    // B6 (g 轮): a bare shell with NO arguments reads and executes stdin as
    // code (`cat x.sh | bash`, `echo x | sh`). Fail closed. Any argument —
    // a script (`bash script.sh`), `-c`/`-n` (handled above), or any option
    // (`bash -x -c "…"`, `bash --norc script.sh`) — names an explicit target
    // and keeps the historical classification; archive exec sinks inside
    // those stay denied at the hook layer via hasArchiveExecSink.
    if (!rest.trim()) {
      return {
        category: 'unknown',
        reason: `bare shell may execute stdin code (unverifiable): ${fullCmd.slice(0, 60)}`,
        targetPaths: [],
      }
    }
    return {
      category: 'local_exec',
      reason: `Shell execution: ${fullCmd}`,
      targetPaths: extractWritePaths(trimmed),
    }
  }

  // xargs executes its inner command on stdin lines — classify that command
  // so `xargs -I{} sh -c "curl …"` / `xargs curl https://…` do not ride on
  // an unknown/local placeholder (R5, audit #60/#88/#120).
  if (firstWord === 'xargs') {
    // R14 W1: escape-aware extraction of the inner shell -c code.
    const shellM = /(?:^|\s)(?:sh|bash|zsh|dash)\s+-c/.exec(rest)
    if (shellM) {
      const code = extractFlagArgument(' ' + rest.slice(shellM.index).trim(), '-c')
      if (code) return classifyBashCommand(code, denyReadPaths)
    }
    const toks = rest.split(/\s+/)
    const first = toks.find((t) => !t.startsWith('-') && t !== '{}')
    if (first) {
      const idx = toks.indexOf(first)
      const innerCmd = toks.slice(idx).join(' ')
      // B7: a write verb whose DESTINATION is the {} placeholder cannot be
      // verified statically — stdin lines are attacker-chosen paths
      // (`echo /etc/x | xargs -I{} cp f {}`). If the placeholder is a SOURCE
      // (`cp {} /tmp/x`), the concrete destination still flows through the
      // normal write-path check.
      const writeVerbM = innerCmd.match(/^(?:cp|mv|tee|dd|install|ln|unlink|rm|trash)\b/)
      if (writeVerbM) {
        const innerToks = innerCmd.split(/\s+/)
        if (innerToks[innerToks.length - 1] === '{}') {
          return {
            category: 'unknown',
            reason: `xargs ${writeVerbM[1]} destination is a stdin placeholder: ${fullCmd}`,
            targetPaths: [],
            mutates: true,
          }
        }
      }
      return classifyBashCommand(innerCmd, denyReadPaths)
    }
    return {
      category: 'local_exec',
      reason: `xargs without extractable command: ${fullCmd}`,
      targetPaths: [],
    }
  }

  // Local code execution / build / test / lint — local effects, rollback-able.
  // Checked BEFORE the network/package blocks so package-manager LOCAL
  // subcommands (npm test, cargo test, go run…) are allowed while install/fetch
  // (which hit the network) stay blocked.
  if (LOCAL_EXEC_COMMANDS.has(firstWord) || PY_INTERPRETER_RE.test(firstWord) || LOCAL_EXEC_COMMANDS.has(fullCmd)) {
    // B8 (g 轮): awk sits in LOCAL_EXEC_COMMANDS. An opaque awk program FILE
    // (`-f/--file=`, incl. glued `-fe`) cannot be verified — fail closed.
    // An inline program that writes/executes through an indirect channel
    // (`-v c="id" 'BEGIN{c|getline}'`, `ENVIRON["CMD"]|getline`,
    // `print "y" > f`) has no literal command/path to match — fail closed.
    if (firstWord === 'awk' || firstWord === 'gawk') {
      // H6: opaque program FILE via `-f PROG`, `--file=PROG`, `--file PROG`
      // (space form) or glued `-fPROG` — the program body is never scanned.
      if (/(?:^|\s)-f(?:\s|$)/.test(rest) || /(?:^|\s)--file(\s|=)/.test(rest) ||
          /(?:^|\s)-f[A-Za-z0-9_.-]/.test(rest) || /(?:^|\s)--file[A-Za-z0-9_.-]/.test(rest)) {
        return {
          category: 'unknown',
          reason: `awk program file (unverifiable): ${fullCmd.slice(0, 60)}`,
          targetPaths: [],
        }
      }
      // Program text may be a quoted block containing spaces; test the whole
      // rest for the indirect command/write surface (`> f` via -v variable,
      // `c|getline`, ENVIRON|getline, system/exec). H7: ENVIRON alone is a
      // read (`print ENVIRON["HOME"]`) — require a real sink (|getline, >).
      if (/\bsystem\s*\(|\bexec\s*\(|\|\s*(?:getline\b|["'])/.test(rest) ||
          />\s*(?:["']|[A-Za-z_]\w*)/.test(rest) ||
          /ENVIRON\[[^\]]*\]\s*(\|\s*getline\b|>\s*["'\w])/.test(rest)) {
        return {
          category: 'unknown',
          reason: `awk program executes indirect commands or writes (unverifiable): ${fullCmd.slice(0, 60)}`,
          targetPaths: [],
        }
      }
    }
    // R14 W1: sensitive-path scan on the inline code now runs inside
    // classifySingleCommand so it flows through every wrapper recursion
    // (nohup/env/assignment/subshell), not just the outer per-segment
    // loop where the first word is the interpreter.
    const sensHit = scanInlineCodeForSensitive(trimmed, denyReadPaths)
    if (sensHit) return sensHit
    // B2: ruby -e (and any future inline interpreter) that calls
    // File.unlink/rmtree deletes files; fail closed instead of local_exec.
    const inlineDestructive = detectInlineDestructiveCode(trimmed, firstWord)
    if (inlineDestructive) return inlineDestructive
    // G8: a bare ruby -r network module load flag (not wrapped in find -exec)
    // reaches LOCAL_EXEC; fail closed instead of riding local execution.
    const flagEgress = moduleFlagEgress(trimmed, firstWord)
    if (flagEgress) {
      return {
        category: 'network',
        reason: `Network module load flag: ${flagEgress}`,
        targetPaths: [],
      }
    }
    // R5: interpreters with inline code — classify the wrapped argv so
    // `python3 -c "subprocess.run(['pip3','install',x])"` and
    // `node -e "process.kill(pid)"` cannot ride on local_exec.
    const isPython = PY_INTERPRETER_RE.test(firstWord)
    const wrapped = extractWrappedCommand(rest, isPython)
    if (wrapped) {
      if (wrapped.kind === 'kill') {
        return {
          category: 'process',
          reason: `Interpreter process.kill: ${fullCmd}`,
          targetPaths: [],
        }
      }
      const inner = classifySingleCommand(wrapped.command, denyReadPaths)
      if (inner.category !== 'local_exec' && inner.category !== 'read') {
        return {
          ...inner,
          reason: `Interpreter-wrapped ${inner.category}: ${wrapped.command.slice(0, 60)}`,
          targetPaths: inner.targetPaths,
          forceDeny: inner.forceDeny,
          mutates: inner.mutates,
        }
      }
      if (wrapped.shellString) {
        // H1: os.system/os.popen execute arbitrary shell. A local/read inner
        // string ('id', 'echo hi') must NOT vouch for the primitive — the
        // caller cannot see data flow (os.system(user_input) with a benign
        // literal at rest is indistinguishable). Fail closed.
        return {
          category: 'unknown',
          reason: `Shell-string exec via os.system/os.popen (unverifiable): ${wrapped.command.slice(0, 60)}`,
          targetPaths: [],
        }
      }
    } else {
      // N2 (review): a dangerous call site whose arguments we cannot verify
      // (require('child_process').execSync(…), `from subprocess import run
      // as r`, destructured/spawn aliases, shell=True strings) fails closed
      // to unknown instead of riding local_exec.
      const code2 = extractInlineCode(rest)
      if (code2 && hasUnverifiableDanger(code2, isPython)) {
        return {
          category: 'unknown',
          reason: `Interpreter code with unverifiable dangerous call: ${fullCmd.slice(0, 60)}`,
          targetPaths: [],
        }
      }
    }
    // A local-exec command carrying explicit write targets is a file write
    // for decide() purposes: TM-protected paths are allowed (snapshot),
    // temp dirs allowed, anything else denied. Without this, ffmpeg/swiftc
    // conversions to /etc or another unprotected dir would sail through
    // (regression risk when widening LOCAL_EXEC_COMMANDS in R1).
    const writes = extractWritePaths(trimmed)
    if (writes.length > 0) {
      return {
        category: 'file_write',
        reason: `Local command with write target: ${fullCmd}`,
        targetPaths: writes,
      }
    }
    // B6 (g 轮): a bare code-host interpreter with NO arguments reads and
    // executes code from stdin (`cat evil.rb | ruby`, `gzip -dc evil.gz |
    // ruby`, `cat x.sh | bash`). The pipe content is not on the command line;
    // fail closed — the same posture as a heredoc. Any argument (a script,
    // -e/-c/-m, heredoc marker, flag) names an explicit target and keeps the
    // historical classification (e.g. `ruby -w`, `node <<'NODE'`,
    // `python3 -m http.server`, `bash -x -c "…"` all stay local_exec).
    if (/^(?:ruby|perl|php|python\d*|node|nodejs|bash|sh|zsh|dash|ksh|tclsh|elixir|elixirc|escript)\b/.test(firstWord) &&
        !rest.trim()) {
      return {
        category: 'unknown',
        reason: `bare interpreter may execute stdin code (unverifiable): ${fullCmd.slice(0, 60)}`,
        targetPaths: [],
      }
    }
    // H3b/F4: `python3 -` / `python3 /dev/stdin` / `node /dev/fd/0` read their
    // CODE from stdin (a pipe or process substitution) — the content is not on
    // the command line, same posture as the bare-interpreter rule. A heredoc
    // (`python3 - <<'PY'`) keeps the historical path: its body IS visible and
    // scanned by the heredoc net. F4-a/b: `python3 - < file` and
    // `node /dev/fd/63 63< file` also feed code via `<` redirection (not a
    // heredoc) — the interpreter's stdin position marker (`-`, /dev/stdin,
    // /dev/fd/N) plus ANY pipe / `<` / process-substitution upstream fails
    // closed, without requiring the pipe branch.
    if (/^(?:ruby|perl|php|python\d*|node|nodejs)\b/.test(firstWord) &&
        (/(?:^|\s)(?:\/dev\/(?:stdin|fd\/\d+))(?:\s|$)/.test(rest) ||
         /\s-\s|\s-\s*$/.test(rest) || /^\s*-\s/.test(rest)) &&
        /(?:^|[|&;])\s*(?:<\s*\(|[^<]*\||[^<]*<(?!<))/.test(trimmed) &&
        !/<<-?/.test(trimmed.replace(/^(?:ruby|perl|php|python\d*|node|nodejs)\b/, ''))) {
      return {
        category: 'unknown',
        reason: `interpreter reads code from stdin (unverifiable): ${fullCmd.slice(0, 60)}`,
        targetPaths: [],
      }
    }
    return {
      category: 'local_exec',
      reason: `Local execution/build/test: ${fullCmd}`,
      targetPaths: [],
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
      if (isLoopbackOnly(target)) {
        return {
          category: 'local_network',
          reason: `open local network (loopback): ${target.slice(0, 80)}`,
          targetPaths: [],
        }
      }
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
      if (isReadOnlyArchiveOp('rsync', trimmed) && !hasOutputRedirect(trimmed)) {
        return {
          category: 'read',
          reason: 'read-only archive operation: ' + fullCmd,
          targetPaths: [],
        }
      }
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
    // R1: npm read-only metadata queries are not package management —
    // `npm pack --dry-run` (zero-write manifest check), `npm config get`
    // (local config inspection), `npm view` / `npm search` (registry
    // lookups with no local side effects). Denying them caused real false
    // positives in production (audit #52/#54/#55/#56/#86/#109/#117).
    if (firstWord === 'npm') {
      if (sub === 'pack' && rest.includes('--dry-run')) {
        return {
          category: 'read',
          reason: `npm pack --dry-run (zero-write manifest check): ${fullCmd}`,
          targetPaths: [],
        }
      }
      if (sub === 'config' && /^config\s+get\b/.test(rest)) {
        return {
          category: 'read',
          reason: `npm config get (local config query): ${fullCmd}`,
          targetPaths: [],
        }
      }
      if (sub === 'view' || sub === 'search') {
        return {
          category: 'read',
          reason: `npm ${sub} (registry lookup, read-only): ${fullCmd}`,
          targetPaths: [],
        }
      }
    }
    return {
      category: 'package',
      reason: `Package manager: ${fullCmd}`,
      targetPaths: [],
    }
  }

  function decompressToStdout(cmd: string): boolean {
  const toks = cmd.split(/\s+/)
  const hasD = toks.some((t) => t === '-d' || t === '--decompress' || t === '--uncompress' ||
    /^-.*d.*$/.test(t) && !t.includes('no'))
  const hasC = toks.some((t) => t === '-c' || t === '--stdout' || t === '--to-stdout' ||
    /^-.*c.*$/.test(t))
  return hasD && hasC
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

    // B3/H1: external-program guard MUST run BEFORE decompressToStdout —
    // adding `-dc` to `--use-compress-program` must not reorder the guard
    // away. Covers the long option (any case, any position/quoting), GNU
    // gzip/xz short `-I PROG` / glued `-Ish` / `-I=sh` / cluster `-dcIsh`,
    // across all supported compressors.
    if (/^(gzip|gunzip|xz|unxz|bzip2|bunzip2|lz4|lzma|unlzma|lzop)\b/.test(firstWord) &&
        (/(?:^|\s)--?(?:use[-_])?compress-program(\s+|=)\S+/i.test(trimmed) ||
         /(?:^|\s)-[a-z0-9]*I[A-Za-z0-9_.=]*/.test(trimmed))) {
      return {
        category: 'unknown',
        reason: `compression with external program (unverifiable): ${fullCmd}`,
        targetPaths: [],
        mutates: true,
      }
    }

    // Compress/decompress to STDOUT (`-dc`, `-d -c`, `--stdout`) writes no
    // file — classify as read so a piped tail (`gzip -dc < a.gz | ruby -e
    // 'File.write("/etc/gz",…)'`) reaches the egress scan on the tail.
    if ((firstWord === 'gzip' || firstWord === 'gunzip' || firstWord === 'bzip2' ||
         firstWord === 'bunzip2' || firstWord === 'xz' || firstWord === 'unxz' ||
         firstWord === 'lz4' || firstWord === 'lzop') &&
        decompressToStdout(trimmed)) {
      return {
        category: 'read',
        reason: `decompress to stdout: ${fullCmd}`,
        targetPaths: [],
      }
    }

    // Pure-listing/print/dry-run archive ops write nothing to disk (unless an
    // explicit output redirection makes them a real write).
    if (isReadOnlyArchiveOp(firstWord, trimmed) && !hasOutputRedirect(trimmed)) {
      return {
        category: 'read',
        reason: `read-only archive operation: ${fullCmd}`,
        targetPaths: [],
      }
    }

    // B4: editor -c/--eval shell escapes and escape writes are invisible to
    // the write-path extractor; fail closed before granting file_write.
    const editorInjection = detectEditorCommandInjection(trimmed, firstWord)
    if (editorInjection) return editorInjection

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
    // B2: find -delete/-exec rm and perl/ruby inline unlink are destructive
    // even though the leading word sits in READ_COMMANDS; do not let them
    // sail through as a bare read with no checkpoint/probe/snapshot.
    const destructive = detectDestructiveRead(trimmed, firstWord)
    if (destructive) return destructive
    // G8: a bare perl -M/-m network module load flag (not wrapped in find -exec)
    // reaches READ_COMMANDS; fail closed instead of sailing through as read.
    const flagEgress = moduleFlagEgress(trimmed, firstWord)
    if (flagEgress) {
      return {
        category: 'network',
        reason: `Network module load flag: ${flagEgress}`,
        targetPaths: [],
      }
    }
    // B8 (g 轮): `awk -f PROGRAM` / `awk --file=PROGRAM` fail-closed — moved
    // to the LOCAL_EXEC_COMMANDS branch where awk actually classifies.
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
      // Escaped char: `\;` in `find -exec … {} \;` is the -exec terminator,
      // NOT a shell segment separator; `\(`, `\&`, `\|` likewise stay literal.
      if (ch === '\\' && next !== undefined) {
        current += ch + next
        i++
        continue
      }
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
 * Extract command-substitution bodies — `$(...)` and backtick `` `…` `` —
 * so sensitive reads smuggled inside them (`echo $(cat ~/.ssh/id_rsa)`) are
 * caught by re-classifying the inner command. Arithmetic `$((x << 2))` yields
 * a harmless body; nesting is handled by the recursive re-classification.
 */
export interface CommandSubstitutionBody {
  body: string
  /** true = backtick source (bash unescapes `\``/`\\` inside it and
   *  re-parses); false = $()/<() source (a `\`` there is a literal backtick
   *  and must NOT be unescaped into a new substitution). */
  bt: boolean
}
export function extractCommandSubstitutions(s: string): CommandSubstitutionBody[] {
  const out: CommandSubstitutionBody[] = []
  // Backtick body may contain escaped backticks (`\``) and backslashes;
  // they stay inside the body so the nested command survives for re-scan.
  // H3: a backtick preceded by `\` is an ESCAPED backtick (not a delimiter).
  // F2: bash closes an unterminated backtick substitution at END OF LINE
  // (verified: `echo \`echo \\\`id\\\`\`` live-runs id), so the closer may
  // be an unescaped backtick OR the end of the string.
  const btRe = /(?<!\\)`((?:\\.|[^`\\])*)(?:`|$)/g
  let m: RegExpExecArray | null
  while ((m = btRe.exec(s)) !== null) {
    out.push({ body: m[1], bt: true })
  }
  let i = 0
  while (i < s.length) {
    // `$(...)`, `>(...)` and `<(...)` process substitutions are command
    // bodies (the `>` form is a write channel — B7 `echo a >(tee /tmp/x)`).
    const dollar = s.indexOf('$(', i)
    const gt = s.indexOf('>(', i)
    const lt = s.indexOf('<(', i)
    const starts = [dollar, gt, lt].filter((v) => v !== -1)
    if (starts.length === 0) break
    const start = Math.min(...starts)
    // H7: `$(( … ))` is arithmetic expansion, NOT a command substitution —
    // skip it so `echo $((1+2))` stays read.
    if (start === dollar && s[start + 2] === '(') {
      i = start + 3
      continue
    }
    let depth = 0
    let end = -1
    for (let j = start + 2; j < s.length; j++) {
      const ch = s[j]
      if (ch === '(') depth++
      else if (ch === ')') {
        if (depth === 0) { end = j; break }
        depth--
      }
    }
    if (end === -1) break
    out.push({ body: s.slice(start + 2, end), bt: false })
    i = end + 1
  }
  return out
}

/** H3/F2: normalize escapes inside an extracted substitution body so a
 *  nested command can be re-scanned one layer deeper. bash consumes one
 *  backslash layer inside a backtick body: `\\` -> `\`, `\`` -> a literal
 *  backtick (which then re-opens a substitution on the next re-parse), and
 *  `\$` -> `$`. Inside a `$(…)` body a backtick is NOT escaped/executed, so
 *  `unescapeBackticks=false` keeps `\`` untouched (literal). */
export function unescapeSubstitutionBody(body: string, unescapeBackticks = true): string {
  return body.replace(/\\([\\`$])/g, (_m, c: string) =>
    c === '`' && !unescapeBackticks ? _m : c)
}

/**
 * Interpreters that accept inline code (-c/-e/--eval/…). The code text is a
 * separate language space the token-level path extractor cannot see, so we
 * scan it directly for sensitive path references (absolute, ~-prefixed and
 * $HOME-prefixed forms) and treat a hit as a sensitive read.
 */
const INTERPRETER_CODE_FLAGS: Record<string, string[]> = {
  python3: ['-c'], python: ['-c'],
  node: ['-e', '--eval'], nodejs: ['-e', '--eval'], npx: ['-e'],
  ruby: ['-e'], perl: ['-e', '-E'], php: ['-r', '-R'],
  osascript: ['-e'], jsc: ['-e'], swift: ['-e'],
  elixir: ['-e'], elixirc: ['-e'], escript: ['-e'],
}

/** Substring hit for an absolute sensitive prefix, with a directory/quote/
 *  paren/space boundary so `/Users/alice/.ssh` does not false-positive on
 *  `/Users/alice/.ssh-evil` appearing as a literal string. */
function codeContainsPath(code: string, absPrefix: string): boolean {
  const idx = code.indexOf(absPrefix)
  if (idx === -1) return false
  const after = code[idx + absPrefix.length] ?? ''
  return after === '' || after === '/' || after === '"' || after === "'" ||
    after === ')' || after === ' '
}

/** Scan interpreter code text for sensitive path references in every form a
 *  script would use: absolute (`/Users/alice/.ssh/…`), `~`-prefixed, $HOME. */
function scanCodeForSensitivePaths(
  code: string,
  denyReadPaths: string[],
): string[] {
  const hits: string[] = []
  // B2: dynamic HOME references (ruby Dir.home / ENV["HOME"], perl $ENV{HOME})
  // concatenated with a sensitive subpath — `File.read(Dir.home+"/.ssh/x")`.
  // A bare `puts ENV["HOME"]` carries no sensitive subpath and stays allowed.
  const dynHomeRef = /Dir\.home\b|ENV\s*\[\s*["']HOME["']\s*\]|\$ENV\s*\{\s*HOME\s*\}|getenv\s*\(\s*["']HOME["']\s*\)|ENV\s*\.\s*fetch\s*\(\s*["']HOME["']/.test(code)
  for (const raw of denyReadPaths) {
    const abs = expandHome(raw).replace(/\/+$/, '')
    const homeRel = raw.replace(/^~\//, '') // e.g. .ssh / Library/Keychains
    if (codeContainsPath(code, abs)) hits.push(abs)
    if (code.includes(`~/${homeRel}`) || code.includes(`"~/${homeRel}`) ||
        code.includes(`'~/${homeRel}`)) hits.push(raw)
    if (code.includes(`$HOME/${homeRel}`) || code.includes(`\${HOME}/${homeRel}`)) {
      hits.push(raw)
    }
    if (dynHomeRef && homeRel && code.includes(homeRel)) hits.push(raw)
  }
  return hits
}

/**
 * R14 W1: match a quoted shell string starting at index i (s[i] is " or '),
 * honoring backslash escapes so a `\"` inside `bash -c "python3 -c \"…\""`
 * does not terminate the string early. Returns captured text (escapes kept
 * verbatim, so literal paths stay visible to the scans) and the index just
 * after the closing quote.
 */
function matchQuotedAt(s: string, i: number): { text: string; end: number } | null {
  const quote = s[i]
  if (quote !== '"' && quote !== "'") return null
  let j = i + 1
  let text = ''
  while (j < s.length) {
    if (s[j] === '\\' && j + 1 < s.length) {
      text += s[j] + s[j + 1]
      j += 2
      continue
    }
    if (s[j] === quote) {
      return { text, end: j + 1 }
    }
    text += s[j]
    j++
  }
  return null
}

/**
 * R14 W1: extract the first argument after a flag (e.g. -c): quoted first
 * (escape-aware, see matchQuotedAt), otherwise the next bare token.
 * Returns null when no argument is present.
 */
function extractFlagArgument(s: string, flag: string): string | null {
  const fm = new RegExp(`\\s${flag}(?:=|\\s)`).exec(s)
  if (!fm) return null
  let i = fm.index + fm[0].length
  while (i < s.length && s[i] === ' ') i++
  if (s[i] === '"' || s[i] === "'") {
    const q = matchQuotedAt(s, i)
    if (q) return q.text
  }
  const bare = /^(\S+)/.exec(s.slice(i))
  return bare ? bare[1] : null
}

/**
 * R14 W1: extract the inline code (-c/-e/…) of a single command and scan
 * it for sensitive-path references, so wrappers that only recurse through
 * classifySingleCommand (nohup / env / bare assignment prefix / subshell)
 * still produce the forceDeny mark. The scan used to live only in
 * classifyBashCommand's per-segment loop, where the segment's first word
 * had to be the interpreter itself — `nohup python3 -c "open('…/.ssh/…')"`
 * therefore rode local_exec.
 */
function scanInlineCodeForSensitive(
  command: string,
  denyReadPaths: string[],
): ClassifyResult | null {
  if (denyReadPaths.length === 0) return null
  const firstWord = command.trim().split(/\s+/)[0]?.toLowerCase().split('/').pop() ?? ''
  const codeFlags =
    PY_INTERPRETER_RE.test(firstWord) ? ['-c'] : INTERPRETER_CODE_FLAGS[firstWord]
  if (!codeFlags) return null
  for (const flag of codeFlags) {
    const codeText = extractFlagArgument(command, flag)
    if (!codeText) continue
    const hits = scanCodeForSensitivePaths(codeText, denyReadPaths)
    if (hits.length > 0) {
      return {
        category: 'read',
        reason: `Sensitive path access blocked (denyReadPaths, interpreter -c): ${hits[0]}`,
        targetPaths: hits,
        forceDeny: true,
      }
    }
  }
  return null
}

/** Private-key / credential file names that -name may carry (precise, no wildcards). */
const SENSITIVE_FIND_NAMES = new Set([
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_ed25519_sk', 'id_ecdsa_sk',
  'credentials', 'token', 'secret', '.netrc', '.npmrc', '.pypirc',
])

/** Content-reading commands that -exec may run on found files. */
const FIND_READ_EXEC = new Set([
  'cat', 'head', 'tail', 'sed', 'strings', 'od', 'xxd', 'base64', 'openssl',
  'nl', 'more', 'less', 'grep', 'awk', 'cut', 'sort', 'dd', 'cp',
])

/**
 * Commands a `find -exec`/`-execdir` may run that mutate or delete the matched
 * files. `find` itself sits in READ_COMMANDS, so without this the destructive
 * action rode through as a bare read with no checkpoint/probe/snapshot (B2).
 */
const FIND_DESTRUCTIVE_EXEC = new Set([
  'rm', 'rmdir', 'unlink', 'mv', 'trash', 'tee', 'truncate',
  'cp', 'dd', 'install', 'ln', 'chmod', 'chown', 'chgrp', 'chflags',
])

/** Inline interpreter code (perl/ruby -e/-E) that deletes files or runs an
 *  arbitrary shell command we cannot verify (system/qx/backticks/exec). */
/**
 * Single filesystem-delete API surface. Both the direct inline detector
 * (INLINE_DESTRUCTIVE_RE) and the find-exec shell-body heuristic match against
 * this source; adding a delete API here covers both channels, so a delete call
 * cannot be caught by the direct detector but missed inside a find-exec shell
 * (the drift that caused B8 remove_tree and B9 remove_dir).
 */
const DELETE_API_SURFACE =
  /\bunlink\b|\brmtree\b|\bremove_tree\b|\bremove_entry(?:_secure)?\b|\bremove_dir\b|FileUtils\.(?:rm|rm_f|rm_r|rm_rf|rmdir|remove_entry_secure|remove_entry|remove_dir)|File\.delete|File\.rmdir|Dir\.(?:rmdir|delete|unlink)|os\.remove|shutil\.rmtree|\.unlink(?:Sync)?\b|\.rmSync\b|\.rmdirSync\b/

const INLINE_DESTRUCTIVE_RE = new RegExp([
  DELETE_API_SURFACE.source,
  // B4 (g 轮): the write-content surface is equally destructive through an
  // inline interpreter — File.write/FileUtils.write, python open(...,"w"),
  // node writeFileSync. Without these, a
  // `find -exec ruby -e 'File.write("/etc/pwn","x")'` sailed through as read.
  // Copy / mkdir methods are deliberately NOT listed (FileUtils.cp/mkdir_p
  // stay local_exec per the FileUtils-narrowing test contract); only content
  // writes and deletions hard-deny. Bare `File.open(...)` is also NOT listed —
  // a read-mode open (`File.open("data.txt"){|f| puts f.gets}`) must stay
  // clean; only an open carrying an explicit write mode string matches below.
  /\bFile\.(?:write|binwrite|truncate)\b/,
  /\bFileUtils\.write\b/,
  /\bFile\.open\s*\([^)]*['"](?:w|a|r\+|w\+|wb|ab|wt)/,
  /\bopen\s*\([^)]*,\s*['"](?:w|a|r\+|w\+|wb|ab)/,
  /\bIO\.(?:write|binwrite|truncate)\s*\(/,
  /\bIO\.open\s*\([^)]*['"](?:w|a|r\+|w\+|wb|ab)/,
  /\bos\.(?:remove|unlink|rmdir)\b/,
  /\bshutil\.(?:move|rmtree)\b/,
  /\.writeFileSync?\s*\(/,
  /Kernel\.(system|exec)/,
  /\bsystem\s*\(/,
  /\bsystem\s+["']\S/,
  /\bexec\s*\(/,
  /\bqx\b/,
  /`[^`]*`/,
  /open\s*\(\s*['"]\|/,
].map((r) => (typeof r === 'string' ? r : r.source)).join('|'))

/** Extract the quoted code body after -e/-E, allowing an immediately-adjacent
 *  quote (`perl -e'...'`) that extractFlagArgument skips. */
function extractInlineCodeBody(trimmed: string, flags: string[]): string | null {
  for (const flag of flags) {
    const re = new RegExp(`${flag}\\s*(?:'([^']*)'|"([^"]*)")`)
    const m = re.exec(trimmed)
    if (m) return m[1] ?? m[2]
  }
  return null
}

/** Fallback: first quoted block, used when the code flag is a merged short
 *  cluster (`ruby -ne`, `perl -pe`) that a standalone-flag match cannot reach. */
function extractQuotedBody(trimmed: string): string | null {
  const m = /(?:'([^']*)'|"([^"]*)")/.exec(trimmed)
  return m ? (m[1] ?? m[2] ?? null) : null
}

/**
 * First non-flag positional argument of `find`/`fd` (the starting directory),
 * parsed before any -exec/-execdir/-ok action clause. Null when unresolvable.
 */
function extractFindStart(trimmed: string): string | null {
  const beforeAction = trimmed.split(/\s+-(?:exec(?:dir)?|ok)\b/i)[0]
  for (const tok of beforeAction.split(/\s+/)) {
    if (!tok || tok === 'find' || tok === 'fd' || tok.startsWith('-')) continue
    const cleaned = tok.replace(/[{};+]/g, '')
    if (cleaned) return cleaned
  }
  return null
}

/**
 * B2: perl/ruby inline code (-e/-E) that deletes files or invokes an
 * unverifiable shell (unlink/rmtree/FileUtils/system/qx/backticks). The
 * interpreter rides either READ_COMMANDS (perl) or LOCAL_EXEC_COMMANDS (ruby),
 * so this is checked from both entrances.
 */
function detectInlineDestructiveCode(
  trimmed: string,
  firstWord: string,
): ClassifyResult | null {
  let code: string | null = null
  if (firstWord === 'perl') {
    code = extractInlineCodeBody(trimmed, ['-E', '-e'])
  } else if (firstWord === 'ruby') {
    // -e, and merged clusters (-ne/-pe) whose code body follows the cluster.
    // The quoted-block fallback applies only when an inline flag is actually
    // present; an external `ruby script.rb 'arg'` must not be scanned.
    const hasInlineFlag = /(^|\s)-(?:e|n|p|[a-z]*[enp])\b/.test(trimmed)
    code = extractInlineCodeBody(trimmed, ['-e'])
      ?? (hasInlineFlag ? extractQuotedBody(trimmed) : null)
  } else {
    return null
  }
  if (code && INLINE_DESTRUCTIVE_RE.test(code)) {
    return {
      category: 'unknown',
      reason: `${firstWord} inline code deletes files or runs an unverifiable shell command`,
      targetPaths: [],
      mutates: true,
    }
  }
  return null
}

/** Destructive verbs carried by a `find -exec/-ok` or `fd -x/--exec` action. */
function actionVerbDestructive(trimmed: string): string | null {
  const re = /(?:--exec|-(?:exec(?:dir)?|ok|x))\s+(\S+)/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(trimmed))) {
    const verb = m[1].split('/').pop()?.toLowerCase() ?? ''
    if (FIND_DESTRUCTIVE_EXEC.has(verb)) return verb
  }
  return null
}

/**
 * B5 (g 轮): extract the trailing destination of a
 * `find -exec cp/mv/ln/install/tee {} DEST` (or `-execdir`) action so the
 * out-of-cwd destination is coverage-checked. The literal `\;`/`+` terminator
 * and the `{}` placeholder are dropped; the last real token is the DEST.
 */
function findExecDestinations(trimmed: string): string[] {
  const out: string[] = []
  const re = /(?:--exec|-(?:exec(?:dir)?|ok|x))\s+(\S+)([^;\n]*?)(?:\\?;\s*|(?:\+\s*))/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(trimmed))) {
    const verb = m[1].split('/').pop()?.toLowerCase() ?? ''
    if (!FIND_DESTRUCTIVE_EXEC.has(verb)) continue
    const tail = (m[2] ?? '').trim()
    if (!tail) continue
    const toks = tail.split(/\s+/).filter((t) => t && t !== '{}' && t !== ';' && t !== '+')
    if (toks.length === 0) continue
    const dst = toks[toks.length - 1].replace(/^["']|["']$/g, '')
    if (dst && !dst.startsWith('-')) out.push(dst)
  }
  return out
}

const SHELL_WRAP = new Set(['sh', 'bash', 'dash', 'zsh', 'ksh', 'tcsh', 'csh'])

/**
 * B3/B4: a shell interpreter wrapped behind `find -exec sh -c '...'` /
 * `fd -x bash -c '...'` whose quoted script body itself deletes files. The
 * interpreter may be an absolute path (`/bin/sh`), follow `env`, or be an
 * unresolved variable (`$SHELL`) — basename-normalize the token and fail closed
 * on a variable shell. The deletion target lives inside the script (often
 * `$0`/`$1`/`{}`) and cannot be resolved statically, so unknown is the verdict.
 */
function wrappedShellDeletes(trimmed: string): boolean {
  const actionRe = /(?:--exec|-(?:exec(?:dir)?|ok|x))/gi
  let am: RegExpExecArray | null
  while ((am = actionRe.exec(trimmed))) {
    const rest = trimmed.slice(am.index + am[0].length)
    // Only the quoted body that follows the -c flag is the script; a quoted
    // interpreter token before it (e.g. "$SHELL") must not be read as the body.
    const cm = rest.match(/(?:-[a-z]*c\s+)(?:'([^']*)'|"([^"]*)")/)
    if (!cm) continue
    const body = cm[1] ?? cm[2] ?? ''
    // B5/B6/B7: only a concrete deletion signal inside the body fails closed.
    // A bare command substitution (`$(...)`, backticks) or an inner interpreter
    // flag is read-only on its own (`$(basename)`, `python3 -c print`) and must
    // not deny. FS delete APIs require a receiver so a list `.remove()` or the
    // word "remove" in a string is not matched; the API surface is shared with
    // the direct inline detector to avoid direct/find drift.
    const fsDeleteApi = DELETE_API_SURFACE
    const directDelete =
      /\b(?:rm|rmdir|unlink|mv|rmtree|remove_tree|truncate|dd|trash)\b/.test(body) ||
      /(?:^|\s)-delete(?:\s|$)/.test(body) ||
      fsDeleteApi.test(body)
    const innerInterpDelete =
      /(?:python\d?|node|perl|ruby)\s+(?:-[ce]\b|--eval\b)/.test(body) &&
      fsDeleteApi.test(body)
    if (!directDelete && !innerInterpDelete) continue
    const lead = rest.slice(0, cm.index).trim()
    const tokens = lead.split(/\s+/).filter(Boolean)
    // Locate the interpreter: skip `env` (any absolute path), its options,
    // env NAME=value assignments, and the -c flag; accept a shell by basename,
    // fail closed on a variable or command-substituted token that cannot be
    // resolved.
    let interp = ''
    for (const t of tokens) {
      const clean = t.replace(/^["']|["']$/g, '')
      const base = clean.split('/').pop()?.toLowerCase() ?? ''
      if (
        base === 'env' ||
        clean.startsWith('-') ||
        /^[A-Za-z_][A-Za-z0-9_]*=/.test(clean)
      )
        continue
      interp = clean
      break
    }
    const base = interp.split('/').pop()?.toLowerCase() ?? ''
    const unresolved =
      base.startsWith('$') || interp.startsWith('`') || interp.startsWith('$(')
    if (SHELL_WRAP.has(base) || unresolved) return true
  }
  return false
}

/** Network/install verbs a `find -exec/-ok` / `fd -x` may launch directly. */
const FIND_EGRESS_VERB = new Set([
  'curl', 'wget', 'aria2c', 'axel', 'ncat', 'nc', 'netcat', 'telnet',
  'ftp', 'sftp', 'ssh', 'scp', 'rsync', 'git',
])

/** Package managers whose install/add/update/download/publish subcommands fetch remotely. */
const FIND_PKG_INSTALL_VERB = new Set([
  'pip', 'pip3', 'npm', 'npx', 'pnpm', 'yarn', 'gem', 'cargo', 'brew', 'uv',
])

/**
 * G1: a `find -exec/-ok` / `fd -x` action that reaches the network or installs
 * a package, either directly (`-exec curl …`) or inside a wrapped shell
 * (`-exec sh -c 'curl …' _ {} \;`). The read path never runs the egress scan,
 * so a smuggled network/install call otherwise rode through as a bare read with
 * no deny, checkpoint, or snapshot. Fail closed to unknown (not network) so a
 * `denyNetwork:false` override cannot resurrect it. Returns the signal label
 * when found, null when the action is offline/local.
 */
function wrappedEgressSignal(trimmed: string): string | null {
  const actionRe = /(?:--exec|-(?:exec(?:dir)?|ok|x))/gi
  let am: RegExpExecArray | null
  while ((am = actionRe.exec(trimmed))) {
    const rest = trimmed.slice(am.index + am[0].length)

    // Direct verb: skip env, its options, NAME=value assignments, flags, then
    // read the launch token basename.
    const leadBody = rest.split(/\s+(?:'[^']*'|"[^"]*")/)[0]
    const leadTokens = leadBody.split(/\s+/).filter(Boolean)
    let verb = ''
    for (const t of leadTokens) {
      const clean = t.replace(/^["']|["']$/g, '')
      const base = clean.split('/').pop()?.toLowerCase() ?? ''
      if (
        base === 'env' ||
        clean.startsWith('-') ||
        /^[A-Za-z_][A-Za-z0-9_]*=/.test(clean)
      ) continue
      verb = base
      break
    }
    if (FIND_EGRESS_VERB.has(verb)) {
      if (verb === 'git') {
        const gm = rest.match(/\bgit\s+(push|pull|clone|fetch|ls-remote|remote)\b/)
        if (gm) return `git ${gm[1]}`
      } else {
        return verb
      }
    }

    // Direct package-manager install/fetch with no shell wrapper (fd -x pip install x).
    if (
      FIND_PKG_INSTALL_VERB.has(verb) &&
      /\b(install|add|update|download|publish|uninstall)\b/.test(rest)
    ) {
      return 'package install'
    }

    // Wrapped shell body: only the quoted body after -c is the script.
    const cm = rest.match(/(?:-[a-z]*c\s+)(?:'([^']*)'|"([^"]*)")/)
    if (!cm) continue
    const body = cm[1] ?? cm[2] ?? ''
    // A bare network verb in a direct interpreter code body (python/node/perl/ruby
    // -c/-e) may live in a comment or string; those bodies are covered by the
    // dedicated inline egress / shell-out rules. Only a real shell wrapper uses the
    // bare-verb scan.
    const shellNet =
      !FIND_INLINE_INTERP.has(verb) &&
      /(?:^|[\s;|&`$()])(curl|wget|aria2c|axel|ncat|netcat|nc|telnet|ftp|sftp|ssh|scp|rsync)\s+/.test(body)
    const gitRemote = /\bgit\s+(push|pull|clone|fetch|ls-remote|remote)\b/.test(body)
    const pkgMgr =
      /\b(pip3?|npm|npx|pnpm|yarn|gem|cargo|brew|uv)\b[^\n;]*\b(install|add|update|download|publish|uninstall)\b/.test(body)
    const innerPyNet =
      /python\d?\s+-[ce]\b[^\n]*(urllib|requests\.(get|post|urlopen)|urlopen|http\.client|socket\.create_connection|socket\.socket)/.test(body)
    const innerNodeNet =
      /node\s+-(?:e|eval)\b[^\n]*(https?\.request|fetch\(|new\s+WebSocket|net\.connect)/.test(body)
    if (shellNet) return 'shell network command'
    if (gitRemote) return 'git remote'
    if (pkgMgr) return 'package install'
    if (innerPyNet) return 'inline python network'
    if (innerNodeNet) return 'inline node network'
  }
  return null
}

/** Interpreters that may appear directly as a find/fd action verb (no sh wrapper). */
const FIND_INLINE_INTERP = new Set([
  'perl', 'perl5', 'ruby', 'python', 'python3', 'python3.12', 'node', 'nodejs',
  'php', 'php-cli',
])

/**
 * G3b/G3c: inline interpreter network APIs reachable through a find/fd action
 * verb directly (`-exec python3 -c urlopen`) or inside the wrapped shell body.
 * The read path never egress-scans these, so fail closed on a match.
 */
const FIND_INLINE_EGRESS_RE = new RegExp([
  /urllib(?:\.request)?/,
  /requests\.(?:get|post|urlopen|request)\b/,
  /urlopen\s*\(/,
  /http\.client/,
  /socket\.(?:socket|create_connection)\b/,
  /\bfetch\s*\(/,
  /https?\.request\s*\(/,
  /require\(\s*\\?['"](?:https?|net)\\?['"]\s*\)/,
  /new\s+WebSocket\b/,
  /net\.connect\s*\(/,
  /LWP::(?:Simple|UserAgent)\b/,
  /\buse\s+LWP\b/,
  /Net::HTTP\b/,
  /net\/http/,
  /open-uri/,
  /IO::Socket(?:::(?:INET|SSL))?\b/,
  /require\s*\(\s*["']socket["']\s*\)/,
  /require\s+["']socket["']/,
  /\bTCPSocket\b/,
  /\bUDPSocket\b/,
].map((r) => r.source).join('|'))

/**
 * H2: interpreter action bodies inside `find … -exec <interp> -e …` are never
 * egress-scanned by the hook (the find read path skips it), so ANY process
 * spawn / shell-out / create-copy primitive inside the inline code fails
 * closed. The direct-command FileUtils cp/mkdir narrowing contract does NOT
 * apply here: the find body is opaque and its target paths are unknown.
 */
const FIND_FIND_DESTRUCTIVE_RE = new RegExp([
  INLINE_DESTRUCTIVE_RE.source,
  /\bFileUtils\.(?:cp|cp_r|mv|mkdir|mkdir_p|touch)\b/,
  /\bFile\.new\s*\([^)]*['"](?:w|a|r\+|w\+|wb|ab|wt)/,
  /\bopen\s*\([^)]*['"]>/,
  /\bfile_put_contents\s*\(/,
  /\bfwrite\s*\(/,
  /\b([A-Za-z_]\w*)\s*=\s*File\b(?![:\w])[\s\S]*?\b\1\s*\.\s*(?:write|binwrite|truncate|delete|unlink)\s*\(/,
  /\bKernel\.(?:system|exec)\b/,
  /\bqx\b/,
  /`[^`]*`/,
].map((r) => (typeof r === 'string' ? r : r.source)).join('|'))

/** Perl `-M`/`-m` and ruby `-r` network modules carried on the load flag rather
 *  than inside the extracted code body; a match fails closed on egress. */const FIND_NET_PERL_FLAG = /(?:^|[\s=])-[mM]\s*=?\s*['"]?[A-Za-z0-9:]+['"]?/g
const FIND_NET_RUBY_FLAG = /(?:^|[\s=])-r\s*=?\s*['"]?[A-Za-z0-9_\/-]+['"]?/g
const FIND_NET_PERL_MODULES = new Set([
  'LWP', 'LWP::Simple', 'LWP::UserAgent', 'IO::Socket::INET',
  'IO::Socket', 'IO::Socket::SSL',
])
const FIND_NET_RUBY_MODULES = new Set([
  'net/http', 'open-uri', 'net/ping', 'socket', 'open3',
])

/** G4c/G5: a subprocess / os.exec* / child-process shell-out that launches a
 *  network command, or python `shell=True`. A bare `subprocess.run(['ls'])` /
 *  `os.execvp('ls')` / `spawnSync('ls')` with a non-network argv stays allowed. */
const FIND_SHELLOUT_RE = new RegExp([
  /subprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True/,
  /subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*\[\s*['"](?:curl|wget|aria2c|axel|ncat|netcat|nc|telnet|ftp|sftp|ssh|scp|rsync)['"]/,
  /subprocess\.(?:getoutput|getstatusoutput)\s*\(\s*['"][^'"]*(?:curl|wget|aria2c|axel|ncat|netcat|nc|telnet|ftp|sftp|ssh|scp|rsync)/,
  /os\.(?:exec[a-z]*|posix_spawn|popen[234]?)\s*\(\s*['"][^'"]*(?:curl|wget|aria2c|axel|ncat|netcat|nc|telnet|ftp|sftp|ssh|scp|rsync)/,
  /require\(\s*\\?['"]child_process\\?['"]\s*\)\s*\.\s*(?:spawn|spawnSync|fork|execFile|execFileSync|exec|execSync)\s*\(\s*['"][^'"]*(?:curl|wget|aria2c|axel|ncat|netcat|nc|telnet|ftp|sftp|ssh|scp|rsync)/,
].map((r) => r.source).join('|'))

/** Network module carried on a perl `-M`/`-m` or ruby `-r` load flag. */
function moduleFlagEgress(action: string, verb: string): string | null {
  if (verb === 'perl' || verb === 'perl5') {
    let m: RegExpExecArray | null
    FIND_NET_PERL_FLAG.lastIndex = 0
    while ((m = FIND_NET_PERL_FLAG.exec(action))) {
      const mod = m[0].replace(/^[\s=]-[mM]\s*=?\s*/, '').replace(/^['"]|['"]$/g, '')
      if (FIND_NET_PERL_MODULES.has(mod)) return `perl load flag ${mod}`
    }
  }
  if (verb === 'ruby') {
    let m: RegExpExecArray | null
    FIND_NET_RUBY_FLAG.lastIndex = 0
    while ((m = FIND_NET_RUBY_FLAG.exec(action))) {
      const mod = m[0].replace(/^[\s=]-r\s*=?\s*/, '').replace(/^['"]|['"]$/g, '')
      if (FIND_NET_RUBY_MODULES.has(mod)) return `ruby load flag ${mod}`
    }
  }
  return null
}

/** Extract the quoted code after -c/-e/-E/--eval from an action substring. */
function findInlineCode(action: string): string | null {
  // H2: php uses `-r`/`-R` for inline code (ruby -e, perl -e/-E, python -c,
  // node -e/--eval). F1-b: `"…\"…\"…"` keeps escaped quotes INSIDE the body
  // (a double-quoted -c/-e body may embed escaped quotes) — extract with an
  // escape-aware double-quote branch.
  const m = action.match(/-(?:c|e|E|r|R|eval)\s*(?:'([^']*)'|"((?:[^"\\\n]|\\.)*)")/)
  return m ? (m[1] ?? m[2] ?? null) : null
}

/**
 * G3: a find/fd action that runs an interpreter inline — directly as the action
 * verb (`-exec perl -e unlink`, `-exec python3 -c urlopen`) or inside the wrapped
 * shell body (`sh -c 'node -e require("http")…'`), plus one nested sh/bash -c
 * layer. Deletion uses the shared destructive surface; network uses the inline
 * egress API set. Returns { kind, signal } or null when offline/local.
 */
/**
 * H3b/F1: the FIRST argument of a process launcher call must be a string
 * literal — a variable (`os.popen(c)`), a concatenation (`'cu'+'rl'`) or a
 * list/other expression hides the executed command from static analysis.
 * Literal argv stays on the per-target egress path (G5/G6 contract).
 */
function nonLiteralLaunchArg(code: string, callRe: RegExp): string | null {
  // Module-level global regexes leak lastIndex across calls — reset before
  // scanning or a match early in a previous code string skips later calls.
  callRe.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = callRe.exec(code))) {
    const openIdx = m.index + m[0].length - 1
    let depth = 0
    let i = openIdx
    for (; i < code.length; i++) {
      if (code[i] === '(') depth++
      else if (code[i] === ')') {
        depth--
        if (depth === 0) break
      }
    }
    const args = code.slice(openIdx + 1, i)
    // FP-1: split the first argument at the first top-level comma (bracket
    // depth 0) — `['ls','-la']` must yield `['ls','-la']` as ONE argument,
    // not `['ls'`. A bare `split(',')` broke multi-element literal argv lists.
    let first = ''
    let bdepth = 0
    for (let k = 0; k < args.length; k++) {
      const ch = args[k]
      if (ch === '[' || ch === '{' || ch === '(') bdepth++
      else if (ch === ']' || ch === '}' || ch === ')') bdepth--
      else if (ch === ',' && bdepth === 0) {
        first = args.slice(0, k).trim()
        break
      }
    }
    if (!first) first = args.trim()
    if (!first) return 'launcher with an empty first argument'
    // A pure string literal or a pure literal list (['ls'] / 'ls' — no
    // concatenation, no interpolated variable) keeps the per-target egress
    // path (FIND_SHELLOUT_RE adjudicates curl/wget/…); `'cu'+'rl'`, a bare
    // variable or a nested expression hides the executed command.
    const PURE_LAUNCH_ARG =
      /^(?:['"](?:[^"'\\\n]|\\.)*['"]|\[\s*(?:['"](?:[^"'\\\n]|\\.)*['"]\s*(?:,\s*['"](?:[^"'\\\n]|\\.)*['"])*\s*)?\])$/
    if (!PURE_LAUNCH_ARG.test(first)) {
      return `launcher first argument not a pure literal: ${first.slice(0, 40)}`
    }
  }
  return null
}

/** Replace string-literal contents with empty quotes so bare-verb nets do not
 * trip on WORDS INSIDE strings (`puts "operating system check"` contains
 * "system"). Structural strings that the nets must inspect (pipe-open "-|",
 * heredoc delimiters) keep their original form and are tested on `code`. */
function maskStringLiterals(code: string): string {
  return code
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
}

const NONPY_LAUNCH_WORD =
  /\b(?:system|spawn|popen|passthru|proc_open|pcntl_exec|shell_exec|exec|fork)\b/

const PY_FIND_LAUNCH_RE =
  /\b(?:os\.(?:popen|exec[a-z]*|posix_spawn)|subprocess\.(?:run|Popen|call|check_call|check_output|getoutput|getstatusoutput))\s*\(/g
const NODE_LAUNCH_RE =
  /(?:require\(\s*['"]child_process['"]\s*\)|child_process)\s*\.\s*(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\(/g

function findActionInlineThreat(trimmed: string, depth = 0): { kind: 'delete' | 'egress'; signal: string } | null {
  if (depth >= 4) {
    // A wrapped-shell chain deeper than 4 layers is unverifiable — the find
    // action runs opaque nested commands; fail closed on the destructive side.
    return { kind: 'delete', signal: 'nested wrapped shell exceeds depth limit' }
  }
  const actionRe = /(?:--exec|-(?:exec(?:dir)?|ok|x))/gi
  let am: RegExpExecArray | null
  while ((am = actionRe.exec(trimmed))) {
    const action = trimmed.slice(am.index + am[0].length)

    // Direct interpreter verb: skip env, options, NAME=value, read the token.
    const tokens = action.split(/\s+/).filter(Boolean)
    let verb = ''
    for (const t of tokens) {
      const clean = t.replace(/^["']|["']$/g, '')
      const base = clean.split('/').pop()?.toLowerCase() ?? ''
      if (
        base === 'env' ||
        clean.startsWith('-') ||
        /^[A-Za-z_][A-Za-z0-9_]*=/.test(clean)
      ) continue
      verb = base
      break
    }
    if (FIND_INLINE_INTERP.has(verb)) {
      const code = findInlineCode(action)
      if (code) {
        // H2: find bodies are opaque and never egress-scanned downstream —
        // use the widened find-specific destructive surface (delete + create
        // + copy + spawn + shell-out).
        if (FIND_FIND_DESTRUCTIVE_RE.test(code)) return { kind: 'delete', signal: `${verb} inline delete/spawn` }
        if (FIND_INLINE_EGRESS_RE.test(code)) return { kind: 'egress', signal: `${verb} inline network` }
        if (FIND_SHELLOUT_RE.test(code)) return { kind: 'egress', signal: `${verb} subprocess shell-out` }
        if (!/^python/.test(verb)) {
          // H2/H3b/F1: ruby/perl/php launchers are opaque — any process
          // primitive fails closed; a benign literal is NOT statically trusted
          // for these languages. Bare-verb words are tested on string-masked
          // code (puts "system" stays read); pipe-open patterns need the
          // original string content so they run on `code`.
          const masked = maskStringLiterals(code)
          if (NONPY_LAUNCH_WORD.test(masked) ||
              // F1-a: Open3 family (capture2/capture2e/capture3/popen2/
              // popen3/pipeline) spawns subprocesses — 37ac047 covered it,
              // the NONPY word list lost it.
              /\bOpen3\s*\.\s*(?:capture2e?|capture3|popen[23]?|pipeline)\s*\(/.test(masked) ||
              /%x\s*[({[]/.test(code) ||
              /Kernel\.(?:send|public_send|__send__)\s*\(/.test(masked) ||
              /IPC::Open[23]\b|\bopen[23]\s*\(/.test(masked) ||
              /open\s*\([^)]*["']-\|["']/.test(code) ||
              /open\s*\([^)]*["']\|-["']/.test(code)) {
            return { kind: 'delete', signal: `${verb} inline launcher` }
          }
        }
        // H2/F1: node exec/execSync run a command STRING through a shell —
        // cannot be proven safe even for a literal; node spawnSync/execFileSync
        // stay on the g-round per-target path (benign spawnSync('ls') stays
        // read) but a non-literal first argument fails closed.
        if ((verb === 'node' || verb === 'nodejs')) {
          if (/\b(?:execSync|exec)\s*\(/.test(code)) {
            return { kind: 'delete', signal: `node inline command-string exec` }
          }
          const nodeThreat = nonLiteralLaunchArg(code, NODE_LAUNCH_RE)
          if (nodeThreat) return { kind: 'delete', signal: `node ${nodeThreat}` }
        }
        // F1: python launcher with a non-literal first argument (os.popen(c),
        // os.execvp('cu'+'rl', …), subprocess.run(cmd)) — literal argv is
        // adjudicated by FIND_SHELLOUT_RE / FIND_INLINE_EGRESS_RE below.
        if (/^python/.test(verb)) {
          const pyThreat = nonLiteralLaunchArg(code, PY_FIND_LAUNCH_RE)
          if (pyThreat) return { kind: 'delete', signal: `python ${pyThreat}` }
        }
      }
      const flag = moduleFlagEgress(action, verb)
      if (flag) return { kind: 'egress', signal: flag }
      // B4 (g 轮): an interpreter with a SCRIPT FILE argument and no -e/-c
      // (`-exec ruby evil.rb {}`) executes an opaque program the read path
      // never scans — fail closed, same posture as awk -f.
      const actionToks = action.split(/\s+/).filter(Boolean)
      const hasInlineFlag = /-(?:e|c|E|n|p|ne|pe|np|pn)\b/.test(action)
      let interpSeen = false
      for (const t of actionToks) {
        const clean = t.replace(/^["']|["']$/g, '')
        const base = clean.split('/').pop()?.toLowerCase() ?? ''
        if (base === verb && !interpSeen) { interpSeen = true; continue }
        if (interpSeen && !clean.startsWith('-') && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(clean)) {
          if (!hasInlineFlag && /\.(?:rb|py|pl|pm|php|js|mjs|cjs)$/.test(clean)) {
            return { kind: 'delete', signal: `${verb} script file (${clean})` }
          }
          break
        }
      }
      // Fallback scan the whole action when nested quotes truncate the extracted
      // code body; the shell-out rule already requires a literal network program.
      if (FIND_SHELLOUT_RE.test(action)) return { kind: 'egress', signal: `${verb} subprocess shell-out` }
    }

    // Wrapped shell body: delete surface + inline egress APIs, one nested layer.
    const cm = action.match(/(?:-[a-z]*c\s+)(?:'([^']*)'|"((?:[^"\\]|\\.)*)")/)
    if (cm) {
      // Keep the extracted body ESCAPED (`\"` stays `\"`): the recursion below
      // re-reads it through findInlineCode, whose escape-aware quote branch
      // handles `\"`; unescaping here first collapsed the inner quotes and
      // truncated `-e "require(\"child_process\")…"` at `require(`.
      const body = cm[1] ?? cm[2] ?? ''
      if (FIND_FIND_DESTRUCTIVE_RE.test(body)) return { kind: 'delete', signal: 'wrapped inline delete/spawn' }
      if (FIND_INLINE_EGRESS_RE.test(body)) return { kind: 'egress', signal: 'wrapped inline network' }
      if (FIND_SHELLOUT_RE.test(body)) return { kind: 'egress', signal: 'wrapped subprocess shell-out' }
      // F1-b: the wrapped body is an arbitrary command — recurse through the
      // inline-interpreter adjudicator so node/python/… launchers inside
      // `sh -c 'node -e "…"'` fail closed exactly like a direct `-exec node`.
      // Depth is bounded (a nested `sh -c 'sh -c …'` chain cannot run forever).
      const innerThreat = findActionInlineThreat(`-exec ${body} {} ;`, 1)
      if (innerThreat) {
        return { kind: innerThreat.kind, signal: `wrapped ${innerThreat.signal}` }
      }
      const nm = body.match(/(?:sh|bash|dash|zsh)\s+-[a-z]*c\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")/)
      if (nm) {
        const inner = nm[1] ?? nm[2] ?? ''
        const nestedNet =
          /(?:^|[\s;|&`$()])(curl|wget|aria2c|axel|ncat|netcat|nc|telnet|ftp|sftp|ssh|scp|rsync)\s+/.test(inner) ||
          /\bgit\s+(push|pull|clone|fetch|ls-remote|remote)\b/.test(inner) ||
          /\b(pip3?|npm|npx|pnpm|yarn|gem|cargo|brew|uv)\b[^\n;]*\b(install|add|update|download|publish|uninstall)\b/.test(inner) ||
          FIND_INLINE_EGRESS_RE.test(inner)
        if (nestedNet) return { kind: 'egress', signal: 'nested shell network' }
      }
    }
  }
  return null
}

/**
 * B2: `find -delete`, `find -exec/-ok rm`, and `fd -x/--exec rm` that
 * READ_COMMANDS would call read but actually deletes/mutates matched files.
 * Returns a write/unknown result, or null when the command is read-only.
 */
function detectDestructiveRead(trimmed: string, firstWord: string): ClassifyResult | null {
  if (firstWord === 'find' || firstWord === 'fd') {
    const hasDelete = /(^|\s)-delete(\s|$)/.test(trimmed)
    const actionVerb = actionVerbDestructive(trimmed)
    const wrapped = wrappedShellDeletes(trimmed)
    if (wrapped && !hasDelete && !actionVerb) {
      return {
        category: 'unknown',
        reason: `${firstWord} wraps a shell script that deletes files; target cannot be resolved statically`,
        targetPaths: [],
        mutates: true,
      }
    }
    if (hasDelete || actionVerb) {
      const start = extractFindStart(trimmed)
      const action = hasDelete ? '-delete' : `-${actionVerb}`
      const targets = hasDelete
        ? (start ? [start] : [])
        : (start ? [start, ...findExecDestinations(trimmed)] : findExecDestinations(trimmed))
      if (targets.length > 0) {
        return {
          category: 'file_write',
          reason: `${firstWord} mutates matched files (${action})`,
          targetPaths: targets,
          mutates: true,
        }
      }
      return {
        category: 'unknown',
        reason: `${firstWord} mutation (${action}) with no resolvable target path`,
        targetPaths: [],
        mutates: true,
      }
    }
    // G3: interpreter inline code run directly as the action verb or inside the
    // wrapped shell (delete surface / inline network API), incl. one nested layer.
    const inlineThreat = findActionInlineThreat(trimmed)
    if (inlineThreat) {
      return {
        category: 'unknown',
        reason:
          inlineThreat.kind === 'delete'
            ? `${firstWord} action runs inline code that deletes files; target cannot be resolved statically (${inlineThreat.signal})`
            : `${firstWord} action reaches the network via inline interpreter code (${inlineThreat.signal}); cannot prove offline`,
        targetPaths: [],
        mutates: inlineThreat.kind === 'delete',
      }
    }
    // G1: network/install smuggled through a find/fd action or its wrapped
    // shell; the read path never egress-scans, so fail closed here.
    const egress = wrappedEgressSignal(trimmed)
    if (egress) {
      return {
        category: 'unknown',
        reason: `${firstWord} action reaches the network or installs packages (${egress}); cannot prove offline`,
        targetPaths: [],
        mutates: false,
      }
    }
  }
  return detectInlineDestructiveCode(trimmed, firstWord)
}

/**
 * B4: editor hosts (vim/nvim/vi/emacs/ex/ed) executing shell escapes or
 * writing through -c/--eval command strings that the write-path extractor
 * cannot see (`vim -es -c ':w /abs/outside' -c q f`, `emacs --eval
 * "(shell-command …)"`). Fail closed to unknown.
 */
function detectEditorCommandInjection(
  trimmed: string,
  firstWord: string,
): ClassifyResult | null {
  const cmd = trimmed
  if (firstWord === 'vim' || firstWord === 'nvim' || firstWord === 'vi' ||
      firstWord === 'ex' || firstWord === 'ed') {
    const cmds = [...cmd.matchAll(/(?:-c|--cmd|-s|-es)\s+(?:"([^"]*)"|'([^']*)'|([^\s-][^\s]*))/g)]
    for (const m of cmds) {
      const c = m[1] ?? m[2] ?? m[3]
      if (/:!|:silent\s*!|:bd?!|:r\s*!|^!/m.test(c)) {
        return { category: 'unknown', reason: `vim/ex -c shell escape: ${c.slice(0, 60)}`, targetPaths: [], mutates: true }
      }
      const wm = c.match(/:w(?:rite)?!?\s+(?:"([^"]+)"|'([^']+)'|(\S+))/)
      if (wm) {
        const target = wm[1] ?? wm[2] ?? wm[3]
        if (target.startsWith('/') || target.startsWith('~') || target.includes('..')) {
          return { category: 'unknown', reason: `vim/ex -c write to escape path: ${target.slice(0, 60)}`, targetPaths: [], mutates: true }
        }
      }
      // embedded interpreter escapes inside the editor command string
      // (`vim -Es -c "lua os.execute('id')"`, `-c "py3 eval(...)"`).
      if (/os\.execute\s*\(|luaeval\s*\(|py3?eval\s*\(|py3?do\s+|\b:lua\b|exe\s*\(/.test(c)) {
        return { category: 'unknown', reason: `editor command embeds interpreter execution: ${c.slice(0, 60)}`, targetPaths: [], mutates: true }
      }
      // A -c value that STARTS an embedded interpreter (vim `-c 'lua …'`,
      // `-c 'py3 …'`, `-c 'perl …'`, `-c 'ruby …'`) is a code-carrying host
      // whose body cannot be statically verified — fail closed.
      if (/^(?:lua|py3?|python|perl|ruby|php)\b/.test(c.trim())) {
        return { category: 'unknown', reason: `editor -c runs embedded interpreter: ${c.slice(0, 60)}`, targetPaths: [], mutates: true }
      }
    }
    // A -s/-S script FILE fed to the editor executes arbitrary command
    // stream the static checker cannot see (vim -s /tmp/cmds.vim).
    const scriptM = cmd.match(/(?:^|[\s;|&])vim\s+(?:-\w+\s+)*-s\s+(\S+)|(?:^|[\s;|&])vim\s+(?:-\w+\s+)*-S\s+(\S+)/)
    if (scriptM) {
      return { category: 'unknown', reason: `vim -s script file (unverifiable command stream): ${scriptM[1] ?? scriptM[2]}`, targetPaths: [], mutates: true }
    }
  }
  if (firstWord === 'emacs') {
    const evals = [...cmd.matchAll(/(?:--eval|-e|--funcall)\s+(?:"([^"]*)"|'([^']*)'|([^\s-][^\s]*))/g)]
    for (const m of evals) {
      const e = m[1] ?? m[2] ?? m[3]
      if (/shell-command|call-process|start-process|write-region|process-\w+/.test(e)) {
        return { category: 'unknown', reason: `emacs eval executes/writes: ${e.slice(0, 60)}`, targetPaths: [], mutates: true }
      }
    }
  }
  return null
}

/**
 * B4: ex/ed/vim silent mode fed an editing command stream via a pipe/printf
 * whose body writes an absolute path or invokes a shell command
 * (`printf 'w /tmp/x' | ex -s f`). The editor's write target lives in the
 * OTHER segment's payload, invisible to this segment's path extractor.
 */
function detectStdinEditorEscape(command: string): ClassifyResult | null {
  // H5: `ed`/`ex`/`vim -es` fed by a stream is a stdin editor; the `-s`
  // silent flag is NOT required (`echo '!id' | ed f.txt` executes the escape
  // and `printf 'wq /etc/x\n' | ex -s f.txt` writes the named target). A bare
  // interactive `ed f.txt` (no pipe) keeps its historical classification.
  const hasEditor = /\b(?:ex|ed)\b|\bvim\s+(?:-[\w]+\s+)*-es\b/i.test(command)
  if (!hasEditor) return null
  if (!/\|/.test(command)) return null
  // Write-and-quit / ranged write commands with an absolute, ~ or escaping
  // target: `w /abs`, `wq /abs`, `wq! /abs`, `x /abs`, `N,Mw /abs`.
  if (/\bw(?:rite)?!?\s+(?:\/|~|\S*\.\.)/.test(command) ||
      /\b[0-9,$]*\s*w\s+(?:\/|~|\S*\.\.)/.test(command) ||
      /\bwq!?\s+(?:\/|~|\S*\.\.)/.test(command) ||
      /\bx\s+(?:\/|~|\S*\.\.)/.test(command)) {
    return { category: 'unknown', reason: `stdin editor writes an absolute/escape path`, targetPaths: [], mutates: true }
  }
  // Shell escapes: `!cmd` (any position), `r !cmd`, `. !cmd`, `%!cmd`.
  if (/["'](?:[^"']*)(?:^|\\)n!|["'][^"']*r\s+!\s|["'][^"']*!\s\S/.test(command) ||
      /\b(?:printf|echo)\s+["'][^"']*!/.test(command)) {
    return { category: 'unknown', reason: `stdin editor receives a shell-escape command line`, targetPaths: [], mutates: true }
  }
  return null
}

/**
 * Detect `find … -name <sensitive-name> -exec <read-cmd> {}` — a read channel
 * whose sensitive path only appears as a pattern + `{}` placeholder, invisible
 * to the literal-path scan. Returns a synthetic sensitive path (or null).
 */
function scanFindExecForSensitiveRead(
  s: string,
  denyReadPaths: string[],
): string | null {
  if (!/(?:^|[;&|]\s*)find\s+/.test(s)) return null
  const nm = /-name\s+(?:"([^"]+)"|'([^']+)'|(\S+))/.exec(s)
  if (!nm) return null
  const name = (nm[1] ?? nm[2] ?? nm[3]).trim()
  if (!SENSITIVE_FIND_NAMES.has(name)) return null
  const em = /-exec\s+(\S+)(?:\s+.*)?\{\}\s*\\?[;+]/.exec(s)
  if (!em) return null
  const exe = em[1].split('/').pop()?.toLowerCase() ?? ''
  if (!FIND_READ_EXEC.has(exe)) return null
  // Synthesize a path under the ssh-style deny prefix so the deny layer
  // rejects it; falls back to the first configured prefix.
  const sshLike = denyReadPaths.find((p) =>
    /(?:^|\/)(?:\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config)$/.test(expandHome(p).replace(/\/+$/, '')),
  )
  return sshLike ? `${sshLike.replace(/\/+$/, '')}/${name}` : null
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
/**
 * Normalize shell HOME parameter-expansion forms so downstream path matching
 * sees a canonical `$HOME`. Covers `${HOME:?}` (and other ${HOME...} forms)
 * plus a leading `VAR=$HOME` assignment whose later `$VAR` references alias
 * HOME — both are the B2 read-side bypass shapes (`cat ${HOME:?}/.ssh/x`,
 * `H=$HOME cat $H/.ssh/x`).
 */
function normalizeEnvForms(command: string): string {
  let s = command.replace(/\$\{HOME(?:[:+=-][^}]*)?\}/g, '$HOME')
  const assign = /(?:^|[\s;|&])([A-Za-z_][A-Za-z0-9_]*)=(\$HOME|\$\{HOME\})(?:\s|$)/.exec(s)
  if (assign && assign[1] !== 'HOME') {
    s = s.replace(new RegExp(`\\$${assign[1]}(?![A-Za-z0-9_])`, 'g'), '$HOME')
  }
  return s
}

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

  // B2: normalize ${HOME...} / $H-alias expansions before any path extraction.
  command = normalizeEnvForms(command)

  // B4: ex/ed/vim silent-mode editing streams whose payload writes an
  // absolute path or shells out — cross-segment, checked on the whole line.
  const stdinEditor = detectStdinEditorEscape(command)
  if (stdinEditor) return stdinEditor

  const segments = splitCommandSegments(command)

  if (segments.length === 0) {
    return { category: 'read', reason: 'Empty command', targetPaths: [] }
  }

  // H3b/F4: a segment reading interpreter CODE from stdin (`python3 -`,
  // `node /dev/stdin`, …) is unverifiable — the code may arrive from an
  // upstream pipeline (already split away here) or the terminal, neither is
  // on the command line. Fail closed. Heredoc-fed interpreters were collapsed
  // by stripHeredocs and keep their historical scanned path.
  const stdinCode = segments.find((p) =>
    /^(?:ruby|perl|php|python\d*|node|nodejs)\s+(?:\/dev\/(?:stdin|fd\/\d+)|-)\s*$/.test(p.trim()))
  if (stdinCode) {
    return {
      category: 'unknown',
      reason: `interpreter reads code from stdin (unverifiable): ${stdinCode.trim().slice(0, 60)}`,
      targetPaths: [],
    }
  }

  const results = segments.map((p) => classifySingleCommand(p, denyReadPaths))

  // Track `cd` across segments so relative paths after `cd dir && …` resolve
  // under `dir` instead of the process cwd (prevents false denials for
  // archive/move/truncate chains inside a subdirectory). The extracted paths
  // are re-resolved per segment against the directory in effect there.
  const cdPattern = /^cd\s+(?:--\s+)?(?:"([^"]*)"|'([^']*)'|(\S+))/i
  let baseDir = process.cwd()
  const resolvedReads: string[] = []
  const resolvedWrites: string[] = []
  const denyPrefixes = denyReadPaths.map((p) => expandHome(p).replace(/\/+$/, ''))
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
    // Preserve targets the per-segment classifier resolved itself (e.g. the
    // starting directory of `find -delete`/`find -exec rm`) when the generic
    // token extractor cannot read the find grammar.
    const segResult = results[i]
    if (segResult && segResult.category === 'file_write') {
      for (const p of segResult.targetPaths) {
        resolvedWrites.push(toAbsolute(p, dir))
      }
    }
    for (const p of extractReadPaths(s)) {
      resolvedReads.push(toAbsolute(p, dir))
    }
    // Command substitution bodies ($(...) / `…`) are re-classified as their
    // own commands: `echo $(cat ~/.ssh/id_rsa)` must be denied even though
    // the outer segment is just echo + a token. B7: a substitution's verdict
    // is part of the segment — `echo $(cp a /outside)` / `echo $(ruby -e
    // 'File.write(...)')` must not be absorbed as a benign read.
    // F2: bash re-unescapes nested backtick bodies one layer per re-parse
    // (`echo \`echo \\\`id\\\`\`` executes the innermost `id`) — unescape to
    // a fixpoint, re-extract, and re-classify at every layer so a command
    // hidden behind ≥2 escaped backtick layers (gzip -I sh at depth 2) fails
    // closed here just like in index.ts's deep loop.
    for (const { body, bt } of extractCommandSubstitutions(s)) {
      let inner = classifyBashCommand(body, denyReadPaths)
      let cur = body
      for (let g = 0; g < 8; g++) {
        const norm = unescapeSubstitutionBody(cur, bt)
        if (norm === cur) break
        const ci = classifyBashCommand(norm, denyReadPaths)
        if (PRIORITY.indexOf(ci.category) < PRIORITY.indexOf(inner.category)) {
          inner = ci
        }
        const nxt = extractCommandSubstitutions(norm)
        if (nxt.length === 0) break
        cur = nxt[0]!.body
      }
      if (inner.forceDeny) {
        resolvedReads.push(...(inner.targetPaths.length > 0 ? inner.targetPaths : [dir]))
      }
      if (PRIORITY.indexOf(inner.category) < PRIORITY.indexOf(results[i].category)) {
        results[i] = {
          ...inner,
          reason: `Command substitution ${inner.category}: ${inner.reason}`,
        }
        // resolvedWrites was collected before this merge; fold in the
        // substitution's targets so `echo $(cp a /etc/evil2)` reports /etc/evil2.
        for (const p of inner.targetPaths ?? []) {
          resolvedWrites.push(toAbsolute(p, dir))
        }
      } else if (inner.category === 'file_write' && results[i].category === 'file_write') {
        // Same severity: union the write targets. Without this,
        // `cat x > >(tee /etc/evil)` keeps the process-substitution token
        // itself (`>(tee …`) as the target and loses /etc/evil.
        results[i] = {
          ...results[i],
          targetPaths: [...new Set([...(results[i].targetPaths ?? []), ...(inner.targetPaths ?? [])])],
        }
        // resolvedWrites was collected from the pre-merge segment; fold in the
        // substitution's targets so the final path check sees /etc/evil.
        for (const p of inner.targetPaths ?? []) {
          resolvedWrites.push(toAbsolute(p, dir))
        }
      }
    }
    // Interpreter -c/-e code strings: scan for sensitive path references the
    // token extractor cannot see (python3 -c "print(open('/Users/alice/.ssh/id_rsa').read())").
    const firstWordCode = s.trim().split(/\s+/)[0]?.toLowerCase().split('/').pop() ?? ''
    // R11-followup: versioned/ABI python names (python3.12, python3.12m,
    // pypy3) share python3's -c inline-code surface — the hardcoded map only
    // knows the bare literals, so mirror PY_INTERPRETER_RE here or a
    // `python3.12 -c "print(open('/Users/x/.ssh/id_rsa').read())"` would
    // slip the sensitive-path scan entirely.
    const codeFlags =
      PY_INTERPRETER_RE.test(firstWordCode) ? ['-c'] : INTERPRETER_CODE_FLAGS[firstWordCode]
    if (codeFlags) {
      for (const flag of codeFlags) {
        // R14 W1: escape-aware extraction (\" inside an inner quoted string
        // must not truncate the code).
        const codeText = extractFlagArgument(s, flag)
        if (codeText) {
          for (const hit of scanCodeForSensitivePaths(codeText, denyReadPaths)) {
            resolvedReads.push(hit)
          }
        }
      }
    }
    // cd-context: a segment executed inside a denyReadPaths directory exposes
    // that directory even with no path argument (`cd ~/.ssh && ls`) or with a
    // bare relative name (`cd ~/.ssh && cat id_rsa` — `id_rsa` has no '/', so
    // extractReadPaths would not collect it). Treat any non-echo/printf/cd
    // segment running inside a sensitive dir as a sensitive read.
    if (dir !== process.cwd() && denyPrefixes.some((pref) => dir === pref || dir.startsWith(pref + '/'))) {
      const first = s.trim().toLowerCase().split(/\s+/)[0]
      if (!['echo', 'printf', 'cd'].includes(first)) resolvedReads.push(dir)
    }
    // find -exec: `find / -name id_rsa -exec cat {} \;` carries no literal
    // sensitive path — the name is a `-name` pattern and `{}` a placeholder —
    // but find resolves real sensitive files and -exec reads their content.
    // Precise private-key / credential file names only, so generic
    // `find -name "*.ts" -exec cat` and name-only listings stay allowed.
    const findHit = scanFindExecForSensitiveRead(s, denyReadPaths)
    if (findHit) resolvedReads.push(findHit)
  }

  // Priority order for "most restrictive"
  const priority = PRIORITY

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

  // Collect every plausible path/pattern value across the common host
  // conventions: single-string keys AND arrays AND pattern/glob fields.
  // A whitelist of one key name misses `filePath`, `paths[]`, `files[]`,
  // `pattern`, `glob` — each is a working read/write channel on some host.
  const pathArgs: string[] = []
  for (const key of ['path', 'file_path', 'file', 'filePath', 'target',
                     'destination', 'src', 'source', 'pattern', 'glob',
                     'paths', 'files', 'inputs']) {
    const v = args[key]
    if (typeof v === 'string' && v) pathArgs.push(v)
    else if (Array.isArray(v)) {
      for (const item of v) if (typeof item === 'string' && item) pathArgs.push(item)
    }
  }

  // --- Semantically independent tool classes checked BEFORE the generic
  // write/read name table: a tool like `tm_snapshot_create`, `subagent_create`
  // or `todo_create` contains write/create words but is NOT a filesystem write.
  // --- Subagent tools (highest risk: child operations can't be verified)
  if (name.includes('subagent') || name.includes('delegate') ||
      name.includes('spawn') || name.includes('fork')) {
    return {
      category: 'mixed',
      reason: `Subagent tool: ${toolName} (cannot verify child operations)`,
      targetPaths: [],
    }
  }

  // --- Our own TM tools (always allowed)
  if (name.startsWith('tm_')) {
    return {
      category: 'read',
      reason: `TM-Guard internal tool: ${toolName}`,
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

  // --- Todo / planning tools (no side effects outside session) ---
  if (name.includes('todo') || name.includes('task') ||
      name.includes('plan') || name.includes('goal')) {
    return {
      category: 'read',
      reason: `Session-internal tool: ${toolName}`,
      targetPaths: [],
    }
  }

  // --- Filesystem tools ---
  if (name.includes('write') || name.includes('edit') ||
      name.includes('delete') || name.includes('remove') ||
      name.includes('create') || name.includes('mkdir') ||
      name.includes('move') || name.includes('rename') ||
      name.includes('copy') || name.includes('chmod') ||
      name.includes('chown') || name.includes('touch') ||
      name.includes('append') || name.includes('overwrite')) {
    const hit = denyHitFor(pathArgs, denyReadPaths)
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
      targetPaths: pathArgs,
    }
  }

  if (name.includes('read') || name.includes('cat') ||
      name.includes('view') || name.includes('list') ||
      name.includes('ls') || name.includes('stat') ||
      name.includes('grep') || name.includes('find') ||
      name.includes('search') || name.includes('glob') ||
      name.includes('head') || name.includes('tail') ||
      name.includes('diff')) {
    const hit = denyHitFor(pathArgs, denyReadPaths)
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
      targetPaths: pathArgs,
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
  /** True when the write is confined to a disposable temp dir */
  temp: boolean
}

/** macOS temp-dir prefixes — disposable scratch, exempt from the
 *  TM-protection requirement (the files are transient by nature). */
const TEMP_PREFIXES = [
  '/tmp', '/private/tmp', '/var/tmp', '/var/folders',
]

export function isTempPath(abs: string): boolean {
  if (!abs.startsWith('/')) abs = toAbsolute(abs)
  // Same normalization as the sensitive-read / write-protection sides
  // (normalizeForMatch collapses `//`, `.`, `..` and lowercases): a path like
  // `/tmp/../etc/evil.txt` resolves to `/etc/evil.txt` and must NOT be treated
  // as temp — the OS lands it outside /tmp.
  const norm = normalizeForMatch(abs)
  return TEMP_PREFIXES.some(
    (p) => norm === p || norm.startsWith(p + '/'),
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

  // Sentinel targets (`/.tmguard-dotdot-escape`, `-.tmguard-symlink-loop`,
  // `-.tmguard-symlink-cap`) mean the raw path crossed a symlink component or
  // could not be canonicalised — the OS write would land somewhere the gate
  // cannot see. Deny them unconditionally instead of relying on "the sentinel
  // happens not to be covered by any protectedPaths prefix" (review-l5b O1).
  if (
    forceDeny ||
    classification.targetPaths.some((t) => t.startsWith('/.tmguard-'))
  ) {
    return {
      allow: false,
      reason: `BLOCKED (${category}, forced deny): ${reason}`,
      category,
      shouldSnapshot: false,
      temp: false,
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
        temp: false,
      }

    case 'file_write':
      if (pathsProtected) {
        return {
          allow: true,
          reason: `Allowed (file_write on TM-protected path): ${reason}`,
          category,
          shouldSnapshot: true,
          temp: false,
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
          temp: true,
        }
      }
      return {
        allow: false,
        reason: `BLOCKED (file_write on path NOT protected by Time Machine): ${reason}`,
        category,
        shouldSnapshot: false,
        temp: false,
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
        temp: false,
      }

    case 'mixed':
    case 'unknown':
    default:
      return {
        allow: false,
        reason: `BLOCKED (${category}, cannot verify TM-rollback-ability): ${reason}`,
        category,
        shouldSnapshot: false,
        temp: false,
      }
  }
}
