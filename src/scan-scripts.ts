/**
 * Static egress scan for locally-executed scripts.
 *
 * The command-level classifier trusts an interpreter (`python x.py`,
 * `node x.js`, `bash deploy.sh`) as `local_exec` because the interpreter
 * itself has no network side effects. The blind spot is the SCRIPT it runs:
 * an HTTP client call, or a shell-out to a downloader inside a .sh, is
 * invisible to string matching on the command line.
 *
 * This module closes that blind spot by inspecting:
 *   1. inline code passed via `python -c "..."` / `node -e "..."`,
 *   2. heredoc bodies fed to an interpreter via stdin (`python - <<'EOF'`),
 *   3. the entry script file(s) named on the command line.
 *
 * It is a static pattern scan, NOT a sandbox: it catches library imports and
 * direct network calls in the entry script and inline code. Transitive imports
 * and `npm run` / `cargo run` manifests are out of scope (documented limit).
 * Posture is fail-closed: dynamic code execution (eval/exec/__import__/new
 * Function) that we cannot prove innocent is reported as "unverifiable".
 */

import { readFile } from 'node:fs/promises'
import { resolve, isAbsolute } from 'node:path'

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

export interface EgressHit {
  kind: 'network' | 'dynamic'
  /** Where the hit was found: 'file:src/x.py:42' | 'inline:python -c' | 'heredoc:python -' */
  where: string
  /** The matched line (trimmed, snippet) */
  snippet: string
  language: string
}

export interface EgressReport {
  /** Network egress indicators found. Empty when clean. */
  hits: EgressHit[]
  /** True when eval/exec/__import__/new Function were seen and we cannot
   *  conclude the script is egress-free. */
  unverifiable: boolean
  /** Files actually read during the scan (for verbose/audit). */
  scannedFiles: string[]
}

/* ------------------------------------------------------------------ */
/* Limits                                                              */
/* ------------------------------------------------------------------ */

const MAX_FILES = 5
const MAX_BYTES_PER_FILE = 256 * 1024
const MAX_HITS = 5

/* ------------------------------------------------------------------ */
/* Interpreter registry                                                */
/* ------------------------------------------------------------------ */

type Lang = 'python' | 'node' | 'shell' | 'ruby' | 'php' | 'perl' | 'tclsh' | 'swift' | 'awk' | 'elixir'

const INTERPRETERS: Record<string, Lang> = {
  python: 'python', python3: 'python', python2: 'python',
  node: 'node', nodejs: 'node', deno: 'node', bun: 'node',
  ruby: 'ruby',
  php: 'php', php7: 'php', php8: 'php',
  perl: 'perl',
  tclsh: 'tclsh', wish: 'tclsh',
  swift: 'swift',
  awk: 'awk',
  elixir: 'elixir', elixirc: 'elixir', escript: 'elixir', mix: 'elixir',
  bash: 'shell', sh: 'shell', zsh: 'shell', ksh: 'shell',
  pwsh: 'shell',
}

/** Value-taking flags whose next token is NOT a script file. */
const VALUE_FLAGS = new Set([
  '-m', '-c', '-e', '--eval', '-I', '-V', '-X', '-B', '-E', '-s',
  '--loader', '--experimental-loader', '--import', '--require',
  '--check', '--mode', '--target',
])

/* ------------------------------------------------------------------ */
/* Per-language network indicators                                     */
/* ------------------------------------------------------------------ */

const LOOPBACK_RE =
  /(?:https?:\/\/)?(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)/i

interface LangRules {
  /** Bare library imports (socket/requests/http…). Only a corroborating
   *  network call or shell-out promotes these to a hit — a module that merely
   *  imports requests but only talks to localhost stays allowed. */
  importNet: RegExp[]
  /** Direct network call sites. Per-line loopback filter applies. */
  callNet: RegExp[]
  /** Shell-out to a network command (os.system("curl …"), child_process…). */
  shellNet: RegExp[]
  dyn: RegExp[]
  /** Unverifiable-risky primitives: file writes/deletes/permission/links,
   *  process spawn/exec, socket connect/bind, pipe opens, ARGV/ENV-carried
   *  targets. We cannot prove these innocent statically, so a hit makes the
   *  whole scan fail closed (unverifiable → conservative deny). */
  risky: RegExp[]
}

const RULES: Record<Lang, LangRules> = {
  python: {
    importNet: [
      /^\s*import\s+(socket|urllib|urllib2|urllib3|requests|http\.client|ftplib|smtplib|poplib|imaplib|telnetlib|xmlrpc\.client|aiohttp|httpx|websockets?|paramiko|pysftp|fabric|boto3|botocore|googleapiclient)\b/m,
      /^\s*from\s+(socket|urllib|requests|http|ftplib|smtplib|poplib|imaplib|telnetlib|xmlrpc|aiohttp|httpx|websockets?|paramiko|boto3|botocore|google)\b/m,
    ],
    callNet: [
      /\b(urllib\.request\.urlopen|requests\.(get|post|put|delete|head|patch|request|session)|httpx\.(get|post|put|delete|head|patch|Client|AsyncClient)|aiohttp\.ClientSession|http\.client\.HTTPConnection|socket\.create_connection|socket\.socket\s*\(|smtplib\.SMTP|ftplib\.FTP|websockets?\.connect|paramiko\.SSHClient)(?![\w$])/,
    ],
    shellNet: [
      /\b(os\.system|subprocess\.(run|Popen|call|check_call|check_output)|popen|Popen)\s*\(\s*[^)]*?\b(curl|wget|n?cat|ssh|scp|sftp|ftp|telnet|git\s+(push|pull|clone|fetch))\b/,
    ],
    dyn: [
      /\b__import__\s*\(\s*["']/,
      /\b(eval|exec)\s*\(/,
      // G2: importlib dynamic import is the __import__ equivalent; the target
      // module and its side effects cannot be proven innocent statically.
      /\bimportlib\s*\.\s*import_module\s*\(/,
      /\bfrom\s+importlib\s+import\s+import_module\b/,
      /\bimport_module\s*\(\s*["']/,
      // F3-c: `import importlib.util as u; u.spec_from_file_location(…)`
      // aliases the module away from the risky literal-name regex below —
      // the import itself is the unverifiable-code-source marker.
      /\bimport\s+importlib\b/,
      /\bfrom\s+importlib\s+import\b/,
    ],
    risky: [
      // H3b/F3: python loading code from a path it mutates (sys.path) or an
      // env override (os.environ PYTHONPATH) — the injected module is
      // unverifiable. os.system executes an arbitrary shell string.
      // FP-2: pure-relative-literal sys.path mutations are exempted inside
      // scanCode() so this layer agrees with the classifier's
      // pythonSysPathThreat (PYTHONPATH=./lib env form is allowed).
      /\bsys\s*\.\s*path\s*\.\s*(?:insert|append|extend|__setitem__)\s*\(/,
      // F3-b: bound-alias mutations — `ins=sys.path.insert; ins(0,"/tmp/evil")`
      // or `p=sys.path; p.insert(0,"/tmp/evil")` — the alias hides the
      // mutation from the literal-name regex above (the `;`-terminated binding
      // and the later `alias(…)` call are both matched).
      /\b([A-Za-z_]\w*)\s*=\s*sys\s*\.\s*path(?:\s*\.\s*(?:insert|append|extend|__setitem__))?\s*(?:\(|;)/,
      // f-round-2 B5: `sys.path.__setitem__(0,"/tmp/evil")` (indexed writer)
      // and `getattr(sys.path,"insert")(0,…)` (string-method dispatch) both
      // hide the mutation from the literal-name nets.
      /\bsys\s*\.\s*path\s*\.\s*__setitem__\s*\(/,
      /getattr\s*\(\s*sys\s*\.\s*path\s*,\s*["'](?:insert|append|extend|__setitem__)["']\s*\)/,
      /\bsys\s*\.\s*path\s*(?:\[[^\]]*\]\s*=|=\s*)/,
      // f-round-2 B4: os.environ assignments to ANY python path override
      // (PYTHONHOME/PYTHONPATH/PYTHONSTARTUP) poison interpreter startup —
      // fail closed regardless of the assigned value's shape.
      /\bos\s*\.\s*environ\s*\[\s*["']PYTHON(?:HOME|PATH|STARTUP)["']\s*\]\s*=/,
      // F3-c: site.addsitedir adds a whole directory of packages at runtime
      // (the classifier's sitecustomize/PYTHONHOME net covers startup paths);
      // importlib.util.spec_from_file_location loads a module from an
      // arbitrary file — both are unverifiable code sources.
      /\bsite\s*\.\s*addsitedir\s*\(/,
      // f-round-2 B5: don't anchor `importlib.util.` — `from importlib.util
      // import spec_from_file_location as s; s(…)` aliases it away; these two
      // functions have no other source.
      /\b(?:spec_from_file_location|module_from_spec)\s*\(/,
      /\bos\s*\.\s*system\s*\(/,
      // f-round-4 B-N1-a (python): subprocess argv whose argv[0] is a shell
      // or interpreter with a -c/-e/-E/-r/--eval flag is a FULL RCE — the
      // network-argv net only catches curl/wget/… literals.
      /\bsubprocess\s*\.\s*(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(\s*\[?\s*["'][^"']*\b(sh|bash|dash|zsh|ksh|python3?|python|node|nodejs|ruby|perl|php)\b[^"']*["']\s*,\s*["'][^"']*-[ceEr][^"']*["']/,
    ],
  },
  node: {
    importNet: [
      /\brequire\s*\(\s*["'](?:node:)?(http|https|net|dgram|tls|dns|child_process|websocket)\b/,
      /\bimport\s+(?:[\s\S]{0,120}?\bfrom\s+)?["'](?:node:)?(http|https|net|dgram|tls|dns|child_process|websocket)["']/,
    ],
    callNet: [
      /\b(fetch|axios)\s*\(|new\s+WebSocket\s*\(|new\s+XMLHttpRequest\s*\(|\bhttp\.request\s*\(|\bhttps\.request\s*\(|\bnet\.connect\s*\(|\btls\.connect\s*\(|\bgaxios\s*\(|node-fetch/,
    ],
    shellNet: [
      /\b(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*["'`][^"'`]*\b(curl|wget|n?cat|ssh|scp|git\s+(push|pull|clone|fetch))\b/,
    ],
    dyn: [
      /\beval\s*\(/,
      /\bnew\s+Function\s*\(/,
    ],
    risky: [
      /\bprocess\.(kill|spawn)\b/,
      /\bDeno\.(run|writeTextFile|writeFile|connect|listen|mkdir|remove|symlink)\b/,
      // f-round-2 B3: node heredoc stdin code running `child_process`
      // exec/execSync executes an arbitrary COMMAND STRING whose target
      // cannot be proven innocent statically — fail closed, matching the
      // ruby/python system()/os.system posture. spawn/spawnSync/execFile
      // take an argv/file and stay on the network-argv shellNet rule, so
      // benign `spawnSync('ls')` remains readable.
      /\b(?:require\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.|child_process\s*\.)\s*(?:exec|execSync)\s*\(/,
      // f-round-4 B-N1-a: literal-argv spawn/execFile whose argv[0] is a
      // shell or interpreter with a -c/-e/-E/-r/--eval flag is a FULL RCE —
      // the shellNet network-argv rule only catches curl/wget/… literals, so
      // `spawnSync("sh",["-c","echo X > /abs"])` rides through as readable.
      // argv[0] may be bare or an absolute path (/bin/sh, /usr/bin/python3).
      /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*["'][^"']*\b(sh|bash|dash|zsh|ksh|python3?|python|node|nodejs|ruby|perl|php)\b[^"']*["']\s*,\s*\[?\s*["'][^"']*-[ceEr][^"']*["']/,
    ],
  },
  shell: {
    importNet: [],
    callNet: [
      /(?:^|[\s;|&`$()])(curl|wget|aria2c|axel|youtube-dl|yt-dlp|ncat|netcat|telnet|ftp|sftp|ssh|scp|slogin|lwp-download|lynx|w3m|httpie|https?)\s+/,
      /\bgit\s+(push|pull|clone|fetch|ls-remote)\b/,
      /\bgit\s+submodule\s+(update|init)\b/,
      /\/dev\/tcp\//,
      /\brsync\s+[^\n]*:[/]/,
    ],
    shellNet: [],
    dyn: [],
    risky: [],
  },
  ruby: {
    importNet: [
      /\brequire\s+['"](net\/http|net\/ftp|net\/smtp|net\/ssh|socket|open-uri|rest-client|faraday|httpclient)['"]/,
    ],
    callNet: [
      /\bNet::HTTP\.|Faraday\.|URI\.open\s*\(|open\s*\(\s*['"]https?:/,
    ],
    shellNet: [],
    dyn: [/\beval\s*\(/],
    risky: [
      // file write / truncate / permission / link / rename primitives
      /\bFile\.(write|binwrite|truncate|chmod|chown|rename|move|symlink|hardlink|link|delete|unlink)\b/,
      // B1: File.open(path,"w") — the write mode may be ANY argument, not just
      // the first string (File.open's first arg is the path). Match a write
      // mode string anywhere inside the parens; File.open("t") read stays clean.
      /\bFile\.open\s*\([^)]*['"](?:w|a|r\+|w\+|wb|ab|wt)/,
      // H4: File.new(path,"w") — constructor variant of the open write.
      /\bFile\.new\s*\([^)]*['"](?:w|a|r\+|w\+|wb|ab|wt)/,
      // H4: receiver ALIAS (`z=File; z.write("/etc/x","y")`) — capture the
      // assigned name and require its later file-mutation call.
      /\b([A-Za-z_]\w*)\s*=\s*File\b(?![:\w])[\s\S]*?\b\1\s*\.\s*(?:write|binwrite|truncate|delete|unlink)\s*\(/,
      // H4: %q(w) / %Q{...} mode-string spellings.
      /\bFile\.(?:open|new)\s*\([^)]*%[qQ][(\[{'"](?:w|a|r\+|w\+|wb|ab|wt)[)\]}"']/,
      // B1/H4: receiver-indirection write — File.send/__send__/public_send
      // with symbol OR string method name, paren or no-paren call forms.
      /\bFile\.(?:send|__send__|public_send)\s*\(\s*(?::?(?:write|binwrite|truncate|delete|unlink|open)\b[,"')]|["'](?:write|binwrite|truncate|delete|unlink|open)["'])/,
      /\bFile\.(?:send|__send__|public_send)\s+(?::?(?:write|binwrite|truncate|delete|unlink|open)\b|["'](?:write|binwrite|truncate|delete|unlink|open)["'])/,
      /\bFileUtils\.(write|cp|cp_r|mv|rm|rm_f|rm_r|rm_rf|remove_file|remove_entry|remove_entry_secure|mkdir|mkdir_p|chmod|chown|symlink|link)\b/,
      /\bDir\.(mkdir|rmdir|delete|unlink)\b/,
      /\bIO\.(write|binwrite|truncate)\b/,
      /\bopen\s*\(\s*['"][|wa+]/,
      // B1: Kernel.open(path, "w…") — mode in a later argument
      /\bopen\s*\([^)]*,\s*['"](?:w|a|r\+|w\+|wb|ab)/,
      // process spawn / exec — FP-5: words inside inert string literals
      // (`puts "operating system check"`) are not call sites; the loop
      // re-tests this pattern on a masked line (only interpolated strings
      // `system("#{cmd}")` keep their hit).
      /\b(system|exec|spawn|fork|Process\.spawn|Process\.kill|IO\.popen)\b/,
      // pipe-open reads execute the command (IO.read("|dig …") etc.)
      /\bIO\.(read|readlines|readline|foreach|gets)\s*\(\s*['"]\|/,
      // sockets
      /\b(TCPSocket|TCPServer|UDPSocket|Socket|IPSocket)\b/,
      // dynamic eval family
      /\b(instance_eval|class_eval|module_eval)\s*\(/,
      // ARGV-carried targets
      /\bARGV\b/,
    ],
  },
  php: {
    importNet: [],
    callNet: [
      /\b(curl_init|curl_exec|fsockopen|pfsockopen|stream_socket_client)\s*\(|file_get_contents\s*\(\s*['"]https?:|fopen\s*\(\s*['"]https?:/,
    ],
    shellNet: [],
    dyn: [/\b(eval|assert)\s*\(/],
    risky: [
      /\b(file_put_contents|fwrite|fputs|unlink|rename|chmod|chown|symlink|mkdir|rmdir|unlink)\b/,
      /\bfopen\s*\([^)]*['"][wa]/,
      /\b(exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\b/,
      /\b(socket_create|socket_connect|stream_socket_server)\b/,
      /\b\$argv\b/,
    ],
  },
  perl: {
    importNet: [
      /\buse\s+(LWP|LWP::Simple|LWP::UserAgent|HTTP::Request|IO::Socket|Net::FTP|Net::SSH2|SOAP::Lite|HTTP::Tiny)\b/,
      /\brequire\s+.*(LWP|HTTP::Request)/,
    ],
    callNet: [],
    shellNet: [],
    dyn: [/\beval\s*(["'{(]|\s*\{)/],
    risky: [
      // open with write/pipe modes
      /\bopen\s*\([^)]*['"](?:>|>>|>\||\|)/,
      /\bopen\s+(?:my\s+)?\$\w+\s*,\s*['"](?:>|>>|\|)/,
      // B1 (g 轮) perl mirrors: object constructor write mode, sysopen
      // with an O_WRONLY/O_RDWR/O_APPEND/O_CREAT flag, or a bare O_* flag
      // carried through an indirect handle.
      /\bIO::File->new\s*\([^)]*['"](?:>|>>)/,
      /\bsysopen\s*\([^)]*O_(?:WRONLY|RDWR|APPEND|CREAT|TRUNC)/,
      /\bO_(?:WRONLY|RDWR|APPEND|CREAT|TRUNC)\b/,
      // file mutation primitives
      /\b(rename|unlink|truncate|chmod|chown|symlink|link|mkdir|rmdir|utime)\b/,
      // process spawn / exec / backticks
      /\b(system|exec)\b|`/,
      // sockets
      /\b(IO::Socket|IO::Socket::INET|IO::Socket::IP|Socket)\b/,
      // ARGV/ENV-carried targets
      /\b\$ARGV\b|\b\$ENV\{/,
    ],
  },
  tclsh: {
    importNet: [],
    callNet: [],
    shellNet: [],
    dyn: [/\beval\b/],
    risky: [
      /\b(exec|socket|open|source)\b/,
      /\bfile\s+(delete|rename|mkdir|link)\b/,
    ],
  },
  swift: {
    importNet: [],
    callNet: [
      /\bURLSession\s*\.\s*(shared|dataTask|downloadTask)\b|\bData\s*\(\s*contentsOf\s*:\s*URL\b/,
    ],
    shellNet: [],
    dyn: [],
    risky: [
      /\b(FileManager|Process)\b/,
      /\bString\s*\(\s*contentsOf(?:File)?\b/,
      /\bwrite\s*\(\s*to\b/,
      /\bsocket\b/,
    ],
  },
  awk: {
    importNet: [],
    callNet: [],
    shellNet: [],
    dyn: [],
    risky: [
      // command execution primitives
      /\bsystem\s*\(/,
      /\bexec\s*\(/,
      // redirections inside the program body (quoted target path)
      /(?:>|>>)\s*["'][^"']+/,
      // pipe to a shell command (`"cmd" | getline`, `cmd | getline`)
      /\|\s*["'][^"']*/,
      /\|\s*getline\b/,
      /\bclose\s*\(\s*["'][^"']*/,
    ],
  },
  elixir: {
    importNet: [],
    callNet: [
      /:gen_tcp\.connect\s*\(|:gen_udp\.open\s*\(|:httpc\.request\s*\(/,
      /\bHTTPoison\.(get|post|put|delete)\s*\(|\bTesla\.(get|post|put|delete)\s*\(/,
      /\bReq\.(get|post|put|delete)\s*\(/,
    ],
    shellNet: [/\bSystem\.cmd\s*\(|\bPort\.open\s*\(/],
    dyn: [/\bCode\.(eval_string|compile_string)\s*\(/],
    risky: [
      /\bFile\.(write!?|rm!?|rm_rf!?|ln_s!?|chmod!?|chown!?|mkdir!?|mkdir_p!?|cp!?|cp_r!?|mv!?|open!?)\b/,
      /\bIO\.binwrite\s*\(|\bIO\.write\s*\(/,
      /\b(exec|spawn)\s*\(/,
    ],
  },
}

/* ------------------------------------------------------------------ */
/* Command parsing helpers                                             */
/* ------------------------------------------------------------------ */

/**
 * Split a command into tokens on whitespace, respecting single/double quotes.
 * Surrounding quotes are stripped.
 */
function tokenize(cmd: string): string[] {
  const out: string[] = []
  let cur = ''
  let quote: string | null = null
  let started = false
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (quote) {
      if (ch === quote && cmd[i - 1] !== '\\') { quote = null; continue }
      cur += ch; continue
    }
    if (ch === '"' || ch === "'") { quote = ch; started = true; continue }
    if (/\s/.test(ch)) {
      if (started) { out.push(cur); cur = ''; started = false }
      continue
    }
    cur += ch; started = true
  }
  if (started) out.push(cur)
  return out
}

/** Split a command on && / || ; | while respecting quotes. */
function splitSeparators(cmd: string): string[] {
  const parts: string[] = []
  let cur = ''
  let quote: string | null = null
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (quote) {
      cur += ch
      if (ch === quote && cmd[i - 1] !== '\\') quote = null
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue }
    if (ch === '&' && cmd[i + 1] === '&') { parts.push(cur); cur = ''; i++; continue }
    if (ch === '|' && cmd[i + 1] === '|') { parts.push(cur); cur = ''; i++; continue }
    if (ch === '|') { parts.push(cur); cur = ''; continue }
    if (ch === ';') { parts.push(cur); cur = ''; continue }
    cur += ch
  }
  parts.push(cur)
  return parts.map((s) => s.trim()).filter(Boolean)
}

interface HeredocHit {
  body: string
  language: Lang
}

/**
 * Pull heredoc bodies out of the command. Returns the bodies (tagged with the
 * language of the interpreter on their starting line) and a cleaned command
 * with body lines blanked out so ; | && inside the body don't fragment it.
 */
function extractHeredocs(command: string): { bodies: HeredocHit[]; clean: string } {
  const lines = command.split('\n')
  const bodies: HeredocHit[] = []
  const clean: string[] = []
  let active: { delim: string; stripTabs: boolean; lang: Lang; body: string[] } | null = null

  for (const line of lines) {
    if (active) {
      const expected = active.stripTabs ? line.replace(/^\t+/, '') : line
      if (expected.trim() === active.delim) {
        bodies.push({ body: active.body.join('\n'), language: active.lang })
        active = null
        clean.push('') // blank the terminator line too
      } else {
        active.body.push(line)
        clean.push('') // blank body lines
      }
      continue
    }

    const m = line.match(/<<-?\s*(?:'([^']+)'|"([^"]+)"|([A-Za-z_][A-Za-z0-9_]*))/)
    if (m) {
      const delim = m[1] ?? m[2] ?? m[3]
      const stripTabs = /<<-/.test(line)
      // Language = interpreter on this line (first word, env stripped).
      const toks = tokenize(line.replace(/^[A-Za-z_]\w*=\S+\s+/, ''))
      const first = (toks[0] ?? '').split('/').pop()?.toLowerCase() ?? ''
      // F1-c: `find … -exec ruby - {} \; <<'RB'` feeds the heredoc to the
      // -exec interpreter, not to `find` — pick the interpreter out of the
      // -exec clause so its body is scanned with the right language instead
      // of being dropped as unverifiable-by-luck.
      const exeM = line.match(/-\s*exec\s+(\S+)/)
      let exeFirst = exeM ? (exeM[1].split('/').pop() ?? '').toLowerCase() : ''
      // f-round-2 B3: `-exec sh -c 'ruby -' {} \; <<'RB'` — the shell wrapper
      // delegates the heredoc to an inner interpreter; take its language so
      // the body is scanned as ruby (not dropped as unverifiable-by-luck).
      if (/^(?:sh|bash|dash|zsh)$/.test(exeFirst)) {
        const inner = line.match(/-c\s*['"]?\s*(ruby|perl|php|python\d*|node|nodejs)\b/)
        if (inner) exeFirst = inner[1]
      }
      const lang = INTERPRETERS[exeFirst] ?? INTERPRETERS[first]
      if (lang) {
        active = { delim, stripTabs, lang, body: [] }
        clean.push(line)
        continue
      }
    }
    clean.push(line)
  }
  return { bodies, clean: clean.join('\n') }
}

/** True when a matched line references only loopback addresses. */
function isLoopbackOnly(line: string): boolean {
  const urls = line.match(/https?:\/\/[^\s'"`)}\]]+/gi) ?? []
  if (urls.length === 0) return false // e.g. a bare `import requests` — cannot prove local
  return urls.every((u) => LOOPBACK_RE.test(u))
}

/** Strip surrounding quotes from an inline-code argument. */
function unquote(s: string): string {
  if (s.length >= 2) {
    const q = s[0]
    if ((q === '"' || q === "'") && s.endsWith(q)) return s.slice(1, -1)
  }
  return s
}

/* ------------------------------------------------------------------ */
/* Code scanning                                                       */
/* ------------------------------------------------------------------ */

/**
 * True when a line's *code* portion is a bare regex literal (a rule
 * definition), as opposed to a statement that happens to contain one.
 *
 * Only matches `X = /.../flags`, `X.push(/.../)`-style lone literals and
 * array entries `  /.../,` — i.e. lines whose trimmed text *starts* with `/`
 * after an optional `name: ` / `name = ` / `(` prefix, or that are just a
 * commented-out pattern. A real call such as `const r = await fetch(u)` does
 * not start with a slash, so it is still scanned.
 *
 * Deliberately conservative: a false negative here (missing a smuggled call
 * hidden inside a regex-looking line) is not achievable, because executing
 * code cannot be written as a lone literal — a regex literal has no side
 * effects. Anything that can actually run still fails the "starts with /"
 * test.
 */
function isRegexLiteralLine(line: string): boolean {
  const t = line.trim()
  // Comment lines carry prose and examples, not executable calls. Only treat
  // doc/comment text as inert for the *call-site* patterns; imports and
  // dynamic-eval checks below still see the full file via their own pass.
  if (t.startsWith('*') || t.startsWith('//') || t.startsWith('/*')) return true

  // Strip an optional `key:` / `key =` prefix and opening bracket/paren.
  const body = t
    .replace(/^(?:[\w$]+|['"][^'"]*['"])\s*[:=]\s*/, '')
    .replace(/^\(+/, '')
  if (!body.startsWith('/')) return false

  // Walk the literal, honouring backslash escapes, to find its true closing
  // delimiter. The naive "first unescaped /" scan stops early on patterns
  // like `/node-fetch/`, leaving the remainder looking like trailing code.
  let closed = -1
  for (let i = 1; i < body.length; i++) {
    if (body[i] === '\\') { i++; continue }
    if (body[i] === '/') { closed = i; break }
    if (body[i] === '\n') return false
  }
  if (closed < 0) return false
  // Only a flag tail and list/statement separator may follow — `/a/.test(x)`
  // and `/a/ + b` are real expressions, so they are NOT treated as inert.
  return /^[gimsuy]*\s*[,;)\]]*\s*$/.test(body.slice(closed + 1))
}

function scanCode(code: string, language: Lang, where: string, out: EgressHit[]): boolean {
  const rules = RULES[language]
  let unverifiable = false
  const lines = code.split('\n')
  const importLines: { n: number; line: string }[] = []
  let hardHits = 0
  // f-round-2 B5: `from importlib.util import spec_from_file_location as s;
  // s("m","/tmp/none.py")` aliases the function away from the risky literal
  // regex. Track the alias per line so a later bare call site is detected.
  let specAlias: string | null = null
  // f-round-3 N1: node `child_process` references can be named through
  // aliases, destructured imports, require aliases, createRequire or dynamic
  // import — the risky literal regex anchors on `require("child_process").`
  // and misses every renamed form. Track module references and bare exec
  // names (cross-line: a heredoc body may bind on line 1, call on line 3).
  const nodeCpRefs = new Set<string>()
  const nodeRequireAliases = new Set<string>()
  const nodeBareExec = new Set<string>()
  // f-round-4 B-N1-b: plain variable-to-variable assignments (`const q=cp;`
  // `q=r;`) build alias chains that the direct `=require("child_process")`
  // collection misses — a two/three-hop alias then calls exec through a name
  // never seen by nodeCpRefs. Collect pairs here, close them transitively
  // before the execThreat adjudication below.
  const nodeAliasPairs: Array<[string, string]> = []
  // f-round-4 N-N1-c: python `os`/`subprocess` module aliases (`o=os;
  // o.system(…)`, `import subprocess as s; s.run(…)`) hide the risky
  // literal `os.system(`/`subprocess.run(` regexes inside find bodies.
  const pyOsAliases = new Set<string>()
  const pySubprocAliases = new Set<string>()
  // f-round-3 F2: python sys.path can also be reached through an object
  // alias (`p=sys.path;p.insert(0,"./lib")`) or a method alias
  // (`ins=sys.path.insert;ins(0,"./lib")`) or getattr dispatch — the
  // relative-literal exemption must cover those too (or they over-deny).
  const pySysPathObj = new Set<string>()
  const pySysPathMethodAlias = new Set<string>()
  const reEscape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // Reused by dyn and risky loops: relative-literal call sites of the spec
  // family (spec_from_file_location/module_from_spec/its alias) load a module
  // inside the session cwd and are verifiable; absolute / non-literal args
  // still fail closed.
  const specCallRE = (l: string): RegExp | null => {
    if (language !== 'python') return null
    if (/\b(?:spec_from_file_location|module_from_spec)\s*\(/.test(l)) {
      return /\b(?:spec_from_file_location|module_from_spec)\s*\(/
    }
    if (specAlias && new RegExp(`\\b${specAlias}\\s*\\(`).test(l)) {
      return new RegExp(`\\b${specAlias}\\s*\\(`)
    }
    return null
  }
  const specRelLiteral = (l: string): boolean => {
    const re = specCallRE(l)
    if (!re) return false
    const strs = [...l.matchAll(/["']([^"']*)["']/g)].map((x) => x[1])
    // f-round-3 F3: `..` traversal escapes the session cwd — reject it here
    // too, matching the B4 taintedPathEnv posture (absolute args were already
    // excluded by the startsWith('/') test).
    return strs.length > 0 && strs.every((s) =>
      !s.startsWith('/') && !s.includes(':') && !s.includes('$') &&
      !s.includes('`') && !s.includes('"') && !s.includes('..'))
  }

  for (let i = 0; i < lines.length && out.length < MAX_HITS; i++) {
    const line = lines[i]
    if (!line || line.trim().length === 0) continue
    // A regex literal is a PATTERN, not a call site. Without this, any file
    // that defines network detection rules — including this one — matches its
    // own patterns and self-reports as egress (`editors/`: `/\bfetch\s*\(/`
    // contains the text `fetch(`). That turned every `node --test test-*.mts`
    // into a false "network" denial the moment the import graph reached the
    // detector's own source.
    if (isRegexLiteralLine(line)) continue

    // f-round-2 B5: track `… as s` aliases of the spec family so a later
    // bare `s(...)` call site is caught by specCallRE above.
    if (language === 'python') {
      const am = line.match(/\b(?:spec_from_file_location|module_from_spec)\s+as\s+(\w+)\b/)
      if (am) specAlias = am[1]
      // f-round-3 F2: sys.path object / method aliases for the relative-literal
      // exemption below.
      for (const m of line.matchAll(/\b(\w+)\s*=\s*sys\s*\.\s*path\b/g)) {
        if (!pySysPathObj.has(m[1])) pySysPathObj.add(m[1])
      }
      for (const m of line.matchAll(/\b(\w+)\s*=\s*sys\s*\.\s*path\s*\.\s*(?:insert|append|extend|__setitem__)\b/g)) {
        if (!pySysPathMethodAlias.has(m[1])) pySysPathMethodAlias.add(m[1])
      }
      // f-round-4 N-N1-c: `o=os` / `import subprocess as s` hide system(…)
      // and subprocess.run(…) behind aliases the risky literal regexes miss.
      for (const m of line.matchAll(/(?:import\s+os\s+as\s+(\w+)|(\w+)\s*=\s*os\b)/g)) {
        if (m[1] && !pyOsAliases.has(m[1])) pyOsAliases.add(m[1])
        if (m[2] && !pyOsAliases.has(m[2])) pyOsAliases.add(m[2])
      }
      for (const m of line.matchAll(/(?:import\s+subprocess\s+as\s+(\w+)|(\w+)\s*=\s*subprocess\b)/g)) {
        if (m[1] && !pySubprocAliases.has(m[1])) pySubprocAliases.add(m[1])
        if (m[2] && !pySubprocAliases.has(m[2])) pySubprocAliases.add(m[2])
      }
      // f-round-4 N-N1-c: `from subprocess import run as s; s.run? no —
      // `s.run(...)` is a METHOD on the module; but `from subprocess import
      // run` binds the function bare, so `run([...])` must fail closed too.
      for (const m of line.matchAll(/\b(?:exec|run|call|Popen|check_output|getoutput|getstatusoutput)\s+as\s+(\w+)\b/g)) {
        if (!pySubprocAliases.has(m[1])) pySubprocAliases.add(m[1])
      }
    }
    // f-round-3 N1: collect every way `child_process` (or its exec/execSync
    // members) can be named on this line — later lines resolve through the
    // sets, so renamed forms cannot escape the fail-closed posture.
    if (language === 'node') {
      for (const m of line.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/g)) {
        nodeCpRefs.add(m[1])
      }
      for (const m of line.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*require\b/g)) {
        nodeRequireAliases.add(m[1])
      }
      // f-round-4 B-N1-b: variable-to-variable aliases (`const q=cp;` then
      // `q.execSync(…)`) — collected here, closed transitively later.
      for (const m of line.matchAll(/\b(?:const|let|var)?\s*(\w+)\s*=\s*(\w+)\b/g)) {
        if (m[1] !== m[2]) nodeAliasPairs.push([m[1], m[2]])
      }
      for (const m of line.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*\(\s*["'](?:node:)?child_process["']\s*\)/g)) {
        if (nodeRequireAliases.has(m[2])) nodeCpRefs.add(m[1])
      }
      for (const m of line.matchAll(/\bimport\s+(?:\*\s+as\s+(\w+)|(\w+))\s+from\s+["'](?:node:)?child_process["']/g)) {
        if (m[1]) nodeCpRefs.add(m[1])
        if (m[2]) nodeCpRefs.add(m[2])
      }
      for (const m of line.matchAll(/\bimport\s*\{([^}]*)\}\s*from\s+["'](?:node:)?child_process["']/g)) {
        for (const nm of m[1].split(',')) {
          const mm = nm.trim().match(/^(\w+)(?:\s+as\s+(\w+))?$/)
          if (mm && /^(exec|execSync)$/.test(mm[1])) nodeBareExec.add(mm[2] ?? mm[1])
        }
      }
      for (const m of line.matchAll(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/g)) {
        for (const nm of m[1].split(',')) {
          const mm = nm.trim().match(/^(\w+)(?:\s*:\s*(\w+))?$/)
          if (mm && /^(exec|execSync)$/.test(mm[1])) nodeBareExec.add(mm[2] ?? mm[1])
        }
      }
      // method binding: `const e = require("child_process").execSync` /
      // `const e = cp.execSync` — later `e(...)` is an exec call.
      for (const m of line.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*[^;]+?\.\s*(?:exec|execSync)\b/g)) {
        nodeBareExec.add(m[1])
      }
    }

    // Shell-out hits are always hard (no loopback downgrade for `curl ...`
    // with a remote host; loopback filter below handles 127.0.0.1 lines).
    for (const re of rules.shellNet) {
      re.lastIndex = 0
      if (re.test(line) && !isLoopbackOnly(line)) {
        out.push({
          kind: 'network',
          where: lines.length > 1 ? `${where}:${i + 1}` : where,
          snippet: line.trim().slice(0, 160),
          language,
        })
        hardHits++
        break
      }
    }

    // Direct call sites — loopback lines are downgraded (local dev probes).
    for (const re of rules.callNet) {
      re.lastIndex = 0
      if (re.test(line)) {
        if (isLoopbackOnly(line)) break
        out.push({
          kind: 'network',
          where: lines.length > 1 ? `${where}:${i + 1}` : where,
          snippet: line.trim().slice(0, 160),
          language,
        })
        hardHits++
        break
      }
    }

    // Bare imports — collected, promoted only if the block actually calls out.
    for (const re of rules.importNet) {
      re.lastIndex = 0
      if (re.test(line)) { importLines.push({ n: i + 1, line }); break }
    }

    for (const re of rules.dyn) {
      re.lastIndex = 0
      if (re.test(line)) {
        // f-round-2 FP-4: `import importlib.util as u;u.spec_from_file_location(
        // "m","./m.py")` hits the dyn `import importlib` marker, but a
        // relative-literal spec-family call on the same line is verifiable —
        // do not fail the whole scan for it. Absolute/non-literal args (and a
        // bare import with no call) still fail closed.
        if (language === 'python' &&
            re.source.includes('importlib') &&
            specRelLiteral(line)) continue
        unverifiable = true
      }
    }

    // Unverifiable-risky primitives (writes/deletes/processes/sockets/ARGV):
    // cannot prove innocent statically → fail closed, but do not report them
    // as network hits (they are not egress; the caller downgrades to unknown).
    for (const re of rules.risky) {
      re.lastIndex = 0
      let rawHit = re.test(line)
      // f-round-2 B5: alias call sites count as a spec-family raw hit even
      // though the risky literal regex cannot see the alias name.
      if (!rawHit && language === 'python' && specAlias &&
          new RegExp(`\\b${specAlias}\\s*\\(`).test(line)) rawHit = true
      // f-round-4 N-N1-c: `o=os; o.system(…)` / `import subprocess as s;
      // s.run(…)` hide the risky literal regexes — any call through a
      // collected os/subprocess alias is a hard shell-out hit.
      if (!rawHit && language === 'python') {
        if (pyOsAliases.size > 0 &&
            new RegExp(`\\b(?:${[...pyOsAliases].map(reEscape).join('|')})\\s*\\.\\s*(?:system|popen|spawn|execv\\w*)\\s*\\(`).test(line)) rawHit = true
        if (pySubprocAliases.size > 0 &&
            new RegExp(`\\b(?:${[...pySubprocAliases].map(reEscape).join('|')})\\s*(?:\\.\\s*(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\\s*)?\\(`).test(line)) rawHit = true
      }
      // FP-5: ruby process words (system/exec/spawn/fork) that occur only
      // inside inert string literals (`puts "operating system check"`) are
      // not call sites — re-test the line with inert strings masked. A
      // double-quoted string containing `#{}` interpolation is NOT masked
      // (`system("#{cmd}")` is a live call), single quotes never interpolate.
      if (rawHit && re.source.startsWith('\\b(system|exec|spawn|fork')) {
        const maskedLine = line
          .replace(/"(?:[^"#\\]|\\.)*(?!#\{)"/g, '""')
          .replace(/'(?:[^'\\]|\\.)*'/g, '""')
        re.lastIndex = 0
        if (!re.test(maskedLine)) continue
      }
      if (rawHit) {
        // FP-2: a sys.path mutation whose string arguments are all pure
        // relative literals ("lib", "./lib", ".", "x/y") stays inside the
        // session cwd — classifier's pythonSysPathThreat allows it and the
        // two layers must agree (PYTHONPATH=./lib env form is allowed).
        // Any absolute path, colon path, variable or substitution still
        // fails closed (and non-literal args yield no string match → deny).
        // f-round-2 FP-3/FP-4: the same relative-literal posture applies to
        // site.addsitedir("./lib") and u.spec_from_file_location("m","./m.py")
        // (a module inside the session cwd is verifiable); absolute or
        // non-literal args stay denied.
        if (language === 'python' &&
            (/\bsys\s*\.\s*path\s*\.\s*(?:insert|append|extend|__setitem__)\s*\(/.test(line) ||
             /getattr\s*\(\s*sys\s*\.\s*path\s*,\s*["'](?:insert|append|extend|__setitem__)["']\s*\)\s*\(/.test(line) ||
             (pySysPathObj.size > 0 &&
              new RegExp(`\\b(?:${[...pySysPathObj].map(reEscape).join('|')})\\s*\\.\\s*(?:insert|append|extend|__setitem__)\\s*\\(`).test(line)) ||
             (pySysPathMethodAlias.size > 0 &&
              new RegExp(`\\b(?:${[...pySysPathMethodAlias].map(reEscape).join('|')})\\s*\\(`).test(line)) ||
             /\bsite\s*\.\s*addsitedir\s*\(/.test(line) ||
             specCallRE(line) !== null)) {
          const strs = [...line.matchAll(/["']([^"']*)["']/g)].map((x) => x[1])
          // f-round-3 F3: `..` traversal escapes the session cwd — the
          // relative-literal exemption must reject it (B4 posture), so an
          // absolute/non-literal OR parent-traversing arg still fails closed.
          if (strs.length > 0 && strs.every((s) =>
            !s.startsWith('/') && !s.includes(':') && !s.includes('$') &&
            !s.includes('`') && !s.includes('"') && !s.includes('..'))) {
            continue
          }
        }
        unverifiable = true
      }
    }

    // f-round-3 N1: node exec/execSync executes a COMMAND STRING whose target
    // cannot be proven innocent statically. The risky literal regex anchors on
    // `require("child_process").`; this block closes every renamed form —
    // module aliases, destructured/imported members, require aliases, bracket
    // keys (literal or variable), method bindings, createRequire and dynamic
    // import — via the cross-line sets collected above. spawn/spawnSync/
    // execFile stay on the network-argv shellNet rule, so literal
    // `spawnSync("ls",["-la"])` remains readable.
    if (language === 'node') {
      // f-round-4 B-N1-b: close alias chains transitively before judging
      // (`const q=cp; const r=q; r.execSync(…)` — two/three hops). Fixpoint
      // over the collected assignment pairs, bounded to 6 passes.
      for (let pass = 0; pass < 6; pass++) {
        let grew = false
        for (const [alias, target] of nodeAliasPairs) {
          if ((nodeCpRefs.has(target) || nodeRequireAliases.has(target) || nodeBareExec.has(target)) &&
              !nodeCpRefs.has(alias) && !nodeBareExec.has(alias)) {
            nodeCpRefs.add(alias)
            grew = true
          }
        }
        if (!grew) break
      }
      let execThreat = false
      if (nodeCpRefs.size > 0) {
        const alt = [...nodeCpRefs].map(reEscape).join('|')
        execThreat =
          new RegExp(`\\b(?:${alt})\\s*\\.\\s*(?:exec|execSync)\\s*(?:\\.\\s*(?:call|apply)\\s*)?\\(`).test(line) ||
          new RegExp(`\\b(?:${alt})\\s*\\[\\s*(?:["'][^"']*(?:exec|execSync)[^"']*["']|\\w+)\\s*\\]\\s*\\(`).test(line)
      }
      // `require("child_process")["execSync"](…)` / `[var](…` (no alias).
      execThreat = execThreat ||
        /require\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\[\s*(?:["'][^"']*(?:exec|execSync)[^"']*["']|\w+)\s*\]\s*\(/.test(line)
      if (nodeBareExec.size > 0) {
        const altB = [...nodeBareExec].map(reEscape).join('|')
        execThreat = execThreat || new RegExp(`\\b(?:${altB})\\s*\\(`).test(line)
      }
      // createRequire("...")("child_process").execSync(…) / dynamic import.
      execThreat = execThreat ||
        /createRequire\s*\([^)]*\)\s*\([^)]*\)\s*\.\s*(?:exec|execSync)\s*\(/.test(line) ||
        /import\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*then\s*\([^)]*(?:exec|execSync)/.test(line) ||
        /\bimport\s*\(\s*["'](?:node:)?child_process["']\s*\)[^;]*(?:exec|execSync)\s*\(/.test(line)
      // f-round-4 B-N1-b: exec-family call present but NOT a directly proven
      // literal `require/import("child_process").execX("bin",[literal argv])`
      // (alias chains, .call/.apply, computed/template keys, variable module
      // ids, createRequire two-line, getBuiltinModule, require.resolve
      // indirections) fails closed. The literal shape keeps `spawnSync("ls")`
      // readable (B2 contract); argv[0]-shell RCE is caught by the risky net.
      if (!execThreat && (
        /\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*(?:\.\s*(?:call|apply)\s*)?\(/.test(line) ||
        /\[["'][^"']*(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)[^"']*["']\s*(?:\+\s*["'][^"']*["']\s*)*\]\s*\(/.test(line))) {
        const literalExec =
          /(?:require\s*\(\s*["'](?:node:)?child_process["']\s*\)|import\s*\(\s*["'](?:node:)?child_process["']\s*\))\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*["'][^"']*["']\s*(?:,\s*\[?\s*["'][^"']*["']\s*(?:,\s*["'][^"']*["'])*\]?\s*)?\)/
        if (!literalExec.test(line)) execThreat = true
      }
      if (execThreat) unverifiable = true
    }
  }

  // Promote bare imports only when there is a corroborating hard hit.
  if (hardHits > 0) {
    for (const imp of importLines) {
      if (out.length >= MAX_HITS) break
      out.push({
        kind: 'network',
        where: lines.length > 1 ? `${where}:${imp.n}` : where,
        snippet: imp.line.trim().slice(0, 160),
        language,
      })
    }
  }
  return unverifiable
}

/* ------------------------------------------------------------------ */
/* File reading with safety caps                                       */
/* ------------------------------------------------------------------ */

const EXCLUDED_SEGMENTS = /(^|\/)(node_modules|\.venv|venv|vendor|__pycache__|\.git|dist|build|out|\.next|target)(\/|$)/
const MAX_DEPTH = 3
const MAX_FILES_TOTAL = 20

interface ScanState {
  hits: EgressHit[]
  unverifiable: boolean
  scannedFiles: string[]
  visited: Set<string>
  cdDirs: string[]
  depth: number
}

async function readScript(
  fileArg: string,
  cdDirs: string[],
): Promise<{ abs: string; code: string } | null> {
  if (!fileArg || fileArg === '-' || fileArg.startsWith('-')) return null
  if (fileArg.includes('://')) return null
  if (fileArg.includes('$') || fileArg.includes('`')) return null
  if (EXCLUDED_SEGMENTS.test(fileArg)) return null
  const roots = [process.cwd(), ...cdDirs]
  for (const root of roots) {
    const abs = isAbsolute(fileArg) ? fileArg : resolve(root, fileArg)
    if (EXCLUDED_SEGMENTS.test(abs)) continue
    try {
      const buf = await readFile(abs)
      if (buf.byteLength > MAX_BYTES_PER_FILE) return null
      if (buf.includes(0)) return null
      return { abs, code: buf.toString('utf8') }
    } catch {
      // try next root
    }
  }
  return null
}

/**
 * Extract LOCAL relative import paths from a scanned file (third-party bare
 * names are left alone — they live in node_modules/.venv and are excluded).
 */
function extractLocalImports(code: string, language: Lang, fileDir: string): string[] {
  const out: string[] = []
  const pushCandidates = (raw: string) => {
    if (!raw || raw.includes('://') || raw.includes('$') || raw.includes('`')) return
    if (EXCLUDED_SEGMENTS.test(raw)) return
    if (language === 'node') {
      const base = raw.startsWith('.') ? resolve(fileDir, raw) : raw
      for (const ext of ['', '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '/index.js', '/index.ts']) {
        out.push(base + ext)
      }
    } else if (language === 'python') {
      const rel = raw.startsWith('.') ? raw.slice(1) : raw
      const asPath = rel.replace(/\//g, '.').split('.').join('/')
      out.push(resolve(fileDir, asPath + '.py'))
      out.push(resolve(fileDir, asPath, '__init__.py'))
    } else if (language === 'ruby') {
      out.push(resolve(fileDir, raw + '.rb'))
    } else if (language === 'php') {
      out.push(resolve(fileDir, raw))
    } else {
      out.push(resolve(fileDir, raw))
    }
  }

  if (language === 'python') {
    for (const m of code.matchAll(/^\s*import\s+([\w.]+)/gm)) pushCandidates(m[1])
    // `from utils import send` → module is `utils`; `from . import sub` →
    // module is the symbol after `import` (sub). Capture BOTH so `.`-relative
    // imports resolve to the sibling module file.
    for (const m of code.matchAll(/^\s*from\s+(\.?[\w.]*)\s+import\s+([\w.]+)/gm)) {
      const mod = m[1]
      if (mod === '.') {
        pushCandidates('.' + m[2])
      } else {
        pushCandidates(mod)
      }
    }
  } else if (language === 'node') {
    // require('./x') — single paren, then the string
    for (const m of code.matchAll(/require\s*\(\s*['"]([^'"]+)['"]/g)) {
      if (m[1].startsWith('.') || m[1].startsWith('/')) pushCandidates(m[1])
    }
    // static esm: `import x from './x'` and `import './x'`
    for (const m of code.matchAll(/import\s+(?:[^'"\n]*?\s+from\s+)?['"]([^'"]+)['"]/g)) {
      if (m[1].startsWith('.') || m[1].startsWith('/')) pushCandidates(m[1])
    }
    // dynamic import('./x')
    for (const m of code.matchAll(/import\s*\(\s*['"]([^'"]+)['"]/g)) {
      if (m[1].startsWith('.') || m[1].startsWith('/')) pushCandidates(m[1])
    }
  } else if (language === 'shell') {
    for (const m of code.matchAll(/^\s*(?:source|\.)\s+(['"]?)(\S+)\1/gm)) {
      const p = m[2]
      if (p.startsWith('.') || p.startsWith('/')) pushCandidates(p)
    }
  } else if (language === 'ruby') {
    for (const m of code.matchAll(/require\s+['"](\.[^'"]+)['"]/g)) pushCandidates(m[1])
  } else if (language === 'php') {
    for (const m of code.matchAll(/(?:require|include)(?:_once)?\s+['"]([^'"]+\.php)['"]/g)) pushCandidates(m[1])
  }
  return out
}

/** Scan one file's code and recursively follow its local imports. */
async function scanFileRecursive(
  abs: string,
  code: string,
  language: Lang,
  state: ScanState,
): Promise<void> {
  if (state.visited.has(abs)) return
  state.visited.add(abs)
  if (!state.scannedFiles.includes(abs)) state.scannedFiles.push(abs)
  if (scanCode(code, language, `file:${abs}`, state.hits)) state.unverifiable = true

  if (state.depth >= MAX_DEPTH || state.scannedFiles.length >= MAX_FILES_TOTAL) return
  const fileDir = resolve(abs, '..')
  for (const cand of extractLocalImports(code, language, fileDir)) {
    if (state.scannedFiles.length >= MAX_FILES_TOTAL) break
    if (state.visited.has(cand)) continue
    const r = await readScript(cand, state.cdDirs)
    if (!r) continue
    // Carry depth down so MAX_DEPTH actually limits local-import recursion
    // (shared arrays/sets stay by reference; depth is copied).
    await scanFileRecursive(r.abs, r.code, language, { ...state, depth: state.depth + 1 })
  }
}

/* ------------------------------------------------------------------ */
/* Manifest-driven runners: package.json scripts, pytest collection    */
/* ------------------------------------------------------------------ */

async function readJson(p: string): Promise<any | null> {
  try { return JSON.parse(await (await readFile(p)).toString('utf8')) } catch { return null }
}

/** npm/pnpm/yarn run <name> → scan the named package.json script body. */
async function scanNpmScript(name: string, state: ScanState): Promise<void> {
  for (const root of [process.cwd(), ...state.cdDirs]) {
    const pkg = await readJson(resolve(root, 'package.json'))
    if (!pkg?.scripts) continue
    const script = pkg.scripts[name]
    if (typeof script !== 'string') continue
    const sub = await scanCommandForEgress(script, state.depth + 1, state.cdDirs)
    state.hits.push(...sub.hits)
    state.unverifiable = state.unverifiable || sub.unverifiable
    for (const f of sub.scannedFiles) if (!state.scannedFiles.includes(f)) state.scannedFiles.push(f)
    return
  }
}

/** pytest / py.test → collect test_*.py / *_test.py under the project. */
async function collectPytestFiles(state: ScanState): Promise<string[]> {
  const found: string[] = []
  const { readdir } = await import('node:fs/promises')
  for (const root of [process.cwd(), ...state.cdDirs]) {
    for (const sub of ['.', 'tests', 'test']) {
      try {
        const dir = resolve(root, sub)
        const entries = await readdir(dir, { withFileTypes: true })
        for (const e of entries) {
          if (e.isFile() && (e.name.startsWith('test_') || e.name.endsWith('_test.py'))) {
            found.push(resolve(dir, e.name))
          }
        }
      } catch { /* not a dir */ }
    }
  }
  return found.slice(0, 10)
}

/* ------------------------------------------------------------------ */
/* Public entry                                                        */
/* ------------------------------------------------------------------ */

/**
 * Scan a bash command for network egress hidden inside locally-executed code.
 * Works on the RAW command string so heredoc bodies and `-c`/`-e` inline
 * code are inspected. Follows local imports recursively (depth 3, 20 files)
 * and resolves manifest runners (npm run, pytest). Pure reads; never executes.
 */
export async function scanCommandForEgress(
  command: string,
  depth = 0,
  cdDirs: string[] = [],
): Promise<EgressReport> {
  const hits: EgressHit[] = []
  const scannedFiles: string[] = []
  const state: ScanState = {
    hits,
    unverifiable: false,
    scannedFiles,
    visited: new Set(),
    cdDirs,
    depth,
  }

  // 1. Heredoc bodies
  const { bodies, clean } = extractHeredocs(command)
  for (const b of bodies) {
    if (hits.length >= MAX_HITS) break
    if (scanCode(b.body, b.language, `heredoc:stdin`, hits)) state.unverifiable = true
  }

  // 2. cd targets so relative script paths resolve
  const cdDirsMerged: string[] = [...cdDirs]
  for (const seg of splitSeparators(clean)) {
    const cm = seg.match(/^cd\s+(?:--\s+)?(?:"([^"]*)"|'([^']*)'|(\S+))/)
    if (cm) {
      const t = cm[1] ?? cm[2] ?? cm[3]
      cdDirsMerged.push(resolve(process.cwd(), t))
    }
  }
  state.cdDirs = cdDirsMerged

  // 3. Each command segment
  outer: for (const seg of splitSeparators(clean)) {
    if (hits.length >= MAX_HITS) break
    // B8: strip every leading `VAR=value` env assignment, including quoted
    // values (`CMD='curl https://evil/x' awk …`) — a bare regex previously
    // only handled one unquoted `\S+` and left the interpreter hidden.
    let segEnvStripped = seg
    for (;;) {
      const m = segEnvStripped.match(/^[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\S+)\s+/)
      if (!m) break
      segEnvStripped = segEnvStripped.slice(m[0].length)
    }
    const toks = tokenize(segEnvStripped)
    if (toks.length === 0) continue
    const first = (toks[0] ?? '').split('/').pop()?.toLowerCase() ?? ''
    const lang = INTERPRETERS[first]

    let isNpx = first === 'npx'
    const isGoRun = first === 'go' && toks[1] === 'run'

    // npm/pnpm/yarn run <script> → read package.json scripts.<script>
    if (['npm', 'pnpm', 'yarn'].includes(first) &&
        ['run', 'run-script', 'test', 'start', 'dev'].includes(toks[1] ?? '')) {
      const name = (toks.find((t, idx) => idx > 1 && !t.startsWith('-')) ?? '').toLowerCase()
      await scanNpmScript(name, state)
      continue
    }
    // pytest → collect test_*.py / *_test.py under the project
    if (['pytest', 'py.test', 'tox'].includes(first) && state.depth < MAX_DEPTH) {
      const files = await collectPytestFiles(state)
      for (const f of files) {
        if (state.scannedFiles.length >= MAX_FILES_TOTAL) break
        const r = await readScript(f, state.cdDirs)
        if (r) await scanFileRecursive(r.abs, r.code, 'python', state)
      }
      continue
    }

    // xargs runs its inner command on stdin lines — recurse so the inner
    // interpreter code / write verbs are scanned (BLOCKER 7b: `echo /etc/x |
    // xargs ruby -e 'File.write(ARGV[0],"x")'`). Skip xargs' own option
    // cluster (incl. value-taking -I/-i/-L/-l/-n/-P/-s/-d/-E and attached
    // forms like -I{} / -n1) and scan the rest as a command.
    if (first === 'xargs') {
      let j = 1
      while (j < toks.length) {
        const t = toks[j]
        if (!t.startsWith('-')) break
        if ((t === '-I' || t === '-i' || t === '-L' || t === '-l' || t === '-n' ||
             t === '-P' || t === '-s' || t === '-d' || t === '-E') &&
            toks[j + 1] && !toks[j + 1].startsWith('-')) { j += 2; continue }
        j++
        continue
      }
      const inner = toks.slice(j).join(' ')
      if (inner) {
        const sub = await scanCommandForEgress(inner, state.depth + 1, state.cdDirs)
        hits.push(...sub.hits)
        state.unverifiable ||= sub.unverifiable
        state.scannedFiles.push(...sub.scannedFiles)
      }
      continue
    }

    if (!lang && !isNpx && !isGoRun) continue

    const language: Lang = isNpx || isGoRun ? 'node' : lang!
    const positionals: string[] = []
    let i = 1
    if (lang === 'awk') {
      // awk: the first non-flag positional is the PROGRAM text (unless -f
      // already supplies a script file); remaining positionals are data or
      // script files. The program is a code space the token extractor cannot
      // see, so scan it like inline code.
      const hasScriptFile = toks.some((t) => t === '-f' || t.startsWith('--file='))
      let sawProgram = false
      while (i < toks.length) {
        const t = toks[i]
        if (t.startsWith('--file=')) { positionals.push(t.slice(7)); i++; continue }
        if (t === '-f') { if (toks[i + 1]) { positionals.push(toks[i + 1]); i += 2 }; continue }
        // B8: `-v name=value` (possibly quoted) assigns an awk variable that a
        // `BEGIN{var|getline}` body may execute — skip BOTH tokens so the
        // program text is scanned as code, not mistaken for a data file.
        if (t === '-v') {
          if (toks[i + 1]) i += 2
          else i += 1
          continue
        }
        if (t.startsWith('-')) { i++; continue }
        if (!hasScriptFile && !sawProgram) {
          if (scanCode(t, 'awk', `inline:awk program`, hits)) state.unverifiable = true
          sawProgram = true
          i++
          continue
        }
        positionals.push(t)
        i++
      }
    } else if (isNpx) {
      while (i < toks.length) {
        const t = toks[i]
        if (/^--(yes|-yes|no-install|no|package=\S+)/.test(t) || /^-[yp]$/.test(t)) { i++; continue }
        if (t.startsWith('-')) { i++; continue }
        positionals.push(t); i++
      }
      positionals.shift()
    } else {
      while (i < toks.length) {
        const t = toks[i]
        if (t === '-c' || t === '-e' || t === '--eval' || t === '-r' || t === '-R') {
          if (i + 1 < toks.length) {
            const code = unquote(toks[i + 1])
            if (scanCode(code, language, `inline:${first} ${t}`, hits)) state.unverifiable = true
            i += 2
            continue
          }
          i++
          continue
        }
        if (/^-(c|e)=/.test(t)) {
          const code = unquote(t.slice(t.indexOf('=') + 1))
          if (scanCode(code, language, `inline:${first}`, hits)) state.unverifiable = true
          i++
          continue
        }
        if (t.startsWith('-')) {
          if (VALUE_FLAGS.has(t) && i + 1 < toks.length) i += 2
          else i++
          continue
        }
        positionals.push(t)
        i++
      }
    }

    if (isGoRun) continue

    for (const p of positionals) {
      if (state.scannedFiles.length >= MAX_FILES_TOTAL) break outer
      const r = await readScript(p, state.cdDirs)
      if (!r) continue
      await scanFileRecursive(r.abs, r.code, language, state)
    }
  }

  return { hits: hits.slice(0, MAX_HITS), unverifiable: state.unverifiable, scannedFiles }
}

