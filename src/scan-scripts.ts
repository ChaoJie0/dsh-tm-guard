/**
 * Static egress scan for locally-executed scripts.
 *
 * The command-level classifier trusts an interpreter (`python x.py`,
 * `node x.js`, `bash deploy.sh`) as `local_exec` because the interpreter
 * itself has no network side effects. The blind spot is the SCRIPT it runs:
 * `requests.get(...)`, `fetch(...)`, `curl` inside a .sh, etc. are invisible
 * to string matching on the command line.
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

type Lang = 'python' | 'node' | 'shell' | 'ruby' | 'php' | 'perl'

const INTERPRETERS: Record<string, Lang> = {
  python: 'python', python3: 'python', python2: 'python',
  node: 'node', nodejs: 'node', deno: 'node', bun: 'node',
  ruby: 'ruby',
  php: 'php', php7: 'php', php8: 'php',
  perl: 'perl',
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
  },
  php: {
    importNet: [],
    callNet: [
      /\b(curl_init|curl_exec|fsockopen|pfsockopen|stream_socket_client)\s*\(|file_get_contents\s*\(\s*['"]https?:|fopen\s*\(\s*['"]https?:/,
    ],
    shellNet: [],
    dyn: [/\b(eval|assert)\s*\(/],
  },
  perl: {
    importNet: [
      /\buse\s+(LWP|LWP::Simple|LWP::UserAgent|HTTP::Request|IO::Socket|Net::FTP|Net::SSH2|SOAP::Lite|HTTP::Tiny)\b/,
      /\brequire\s+.*(LWP|HTTP::Request)/,
    ],
    callNet: [],
    shellNet: [],
    dyn: [/\beval\s*(["'{(]|\s*\{)/],
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
      const lang = INTERPRETERS[first]
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

function scanCode(code: string, language: Lang, where: string, out: EgressHit[]): boolean {
  const rules = RULES[language]
  let unverifiable = false
  const lines = code.split('\n')
  const importLines: { n: number; line: string }[] = []
  let hardHits = 0

  for (let i = 0; i < lines.length && out.length < MAX_HITS; i++) {
    const line = lines[i]
    if (!line || line.trim().length === 0) continue

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
      if (re.test(line)) unverifiable = true
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
      const asPath = raw.replace(/\//g, '.').split('.').join('/')
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
    for (const m of code.matchAll(/^\s*from\s+(\.?[\w.]*)\s+import\b/gm)) {
      const mod = m[1]
      if (mod === '.') {
        const sub = m[0].match(/import\s+([\w.]+)/)
        if (sub) pushCandidates('.' + sub[1])
      } else {
        pushCandidates(mod)
      }
    }
  } else if (language === 'node') {
    const re = /(?:require\s*\(|import\s*(?:[\s\S]{0,120}?from\s+)?|import\s*)\(\s*['"]([^'"]+)['"]/g
    for (const m of code.matchAll(re)) {
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
    await scanFileRecursive(r.abs, r.code, language, state)
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
    const toks = tokenize(seg.replace(/^[A-Za-z_]\w*=\S+\s+/, ''))
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

    if (!lang && !isNpx && !isGoRun) continue

    const language: Lang = isNpx || isGoRun ? 'node' : lang!
    const positionals: string[] = []
    let i = 1
    if (isNpx) {
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
        if (t === '-c' || t === '-e' || t === '--eval') {
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

