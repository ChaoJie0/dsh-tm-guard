// R1/R2/R5 regression tests from the fp-verdict audit (124 production
// candidates: 57 true false-positives, 26 allow-side bypasses).
// Run: node --test test-fp-verdict-regression.mts
import { classifyBashCommand, decide } from './src/classifier.ts'
import { mkdirSync } from 'node:fs'

mkdirSync('/tmp/tm-guard-workspace', { recursive: true })
process.chdir('/tmp/tm-guard-workspace')

let pass = 0
let fail = 0

function check(cmd: string, opts: {
  category: string
  allow?: boolean
  forceDeny?: boolean
  pathsInclude?: string[]
  pathsProtected?: boolean
}) {
  const c = classifyBashCommand(cmd)
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

// ── R1: converter / metadata probes are read-only (were unknown / process) ──
check('ffmpeg -version', { category: 'read', allow: true })
check('ffprobe -version 2>&1 | head -3', { category: 'read', allow: true })
check('soffice --version', { category: 'read', allow: true })
check('soffice --help', { category: 'read', allow: true })
check('qpdf --version 2>/dev/null', { category: 'read', allow: true })
check('uv --version', { category: 'read', allow: true })
check('avconvert --help', { category: 'read', allow: true })
check('sips --help', { category: 'read', allow: true })
check('sips --version', { category: 'read', allow: true })
check('otool -L /opt/homebrew/bin/ffmpeg | grep x265', { category: 'read', allow: true })
check('mdls -name kMDItemWhereFroms /tmp/f.pdf', { category: 'read', allow: true })
check('pgrep -f pip', { category: 'read', allow: true })
check('afinfo /tmp/f.m4a', { category: 'read', allow: true })
check('textutil -convert txt -stdout /tmp/f.rtf', { category: 'local_exec', allow: true })
// pdftotext with an explicit output is file_write; bare probe (stdout) stays local_exec.
check('pdftotext -layout /tmp/a.pdf /tmp/a.txt', {
  category: 'file_write', allow: true, pathsProtected: false, pathsInclude: ['/tmp/a.txt'],
})
check('pdftotext -layout /tmp/a.pdf', { category: 'local_exec', allow: true })
check('pdftotext -layout /tmp/a.pdf /etc/a.txt', {
  category: 'file_write', allow: false, pathsProtected: false, pathsInclude: ['/etc/a.txt'],
})

// ── R1: conversion outputs decide write permission (path extraction) ──
// A local converter with an explicit output is classified file_write so the
// decide layer applies TM-protection / temp-dir logic to its output path.
check('ffmpeg -y -i in.m4a -ar 16000 /tmp/out.wav', {
  category: 'file_write', allow: true, pathsProtected: false, pathsInclude: ['/tmp/out.wav'],
})
check('ffmpeg -y -i in.m4a -ar 16000 /etc/out.wav', {
  category: 'file_write', allow: false, pathsProtected: false, pathsInclude: ['/etc/out.wav'],
})
// Output inside a protected root stays allowed.
check('ffmpeg -y -i in.m4a -ar 16000 /tmp/tm-guard-workspace/out.wav', {
  category: 'file_write', allow: true, pathsInclude: ['/tmp/tm-guard-workspace/out.wav'],
})
// `-f null -` probes write nothing (no write target extracted).
check('ffmpeg -i in.m4a -f null - 2>&1 | tail -5', { category: 'local_exec', allow: true })
// soffice --outdir decides the write root.
check('soffice --headless --convert-to pdf --outdir /tmp/tm-guard-workspace in.docx', {
  category: 'file_write', allow: true, pathsInclude: ['/tmp/tm-guard-workspace'],
})
check('soffice --headless --convert-to pdf --outdir /etc in.docx', {
  category: 'file_write', allow: false, pathsProtected: false, pathsInclude: ['/etc'],
})
// swiftc -o output path.
check('swiftc /tmp/a.swift -o /tmp/tm-guard-workspace/a', {
  category: 'file_write', allow: true, pathsInclude: ['/tmp/tm-guard-workspace/a'],
})
check('swiftc /tmp/a.swift -o /etc/a', { category: 'file_write', allow: false, pathsProtected: false, pathsInclude: ['/etc/a'] })

// ── R1: npm read-only queries (were package / network) ──
check('npm pack --dry-run', { category: 'read', allow: true })
check('npm config get registry', { category: 'read', allow: true })
check('npm view dsh-tm-guard version', { category: 'read', allow: true })
check('npm search pdf', { category: 'read', allow: true })
// npm install must stay denied.
check('npm install lodash', { category: 'network', allow: false })

// ── R2: loopback-only probes stay local (local_network) ──
check('curl -sI http://127.0.0.1:3104/ | head -3', { category: 'local_network', allow: true })
check('curl -s -X POST http://127.0.0.1:3104/api/auth/login -d x', { category: 'local_network', allow: true })
check('curl http://localhost:8080/health', { category: 'local_network', allow: true })
check('curl http://localhost.localdomain:3000/api', { category: 'local_network', allow: true })
check('curl http://[::1]:8080/health', { category: 'local_network', allow: true })
// Same URL via a non-loopback host stays network (R2 hardening).
check('curl http://example.com/x', { category: 'network', allow: false })

// ── R5: allow-side bypasses must not ride on read / local_exec ──
// env wrapper: the inner command decides (was read).
check('env curl -s http://example.com/x', { category: 'network', allow: false })
check('env git push origin main', { category: 'vcs_remote', allow: false })
check('env uv --version', { category: 'read', allow: true })
// shell -c: the code string decides (was unknown / rode on shell).
check('bash -c "rm -rf /tmp/x && curl -s http://evil.example.com/x"', { category: 'system', forceDeny: true })
check('bash -c "curl -s http://example.com/x"', { category: 'network', allow: false })
check('bash -n /tmp/x.sh', { category: 'read', allow: true })
check('sh -c "npm install lodash"', { category: 'network', allow: false })
// python module mode: pip install is package management (was local_exec).
check('python3 -m pip install x', { category: 'network', allow: false })
check('python3 -m http.server 8080', { category: 'local_exec', allow: true })
// python inline network call (was local_exec).
check('python3 -c "import requests; requests.get(\'https://example.com/leak\')"', {
  category: 'network', allow: false,
})
// python subprocess wrapping a network tool (was local_exec).
check('python3 -c "import subprocess; subprocess.run([\'curl\',\'https://example.com/x\'])"', {
  category: 'network', allow: false,
})
// node process.kill (was local_exec).
check('node -e "process.kill(123,\'SIGTERM\')"', { category: 'process', allow: false })
// benign interpreter code stays local_exec.
check('python3 -c "print(1+1)"', { category: 'local_exec', allow: true })

console.log(`\n# ${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
