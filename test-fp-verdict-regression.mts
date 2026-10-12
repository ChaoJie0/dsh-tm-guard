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

// ── dsh independent review (fp-review-f7057e6): N1 converter outputs ──
// Writes must surface as file_write with the output path extracted — the
// prior bug was local_exec with NO snapshot. Under TM protection decide()
// allows with shouldSnapshot (the rollback promise); the guard rails are
// the classification + path extraction, asserted here.
check('magick in.png /etc/cron.d/evil', { category: 'file_write', pathsInclude: ['/etc/cron.d/evil'] })
check('convert x.png /etc/sudoers.d/x', { category: 'file_write', pathsInclude: ['/etc/sudoers.d/x'] })
check('qpdf --decrypt in.pdf /etc/o.pdf', { category: 'file_write', pathsInclude: ['/etc/o.pdf'] })
check('gs -sOutputFile=/etc/o.pdf in.pdf', { category: 'file_write', pathsInclude: ['/etc/o.pdf'] })
check('mutool draw -o /etc/o.pdf in.pdf', { category: 'file_write', pathsInclude: ['/etc/o.pdf'] })
check('textutil -convert txt /tmp/in.rtf -output /etc/o.txt', { category: 'file_write', pathsInclude: ['/etc/o.txt'] })
// Benign converter targets stay allowed.
check('magick in.png /tmp/tm-guard-workspace/o.png', { category: 'file_write', allow: true })
check('mutool draw -o /tmp/o.pdf in.pdf', { category: 'file_write', allow: true })

// ── N2: unverifiable dangerous call sites fail closed to unknown ──
// chr()-obfuscated require / from-import aliases cannot be validated.
check('node -e "require(chr(99)+chr(104)+chr(105)+chr(108)+chr(100)+chr(95)+chr(112)+chr(114)+chr(111)+chr(99)+chr(101)+chr(115)+chr(115)).execSync(chr(99)+chr(117)+chr(114)+chr(108))"', {
  category: 'unknown', allow: false,
})
check('python3 -c "from subprocess import run as r; r([chr(99)+chr(117)+chr(114)+chr(108)])"', {
  category: 'unknown', allow: false,
})
check('node -e "spawn(chr(114)+chr(109),chr(91)+chr(45)+chr(114)+chr(102)+chr(44)+chr(47)+chr(116)+chr(109)+chr(112)+chr(47)+chr(120)+chr(93))"', {
  category: 'unknown', allow: false,
})

// ── N3: argv-list reassembly classifies the real inner command ──
check('python3 -c "import subprocess; subprocess.run([\'bash\',\'-c\',\'curl http://example.com/x\'])"', {
  category: 'network', allow: false,
})
check('python3 -c "import subprocess; subprocess.run([\'ls\'])"', { category: 'local_exec', allow: true })
check('python3 -c "import subprocess; subprocess.run([\'pip3\',\'install\',\'x\'])"', {
  category: 'package', allow: false,
})

// ── N2 (review M1): indirect/aliased call shapes fail closed ──
// The old regex net missed subscript, aliased assignment, module-alias and
// getattr forms; each previously sailed through as local_exec.
check('node -e "process[\'kill\'](123)"', { category: 'unknown', allow: false })
check('node -e "const f=fetch; f(\'http://example.invalid/x\')"', { category: 'unknown', allow: false })
check('node -e "const cp=require(\'child_process\'); cp.exec(\'curl http://example.invalid/x\')"', {
  category: 'unknown', allow: false,
})
check('node -e "const {execSync}=require(\'child_process\'); execSync(\'curl http://example.invalid/x\')"', {
  category: 'unknown', allow: false,
})
check('python3 -c "import subprocess as s; s.run([\'bash\',\' -c\',\'curl http://example.invalid/x\'])"'.replace("' -c'", "'-c'"), {
  category: 'unknown', allow: false,
})
check('python3 -c "import subprocess as s; getattr(s,\'run\')([\'bash\',\' -c\',\'curl http://example.invalid/x\'])"'.replace("' -c'", "'-c'"), {
  category: 'unknown', allow: false,
})
check('python3 -c "from shutil import rmtree as r; r(\'/etc/x\')"', { category: 'unknown', allow: false })
check('python3 -c "from subprocess import run as r; r([\'curl\',\'http://example.invalid/x\'])"', {
  category: 'unknown', allow: false,
})
check('python3 -c "import urllib.request as u; u.urlopen(\'http://example.invalid/x\')"', {
  category: 'unknown', allow: false,
})
check('python3 -c "import subprocess; subprocess.run(\'curl http://example.invalid/x\', shell=True)"', {
  category: 'unknown', allow: false,
})
check('node -e "require(\'fs\').writeFileSync(\'/etc/x\',\'a\')"', { category: 'unknown', allow: false })
check('node -e "globalThis.fetch(\'http://example.invalid/x\')"', { category: 'unknown', allow: false })

// ── N2 (review M2): provably read-only stdlib stays local_exec ──
check('python3 -c "import os; print(os.getcwd())"', { category: 'local_exec', allow: true })
check('python3 -c "import shutil; print(shutil.which(\'ls\'))"', { category: 'local_exec', allow: true })
check('python3 -c "import shutil; print(shutil.disk_usage(\'/\'))"', { category: 'local_exec', allow: true })
check('python3 -c "import pathlib; print(pathlib.Path(\'.\').exists())"', { category: 'local_exec', allow: true })
check('python3 -c "import os; print(os.listdir(b\'.\'))"', { category: 'local_exec', allow: true })
check('python3 -c "from pathlib import Path; Path(\'.\').resolve()"', { category: 'local_exec', allow: true })
check('python3 -c "import os.path; print(os.path.join(\'a\',\'b\'))"', { category: 'local_exec', allow: true })
check('python3 -c "from subprocess import TimeoutExpired; print(\'x\')"', { category: 'local_exec', allow: true })
check('node -e "console.log(\'m\')"', { category: 'local_exec', allow: true })
check('node -e "process.env.PATH"', { category: 'local_exec', allow: true })
check('node -e "require(\'path\').join(\'a\',\'b\')"', { category: 'local_exec', allow: true })
check('node -e "require(\'fs\').readFileSync(\'/etc/hosts\',\'utf8\')"', { category: 'local_exec', allow: true })

// ── N4: uv package operations denied, read/run forms allowed ──
check('uv pip install x', { category: 'package', allow: false })
check('uv add x', { category: 'package', allow: false })
check('uv tool install x', { category: 'package', allow: false })
check('uv run --with x python s.py', { category: 'package', allow: false })
check('uv pip list', { category: 'local_exec', allow: true })
check('uv --version', { category: 'read', allow: true })
check('uv run python s.py', { category: 'local_exec', allow: true })

// ── N5: loopback exact-host matching (masquerades denied, forms allowed) ──
check('curl http://localhost.evil.example.invalid/x', { category: 'network', allow: false })
check('curl http://127.0.0.1.nip.io/x', { category: 'network', allow: false })
check('curl http://evillocalhost/x', { category: 'network', allow: false })
check('curl 127.0.0.1.evil.example.invalid:8080', { category: 'network', allow: false })
check('curl http://localhost:8080/health', { category: 'local_network', allow: true })
check('curl http://[0:0:0:0:0:0:0:1]:8080/', { category: 'local_network', allow: true })
check('curl http://[::ffff:127.0.0.1]:8080/', { category: 'local_network', allow: true })
check('curl http://[::ffff:7f00:1]:8080/', { category: 'local_network', allow: true })
check('curl http://[::ffff:7f000001]:8080/', { category: 'local_network', allow: true })
check('curl 127.0.0.1:8080', { category: 'local_network', allow: true })

// ── T3: false-positive regressions from R1 converter handling ──
check('ffmpeg -y -i in.mov -f null - 2>/dev/null', { category: 'local_exec', allow: true })
check('ffprobe in.mov', { category: 'local_exec', allow: true })
check('ffmpeg -h long | head -3', { category: 'read', allow: true })
check('ffmpeg -y -i in.mov /tmp/a.wav', { category: 'file_write', allow: true })

console.log(`\n# ${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
