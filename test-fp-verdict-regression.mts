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
// Networking stdlib requires must NOT be whitelisted read-only (they would be
// stripped whole and ride local_exec): require('http').request / https.get /
// net.connect all deny.
check('node -e "require(\'http\').request(\'http://example.invalid/x\',cb)"', { category: 'unknown', allow: false })
check('node -e "require(\'https\').get(\'https://example.invalid/x\')"', { category: 'unknown', allow: false })
check('node -e "require(\'net\').connect(\'1.2.3.4:443\')"', { category: 'unknown', allow: false })
// Symmetric dynamic-import() entries (H4): read-only import('path') allowed,
// networking/child_process dynamic imports denied.
check('node -e "import(\'path\').then(p=>console.log(p.join(\'a\',\'b\')))"', { category: 'local_exec', allow: true })
check('node --input-type=module -e "import(\'child_process\').then(m=>m.execSync(\'curl https://example.invalid/x\'))"', { category: 'unknown', allow: false })
check('node --input-type=module -e "import(\'http\').then(h=>h.get(\'http://example.invalid/x\'))"', { category: 'unknown', allow: false })

// ── H1: os.system/os.popen are shell-string exec primitives — fail closed ──
check('python3 -c "import os; os.system(\'id\')"', { category: 'unknown', allow: false })
check('python3 -c "import os; os.system(\'bash -i\')"', { category: 'unknown', allow: false })
check('python3 -c "import os; print(os.system(\'id\'))"', { category: 'unknown', allow: false })
check('python3 -c "import os; os.system(\'id\') # comment"', { category: 'unknown', allow: false })
check('python3 -c "import os; os.popen(\'id\')"', { category: 'unknown', allow: false })

// ── H2/H6: member-expression RHS aliases & requests from-import ──
check('node -e "const f=globalThis.fetch;f(\'http://example.invalid/x\')"', { category: 'unknown', allow: false })
check('node -e "const f=globalThis.fetch\nf(\'http://example.invalid/x\')"', { category: 'unknown', allow: false })
check('node -e "const k=globalThis.process.kill;k(123)"', { category: 'unknown', allow: false })
check('python3 -c "from requests import get as g; g(\'http://example.invalid\')"', { category: 'unknown', allow: false })

// ── H3: builtin open() write modes / Path-family write methods / from-import
// source-constrained aliases ──
check('python3 -c "open(\'/etc/guardtest/x\',\'w\').write(\'a\')"', { category: 'unknown', allow: false })
check('python3 -c "with open(\'/etc/cron.d/gx\',\'w\') as f: f.write(\'a\')"', { category: 'unknown', allow: false })
check('python3 -c "from pathlib import Path as P; P(\'/etc/guardtest/x\').write_text(\'a\')"', { category: 'unknown', allow: false })
check('python3 -c "from pathlib import Path as P\nP(\'/etc/guardtest/x\').write_text(\'a\')"', { category: 'unknown', allow: false })
check('python3 -c "Path(\'/etc/guardtest/x\').write_text(\'a\')"', { category: 'unknown', allow: false })
check('python3 -c "from os import chmod; chmod(\'/etc/guardtest/x\',0o777)"', { category: 'unknown', allow: false })
check('python3 -c "from os import remove; remove(\'/etc/guardtest/x\')"', { category: 'unknown', allow: false })
// read-mode open / aliased-Path read-only stay allowed
check('python3 -c "open(\'/etc/hosts\').read()"', { category: 'local_exec', allow: true })
check('python3 -c "open(\'/etc/hosts\',\'rb\').read()"', { category: 'local_exec', allow: true })
check('python3 -c "from pathlib import Path as P; print(P(\'.\').resolve())"', { category: 'local_exec', allow: true })

// ── H5: uv python install/uninstall, tool run/upgrade, self update ──
check('uv python install 3.12', { category: 'package', allow: false })
check('uv python uninstall 3.11', { category: 'package', allow: false })
check('uv tool run ruff', { category: 'package', allow: false })
check('uv tool upgrade ruff', { category: 'package', allow: false })
check('uv self update', { category: 'package', allow: false })
check('uv python list', { category: 'local_exec', allow: true })
check('uv tool list', { category: 'local_exec', allow: true })
check('uv self version', { category: 'local_exec', allow: true })

// ── H7: fs held in a variable — read-only members allowed, write members
// still denied via the fs module-member net ──
check('node -e "const fs=require(\'fs\');console.log(fs.existsSync(\'/tmp/x\'))"', { category: 'local_exec', allow: true })
check('node -e "const fs=require(\'fs\');fs.statSync(\'/tmp\')"', { category: 'local_exec', allow: true })
check('node -e "const fs=require(\'fs\');fs.writeFileSync(\'/etc/guardtest/x\',\'a\')"', { category: 'unknown', allow: false })

// ── W4: vm run* contexts are code-execution primitives ──
check('node -e "require(\'vm\').runInNewContext(\'os.system(\'id\')\')"', { category: 'unknown', allow: false })

// ── N1: dotted-submodule from-import source (urllib.request) ──
check('python3 -c "from urllib.request import urlopen as u; u(\'http://example.invalid\')"', { category: 'unknown', allow: false })

// ── N2: fs.promises namespace + ESM static named imports of node:fs ──
check('node -e "const fs=require(\'fs\'); fs.promises.writeFile(\'/etc/guardtest/x\',\'a\')"', { category: 'unknown', allow: false })
check('node -e "const fs=require(\'fs\'); fs.promises.rm(\'/etc/guardtest/x\')"', { category: 'unknown', allow: false })
check('node -e "const fs=require(\'fs\'); fs.promises.unlink(\'/etc/guardtest/x\')"', { category: 'unknown', allow: false })
check('node -e "const fs=require(\'fs\'); fs.promises.appendFile(\'/etc/guardtest/x\',\'a\')"', { category: 'unknown', allow: false })
check('node -e "const fs=require(\'fs\'); fs.promises.chmod(\'/etc/guardtest/x\',0o777)"', { category: 'unknown', allow: false })
check('node --input-type=module -e "import {writeFileSync} from \'node:fs\'; writeFileSync(\'/etc/guardtest/x\',\'a\')"', { category: 'unknown', allow: false })
check('node --input-type=module -e "import fs from \'node:fs\'; fs.promises.writeFile(\'/etc/guardtest/x\',\'a\')"', { category: 'unknown', allow: false })
// promises read-only stays allowed
check('node -e "const fs=require(\'fs\'); fs.promises.readFile(\'/etc/hosts\',\'utf8\')"', { category: 'local_exec', allow: true })

// ── N3: Path bound to a variable, then write method (variable-held form) ──
check('python3 -c "from pathlib import Path as P; p=P(\'/etc/guardtest/x\'); p.write_text(\'a\')"', { category: 'unknown', allow: false })
check('python3 -c "from pathlib import Path as P\np=P(\'/etc/guardtest/x\')\np.write_text(\'a\')"', { category: 'unknown', allow: false })
check('python3 -c "from pathlib import Path as P; p=P(\'/etc/guardtest/x\'); p.unlink()"', { category: 'unknown', allow: false })
// variable-held read-only stays allowed
check('python3 -c "from pathlib import Path as P; p=P(\'.\'); print(p.resolve())"', { category: 'local_exec', allow: true })

// ── N4: destructuring / array-binding / optional-chain receivers + exp flag ──
check('node -e "const {fetch: fc}=globalThis; fc(\'http://example.invalid/x\')"', { category: 'unknown', allow: false })
check('node -e "const [f]=[globalThis.fetch]; f(\'http://example.invalid/x\')"', { category: 'unknown', allow: false })
check('node -e "const f=globalThis?.fetch; f(\'http://example.invalid/x\')"', { category: 'unknown', allow: false })
check('node --experimental-default-type=module -e "import(\'http\').then(h=>h.get(\'http://example.invalid/x\'))"', { category: 'unknown', allow: false })

// ── W1: open r+ write mode ──
check('python3 -c "open(\'/etc/guardtest/x\',\'r+\').write(\'a\')"', { category: 'unknown', allow: false })

// ── W3: read-only names from high-risk sources stay allowed (dotted forms
// already allowed; from-import must not be source-guilty for these) ──
check('python3 -c "from os import getcwd; print(getcwd())"', { category: 'local_exec', allow: true })
check('python3 -c "from os import getcwd as g; print(g())"', { category: 'local_exec', allow: true })
check('python3 -c "from os import getenv; print(getenv(\'HOME\'))"', { category: 'local_exec', allow: true })
check('python3 -c "from shutil import which as w; print(w(\'ls\'))"', { category: 'local_exec', allow: true })
check('python3 -c "from os.path import join; print(join(\'a\',\'b\'))"', { category: 'local_exec', allow: true })

// ── W4: fs destructuring with rename is read-only too ──
check('node -e "const {readFileSync: r}=require(\'fs\'); console.log(r(\'/etc/hosts\',\'utf8\'))"', { category: 'local_exec', allow: true })
check('node -e "const {readFileSync}=require(\'fs\'); console.log(readFileSync(\'/etc/hosts\',\'utf8\'))"', { category: 'local_exec', allow: true })

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
