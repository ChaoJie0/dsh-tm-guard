// Verifies the pre-execute gate reads dsh's ToolExecution fields correctly.
// dsh passes exec = { name, arguments, callId, ... } — NOT { tool, args, input }.
// This replicates exactly the extraction + classification the hook performs.
import { classifyToolCall, decide, isTempPath } from './src/classifier.ts'

let pass = 0
let fail = 0
function check(label: string, execLike: { name: string; arguments: unknown }, opts: {
  allow: boolean
  category: string
  paths?: string[]
}, protectedPaths = ['/tmp/tm-guard-home'], cwdProtected = true) {
  // Mirror src/index.ts gate extraction:
  const toolName = (execLike as any).name ?? 'unknown'
  const args = ((execLike as any).arguments ?? {}) as Record<string, unknown>
  const c = classifyToolCall(toolName, args)

  // Path protection (only file_write with paths is checked in index.ts)
  // Mirror src/index.ts zero-target branch (review-029-r1 F1/F2): a
  // strict-GET curl download with no concrete target, or an archive command
  // with a "bytes -> interpreter" sink (tar --to-command / --checkpoint-action
  // =exec, cpio -r), is forced unprotected. Other implicit-target commands are
  // judged by the SESSION CWD's rollback coverage (cwdProtected), not a
  // vacuous true — closing the out-of-workspace write gap while keeping
  // protected/baselined workspaces functional.
  let pathsProtected = true
  const command = (args.command as string) ?? ''
  const isCurlZeroTarget = c.reason.startsWith('Read-only curl download')
  const isArchiveExecSink =
    command.includes('--to-command') ||
    command.includes('--checkpoint-action=exec') ||
    (/^cpio\b/.test(command.trim()) && /\s-r\b/.test(command))
  // F2: archive exec sinks are denied in EVERY workspace state (mirror of the
  // first index.ts branch, which precedes the zero-target branch).
  if (isArchiveExecSink) {
    pathsProtected = false
  } else if (c.category === 'file_write' && c.targetPaths.length === 0) {
    if (isCurlZeroTarget) pathsProtected = false
    else pathsProtected = cwdProtected
  } else if (c.category === 'file_write' && c.targetPaths.length > 0) {
    // Mirror src/index.ts per-target rollback checks: a target is covered by
    // a protected-prefix match OR a local git baseline. The baseline branch
    // mirrors ensureGitBaseline(): a non-temp target inside the session cwd
    // (target == cwd or under it) is auto-baselined and therefore
    // rollback-covered; a target outside cwd with no protected prefix is
    // unprotected.
    const cwdAbs = process.cwd()
    pathsProtected = c.targetPaths.every((p: string) => {
      const abs = p.startsWith('/') ? p : `${cwdAbs}/${p}`
      if (protectedPaths.some((pref) => abs === pref || abs.startsWith(pref + '/'))) {
        return true
      }
      const nonTemp = !isTempPath(abs)
      const inside = abs === cwdAbs || abs.startsWith(cwdAbs + '/')
      return nonTemp && inside
    })
  }
  const d = decide(c, pathsProtected)

  const okCat = c.category === opts.category
  const okAllow = d.allow === opts.allow
  const okPaths = !opts.paths || opts.paths.every((p) => c.targetPaths.includes(p))
  if (okCat && okAllow && okPaths) { pass++; console.log(`PASS: ${label}`) }
  else {
    fail++
    console.log(`FAIL: ${label}\n  expected cat=${opts.category} allow=${opts.allow} paths=${opts.paths}\n  got      cat=${c.category} allow=${d.allow} paths=${JSON.stringify(c.targetPaths)}\n  reason: ${c.reason}`)
  }
}

// dsh `write` tool: name="write", arguments.file_path — the case the user hit.
check('write tool (protected path)',
  { name: 'write', arguments: { file_path: '/tmp/tm-guard-temp/test.txt', content: 'hi' } },
  { allow: true, category: 'file_write', paths: ['/tmp/tm-guard-temp/test.txt'] })

check('write tool (OUTSIDE prefix -> deny)',
  { name: 'write', arguments: { file_path: '/etc/hosts', content: 'x' } },
  { allow: false, category: 'file_write' })

// dsh `bash` tool: name="bash", arguments.command — previously all seen as empty -> read.
check('bash curl (must BLOCK)',
  { name: 'bash', arguments: { command: 'curl https://example.com', description: 'fetch' } },
  { allow: false, category: 'network' })

check('bash sudo rm (must BLOCK)',
  { name: 'bash', arguments: { command: 'sudo rm -rf /etc/foo', description: 'x' } },
  { allow: false, category: 'process' })

check('bash rm -rf / (catastrophic, must BLOCK)',
  { name: 'bash', arguments: { command: 'rm -rf /', description: 'x' } },
  { allow: false, category: 'system' })

check('bash local write on protected path (allow)',
  { name: 'bash', arguments: { command: 'echo hi > "/tmp/tm-guard-temp/a.txt"', description: 'write' } },
  { allow: true, category: 'file_write' })

check('bash npm install (must BLOCK)',
  { name: 'bash', arguments: { command: 'npm install', description: 'install deps' } },
  { allow: false, category: 'network' })

check('bash read-only ls (allow)',
  { name: 'bash', arguments: { command: 'ls -la', description: 'list' } },
  { allow: true, category: 'read' })

// tm_* internal tools always allowed
check('tm_status internal',
  { name: 'tm_status', arguments: {} },
  { allow: true, category: 'read' })

// R1 integration regression (dsh review-029-b1b2-closeout): archive and
// transform commands with implicit targets must NOT be denied by the
// zero-target fail-closed branch — they keep protection-layer semantics
// (protected workspace -> allow).
check('bash tar extract in protected workspace (allow, R1)',
  { name: 'bash', arguments: { command: 'tar -xzf /tmp/tm-guard-home/pkg.tgz', description: 'extract' } },
  { allow: true, category: 'file_write' })

check('bash unzip in protected workspace (allow, R1)',
  { name: 'bash', arguments: { command: 'unzip -d /tmp/tm-guard-home/out /tmp/tm-guard-home/a.zip', description: 'unzip' } },
  { allow: true, category: 'file_write' })

// A strict-GET curl download with no concrete file target stays fail-closed
// (R1 scope: `curl -o -- URL` must remain denied).
check('bash curl -o -- (zero target, fail-closed, R1)',
  { name: 'bash', arguments: { command: 'curl -o -- https://example.com/x', description: 'download' } },
  { allow: false, category: 'file_write' })

// review-029-r1-closeout F2: archive "bytes -> interpreter" sinks are denied
// in EVERY workspace state (B1-class RCE; previously allowed as file_write/0).
check('bash tar --to-command=sh (exec sink deny, F2)',
  { name: 'bash', arguments: { command: 'tar --to-command=sh -xf a.tar', description: 'extract via shell' } },
  { allow: false, category: 'file_write' })

check('bash tar --to-command=/bin/sh (exec sink deny, F2)',
  { name: 'bash', arguments: { command: 'tar --to-command=/bin/sh -xf a.tar', description: 'extract via shell' } },
  { allow: false, category: 'file_write' })

check('bash tar --checkpoint-action=exec (exec sink deny, F2)',
  { name: 'bash', arguments: { command: 'tar --checkpoint-action=exec=sh -cf o.tar d', description: 'checkpoint exec' } },
  { allow: false, category: 'file_write' })

// review-029-r1-closeout F1: implicit-target writes are judged by the SESSION
// CWD's rollback coverage. Extracted targets (tar/unzip/rsync/7z) outside any
// protected prefix are denied; unextractable implicit targets (gzip) in an
// unprotected cwd are also denied. (Temp paths are deliberately excluded: /tmp
// keeps its scratch semantics — decide()'s temp branch + TM coverage. And a
// tar extract INTO the session cwd stays allowed when that cwd is a git
// repo — the write is rollback-able via the baseline.)
check('bash tar extract into git-baselined cwd (allow, F1 covered)',
  { name: 'bash', arguments: { command: 'tar -xzf a.tgz', description: 'extract' } },
  { allow: true, category: 'file_write' }, [])

check('bash tar create to UNPROTECTED path (deny, F1)',
  { name: 'bash', arguments: { command: 'tar -cf /srv/unprotected/o.tar -C /tmp/dir .', description: 'create archive' } },
  { allow: false, category: 'file_write' }, [])

check('bash unzip to UNPROTECTED dir (deny, F1)',
  { name: 'bash', arguments: { command: 'unzip -d /srv/unprotected a.zip', description: 'unzip' } },
  { allow: false, category: 'file_write' }, [])

check('bash rsync to UNPROTECTED dst (deny, F1)',
  { name: 'bash', arguments: { command: 'rsync -a /tmp/src/ /srv/unprotected/', description: 'local sync' } },
  { allow: false, category: 'file_write' }, [])

check('bash gzip in UNPROTECTED cwd (deny, F1 fw/0)',
  { name: 'bash', arguments: { command: 'gzip big.log', description: 'compress' } },
  { allow: false, category: 'file_write' }, [], false)

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail > 0 ? 1 : 0)
