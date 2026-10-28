# Changelog

All notable changes to dsh-tm-guard will be documented in this file.

## [Unreleased]

## [0.2.10] - 2026-10-27

### Fixed
- **Fresh-workspace one-shot mkdir+write no longer blocked.** A command such
  as `mkdir -p fresh && echo hi > fresh/f.txt` inside a brand-new (no git)
  workspace is decided before `mkdir` runs, so the target directory does not
  exist yet. The gate previously called `git init` with the missing directory
  as cwd, hit ENOENT and fail-closed denied the whole command. The git
  baseline is now anchored at the nearest existing ancestor directory when the
  target's parent is absent; the command then runs and the files fall under
  the anchor's work tree, so they remain rollback-able. No directory is
  pre-created by the fallback.
- **Concurrent baseline init no longer races on `.git/index.lock`.** The gate
  runs one check per write target in parallel; after the nearest-ancestor
  fallback, several targets of the same command can anchor on the same
  directory. Concurrent `git init` + commit previously raced on the index lock
  and one randomly failed, which could deny an otherwise-safe command.
  `ensureGitBaseline` now deduplicates in-flight initialization per directory,
  so concurrent callers share a single init/commit.
- **Symlink escape through a missing component is now closed (O1).** A
  symlink ancestor pointing outside the workspace, followed by one or more
  not-yet-existing components (`elink -> /outside`, then `echo > elink/newdir/f.txt`),
  previously fell back to the lexical path in `canonicalTarget` and was judged
  inside the workspace; with the ancestor fallback above it could be allowed,
  and the baseline init followed the link and created a `.git` in the external
  real directory. The parent now resolves to its nearest existing ancestor's
  REAL location before the missing suffix is re-appended (dangling links
  followed through their chain), so such targets are denied; `isAutoInitSafe`
  additionally refuses any anchor whose realpath escapes the session cwd, so a
  baseline can never be created outside the workspace.
- **Lexical protected-path hit can no longer short-circuit a canonical
  escape (B3).** When a symlink inside the workspace points outside
  (`elink -> /outside`), a target like `elink/new/f.txt` matched the
  configured `protectedPaths` lexically, and the gate's `every(protected ||
  git)` combination let that lexical hit bypass the canonical inside-workspace
  check entirely, allowing the OS write to land outside. Escape targets are
  now tagged during the canonical walk and are decided solely by a protection
  check on the real landing point — the lexical hit alone never allows them.
- **Symlink cycles and over-long chains resolve to a denial sentinel (B1/B2).**
  An in-workspace cycle (`a -> b`, `b -> a`) or a chain longer than the hop
  limit followed by a missing component previously resolved back into a
  workspace path and could be allowed even though the OS write fails with
  ELOOP; the canonical fallback now returns a bare `/.tmguard-symlink-loop` /
  `/.tmguard-symlink-cap` sentinel (never with the basename re-appended), so
  such targets are conservatively denied and gate behaviour matches the OS.

### Security (unchanged boundaries)
- The ancestor fallback happens only after the canonical inside-workspace
  check passes; targets outside the session cwd, `/`, home and system roots
  are still denied, and auto-init is never performed on them. `temp` writes
  still take their existing branch. Symlink ancestors that resolve outside
  the workspace are now canonicalised to their real location before the
  inside-workspace check, so the boundary also holds for links followed by
  not-yet-existing path components (O1).

## [0.2.9] - 2026-10-26

### Security
- **Strict-GET download exemption switched from a denylist to a flag
  allowlist.** The readonly curl download path now tokenizes the command and
  approves only when every flag is on an explicit benign allowlist, there is
  exactly one http(s) URL, and at least one output is present. Closes gaps
  where the previous denylist was bypassed by: proxy redirection (`-x`,
  `--proxy1.0`); credential flags (`-b`, `-c`, `--oauth2-bearer`, `--netrc`,
  `--cert`, `--key`, `-u`); TLS weakening (`--cacert`, `--pinnedpubkey`,
  `-k`); connection-destination overrides (`--resolve`, `--connect-to`,
  `--socks5`, `--interface`); and non-download verbs (`-I`/HEAD, `-J`, `-A`,
  `-e`, `-H`, `-X`, `-d`, `-T`, `-F`, `-K`).
- **Symlink escape hardening.** Target paths are canonicalized before the
  inside-workspace boundary check: the whole path is realpath'd when it exists
  (covers an existing file-symlink pointing outside); dangling (broken) links
  are resolved with lstat/readlink and followed hop by hop (covers single-hop
  and chained dangling links, including a target containing `..`); a chain
  that exhausts the hop cap is denied. A cwd-internal symlink pointing outside
  no longer vouches the write or creates a git repo outside the session.
- **Non-file curl output sinks rejected.** `-o -` / `-o /dev/stdout` /
  `/dev/stderr` / `/dev/fd/*` (stdout that can be piped into a shell) and
  process substitution (`>(sh)`, `<(sh)`) or shell-metacharacter targets are
  classified as network, closing the RCE-whitening path where a "download"
  fed the response body to a shell.
- **Auto-init scope guard.** Automatic `git init` for a new workspace is
  restricted to the session cwd: absolute paths containing literal `..` and
  cwd-internal symlinks to outside are canonicalized first, system roots
  (`/System`, `/Library`, `/usr`, `/opt`, `/private`, `/home`, ...) and their
  subpaths are blocked by prefix match, and `/private/tmp`, `/private/var`,
  `/private/etc` (macOS rootless links) are covered.
- **Archive exec-sink denials (bytes → interpreter).** Archive commands whose
  options hand archive bytes to an interpreter are force-denied in every
  workspace (fail-closed): `tar --to-command`, `--checkpoint-action=...exec`,
  `--rmt-command` / `--rsh-command`, `-I` / `--use-compress-program` with a
  non-whitelisted compressor, and `cpio -r` (rename) forms. Detection also
  recurses into shell wrappers (`bash -c 'tar ...'` / `sh -c`), option-cluster
  forms (`bash -exop pipefail -c ...`, getopts clusters), env-prefixed
  commands, and quote/escape-obfuscated option names, with per-shell
  validation of the `-c` remainder (bash/sh/dash letters; zsh also digits and
  a trailing `-`); unsupported shells fail closed. This closes the RCE path
  where an untrusted archive could execute a command on extract. Read-only
  archive listing ops (`tar -t/-O`, `unzip -l/-p/-Z`, `7z l/i`, `rsync -n`)
  remain allowed.

### Added
- **Zero-config new workspaces.** The first write inside a session's working
  directory that is not Time Machine protected now auto-initializes a local git
  baseline and is then treated as rollback-protected and allowed, so a freshly
  created project works without manual setup. Temp paths (`/tmp`, ...) keep
  using the temp branch; an unprotected temp write is never given a git net,
  so a session whose cwd is the temp root itself cannot `git init` at a
  forbidden root.
- **No-target file writes fail closed.** A file-write classified command with
  no concrete local target path is denied instead of being treated as
  vacuously protected.

### Changed
- `curl -O`/`--remote-name`/`--remote-name-all` now correctly count as an
  output and anchor the baseline at the session cwd rather than its parent.
- URL scheme detection is case-insensitive (accepts `HTTP://`).

### Documentation
- README documents the curl download exception, the allowlist model, the three
  locations where writes are allowed, and that a proxy set through an
  environment variable (e.g. `env https_proxy=... curl`) is not inspected and
  should be controlled with an external firewall.

## [0.2.8] - 2026-10-20

### Added
- **Per-file git recoverability probe + forced fresh snapshot for targets git
  cannot restore.** Before an allowed file write/delete, each target is probed
  individually against the local git baseline: `yes` (tracked/committable, git
  can restore it), `no` (git-ignored — e.g. `.env.local`, which `git add -A`
  never commits, so git cannot restore it), `unknown` (no baseline or probe
  failed), and `unrecoverable` (tracked but a special layout a standard offline
  command cannot restore: a skip-worktree/sparse-excluded entry, a gitlink
  submodule directory `160000`, or a symlink `120000` pointing outside the
  repo). Targets classified `no` or `unrecoverable` bypass the cooldown skip and
  force exactly one fresh APFS snapshot before the write; the allow audit record
  carries `git=no(n)` for ignored targets and `git=unsafe(n)` for special-layout
  targets. The write is still **allowed, never denied** — zero-intervention is
  unchanged; this only raises snapshot frequency for a file git cannot roll back.
- Advisory-only `warnOnIgnoredDelete` (default `false`): when `true`, also
  `console.warn`s the ignored path(s); otherwise silent.
- `tm_audit` and `tm_status` render the `git=no(n)` and `git=unsafe(n)` counts
  and a `git-unrecoverable targets in recent window` aggregate line.

### Fixed
- **B1: a failed pre-write checkpoint no longer reports a false git `yes`.**
  `commitCheckpoint` now returns `{ ok, reason }` instead of swallowing
  `add`/`commit` errors (locked `index.lock`, read-only `.git`, full disk, a
  rejecting hook). When any checkpoint fails, the gate stops vouching for a
  git restore point, downgrades per-target `yes` to `unknown` in the audit, and
  forces one fresh Time Machine snapshot outside the cooldown window so the
  TM backstop still covers the write; the write itself stays allowed.
- **B2: destructive commands the read whitelist used to pass through.**
  `find -delete`, every `find -exec/-execdir/-ok` that runs a destructive verb
  (rm/rmdir/mv/cp/ln/...), and `fd -x/--exec rm` now classify as `file_write`
  with the starting directory as the target (checkpoint + probe + snapshot).
  Inline interpreters fail closed to `unknown` (deny) instead of riding
  `read`/`local_exec`: `perl -e/-E` catches `unlink` (bare, `q()`/`qq()`),
  `system(...)`, `qx`, backticks, and pipe-opener `open`, including the
  space-less `perl -e'...'` form; `ruby -e` catches `File.unlink/delete`,
  `FileUtils.rm/rm_f/rm_r/rm_rf`, `File.rmdir`, `Dir.rmdir`, and backticks.
  Read-only `find -name/-type/-exec cat`, `perl -ne`/`perl print`, `ruby puts`,
  and a plain `fd` listing are unaffected.
- **B3: deletion hidden behind an interpreter wrapper.** A shell script carried
  by `find -exec/-execdir sh|bash|dash|zsh -c '...'` / `fd -x bash -c '...'`
  that itself calls `rm/rmdir/unlink/mv/...` now fails closed to `unknown` (the
  in-script target cannot be resolved statically). Inline interpreters also catch
  `Dir.delete`, `Kernel.system`/`Kernel.exec`, call-form `system`/`exec(...)`, and
  the merged `ruby -ne` cluster; a read-only `sh -c 'echo'` wrapper stays
  allowed. The quoted-block fallback runs only on an inline flag, and `system`
  matches call forms (`system(`/`system "`)` rather than the bare word, so a
  benign `ruby script.rb 'a system path'` or a `"system"` string is not denied.
  Remaining non-deletion rewrites (perl bare-word write `open(F,">")`,
  `perl -pi` in-place edit) are covered by the default snapshot net and tracked
  as a minor backlog item.
- **B4: absolute-path / variable interpreter wrappers.** The wrapped-shell
  detector skips `env` at any absolute path (`/usr/bin/env bash`) and
  basename-normalizes the interpreter token, so `/bin/sh`, `/bin/bash`,
  `/bin/dash`, `/usr/local/bin/zsh`, `tcsh`, and `/usr/bin/env /bin/sh` behind
  `-exec` are caught the same as a bare `sh`; an unresolved variable shell
  (`"$SHELL" -c '...'`) fails closed because the interpreter cannot be proven
  safe. `FileUtils` matching is narrowed to destructive methods
  (`rm/rm_f/rm_r/rm_rf/remove_entry/remove_dir/rmdir`), so
  `mkdir_p/cp/chmod/cd` no longer hard-deny.
- **B5: deletion nested one layer deeper inside the wrapped shell body.** The
  `-exec` wrapper now reads only the quoted script that follows `-c`, and treats
  a non-resolvable inner deletion signal as fail-closed `unknown`: an inner
  `find -delete`, another interpreter `-c/-e` (e.g. `python3 -c os.remove`),
  `env -i <shell>` options before the interpreter, and a backtick/`$(`
  substituted interpreter (`` `which sh` ``) can no longer ride `read`. A
  read-only `sh -c 'echo'` wrapper stays allowed. `system` call matching splits
  into `system(` and `system "arg"` so a benign trailing quote such as
  `puts "operating system"` is not denied.
- **B6: env variable assignments before the interpreter.** `env FOO=bar /bin/sh`
  and `env -i PATH=/bin /bin/sh` behind `-exec`/`-x` no longer mis-locate the
  interpreter at the `NAME=value` token; assignment tokens are skipped alongside
  `env` and its options, so these fail closed to `unknown`. The wrapper body
  heuristic is also narrowed: a bare command substitution (`$(...)`, backticks)
  or an inner interpreter flag only fails closed when the body carries a real
  delete signal, so read-only `$(basename)`, `$(wc -l)`, and a read-only inner
  `python3 -c print` / `ruby -e puts` stay allowed.
- **B7: inner interpreter delete-API completeness.** An inner `node -e` /
  `node --eval` calling `fs.rmSync`, and an inner `ruby -e` calling
  `FileUtils.rm_rf`/`FileUtils.rm`, inside a `-exec` shell, now fail closed.
  The bare `\bremove\b` match is replaced by receiver-anchored FS delete APIs
  (`os.remove`, `.unlink(Sync)`, `.rmSync`, `.rmdirSync`, `FileUtils.rm`,
  `File/Dir.delete`, `shutil.rmtree`), so a list `.remove()` and the word
  "remove" in a string stay allowed.
- **B8: perl `File::Path::remove_tree`.** The modern recursive-deletion name
  `remove_tree` (alongside the legacy `rmtree`) now fails closed in both the
  direct inline detector and the find-exec shell body.
- **B9: ruby `FileUtils.remove_dir` inside a find-exec shell, plus a shared
  delete-API surface.** The direct inline detector and the find-exec shell-body
  heuristic previously kept two separate delete-API word lists that drifted
  (B8 `remove_tree`, B9 `remove_dir` were caught by one but missed by the
  other). They now match a single `DELETE_API_SURFACE`, so adding a delete API
  covers both channels; `FileUtils.remove_dir` (including the recursive
  `force=true` form) and `FileUtils.remove_entry_secure` fail closed in both.
  The bare `remove_dir`/`remove_entry` branches carry word boundaries so helper
  identifiers that merely contain the substring (e.g. `my_remove_dir_helper`,
  `remove_dirname`) stay allowed.
- **G1: network/package install smuggled through a find/fd action rode `read`.**
  The read path never runs the egress scan, so `find -exec sh -c 'curl …'`,
  `fd -x wget …`, an env-prefixed `/bin/sh` wrapper, an inner inline
  `python3 -c urllib`/`node -e fetch`, a package install in the wrapper, and a
  direct `git push`/`pip install` as the action verb all classified as `read`
  with no deny, audit, checkpoint, or snapshot. The find/fd branch now fails
  closed to `unknown` on a network verb, a git remote subcommand, a package
  manager install/add/update/download/publish/uninstall, or an inline interpreter
  network call inside the wrapped shell. It fails closed to `unknown` (not
  `network`) so a `denyNetwork:false` override cannot resurrect it. A plain
  listing, `-exec cat/grep`, `sh -c 'echo'`, and a wrapped local `git log` stay
  allowed.
- **G2: `importlib.import_module` deletion/egress rode `local_exec`.** The
  dynamic-import scan only recognized `__import__('…')`; `importlib.import_module`,
  `import importlib as m; m.import_module(…)`, and `from importlib import
  import_module` were treated as clean local exec, so a module fetched for
  `os.remove`/`shutil.rmtree` or `urllib.request.urlopen` ran without a checkpoint
  or probe. These now mark the inline code unverifiable and fail closed to
  `unknown`, matching `__import__`; a plain `import importlib` with no call stays
  allowed.
- **G3: an interpreter run directly as the find/fd action verb, or inline in the
  wrapped shell / one nested layer, rode `read`.** `find -exec perl -e unlink`,
  `-exec ruby -e File.unlink/delete`, and `-exec python3 -c os.remove/shutil.rmtree`
  deleted files with no checkpoint; `-exec python3 -c urlopen`, `-exec node -e
  fetch`, `-exec ruby -rnet/http Net::HTTP.get`, `-exec perl -MLWP::UserAgent get`,
  wrapped `node -e require("http"/"net")`, `perl -MLWP::Simple get`,
  `ruby Net::HTTP.get`, and a nested `sh -c 'sh -c "curl …"'` reached the network
  with no deny or egress scan. The find/fd branch now extracts the inline code from
  a direct interpreter verb (perl/ruby/python/node) and from the wrapped shell body,
  applies the shared delete surface and the inline egress API set, peels one nested
  sh/bash -c layer, and fails closed to `unknown`. A plain `python3 -c print`,
  `node -e console.log`, a benign `ruby puts`, and a nested `echo` stay allowed.
- **G4: network capability carried on a load flag or launched through a
  subprocess shell-out rode `read`.** A direct perl `-MLWP::Simple -e get/getstore`,
  `-MLWP::UserAgent -e get`, `-MIO::Socket::INET`, a ruby `-ropen-uri open()`, a
  python `subprocess.run(['curl',…])` / `shell=True`, and a node
  `child_process.spawn('curl',…)` reached the network with no deny or egress scan,
  because the module name lived on the `-M`/`-r` flag (outside the extracted code
  body) or behind a subprocess call. The find/fd branch now inspects the perl
  `-M`/`-m` and ruby `-r` load flags against a network-module set, recognizes
  IO::Socket and open-uri in the body, and fails closed on a subprocess list /
  `shell=True` or child_process spawn/execFile that launches a network command. A
  local `-Mstrict`/`-rjson` flag and a non-network argv (`subprocess.run(['ls'])`)
  stay allowed. Three-plus nested `sh -c` layers remain outside the single peel
  disclosed for G3.
- **G5/G6: direct-exec launchers inside a find action rode `read`.** A python
  `os.execv/execvp/execvpe/posix_spawn`, the variadic `os.execl/execle/execlp/
  execlpe` family, and `os.popen('curl …')`, plus a node
  `child_process.fork/execSync/spawnSync/execFileSync('curl',…)`, reached the
  network from a find action even though the plain command path already denied
  them; the shell-out launcher list only covered `subprocess.*` and the async node
  spawn/execFile/exec. The find/fd shell-out set now matches the whole `os.exec*`
  family, `posix_spawn`, and `popen`, together with the node `fork` and `*Sync`
  launchers, triggered only when the literal first argument / command string names
  a network program; when nested quotes truncate the extracted code body the whole
  action falls back to the same shell-out scan. `os.execvp('ls')`,
  `os.execl('/bin/ls')`, `os.popen('ls')`, and `spawnSync('ls')` stay allowed; a
  network verb mentioned only in an interpreter comment or string (e.g. a python
  `-c` note about curl) no longer trips the bare-verb scan, which now applies only
  to a real `sh`/`bash` wrapper.
- **G7: `subprocess.getoutput` / `getstatusoutput` rode `read` inside a find
  action.** Both convenience functions run a shell command string and reached the
  network from a find action even though the plain command path already denied
  them; the shell-out list covered `run/Popen/call/check_call/check_output` but not
  these two. The find/fd shell-out set now also matches `getoutput` /
  `getstatusoutput`, triggered only when the command string names a network program;
  `getoutput('ls -la')` stays allowed.
- **G8: a bare perl `-M`/`-m` or ruby `-r` network module load flag rode
  `read`/`local_exec` outside a find action.** The module-flag egress check only ran
  inside the find/fd `-exec` branch, so a direct `perl -MLWP::Simple -e get(...)`,
  `perl -MIO::Socket::INET`, `perl -M=LWP::UserAgent`, `ruby -ropen-uri`, or
  `ruby -rsocket` was classified read-only/local and actually reached the network.
  The load-flag check now also runs on the plain perl (read) and ruby
  (local_exec) paths; a non-network local flag (`-Mstrict`, `-MDigest::MD5`,
  `-rdate`) stays allowed.
- **G8-B1: a zero-argument env flag swallowed the interpreter.** The env wrapper
  tokenizer treated every short flag as taking an optional argument, so
  `env -i perl -MLWP::Simple …`, `env -0 …`, clustered `env -iv …`, and the ruby
  equivalent consumed `perl`/`ruby` as a phantom option argument; the remnant
  hit the unconditional `env help/flag` allow and the network module egressed.
  Only argument-taking options (`-u NAME`, `-C DIR`, `--unset`, `--chdir`, …)
  consume the next token; zero-argument flags (`-i`/`--ignore-environment`,
  `-0`/`--null`, clusters) strip themselves and recurse into the surviving
  command, so a benign `env -i ls` / `env -i perl -Mstrict` still stays allowed.
- **G8-B2: a shell-quoted module token was not parsed.** `perl -M'LWP::Simple'`,
  `perl -M"LWP::Simple"`, `perl -M='LWP::Simple'`, `ruby -r'socket'`, and
  `ruby -r"socket"` were allowed because the flag regex's module character
  class excluded the surrounding quote; the shell strips the quote at execution
  and the module loads. Module extraction now tolerates and removes an optional
  enclosing quote pair, on both the plain and find/fd paths; `perl -M'strict'`
  stays allowed.
- **G8-B3: an attached value on a value-taking env short letter collapsed to a
  bare read.** The env tokenizer only recognized separate-argument `-C DIR` /
  `-u NAME` and pure letter clusters, so the attached forms `env -C/ …`,
  `env -C// …`, in-cluster `env -iC/ …`, and the ruby `-C/ … -rsocket/
  -ropen-uri` variant broke out of the strip loop; the residual collapsed to a
  bare `perl`/`ruby` read/local_exec and physically egressed. An attached value
  on `C` (chdir) or `u` (unset) — `-C<dir>`, `-u<name>`, `-iC<dir>` — now
  strips with its value and the surviving command is re-classified; benign
  `env -C/ perl -Mstrict` and `env -C/ ls` stay allowed.
- **L5-B: `command`, `time`, and absolute-path `env` prefixes failed open to a
  bare read.** The builtin allow-block returned `read` for `command`/`time`
  after only an eval/exec special case, and the env unwrapper matched only a
  leading `env` token, so `command curl …`, `time pip install …`,
  `command git push`, `/usr/bin/env curl`, and `/bin/env wget` were allowed
  with no egress scan, checkpoint, probe, or snapshot; the same prefixes hid a
  protected-cwd deletion (`command rm`, `time rm`, `/usr/bin/env rm`) from the
  rollback net. `command`/`builtin`/`time` now strip the prefix and re-classify
  the tail (`command -v/-V` query flags stay read); an absolute-path env launcher
  (`/usr/bin/env`, `/bin/env`, `/usr/env`) normalizes to bare `env` and goes
  through the existing env unwrapper. Benign `time ls`, `command -v ls`,
  `/usr/bin/env ls`, and `type ls` stay allowed.

### Notes
- No new deny surface; the default decision is unchanged. Setting
  `requireGitBaseline: false` disables this probe and its forced snapshot too.
- Backlog (not in this release): large-batch `ls-files` over stdin (ARG_MAX),
  dangling-symlink strict `unknown`, audit path-form normalization; broader
  perl/ruby network-library coverage (`HTTP::Tiny`, `Net::FTP`, `LWP::Protocol`,
  `net/ftp`, `pty.spawn`) that is allowed identically on the
  plain command path and inside a find action, alongside the asyncio
  `create_subprocess_exec` / `create_subprocess_shell` helpers, all allowed
  identically on both paths and to be widened together with the shared
  scan-scripts language table.

### Test
- 501 tests pass / 0 fail; peer matrix 19/19; pack audit clean; real-machine
  APFS drill verified end to end (one forced snapshot on an ignored delete,
  zero extra snapshot on a tracked delete inside cooldown), independently
  re-run and rechecked. B1/B2/B3/B4/B5 covered by fault-injection cases for a
  failed checkpoint and destructive find/fd/perl/ruby classification (incl.
  round-3 residuals: perl -E/q()/system/qx/backticks, ruby FileUtils.rm_rf,
  find -ok/multi-exec, fd -x; round-4 B3 wrappers: find -exec sh/bash -c 'rm',
  ruby Dir.delete/Kernel.system/-ne, perl exec; round-5 B4: /bin/sh, env
  /bin/sh, "$SHELL", /usr/bin/env bash, dash/zsh/tcsh, and FileUtils
  narrowing; round-6 B5: inner find -delete, inner python3 -c os.remove,
  env -i shell, backtick-substituted shell, and the system trailing-quote
  false-positive control; round-7 B6: env NAME=value/PATH assignments, fd -x
  env, and read-only $(basename)/$(wc -l)/inner print benign controls;
  round-8 B7: inner node -e/--eval rmSync, inner ruby FileUtils.rm_rf, and the
  list .remove()/"remove" string benign controls; round-9 B8: perl File::Path
  remove_tree direct and find-exec body; round-10 B9: ruby FileUtils.remove_dir
  and remove_entry_secure direct/find body under the shared delete surface, with
  word-boundary controls for remove_dir/remove_entry substring identifiers;
  G1: find/fd wrapped and direct curl/wget/pip-install/git-remote fail closed
  with benign listing/`sh -c echo`/wrapped `git log`/grep controls; G2: all
  four importlib forms fail unverifiable with a plain `import importlib`
  control; G3: direct-interpreter-verb inline delete/egress (perl unlink, ruby
  File.unlink/delete, python os.remove/rmtree/urlopen, node fetch, ruby
  Net::HTTP, perl LWP), wrapped require(http/net)/LWP::Simple/Net::HTTP, and a
  nested sh/bash -c layer fail closed, with benign print/console.log/puts/echo
  controls; G4: perl -MLWP::Simple/UserAgent and -MIO::Socket::INET load flags,
  ruby -ropen-uri, python subprocess list/shell=True, and node child_process
  spawn/execFile launchers fail closed, with benign -Mstrict/-rjson and
  subprocess(['ls'])/spawn('ls') controls; G5/G6: the whole python os.exec* family,
  posix_spawn, popen (incl. inner-double-quote form), and node fork/execSync/
  spawnSync/execFileSync network launchers fail closed, with benign
  os.execvp('ls')/execl('/bin/ls')/popen('ls')/spawnSync('ls') controls; G7:
  subprocess.getoutput/getstatusoutput network command strings fail closed, with a
  benign getoutput('ls -la') control; G8: bare perl -MLWP::Simple, -MIO::Socket::INET,
  -M=LWP::UserAgent and ruby -ropen-uri/-rsocket fail closed as network, with benign
  -Mstrict/-MDigest::MD5/-rdate controls; G8-B1: env -i/-0/-iv/--ignore-environment
  and env -u/-C network module loads fail closed, with benign env -i ls /
  env -i perl -Mstrict controls; G8-B2: quoted perl -M'LWP::Simple'/-M"LWP::Simple"/
  -M='LWP::Simple' and ruby -r'socket'/ -r"socket" fail closed on both plain and
  find paths, with benign perl -M'strict' control; G8-B3: attached env chdir/
  unset values env -C/, env -C//, env -iC/, env -C/tmp, env -C/ ruby -rsocket/
  -ropen-uri fail closed as network, with benign env -C/ perl -Mstrict and
  env -C/ ls controls).
- Isolated real-host process smoke (separate profile/port/cwd, production host
  untouched): read-only allowed, recoverable-write checkpointed+allowed, and a
  sensitive read force-blocked inside the harness; independently re-reviewed
  (PASS, no blockers). The network/system deny branches share the same
  `decide()`/short-circuit and are covered by unit tests plus the isolated
  delete/restore drill; a live network/system block sample is deferred to a
  future isolated turn.

## [0.2.7] - 2026-10-14

### Keep-all 定稿（0.2.6 废弃说明）
- **0.2.6（npm 已发布版）为有界默认版，已废弃（deprecated）**：npm 0.2.6 发布于
  keep-all 定稿前，审计日志默认 10MiB 轮转、物理删最老代——与最终拍板相反。
  **请升级 0.2.7**；`npm view dsh-tm-guard deprecated` 可看到废弃提示。
- **审计日志默认保留全部（keep-all）随 0.2.7 定稿**：默认 `auditMaxBytes: 0`——
  不轮转、不生成任何 `.N` 代、记录全量保留；轮转为 opt-in（配置 `auditMaxBytes` 启用，
  `auditRetainFiles` 控制代数，`auditTotalMaxBytes` 设硬顶）。基线报告版本 `3`。
- **市场措辞最终形态**：README/description 明确"写操作自动放行并**自动打快照**
  （本地 git 基线 / Time Machine）"、"审计日志默认保留全部，可配置启用**自动清理
  最旧审计记录**"——无参数名/术语噪音，参数细节见正文 Configuration 与 § Audit log
  rotation。

### Fixed / Test
- **真机 TM 测试断言双布局**：回滚源接受外部盘 `.previous` 完成备份或本地快照树
  （`Backups.backupdb`）任一合法 TM 源，对齐 `src/tm.ts` 既有枚举+最新优先行为
  （`src/tm.ts` 零改动）。
- 门禁：300/300 测试、verify:fast exit 0（peer 19/19、18 files byte-identical）。

## [0.2.6] - 2026-10-14

> ⚠️ **废弃**：npm 0.2.6 为有界默认版（审计默认 10MiB 轮转、物理删最老代），
> 与 keep-all 定稿相反。请使用 **0.2.7**（本条目内容为发布时的代码状态，随 0.2.7
> 的 keep-all 反转在下方 [0.2.7] 描述）。

### Disclosure & hardening (review-gap fill)
- **auditMaxBytes:0 关闭轮转契约补测**：`auditMaxBytes: 0`（及负值）短路
  轮转（`maybeRotate()` 返回 false、`record()` 永不触发轮转、不生成任何 `.N` 代）。
  **0 现为默认值**——0.2.6 定稿将默认反转为保留全部（见下方 Changed）。
- **基线报告版本化重生成（存量升级用户可见披露）**：报告此前"存在即跳过"，
  0.2.5 老用户升级后永远看不到 §6 新增的审计保留窗口披露。报告现在带 schema 版本
  （`报告版本 | 3 |`），版本不匹配自动重新生成；稳态成本仍是一次 `existsSync` +
  ~512B 头部读。补 2 条测试（旧报告重生成 / 当前版本不重写）。
- **轮转日志按实际删除区分措辞**：此前每次轮转都打印 "physically deleted"，
  但前 `retainFiles` 次轮转实际没有删除任何文件（窗口未满）。`RotateInfo` 新增
  `evicted` 计数，日志改为：未满窗口时明说 "no file evicted yet — retention window
  just shifted"，真删除时报告 "physically deleted N generation(s)"。补 evicted 两条测试（窗口驱逐 evicted=1、总字节顶 backstop 删除计入 evicted）。

### Fixed (edges promised in 0.2.5)
- **存量边界 1 修复（temp 前缀穿越）**：写门控的 temp 豁免现在与敏感读/写保护
  使用同一规范化（`normalizeForMatch` 折叠 `//`、`.`、`..` 并 lowercase）。
  `echo x > /tmp/../etc/evil.txt` 之前被按 temp 放行（实际落点在 `/tmp` 之外），
  现在正确解析为 `/etc/evil.txt` → 非 temp、非保护 → BLOCKED。补穿越单测。
- **存量边界 2 修复（curl 捆绑短选项）**：curl 判定新增短选项簇展开
  （`-sLk` → `-s -L -k`），`curl -sLk -o a …` / `-sLd x=y` / `-sLH "X:y"` 中的
  `-k`/`-d`/`-H` 不再被捆绑隐藏 → 恢复 network/deny（不再降级为 file_write）。
- **误拦修复（curl -o 分离值提取）**：`curl -o /tmp/x https://…` 的下载目标路径
  之前提取为空（temp 豁免不触发 → 合法下载被 BLOCKED）；现在提取 `-o/--output`
  分离值，合法 `/tmp` 下载恢复 temp 豁免放行。
- **回归封口（curl -K/--config 配置注入）**：独立对抗复查发现 `-K/--config`
  配置文件注入可携带 `-k/-d/-H/--output` 任意参数（配置内容 curl 真实执行）；
  `-K`/`--config` 已加入危险 flag 表 → `curl -K cfg / -K - / -Kcfg` 一律
  network/deny（不再降级为只读下载）。
- **误拦封口（curl -o 粘值误拆）**：`-o` 是带参短选项，`curl -oout`/`-odata`
  是「选项+文件名」而非 flag 簇——簇展开对 `-o` 开头的粘值不展开，避免从
  文件名拆出虚构的 `-u`/`-d` 等 blocked flag 把合法下载误判为 network。
- **放行封口（危险短选项任意位置）**：危险短选项识别改为 **token 级任意位置**
  ——危险字母前粘良性簇前缀（`-sHX:y`、`-sLdsecret=1`、`-suadmin:pw`、
  `-sFkey=@f`、`-sehttp://r`、`-sK./cfg`、`-sk./x`、`-XPOST`）同样
  network/deny（含 `-K` 配置注入与 `-k` TLS 绕过形态）；**引号整体包裹的
  选项**（`"-HX:y"`、`"--insecure"`、`"--config"`）检测前统一剥引号，短/长
  选项均不因引号逃逸。`-o` 在任意位置（token 首位或簇中段）均视为带参选项、
  其余为本地文件名（`-oT`/`-odata`/`-sodata`/`-soxH:y`），不参与危险判定、
  不误拦合法下载。分隔/粘连/簇内/任意前缀/引号包裹形态全部 network/deny。

### Changed
- **审计日志默认反转为保留全部（0.2.6 定稿）**：默认 `auditMaxBytes: 0`——不轮转、
  完整留痕（磁盘无界增长由用户自行管理，README Limitations 已如实披露）；有界轮转
  改为 **opt-in**（显式设 `auditMaxBytes` + `auditRetainFiles`）。同步反转 README
  开头段/配置表/轮转章节/Limitations、npm description、基线报告 §6
  （`报告版本 | 3 |`，升级用户自动重生成）、轮转日志文案
  （"rotation is opt-in; default keeps all"）。
- **审计轮转披露补强（B1/B2/O1/O2）**——轮转对用户数据保留有实质影响（窗口外
  最老代被物理删除、不可恢复），披露从"深渠道"补齐到"用户必经渠道"：
  - 运行时轮转日志点明后果：`audit rotated → .1; oldest generation beyond N
    retained (~X MiB/file, Y MiB cap) physically deleted — forensics reach back
    only this far (rotation is opt-in; default keeps all)`（之前只说
    rotated/retained，没说删除与取证窗口；无宿主 logger 时回退 console 同款文案）。
  - 首次基线报告第 6 节披露本机审计数据保留事实（0.2.6 起默认保留全部；显式配置
    才启用有界轮转；窗口满后最老代物理删除不可恢复；看当前窗口的方法）——把深
    README 事实落到用户最可能打开的持久产物。
  - README § Limitations 更新为 **The audit log keeps everything by default
    (since 0.2.6)** 条目（与其它 since 0.2.5/0.2.6 条目同格式，链接 § Audit log
    rotation）。
  - npm/market 包描述（description）同步为：审计默认保留全部、可选启用
    有界轮转——命中安装前唯一几乎必读的渠道。

## [0.2.5] - 2026-10-13

### Security (important)
- **解释器内联代码全链进危险网（R10–R15）**。十五轮独立对抗复核驱动下的
  allow 侧封口，全部为真实 fail-open 修复：
  - 版本化/ABI 解释器名（`python3.12`、`python3.12m/t/d`、`pypy3`、
    `-dbg`）与裸名共享 `-c` 内联代码的危险网与敏感路径扫描，不再因名单
    缺字面量而漏（R10/R11）。
  - `uv run <解释器> -c "<危险码>"` 递归进入解释器危险网：`python`/`node`/
    `ruby`/`bash` 等包装均不再整体放行（R12/R13）。
  - uv flag 按真实语法 token 化：布尔 flag（`--no-sync/--frozen/--locked/
    --offline/--no-dev/--no-project` 等）不再吞掉解释器名；`--x=y`、`-p 3.12`、
    `--` 分隔符全部正确处理；`uv run <伪造解释器名>` fail-closed（R13 阻断）。
  - `denyReadPaths`（敏感路径 forceDeny）沿全部递归边界透传：uv、bash -c、
    xargs、nohup/env/管道/子 shell/裸赋值前缀，`-c` 代码内读
    `.ssh/id_rsa` 等一律 forceDeny（R13/R14 阻断 + W1）。
  - 转义感知引号提取：`bash -c "python3 -c \"…\""` 双层嵌套不再被 `\"`
    截断而漏敏感扫描。
  - 仓库卫生：文档与源码清除本机用户名路径，host 矩阵脚本移出版本库，
    dsh 复核工作目录 ignore（发布物隐私净化延续）。

### Added
- **First-run safety baseline report (U-27)**. The first `apply()` in a
  workspace writes `.tm-guard/baseline-report.md` and prints a one-line pointer
  to it. The report probes *this* machine — TM destination and health, the
  effective writable scope, whether `git` is on PATH and the directory is a work
  tree, the effective `denyReadPaths` count and merge semantics, the platform
  mode — and closes with the residual risks from README § Limitations, so the
  honest boundaries are facts on the user's machine rather than a README section
  they may never scroll to. Previously `tm_status` was the only source of these
  facts, it had to be asked, and it left nothing behind.
  - **First run is detected by the absence of the file**, not by a flag in
    `state.json`: self-describing, survives a wiped state file, and lets a user
    regenerate by deleting the report. Later `apply()`s cost one `existsSync`.
  - **Strictly read-only, and it says so.** The git probe is `git rev-parse`
    and stops — it does **not** call `ensureGitBaseline` (which runs `git init`
    + a baseline commit) during plugin load. The report states that the baseline
    is created lazily at the first write. No snapshot, no config change.
  - **Published synchronously.** The report exists when `apply()` returns; the
    (async) tmutil section is filled in afterwards and renders as an explicit
    "unknown — check `tm_status`" until it lands, never as a false "configured".
  - **Never fatal**: an unwritable report degrades to a `console.warn` and the
    gate still loads (a display artifact never stops the safety mechanism).
  - `tm_status` 【Data sources】 now echoes the report path so it is discoverable
    from the diagnostic tool. New `src/baseline-report.ts`; new
    `probeGitSync` in `src/git.ts` (sync, read-only, test-seamed).

### Changed
- **`autoApprove` risk made explicit (U-25)**. `autoApprove` defaults to `true`,
  which means the plugin answers DSH approval prompts on the user's behalf; its
  safety depends on this plugin's `prepend` registration order relative to any
  other permission plugin. `apply()` now prints a startup warning stating this,
  with a README pointer. A second warning fires for the combination
  `failClosed=false` + `autoApprove=true`, which leaves no human confirmation
  step and no rollback gate. No behaviour change — announcements only.
- **Audit log rotation (new default behaviour)**. `audit.jsonl` now rotates at
  10 MiB, keeps 5 generations, total ≈ 50 MiB (100 MiB hard cap), with a
  cross-process lock. **The oldest generation is physically deleted once the
  retained window is full** — rollback/forensics reach back only as far as the
  window. This replaces 0.2.4's unbounded log, so the audit can never silently
  fill the disk (which would break the write path rollback depends on). Tune
  via `auditMaxBytes`/`auditRetainFiles`/`auditTotalMaxBytes`; set
  `auditMaxBytes: 0` to disable rotation entirely. See README § Audit log
  rotation.

### Known UX notes（发布说明，非缺陷）
- **解释器内联代码里再包本地开发命令会被拦（R15 起新增 deny 面）**：
  `python3 -c "import subprocess; subprocess.run(['npm','test'])"`、
  `node -e "execFileSync('git',['status'])"` 这类写法会按
  package/vcs_remote/unknown 类别拒绝——请**直接运行** `npm test`/`git status`/
  `cargo test`/`go run` 等命令，或写成脚本文件执行（`node x.js`/`python x.py`
  文件形态不受内联码网限制）。直接形式不受影响。
- **`uv run --with <pkg> script.py` / `--with-requirements` 按包操作拒绝**：
  属于既有"包操作默认拒绝"立场（profile 定向放行即可）；可先 `uv sync` 再
  `uv run`，或去掉 `--with` 直接运行。`--with` 精确 token 化留待下个版本。
- 上述均为安全方向的收紧，被拦命令不会执行。真实生产语料回放显示内联
  解释器写法（`python/node -c/-e`）会大幅收紧，具体踩不踩中取决于内联码
  里是否出现高危 import/原语——请以内联码改写指引为准，而非一个固定
  百分比（既有 "1–3%" 估算无干净语料支撑，已撤回）。
- **audit 自动轮转（升级须知）**：默认 10MiB/5 代/100MiB，保留窗口填满后
  最旧审计会被**物理删除**——若你需要更长回滚/取证历史，用
  `auditMaxBytes`/`auditRetainFiles` 调大窗口，或 `auditMaxBytes: 0` 完全
  关闭轮转（回到无界增长）。
- **已知边界**：纯 socket 外联（`socket.create_connection(...)`，无 URL
  字面量）静态扫描不识别；0.2.5 起版本化解释器名（`python3.12`/`pypy3`）
  与裸名共享此边界（非回归，两版一致）。高需求用户可从可信工具移除内联
  解释器，或配出口防火墙（见 README § Limitations）。
- **存量边界 1（temp 前缀未规范化）**：写门控的 temp 豁免对**未规范化的
  `/tmp/../` 前缀**误判——`echo x > /tmp/../etc/evil.txt` 会按 temp 放行，
  而 OS 实际落点在 `/tmp` 之外。0.2.4 行为相同（非 0.2.5 回归），且外层
  沙箱/git-net 实测兜底；计划 0.2.6 让 temp 判定与受保护路径判定使用同一
  规范化逻辑并补穿越单测。
- **存量边界 2（curl 捆绑短选项）**：curl 只读下载的危险 flag 以**独立
  token** 匹配，`curl -sLk -o a https://…`、`-sLd x=y`（POST body）、
  `-sLH "X:y"`（任意头）等捆绑短选项可绕过检测、被降级为 file_write 判定
  （受保护路径/`/tmp` 下会放行落地，但远端内容不执行、仍受写门控+快照
  约束）。0.2.4 行为相同（非回归）；计划 0.2.6 短选项簇展开解析。

## [0.2.4] - 2026-10-03

### Changed
- **发布物隐私净化**：清除包内所有本机用户名路径——源码注释与 README
  文档示例路径统一中性化为 \`/Users/alice\`；测试文件改用 os.homedir()
  动态构造（无本机用户名硬编码）。无代码逻辑变更。

## [0.2.3] - 2026-10-02

### Security (important)
- **Sensitive-read bypass closed** — `dd` input operands (`if=`) were never
  extracted as read paths (mistaken for env assignments), so `dd if=~/.ssh/id_rsa
  of=<writable>/stolen.key` exfiltrated keys/credentials in one command. `if=`
  now feeds the read-side denyReadPaths check; `of=` (previously never
  extracted either) now feeds write-path protection. Found by independent
  review; regression-covered.
- **Write-side `..` escape closed** — `isPathProtected` used raw prefix
  matching, so `<protected>/../secrets.txt` was treated as protected and the
  write was allowed (no rollback coverage, outside the writable scope). The
  write side now shares the same normalization as the read side (`..`, `//`,
  case folding). Relative `protectedPaths` (e.g. `"."`) are resolved against
  cwd first — previously they collapsed to `/` and silently widened the
  writable scope to the whole disk.
- **Glued-flag bypass closed** — `--flag=value` tokens were dropped whole, so
  `grep --file=~/.ssh/id_rsa` / `sort --output=~/.ssh/x` bypassed both read and
  write checks. Path-like glued values are now extracted on the read side
  (generic) and on the write side (write-typed flags: `--output/--out/-o/
  --target/--dest/--destination/--outfile/--output-file/--target-directory/
  --dest-dir/--destination-directory/--output-directory`). Read-typed flags
  (`--files-from`, `--from-file`) deliberately stay read-side only, so
  legitimate in-scope writes are not false-denied.
- **Tool-arg key-name gap closed** — `classifyToolCall` only recognized a
  single `path`-family key, so `filePath`, `paths[]`/`files[]` arrays, and
  `pattern`/`glob` fields bypassed sensitive-path checks. All plausible
  path/pattern keys (including arrays) are now collected and checked.

### Changed
- Config hardening: array/bool/number fields tolerate wrong types instead of
  crashing or silently flipping policy (`normalizeArray/Bool/Number`); empty
  `protectedPaths` now emits an explicit warning (it means *every* write is
  denied).
- `export DEFAULT_CONFIG` for programmatic consumers and tests.
- `ensureGitBaseline` cache now maps dir → real repo root (first-call and
  cache-hit results agree).
- Scan-scripts recursion depth quota fixed (depth now increments; MAX_DEPTH /
  MAX_HITS / MAX_FILES_TOTAL enforced).
- README peer range corrected to the four-segment range matching
  package.json; `test-readme.mts` now asserts README↔package.json verbatim
  consistency.

### Added
- Test suite grown to 205 tests (97.9% coverage): classifier fuzz (400 random
  commands), decide truth table (104 combos), sensitive-path variant matrix,
  scan-scripts quota + egress fuzz, real Time Machine integration, real-git
  rollback drill, config-fault/concurrency, perf storm (sub-millisecond),
  README consistency, and bypass-regression suites (M1/M2/M3/S1/R1/R2/R1b).
- 3-host end-to-end matrix (dsh 0.1.7-rc.2 / 0.2.0-rc.1 / 0.2.0-rc.2) and
  production-profile real-environment install verification.

### Known limitations (honest)
- Write-typed flag handling is a curated allow-list; new write flags (or
  exotic variants) must be reviewed and added. Read-side path extraction is
  heuristic, not a parser. Static analysis can still miss runtime-constructed
  paths inside interpreter `-c/-e` code; `denyNetwork` egress blocking is the
  backstop.

## [0.2.2] - 2026-10-01

### Fixed
- **peer 兼容缺口（重要）**：0.2.0 的三段式声明 `>=0.1.0-rc.1 <0.1.0 || >=0.1.2-0 <0.2.0-0 || >=0.2.0-0 <0.3.0-0` 只覆盖了 0.1.0-rc.1 与 0.1.2-rc.1，**漏掉了 dsh 0.1.0/0.1.1 正式版**（段 1 上界 `<0.1.0` 排除 stable，段 2 下界 `>=0.1.2-0` 又把 0.1.1 挡在门外）。该缺口由新增的 peer 兼容矩阵（`npm run verify:peer`）首跑抓出。
- 修复为四段式：`>=0.1.0-rc.1 <0.1.0 || >=0.1.0 <0.1.2-0 || >=0.1.2-0 <0.2.0-0 || >=0.2.0-0 <0.3.0-0`——覆盖全部 0.1.x（含 stable 0.1.0/0.1.1）+ 全部 0.2.x，排除 0.3.0。矩阵 12/12 全绿（真实 semver 引擎）。

### Added
- **测试机制落地**：`TESTING.md`（分层架构 L0–L6 + 用例注册表）、`RELEASE.md`（发布门禁 checklist）、CI（`.github/workflows/test.yml`，push/PR 自动跑 L0–L3）
- 验证脚本：`verify-peer-matrix.mjs`（L3）、`verify-reproducible-build.mjs`（L1）、`verify-pack-audit.mjs`（L2）；一键门禁 `npm run release:check`

## [0.2.1] - 2026-10-01

### Changed
- 市场体验改进（仅文档/描述/模板，无代码变更）：
  - package.json `description` 增加配置提示：安全默认开箱生效，使用 subagent/workflow/web 需配置 `protectedPaths`/`extraAllowTools`（详见 README）
  - README 顶部新增「Quick Start（2 分钟上手）」：安装 → 验证加载 → 配置保护路径 → 解锁信任工具（含白名单红线警示），并链接 Configuration 章节
  - `cordis.patch.yml` 增加推荐配置模板（注释形式，不改变自动层行为）：示例 `protectedPaths`、`denyReadPaths`、`extraAllowTools` 及开关，供用户复制到 profile 层配置

## [0.2.0] - 2026-10-01

### Changed
- 放宽 peer：`@deepseek-ai/dsh-tools` 改为 `>=0.1.0-rc.1 <0.1.0 || >=0.1.2-0 <0.2.0-0 || >=0.2.0-0 <0.3.0-0`，兼容 dsh 0.1.x（含 0.1.2-rc.1）与 dsh 0.2.0（含 0.2.0-rc.2，排除 0.3.0）。按 npm semver 规则，prerelease 版本必须存在同主次补丁三元组的 prerelease comparator 才会被范围匹配，故分段声明
- 新增 `engines.dsh` 兼容性声明（范围同上）
- cordis 保持 `>=4.0.0`（dsh 0.2 仍在 cordis 4.x 线）

## [0.1.1] - 2026-09-19

### Fixed
- 修正 README 中 GitHub 仓库链接的用户名（从 bk5k27n8g8-code 改为 ChaoJie0）

## [0.1.0] - 2026-09-19

### Added
- 首次发布
- 权限门控：自动放行可回滚操作，拦截不可逆操作
- 本地 git 基线快照：写文件前自动 commit
- Time Machine 兜底回退：非 git 目录用 tm_rollback
- 审计日志：记录所有放行/拦截决策
- 系统提示注入：告诉 Agent 权限边界和回退工作流
- 默认拦截敏感路径读取（~/.ssh、~/.aws、Keychains 等）
