# dsh-tm-guard

**A zero-intervention permission gate for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH) agents on macOS — active on install.** Writes that can be undone via a local git baseline or macOS Time Machine are auto-approved and snapshot-checkpointed; network access, package installs, process/system management, and reads of sensitive credential paths are blocked; every decision is audited — the audit log keeps everything by default (optional bounded rotation via `auditMaxBytes`).

> Core rule: **operations that can be rolled back are allowed; operations that cannot be rolled back are denied.**

---

## Quick Start (2 minutes)

1. **Install**: `dsh plugin --profile <name> add dsh-tm-guard` (see [Installation](#installation)).
2. **Verify it loaded**: boot the profile — the console prints `[tm-guard] Loaded. Protected paths: ...` (see [Verify the install](#verify-the-install)).
3. **Protect your workspace**: defaults already protect `process.cwd()`, deny network/system operations, and block reads of 12 sensitive credential paths. To protect more directories, add `protectedPaths` to your profile's `cordis.patch.yml` ([Configuration](#configuration)).
4. **Unlock the tools you explicitly trust**: `subagent`, `workflow`, `web_search`, `web_fetch`, `skill`, ... are **DENIED by default** (classified `mixed`/`unknown`). Add the ones you trust to `extraAllowTools` in your profile's `cordis.patch.yml`. ⚠️ Never add `subagent` / `subagent_fork` / `workflow` / `job_output` — the allow-list short-circuits the classifier (see [Limitations](#limitations--honest-scope)).

> The two fields that change the experience most: `protectedPaths` (what the agent may write) and `extraAllowTools` (which tools bypass the gate). Everything else has a safe default.

## What this is — and isn't

**It is** a DSH [Cordis](https://github.com/deepseek-ai/cordis) **plugin / bundle**: an npm package (`dsh-tm-guard`) that declares `dsh.bundle.patch`, hooks DSH's `tools/pre-execute` waterfall, registers `tm_*` model tools, and injects an operating-mode system-prompt section. It installs with the official `dsh plugin add` flow and runs inside the DSH host process with the host's permissions.

**It is not:**

- a Claude Code plugin (no Claude Code plugin manifest or Claude Code hooks),
- a VS Code extension,
- a standalone CLI or product,
- **a security sandbox** (see [Limitations & honest scope](#limitations--honest-scope)).

---

## Prerequisites

- **macOS** with APFS. The plugin shells out to `/usr/bin/tmutil` and uses local APFS snapshots; there is no non-macOS support.
- **Time Machine configured** with a backup destination, and the workspace on a TM-backed volume that is **not** in Time Machine's exclusion list. Verify:

  ```sh
  tmutil destinationinfo
  tmutil listlocalsnapshots /
  ```

- **Full Disk Access** granted to the terminal/app that runs `dsh` (needed for browsable-backup restore and some `tmutil` operations), if you want automated rollback from completed backups. Local snapshot creation itself needs no sudo on normal user volumes.
- **`git` on PATH** for the primary instant rollback net (a local baseline is auto-created per writable directory; all git operations are local/offline).
- **DSH CLI installed**, matching the peer range in `package.json` — currently `@deepseek-ai/cordis >=4.0.0` and `@deepseek-ai/dsh-tools >=0.1.0-rc.1 <0.1.0 || >=0.1.0 <0.1.2-0 || >=0.1.2-0 <0.2.0-0 || >=0.2.0-0 <0.3.0-0` (covers dsh 0.1.x including `0.1.2-rc.1` and dsh 0.2.x including `0.2.0-rc.2`).

---

## Installation

A DSH profile installs out-of-tree bundles via `dsh plugin --profile <name> ...` (forwarded to pnpm inside the profile directory). Choose any profile name, e.g. `web` or a throwaway `tm-lab`.

### From npm (recommended)

Prebuilt `lib/` ships in the package, so no build step or build-script approval is needed:

```sh
dsh plugin --profile web add dsh-tm-guard
```

### From GitHub / source

```sh
# pnpm >=10 blocks git-dependency build scripts until you allow them.
# The package's prepare script runs its zero-dependency build (see Development).
dsh plugin --profile web add github:ChaoJie0/dsh-tm-guard
```

If the install fails on the build-script approval, add the key pnpm prints to the profile's `pnpm-workspace.yaml`:

```yaml
allowBuilds:
  dsh-tm-guard: true
```

and re-run the command. Treat that allowance as permission to run the package's code at install time on your machine; pin a commit when auditing supply chain: `github:ChaoJie0/dsh-tm-guard#<sha>`.

### Local checkout (testing)

```sh
git clone <repo> dsh-tm-guard
cd dsh-tm-guard
npm install        # no runtime deps; runs prepare → builds lib/
dsh plugin --profile tm-lab add .
# or a packed tarball: npm pack → dsh plugin --profile tm-lab add ./dsh-tm-guard-<version>.tgz
```

### Direct source overlay (development only)

Without installing, load the TypeScript source straight into a running DSH via the local overlay file (the path is machine-specific; this is the file shipped in the maintainer's checkout, **not** the bundle patch):

```sh
dsh web --patch "/abs/path/to/dsh-tm-guard/cordis.patch.local.yml"
```

---

## Verify the install

```sh
# 1. The composed tree must contain a dsh-tm-guard layer with a tm-guard row:
dsh --profile tm-lab --dump-config | grep -A2 'dsh-tm-guard'
#   # == dsh-tm-guard
#   - id: tm-guard
#     name: dsh-tm-guard

# 2. Boot the profile — the console should print:
#   [tm-guard] Loaded. Protected paths: ... Audit log: ... Deny-read paths: ...
#   [tm-guard] 首次运行基线报告已生成: .tm-guard/baseline-report.md — 请查看你的实际保护等级
dsh --profile tm-lab

# 3. Read the first-run baseline report — what THIS machine actually protects:
cat .tm-guard/baseline-report.md

# 4. In a session, the registered tools are available — ask the agent to run
#    tm_status, or call tm_audit to inspect the gate log.
```

Remove cleanly with:

```sh
dsh plugin --profile tm-lab remove dsh-tm-guard
```

---

## How it works

```
agent tool call
      │
      ▼
ctx.on('tools/pre-execute')   ← registered with prepend: runs FIRST
      │
      ├─ classify tool + parse every bash segment (chains split on ; && || |)
      ├─ static script egress scan (inspect interpreter scripts, see limits)
      ├─ check target paths against protectedPaths / denyReadPaths
      ├─ ensure a local-git baseline exists for write dirs (instant rollback)
      ├─ fail-closed health check when the git net is absent (Time Machine)
      └─ allow (checkpoint first) or deny with an audited reason
```

Three decision classes:

1. **Local, reversible** — reads; writes under `protectedPaths`; local/offline git (`init/add/commit/reset/checkout/restore/clean/stash/...`); recognized local executors. Allowed. A git baseline is ensured before the first write and an APFS snapshot is taken (throttled by `snapshotCooldownSeconds`).
2. **Irreversible / non-local** — network commands (`curl`, `wget`, `ssh`, `git push/pull/clone/fetch`), package managers (`npm/pip/brew/cargo/... install`), process/system management (`kill`, `sudo`, `launchctl`, `shutdown`), subagent delegation, catastrophic patterns (`rm -rf /`). Denied.
3. **Sensitive reads** — anything touching `denyReadPaths`. The built-in list (see [Sensitive paths](#sensitive-paths)) covers `~/.ssh`, `~/.ssh/config`, `~/.aws`, `~/.aws/credentials`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.config`, `~/.config/gh/hosts.yml`, `~/.cursor`, `~/.codex`, `~/.claude.json`, `~/.claude`, `~/.gemini`, `~/.aider.conf.yml`, `~/.continue`, `~/Library/Keychains`, `~/Library/Cookies`, including redirection smuggling (`cat ~/.ssh/config > project/out.txt`). Denied and audited.

Anything unrecognized is denied by default (conservative). For locally executed interpreter scripts, the plugin additionally performs a **static, read-only** egress scan of the entry file, inline `-c`/`-e` code, and heredoc bodies — and follows local imports a few levels deep — flagging real outbound requests or unverifiable `eval/exec/__import__`.

**Rollback.** Local git is the primary mechanism (instant, offline, root-free, covers tracked files and files created after the baseline). Time Machine is the disaster-recovery backstop. `tm_rollback` tries, in order: (1) copy from a browsable completed TM backup (`tm-backup`, needs Full Disk Access), (2) mount the local APFS snapshot (`manual-mount`, needs root), and (3) print exact manual instructions (`manual`).

**Audit & reports.** Every allow/deny is appended to `<workspace>/.tm-guard/audit.jsonl` (tool, category, reason, target paths, snapshot id). After each agent turn with tool activity, a structured Markdown report with an independent acceptance check is written to `.tm-guard/reports/turn-<timestamp>.md`. When `autoApprove` is on (default), the plugin answers DSH approval requests with `allowed-once` for calls the prepended gate already permitted — that is what makes runs prompt-free; only pre-approved calls can reach that stage.

---

## Registered tools

| Tool | Purpose |
|---|---|
| `tm_snapshot` | Create a Time Machine local APFS snapshot checkpoint; takes a `note` label, returns the snapshot date id. |
| `tm_list_snapshots` | List available local snapshots with dates, for choosing a rollback point. |
| `tm_rollback` | Restore an explicit `path` (optionally at `snapshot_date`), or `last_operation=true` to undo the most recent write recorded in the audit log. |
| `tm_audit` | Show recent gate decisions (allow/block, category, target paths, snapshot ids); `limit`, `only_writes`. |
| `tm_status` | Print TM health/destination/snapshot count, workspace protection, gate policy, and audit-log stats. |
| `tm_backup` | Start a backup to the configured TM disk; background by default, `wait=true` blocks for a browsable restore point. |
| `tm_backup_status` | Show whether a backup is running, percent complete, and current phase. |

### First-run baseline report

On the **first** `apply()` in a workspace — detected by `.tm-guard/baseline-report.md` not existing — the plugin writes `.tm-guard/baseline-report.md` and prints one line pointing at it. The report answers the question a fresh install otherwise cannot: **what protection level am I actually in right now?**

It contains six sections, each a read-only probe of *this* machine:

| # | Section | What it reports |
|---|---|---|
| 1 | Time Machine 配置 | `tmutil destinationinfo` result, workspace TM-protection, overall TM health |
| 2 | Workspace 保护状态 | the effective writable scope, and which paths TM's exclusion list misses |
| 3 | Git baseline 可建性 | whether `git` is on PATH and the directory is already a work tree |
| 4 | denyReadPaths 实际生效项 | the effective count and the full list, with the merge semantics in force |
| 5 | 平台支持状态 | `full mode` on macOS, `limited mode` elsewhere |
| 6 | 已知残余风险 | the residual risks from [Limitations](#limitations--honest-scope), restated on your machine |

Three properties are worth stating explicitly:

- **Read-only.** The git probe runs `git rev-parse` and stops. It does **not** call `git init`, does **not** commit, does **not** create a snapshot, and does **not** touch your config. The report says so itself, and section 3 states that the baseline is created lazily at your first write. (This is why the report can be generated at load time without mutating the workspace.)
- **Generated once, kept.** Later `apply()`s do a single `existsSync` and leave the file alone — the report is a first-run *snapshot*, not a live view. If your Time Machine setup changes afterwards, the file keeps showing what was true at first run; use `tm_status` for the live answer. To regenerate, delete the file and restart the session.
- **Never fatal.** If the report cannot be written, `apply()` logs a warning and the gate loads normally. A display artifact must never stop the safety mechanism it describes.

`tm_status` echoes the path in its 【Data sources】 section, so the report is discoverable from the tool a user reaches for when something looks wrong.

### Auto-approval and its blast radius

When `autoApprove` is `true` (the default), the plugin answers DSH approval requests with `allowed-once` on your behalf — that is what makes unattended runs prompt-free. The safety argument for this is narrow and worth stating plainly:

- The `tools/pre-execute` gate is registered with **`prepend`**, so it classifies and denies *before* any other listener can raise an approval `ask`. Only operations that already passed the gate reach the approval stage.
- If another permission plugin registers earlier in the waterfall, or bypasses the gate entirely, an operation could reach that stage **without** having been checked — and it would still be auto-approved. This plugin cannot verify the ordering of plugins it does not control.

For that reason the plugin prints a startup warning whenever `autoApprove` is `true`, telling you to check the ordering if you run it alongside other permission plugins. Set `autoApprove: false` to let approval asks reach the user (or fail closed) instead.

There is one combination with **no backstop at all**: `failClosed: false` (writes are no longer blocked when no rollback net exists) together with `autoApprove: true` (the human prompt that would have caught it is auto-answered). The plugin warns specifically about this pair at startup. Keep `failClosed: true` unless you have a deliberate reason not to.

---

## Configuration

The plugin accepts a `Partial<TmGuardConfig>` on its inserted row. Users normally override fields from their own profile's `cordis.patch.yml` (later patch layers win per row; a patch replaces the whole row `config`).

| Field | Type | Default | Meaning |
|---|---|---|---|
| `protectedPaths` | `string[]` | `[process.cwd()]` | Absolute path prefixes writable by the agent. |
| `snapshotCooldownSeconds` | `number` | `30` | Min seconds between automatic pre-write APFS snapshots. `0` snapshots before every write; negative disables auto-snapshot. |
| `denyNetwork` | `boolean` | `true` | Deny classified network operations. |
| `denySystem` | `boolean` | `true` | Deny process/system-management commands. |
| `denyReadPaths` | `string[]` | credential/keychain paths listed above | Absolute or `~`-prefixed paths the agent may not read. **Additive by default**: entries are appended to the built-in list ([Sensitive paths](#sensitive-paths)), so you cannot accidentally drop the defaults by listing one path. `[]` adds nothing. |
| `denyReadPathsReplace` | `boolean` | `false` | When `true`, `denyReadPaths` **replaces** the built-in sensitive-path list instead of being appended to it. Replacement is the fail-open direction — the dropped defaults are named in a startup warning — so set this only when you are curating the whole list deliberately. |
| `extraAllowTools` | `string[]` | `[]` | Tool names that bypass classification and are always allowed. |
| `extraDenyTools` | `string[]` | `[]` | Tool names that are always denied. |
| `verbose` | `boolean` | `true` | Log every gate decision to the host console. |
| `requireTaskSnapshot` | `boolean` | `true` | System-prompt guidance requires a checkpoint before multi-step tasks. |
| `failClosed` | `boolean` | `true` | Block writes when no rollback net exists (git baseline uncreatable **and** Time Machine unhealthy). |
| `failClosedBlockReads` | `boolean` | `false` | Also block reads when the backstop is unhealthy. Left false so the agent can diagnose. |
| `turnReports` | `boolean` | `true` | Write the per-turn Markdown report + acceptance check. |
| `blockingBackupBeforeWrite` | `boolean` | `false` | Run a blocking full TM backup before each write (slow, SD-card-heavy) instead of an instant local snapshot. |
| `requireGitBaseline` | `boolean` | `true` | Require a committed local-git baseline (auto-created) for file writes. |
| `autoApprove` | `boolean` | `true` | Answer DSH approval requests `allowed-once` for calls already passed by the prepended gate. Prints a startup warning; **its safety depends on this plugin's `prepend` order** — see [Auto-approval and its blast radius](#auto-approval-and-its-blast-radius). Set false to let approval asks reach the user / fail closed. |

| `auditMaxBytes` | `number` | `0` | Per-file audit rotation threshold in **bytes** (default `0` = rotation off, the audit log keeps everything). Set a positive value (e.g. `10485760` = 10 MiB) to enable rotation: when the live `audit.jsonl` would exceed it, the current content is rotated to `.1` and a fresh file starts. See [Audit log rotation](#audit-log-rotation). |
| `auditRetainFiles` | `number` | `5` | How many rotated generations (`.1`, `.2`, …) are kept before the **oldest is physically deleted**. Total retained ≈ `auditMaxBytes × (1 + auditRetainFiles)`. |
| `auditTotalMaxBytes` | `number` | `104857600` | Optional global cap in **bytes** (default 100 MiB) across all generations; a safety net if `maxBytes`/`retainFiles` are raised. |

> **⚠️ Do NOT put `subagent` / `subagent_fork` / `workflow` / `job_output` in `extraAllowTools`.** The allow-list short-circuits classification entirely, so a whitelisted subagent tool bypasses the gate's `mixed`-category denial and can write outside `protectedPaths` without rollback coverage. Subagents are `mixed` by default and denied for exactly that reason; keep them out of the allow-list (see Limitations).

Example — your profile's `cordis.patch.yml` (the shipped bundle itself inserts a bare row; this is how a user configures it):

```yaml
- insert:
    - id: tm-guard
      name: dsh-tm-guard
      config:
        protectedPaths:
          - '/Users/you/projects'
        denyReadPaths:
          - '~/.ssh'
          - '~/.aws'
          - '~/Library/Keychains'
        snapshotCooldownSeconds: 30
        denyNetwork: true
        denySystem: true
        failClosed: true
        requireGitBaseline: true
        turnReports: true
```

### Audit log rotation

Since 0.2.6 the audit log **keeps everything by default** — rotation is off, so
an unattended machine's full history is retained. Rotation is **opt-in** for
users who prefer bounded disk usage: set `auditMaxBytes` (per-file threshold in
**bytes**, e.g. `10485760` = 10 MiB); `auditRetainFiles` is optional and
defaults to 5 generations. With 10 MiB × 5 generations the total is ≈ 50 MiB
(100 MiB hard cap).

- Rotation is **pre-append**: the triggering record lands in the fresh file,
  and `.1` is byte-for-byte the pre-rotation history.
- **The oldest generation is physically deleted** once the retained window is
  full — this is a real, intentional trade-off (0.2.4 had an unbounded log;
  0.2.5 rotated by default; 0.2.6 made rotation opt-in).
  Rollback/forensics reach back only as far as the retained window.
- Cross-process lock keeps several hosts from corrupting the same file.
- **To enable rotation** (bounded disk usage — only for users who prefer a cap
  over full history): set `auditMaxBytes: 10485760` (10 MiB); `auditRetainFiles`
  defaults to 5 if omitted.
- **To keep more history** without going unbounded, raise both, e.g.
  `auditMaxBytes: 104857600` (100 MiB) + `auditRetainFiles: 20`
  (≈ 21 × 100 MiB retained).
- Each rotation is recorded through the plugin's structured logger under the
  name `tm-guard` (visible in the host log surface; e.g. web profile:
  `/tmp/dsh-web.log`), and the current generation count is always readable via
  `tm_status` → 【Data sources】. Rotation is a normal self-healing event — it
  does not interrupt or notify you.

```yaml
config:
  auditMaxBytes: 0              # default: rotation off, keep everything
  # or
  auditMaxBytes: 10485760       # bytes per file (10 MiB, rotation on)
  auditRetainFiles: 5           # generations kept (optional, default 5)
```

---

## Sensitive paths

`denyReadPaths` is a list of **prefixes**. Every entry matches the path itself and everything beneath it, so `~/.ssh` covers `~/.ssh/id_rsa`, `~/.ssh/config` and so on. A match denies the operation whether the path is being read *or* written — the list protects credentials from being overwritten, not just read.

The built-in list ships with the plugin (source of truth: `src/sensitive-paths.ts`, exported as `DEFAULT_SENSITIVE_PATHS`):

| Group | Paths | What it protects |
|---|---|---|
| Cloud & shell credentials | `~/.ssh`, `~/.ssh/config`, `~/.aws`, `~/.aws/credentials`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.config` | Private keys, cloud CLI credentials and SSO token caches, GPG keyrings, kubeconfig bearer tokens, registry auth, plaintext HTTPS tokens. `~/.config` is the XDG base directory (`gh`, `gcloud`, `heroku`, …). |
| Agent & CLI credentials | `~/.config/gh/hosts.yml`, `~/.cursor`, `~/.codex`, `~/.claude.json`, `~/.claude`, `~/.gemini`, `~/.aider.conf.yml`, `~/.continue` | Credential stores belonging to the agent/CLI tools this plugin runs alongside — the GitHub CLI OAuth token, and the auth/session state of the Cursor, Codex, Claude Code, Gemini, Aider and Continue tooling. These are long-lived tokens for *other* execution surfaces, so an autonomous agent reading them widens its own blast radius. |
| Platform keystores | `~/Library/Keychains`, `~/Library/Cookies` | The macOS login/System keychain databases and browser session cookies. |

### Adding your own paths (additive by default)

`config.denyReadPaths` is **appended** to the built-in list, so a profile can add a project-specific secret location without weakening anything:

```yaml
- insert:
    - id: tm-guard
      name: dsh-tm-guard
      config:
        denyReadPaths:
          - '~/work/private-credentials'   # added to the defaults above
```

This is deliberate. The earlier semantics replaced the whole list, so a profile that appended one path silently dropped *every* cloud and agent credential entry — a fail-open change disguised as a small config tweak.

To replace the list outright (e.g. you curate the set yourself and want a narrower policy), set `denyReadPathsReplace: true`. The plugin then names every dropped default in a startup warning, because losing them is exactly the kind of change that should never be silent:

```yaml
      config:
        denyReadPathsReplace: true
        denyReadPaths:
          - '~/.ssh'
          - '~/.aws'
```

`denyReadPaths: []` with `denyReadPathsReplace: true` disables the restriction entirely. That is a documented opt-out — reads are then unrestricted, including of private keys, so it is only appropriate on a disposable machine with no real credentials.

---

## Platform support

The plugin probes `process.platform` at load time.

On **macOS (`darwin`)** it runs in **full mode**: local APFS snapshots, `tmutil` health checks, rollback strategies and the fail-closed Time Machine backstop are all active.

On **any other platform** there is no `tmutil`, so the plugin runs in **limited mode** rather than pretending otherwise:

- A one-line `console.error` states the platform is unsupported and that the gate is running in "no Time Machine rollback net" mode — write protection rests on the **git baseline only**.
- The gate **does not block writes** for absence of a TM net (there is none to check); the TM-health fail-closed check and every `tm_*` snapshot/rollback path are inert. The git baseline is still created and committed before writes exactly as on macOS.
- A `console.warn` restates the degradation **once per apply()** the first time a write is approved, so a long unattended run cannot forget it. It is deliberately not repeated per call — a warning that fires constantly is one users learn to ignore.
- `tm_status` reports `platform: <platform> — limited mode (no TM)` and marks TM health `N/A — no TM on this platform (git baseline is the rollback net)` instead of the misleading `UNHEALTHY — writes BLOCKED`.
- The **first-run baseline report** labels section 5 `limited mode（无 TM）`, names the git baseline as the only rollback net, and renders section 1 as "TM 不适用 … 能力限制，不是故障" — it never claims a Time Machine destination or health it cannot have. This is pinned by test: a non-macOS report must not contain `TM 已配置` or `HEALTHY ✅`.

The point of stating this loudly is that **silent degradation is the dangerous outcome in a safety tool**. Before this probe, a non-macOS user saw a handful of failing `tm_*` tools while the gate still spoke fail-closed language about Time Machine protection — easy to read as "a rollback net exists" when none did. If you need real rollback guarantees, run on macOS with Time Machine configured, or use a disposable VM/profile.

---

## Limitations & honest scope

Please read this before trusting the plugin. It raises the bar for unattended runs; it is not a proof of isolation.

- **macOS + Time Machine only.** Everything on the snapshot side depends on `/usr/bin/tmutil`, APFS local snapshots, and a configured TM destination. There is no Linux/Windows path. Local snapshot creation is sub-second, but mounting a fresh local snapshot back for command-line restore needs root or the Time Machine UI — prefer the git baseline for instant undo. On a non-macOS host the plugin still loads and still gates, but degrades to **limited mode** — see [Platform support](#platform-support).
- **Full Disk Access matters.** Without it, automated restore from completed TM backups (`tm-backup` strategy) cannot read the backup; the plugin falls back to root-required mounting or printed manual steps.
- **The static egress scan has blind spots.** It is a regex/text analysis, not execution tracing. URLs assembled at runtime, `eval(decodedBytes)`, targets hidden behind Makefiles or `cargo run`, or code in unscanned transitive files are not caught. `denyNetwork=true` also does not prevent a determined actor from using an allowed channel.
- **It is not a kernel-level sandbox.** The plugin runs as trusted host code with the DSH process's own permissions; the gate inspects tool calls the harness routes through it. It does not confine syscalls. The maintainer's own deployment pairs it with **[LuLu](https://objective-see.org/products/lulu.html)**, an **external, separately installed** macOS network firewall, to block outbound traffic at the process layer (e.g. deny egress for `python3`/`bash`, allow only the host's model endpoint). LuLu is a third-party product; this plugin neither installs nor configures it.
- **Heuristic command classification.** Exotic one-liners may be misclassified; the default for the unknown is deny. Tune with `extraAllowTools`/`extraDenyTools`, and keep `denyNetwork`/`denySystem` on.
- **Path extraction is heuristic, and the write-flag list is curated.** Paths carried by command arguments (positional paths, redirections, `key=value` operands, glued `--flag=value` values) are recovered by pattern matching, not by a shell parser. The write-side glued-flag list (`--output`, `--outfile`, `--target-directory`, …) is a maintainer-curated allow-list: a new write flag or exotic variant not yet listed will not be surfaced to the write-protection check. Unknown = denied by default keeps the common case fail-closed; review new write flags as you encounter them, and keep `denyNetwork` on as the egress backstop.
- **Interpreter `-c/-e` code is only scanned for literal sensitive paths.** `python3 -c "print(open('/Users/alice/.ssh/id_rsa').read())"` is blocked, but the code text is a Turing-complete program — dynamically assembled paths (`'.'+'ssh'`, `os.path.join(expanduser('~'), ...)`, decoding, …) can evade the text scan. That residual gap is covered by `denyNetwork` egress blocking, the audit log, and the agent's own judgment; remove `python3 -c`/`node -e` from your trusted tools if you need stricter behavior.
- **Inline code that wraps local dev commands is denied since 0.2.5.** `python3 -c "subprocess.run(['npm','test'])"`, `node -e "execFileSync('git',['status'])"` or any inline `npm/git/cargo/go` invocation are rejected (`package`/`vcs_remote`/`unknown`): static analysis cannot prove the wrapped `npm` is `test` and not `install`, or that the wrapped `git` is local `status` and not a remote op. The direct forms (`npm test`, `git status`, `cargo test`, `go run`) still pass, and **script-file forms are unaffected** — `node x.js` / `python x.py` are scanned as files, not as inline code. Prefer running the command directly or writing it to a script file.
- **The audit log keeps everything by default (since 0.2.6).** Rotation is off unless you opt in: set `auditMaxBytes` (e.g. `10485760` = 10 MiB) + `auditRetainFiles` to enable bounded retention; **once the window is full the oldest generation is physically deleted and cannot be recovered** — forensics and rollback reach back only as far as the retained window. With the cap off, unbounded growth becomes your own disk problem. See [Audit log rotation](#audit-log-rotation).
- **Raw socket egress without a URL literal is not detected.** `python3 -c "import socket; socket.create_connection(('host',4444))"` has no URL/`urllib`/`requests` pattern for the egress net to match — a static-text limitation that exists in every version (README's "honest scope"). Since 0.2.5 recognizes versioned interpreter names (`python3.12`, `pypy3`, …) instead of mis-blocking them as `unknown`, this same blind spot now also applies to those names — identical to bare `python3`, not a regression. `denyNetwork` still blocks the *category* when the command is classified network; socket is the residual hole. For credential-rich hosts, remove inline interpreters from your trusted tools and pair with an egress firewall (see below).
- **Temp-dir exemption normalizes paths (since 0.2.6).** Scratch writes under `/tmp`, `/private/tmp`, `/var/tmp`, `/var/folders` are allowed without a snapshot; the check now resolves `//`, `.`, `..` and case (same normalization as the sensitive-path checks), so `/tmp/../etc/…` no longer matches the exemption (the OS would land it outside `/tmp`).
- **`curl` download flags are cluster-expanded (since 0.2.6).** `curl -sLk -o file https://…` (bundled `-k`), `-sLd x=y` (POST body) and `-sLH "X:y"` (arbitrary header) no longer bypass the readonly-download blocklist: glued short-option clusters are expanded (`-sLk` → `-s -L -k`) before matching, so they classify as `network` deny.
- **Subagents are blocked by default** because child operations cannot be fully verified; only enable them if they inherit equivalent constraints.
- **For production or credential-rich machines**, use a real OS sandbox / disposable profile / VM, least-privilege credentials, and egress filtering in addition to this plugin. Review the source before installing any DSH plugin — a plugin is trusted host code, not sandboxed agent code.

---

## Development

The build is **zero-dependency**, using Node's built-in TypeScript type-stripping (`module.stripTypeScriptTypes`). Build machine requirement: **Node.js ≥ 22.6 (or ≥ 20.19 LTS)**. The emitted `lib/` is plain ESM JavaScript plus a hand-maintained `lib/index.d.ts`; consumers need no TypeScript toolchain.

```sh
npm run build      # node scripts/build/build.mjs → lib/
npm run prepare    # alias of build; run automatically on npm/git installs
```

Project layout:

```text
src/
  index.ts         # plugin entry: pre-execute gate, hooks, system prompt, tm_* tools
  classifier.ts    # tool mapping + bash segment parser + decision matrix
  scan-scripts.ts  # static egress scan for interpreter scripts / inline code / heredocs
  tm.ts            # tmutil wrapper: snapshots, health, 3-strategy rollback
  git.ts           # local-git baseline creation
  audit.ts         # JSONL audit log
  report.ts        # per-turn markdown report
  verify.ts        # independent per-turn acceptance check
  status.ts        # tm_status layered rendering (pure)
  baseline-report.ts # first-run safety baseline self-check (U-27, read-only)
cordis.patch.yml       # bundle layer (references the package by name)
cordis.patch.local.yml # maintainer-only absolute-source overlay (not published)
scripts/build/build.mjs
```

Smoke tests are dependency-free Node scripts importing the TypeScript source (Node strips types at import time; same Node version requirements as the build):

```sh
node --experimental-strip-types test-classifier.mts
node --experimental-strip-types test-scan-scripts.mts
node --experimental-strip-types test-runtime.mts
node --experimental-strip-types test-git-rollback.mts
node --experimental-strip-types test-rollback.mts
node --experimental-strip-types test-verify.mts
node --experimental-strip-types test-report.mts
node --experimental-strip-types test-hook.mts
```

Some tests invoke real `tmutil`/git on the local machine and create temp directories; they do not touch the network.

Inspect what would be published:

```sh
npm pack --dry-run
```

---

## License

[MIT](LICENSE) © 2026 dsh-tm-guard contributors.
