# dsh-tm-guard

**A zero-intervention permission gate for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH) agents on macOS.** Local, reversible operations — writes that can be undone via a local git baseline or macOS Time Machine — are auto-approved and checkpointed; network access, package installs, system/process management, remote VCS, and reads of sensitive credential paths are blocked and audited. The agent runs unattended inside a protected workspace with no approval prompts.

> Core rule: **operations that can be rolled back are allowed; operations that cannot be rolled back are denied.**

---

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
- **DSH CLI installed**, matching the peer range in `package.json` — currently `@deepseek-ai/cordis >=4.0.0` and `@deepseek-ai/dsh-tools >=0.1.0-rc.1 <0.2.0-0` (the range includes prereleases such as `0.1.2-rc.1`).

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
# or a packed tarball: npm pack → dsh plugin --profile tm-lab add ./dsh-tm-guard-0.1.0.tgz
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
dsh --profile tm-lab

# 3. In a session, the registered tools are available — ask the agent to run
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
3. **Sensitive reads** — anything touching `denyReadPaths` (default: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.config`, `~/Library/Keychains`, `~/Library/Cookies`), including redirection smuggling (`cat ~/.ssh/config > project/out.txt`). Denied and audited.

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

---

## Configuration

The plugin accepts a `Partial<TmGuardConfig>` on its inserted row. Users normally override fields from their own profile's `cordis.patch.yml` (later patch layers win per row; a patch replaces the whole row `config`).

| Field | Type | Default | Meaning |
|---|---|---|---|
| `protectedPaths` | `string[]` | `[process.cwd()]` | Absolute path prefixes writable by the agent. |
| `snapshotCooldownSeconds` | `number` | `30` | Min seconds between automatic pre-write APFS snapshots. `0` snapshots before every write; negative disables auto-snapshot. |
| `denyNetwork` | `boolean` | `true` | Deny classified network operations. |
| `denySystem` | `boolean` | `true` | Deny process/system-management commands. |
| `denyReadPaths` | `string[]` | credential/keychain paths listed above | Absolute or `~`-prefixed paths the agent may not read. Empty list disables the restriction. |
| `extraAllowTools` | `string[]` | `[]` | Tool names that bypass classification and are always allowed. |
| `extraDenyTools` | `string[]` | `[]` | Tool names that are always denied. |
| `verbose` | `boolean` | `true` | Log every gate decision to the host console. |
| `requireTaskSnapshot` | `boolean` | `true` | System-prompt guidance requires a checkpoint before multi-step tasks. |
| `failClosed` | `boolean` | `true` | Block writes when no rollback net exists (git baseline uncreatable **and** Time Machine unhealthy). |
| `failClosedBlockReads` | `boolean` | `false` | Also block reads when the backstop is unhealthy. Left false so the agent can diagnose. |
| `turnReports` | `boolean` | `true` | Write the per-turn Markdown report + acceptance check. |
| `blockingBackupBeforeWrite` | `boolean` | `false` | Run a blocking full TM backup before each write (slow, SD-card-heavy) instead of an instant local snapshot. |
| `requireGitBaseline` | `boolean` | `true` | Require a committed local-git baseline (auto-created) for file writes. |
| `autoApprove` | `boolean` | `true` | Answer DSH approval requests `allowed-once` for calls already passed by the prepended gate. Set false to let approval asks reach the user / fail closed. |

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

---

## Limitations & honest scope

Please read this before trusting the plugin. It raises the bar for unattended runs; it is not a proof of isolation.

- **macOS + Time Machine only.** Everything depends on `/usr/bin/tmutil`, APFS local snapshots, and a configured TM destination. There is no Linux/Windows path. Local snapshot creation is sub-second, but mounting a fresh local snapshot back for command-line restore needs root or the Time Machine UI — prefer the git baseline for instant undo.
- **Full Disk Access matters.** Without it, automated restore from completed TM backups (`tm-backup` strategy) cannot read the backup; the plugin falls back to root-required mounting or printed manual steps.
- **The static egress scan has blind spots.** It is a regex/text analysis, not execution tracing. URLs assembled at runtime, `eval(decodedBytes)`, targets hidden behind Makefiles or `cargo run`, or code in unscanned transitive files are not caught. `denyNetwork=true` also does not prevent a determined actor from using an allowed channel.
- **It is not a kernel-level sandbox.** The plugin runs as trusted host code with the DSH process's own permissions; the gate inspects tool calls the harness routes through it. It does not confine syscalls. The maintainer's own deployment pairs it with **[LuLu](https://objective-see.org/products/lulu.html)**, an **external, separately installed** macOS network firewall, to block outbound traffic at the process layer (e.g. deny egress for `python3`/`bash`, allow only the host's model endpoint). LuLu is a third-party product; this plugin neither installs nor configures it.
- **Heuristic command classification.** Exotic one-liners may be misclassified; the default for the unknown is deny. Tune with `extraAllowTools`/`extraDenyTools`, and keep `denyNetwork`/`denySystem` on.
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
