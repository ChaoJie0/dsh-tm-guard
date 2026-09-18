/**
 * dsh-tm-guard — Time-Machine-backed autonomous agent permission gate.
 *
 * Allows operations that can be rolled back via macOS Time Machine
 * local snapshots; blocks everything else.  Enables zero-intervention
 * autonomous agent runs within a TM-protected workspace.
 *
 * Extension points used:
 *   - tools/pre-execute  : permission gate (allow/deny) + audit logging
 *   - ctx.tools.register : tm_snapshot / tm_rollback / tm_audit / tm_status
 *   - ctx.systemPrompt   : injects operating-mode guidance + workflow
 *
 * Features (v0.1.0):
 *   - Audit log (JSONL) records every gate decision for post-hoc traceability
 *   - Multi-strategy rollback (auto-mount → tmutil → manual mount → instructions)
 *   - "Roll back last operation" via audit log
 *   - Enforced agent workflow: snapshot → modify → verify → rollback on failure
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'

import {
  createSnapshot,
  listSnapshots,
  latestSnapshot,
  isPathProtected,
  getTmStatus,
  getTmHealth,
  invalidateHealthCache,
  rollbackPath,
  rollbackPaths,
  startBackup,
  getBackupStatus,
  type SnapshotInfo,
  type RollbackResult,
  type TmHealth,
} from './tm.ts'
import {
  classifyToolCall,
  decide,
  type GateDecision,
} from './classifier.ts'
import { scanCommandForEgress } from './scan-scripts.ts'
import { AuditLog } from './audit.ts'
import { ensureGitBaseline, commitCheckpoint } from './git.ts'
import { buildTurnReport } from './report.ts'
import { verifyTurn } from './verify.ts'
import { dirname, join, resolve } from 'node:path'
import { execSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'

/* ------------------------------------------------------------------ */
/* Plugin configuration                                                */
/* ------------------------------------------------------------------ */

export interface TmGuardConfig {
  /**
   * Path prefixes that are protected by Time Machine.
   * Defaults to the current working directory (workspace root).
   */
  protectedPaths: string[]
  /**
   * Minimum seconds between automatic pre-operation snapshots.
   * Default 30 seconds.  Set to 0 to create a fresh TM snapshot before
   * EVERY write operation (finest rollback granularity).  Higher values
   * reduce snapshot overhead but group multiple writes under one checkpoint.
   */
  snapshotCooldownSeconds: number
  /**
   * When true, network operations are denied (default true).
   */
  denyNetwork: boolean
  /**
   * When true, system/process operations are denied (default true).
   */
  denySystem: boolean
  /**
   * Sensitive path prefixes (absolute or ~-prefixed) that the agent may not
   * READ — e.g. '~/.ssh', '~/.aws', '~/Library/Keychains'. Any operation
   * (read or write) referencing a path under one of these prefixes is denied
   * and audited. This closes the zero-intervention gap where the agent runs
   * with the user's full read access: credentials, keys and configs outside
   * the workspace stay out of reach. Empty list disables the restriction.
   */
  denyReadPaths: string[]
  /**
   * Additional tool names to always allow (bypass classification).
   */
  extraAllowTools: string[]
  /**
   * Additional tool names to always deny.
   */
  extraDenyTools: string[]
  /**
   * When true, log every gate decision to the harness console.
   */
  verbose: boolean
  /**
   * When true, require the agent to create a snapshot before any
   * multi-step task.  Enforced via system prompt guidance.
   */
  requireTaskSnapshot: boolean
  /**
   * When true (default), block ALL write operations if Time Machine
   * is unhealthy (no destination, no snapshots, or workspace not
   * protected).  This is the fail-closed safety net: if the rollback
   * mechanism is broken, the agent must not make changes.
   */
  failClosed: boolean
  /**
   * When true, also block read operations when TM is unhealthy.
   * Default false — reads are harmless and the agent needs them to
   * diagnose the issue.
   */
  failClosedBlockReads: boolean
  /**
   * When true (default), generate a structured markdown completion report
   * after every agent turn that had tool activity: what was allowed/blocked,
   * changed files, produced artifacts, rollback readiness. Reports are
   * written next to the audit log under `.tm-guard/reports/turn-<ts>.md` and
   * a one-line summary prints to the harness console. This is feedback
   * layer 1 (completion feedback); layer 2 (real-time alerts) is separate.
   */
  turnReports: boolean
  /**
   * When true, run a BLOCKING full Time Machine backup to the backup disk
   * (tm_backup, wait) before EVERY file write. This gives each write a
   * restore point that tm_rollback can read back WITHOUT root/sudo — at the
   * cost of waiting for a backup (tens of seconds to minutes) per write and
   * heavy SD-card use. When false (default), an instant local APFS snapshot
   * is taken before writes instead (sub-second, but reading it back needs
   * root or the Time Machine UI).
   */
  blockingBackupBeforeWrite: boolean
  /**
   * When true (default), every file write is gated at the tool layer on a local
   * git baseline: the target directory must be inside a git work tree with a
   * committed baseline, else the plugin creates one (git init + .gitignore +
   * baseline commit). Local git is the instant, root-free, offline rollback
   * net. Writes where a baseline cannot be established are denied.
   */
  requireGitBaseline: boolean
  /**
   * When true (default), auto-approve the dsh approval/request waterfall with
   * 'allowed-once' so the agent runs with zero human prompts. This is safe ONLY
   * because the tools/pre-execute gate is registered with prepend (it runs
   * first and denies anything non-rollback-able before a later gate can raise
   * an approval 'ask'); ops reaching the approval stage have already passed the
   * gate. Set false to let escalation asks fall through to the user/deny.
   */
  autoApprove: boolean
}

const DEFAULT_CONFIG: TmGuardConfig = {
  protectedPaths: [process.cwd()],
  snapshotCooldownSeconds: 30,
  denyNetwork: true,
  denySystem: true,
  // Sensitive-path read restriction: default deny list for the most common
  // credential/config locations outside the workspace. Override per profile
  // via cordis.patch.yml (see both patch files for the active list).
  denyReadPaths: [
    '~/.ssh', '~/.aws', '~/.gnupg', '~/.kube', '~/.docker',
    '~/.netrc', '~/.git-credentials', '~/.npmrc', '~/.pypirc',
    '~/.config', '~/Library/Keychains', '~/Library/Cookies',
  ],
  extraAllowTools: [],
  extraDenyTools: [],
  verbose: true,
  requireTaskSnapshot: true,
  failClosed: true,
  failClosedBlockReads: false,
  turnReports: true,
  // Default off: local git is the instant, root-free rollback mechanism (see the
  // system-prompt workflow). Set true to instead run a blocking (~1 min) TM backup
  // before every state-changing op for non-git directories.
  blockingBackupBeforeWrite: false,
  // Tool-layer safety net: every file write requires a committed local-git
  // baseline (auto-created if absent). This is what makes rollback instant,
  // offline, and root-free; Time Machine remains the backstop for git's blind
  // spots (metadata, ignored files, git-cleaned files, disk failure).
  requireGitBaseline: true,
  // Zero-intervention: auto-answer dsh's approval prompts for ops that already
  // passed the (prepended) TM-Guard gate.
  autoApprove: true,
}

/* ------------------------------------------------------------------ */
/* Snapshot throttling + failure tracking                             */
/* ------------------------------------------------------------------ */

let lastSnapshotTime = 0
let consecutiveSnapshotFailures = 0

async function maybeSnapshot(cooldownSeconds: number): Promise<string | null> {
  const now = Date.now()
  if (now - lastSnapshotTime < cooldownSeconds * 1000) {
    return null
  }
  try {
    const date = await createSnapshot()
    lastSnapshotTime = now
    consecutiveSnapshotFailures = 0
    invalidateHealthCache()
    return date
  } catch (err) {
    consecutiveSnapshotFailures++
    const errMsg = err instanceof Error ? err.message : String(err)
    const hint = /permission|denied|not privileged|eperm|eacces/i.test(errMsg)
      ? ' (snapshot creation denied: grant Full Disk Access to your terminal/dsh, or configure sudo NOPASSWD for tmutil localsnapshot)'
      : ''
    console.warn(
      `[tm-guard] Failed to create TM snapshot (attempt ${consecutiveSnapshotFailures}): ${errMsg}${hint}`,
    )
    if (consecutiveSnapshotFailures >= 5) {
      console.warn(
        '[tm-guard] ⚠️  TM snapshot creation has failed 5+ times consecutively. ' +
        'Writes will proceed but may not have fresh rollback points. ' +
        'Run tm_status to diagnose.',
      )
    }
    return null
  }
}

/* ------------------------------------------------------------------ */
/* Plugin definition                                                   */
/* ------------------------------------------------------------------ */

export const name = 'tm-guard'
export const inject = ['tools']

export function apply(ctx: Context, rawConfig?: Partial<TmGuardConfig>) {
  const config: TmGuardConfig = { ...DEFAULT_CONFIG, ...rawConfig }
  const audit = new AuditLog(process.cwd())

  /* -------------------------------------------------------------- */
  /* Startup health check (fail-closed)                            */
  /* -------------------------------------------------------------- */

  let startupHealth: TmHealth | null = null
  if (config.failClosed) {
    // Run asynchronously; don't block plugin load. The pre-execute
    // hook will re-check if this hasn't resolved yet.
    getTmHealth(config.protectedPaths)
      .then((health) => {
        startupHealth = health
        if (!health.healthy) {
          console.warn(
            '[tm-guard] ⚠️  Time Machine is NOT healthy. Write operations will be BLOCKED (fail-closed).',
          )
          for (const issue of health.issues) {
            console.warn(`[tm-guard]   - ${issue}`)
          }
        } else if (config.verbose) {
          console.log(
            `[tm-guard] TM health check passed (${health.snapshotCount} snapshots, workspace protected).`,
          )
        }
      })
      .catch((err) => {
        console.warn('[tm-guard] TM health check failed:', err)
      })
  }

  /* -------------------------------------------------------------- */
  /* System prompt: operating mode + enforced workflow             */
  /* -------------------------------------------------------------- */

  try {
    ctx.systemPrompt?.section({
      id: 'tm-guard-mode',
      title: 'TM-Guard Autonomous Mode',
      priority: 100,
      content: [
        '## TM-Guard Autonomous Mode',
        '',
        'You are running in TM-Guard mode. Every tool call is intercepted by a permission gate.',
        'You work fully autonomously and LOCALLY: there is no human to approve actions, and there',
        'is no network. Your safety net is LOCAL GIT for instant rollback, with Time Machine as a',
        'disaster-recovery backstop.',
        '',
        '### What is allowed (auto-approved)',
        '- Reading files and directories',
        '- Creating, editing, deleting, moving files on protected paths',
        '- Local git: init, add, commit, reset, checkout, restore, clean, stash, branch, diff, log, status (all OFFLINE — no remote needed)',
        '- Running local commands that only read or modify local files',
        '',
        '### What is BLOCKED (irreversible / not local)',
        '- Any network access: curl, wget, ssh, scp, git push/pull/clone/fetch',
        '- Package managers: npm install, pip install, brew install, yarn, cargo',
        '- Process/system management: kill, launchctl, sudo, shutdown, tmutil',
        '- Subagent delegation (cannot verify child operations)',
        '- Reading sensitive paths (SSH keys, cloud credentials, keychains, dotfile secrets): ' +
          (config.denyReadPaths.join(', ') || '(none)'),
        '- Any command not recognized (conservative default = deny)',
        '',
        '### MANDATORY WORKFLOW — local git is your rollback mechanism',
        '',
        'Local git is INSTANT, offline, root-free, and can both revert edits AND delete newly-created',
        'files. Use it for every code/file task. (Time Machine backups are slow and macOS does not',
        'expose a just-finished backup to the command line immediately, so do NOT rely on tm_rollback',
        'for instant undo — it is a last resort.)',
        '',
        '1. **CHECKPOINT (git)**: Before changing anything, ensure a clean committed baseline:',
        '   - If the project is not a git repo: `git init`, then `git add -A && git commit -m "baseline before <task>"`.',
        '   - If it is: `git add -A && git commit -m "checkpoint before <task>"` (commit untracked/modified work so it can be restored).',
        '   These are local commits only; no remote is used or needed.',
        '',
        '2. **MODIFY**: Make your changes freely. File operations are auto-approved on protected paths.',
        '',
        '3. **VERIFY**: Run validation — tests, lint, build, type-check — and READ the results carefully.',
        '',
        '4. **IF VERIFICATION FAILS — roll back YOURSELF, immediately, no human needed**:',
        '   - Revert tracked edits: `git reset --hard HEAD` (back to your checkpoint commit).',
        '   - Remove files you created after the checkpoint: `git clean -fd`.',
        '   - Confirm the tree is clean with `git status`, then report what went wrong. Never leave',
        '     the workspace in a broken state.',
        '',
        '5. **IF VERIFICATION PASSES**: `git add -A && git commit -m "<result>"` to record the good',
        '   state, then report completion.',
        '',
        '### Time Machine backstop (non-git directories / disaster recovery)',
        '- For work that is NOT under git, Time Machine still backs files up (hourly, and via `tm_backup`).',
        '  To recover an older version of a file use `tm_rollback(path=...)`; it restores from the most',
        '  recent mounted backup. Note: TM recovers PREVIOUS versions of files — it cannot undo a file',
        '  created after the last backup, and a backup taken seconds ago may briefly need the Time',
        '  Machine UI (macOS mounts completed backups lazily). Prefer git whenever possible.',
        '',
        '### Rules',
        '- NEVER retry a blocked operation. If denied, adapt to a local-only / offline approach.',
        '- NEVER modify files outside the protected workspace paths.',
        '- ALWAYS make a git checkpoint commit before the first write in any task.',
        '- ALWAYS verify, and on failure ALWAYS `git reset --hard` + `git clean -fd` to your checkpoint before reporting.',
        '- Use `tm_audit` to review this session\'s actions and `tm_status` to check protection.',
      ].join('\n'),
    })
  } catch {
    // systemPrompt service may not be available in all profiles
  }

  /* -------------------------------------------------------------- */
  /* Permission gate: tools/pre-execute + audit logging             */
  /* -------------------------------------------------------------- */

  ctx.on(
    'tools/pre-execute',
    async (exec: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision> => {
      // dsh ToolExecution exposes `name` (tool name) and `arguments` (the
      // validated, frozen model arguments). There is no `exec.tool`/`exec.args`;
      // reading those yields undefined and silently disables the gate.
      const toolName = exec.name ?? 'unknown'
      const args = ((exec.arguments ?? {}) as Record<string, unknown>)

      // Explicit allow/deny lists
      if (config.extraDenyTools.includes(toolName)) {
        audit.record({
          tool: toolName,
          category: 'explicit-deny',
          decision: 'deny',
          reason: 'Tool in deny list',
          targetPaths: [],
          args,
        })
        return {
          kind: 'deny',
          reason: `TM-Guard: tool "${toolName}" is in the deny list.`,
        }
      }
      if (config.extraAllowTools.includes(toolName)) {
        audit.record({
          tool: toolName,
          category: 'explicit-allow',
          decision: 'allow',
          reason: 'Tool in allow list',
          targetPaths: [],
          args,
        })
        if (config.verbose) {
          console.log(`[tm-guard] ALLOW (explicit): ${toolName}`)
        }
        return next()
      }

      // Classify
      const classification = classifyToolCall(
        toolName,
        args,
        config.denyReadPaths,
      )

      // Static egress scan: an interpreter (`python x.py`, `node x.js`,
      // `bash deploy.sh`) is trusted as local_exec by the command classifier,
      // but the SCRIPT it runs may itself call out to the network. Inspect the
      // entry script file, `-c`/`-e` inline code and heredoc bodies on the
      // RAW command before trusting the "local" label. Hits are force-denied
      // so a `denyNetwork=false` config override cannot resurrect smuggled
      // egress; eval/exec/__import__ we cannot prove innocent is downgraded to
      // unknown (conservative deny).
      if (classification.category === 'local_exec') {
        const rawCmd =
          (args.command as string) ??
          (args.input as string) ??
          (args.cmd as string) ??
          (args.code as string) ??
          ''
        if (typeof rawCmd === 'string' && rawCmd) {
          const egress = await scanCommandForEgress(rawCmd)
          if (egress.hits.length > 0) {
            const h = egress.hits[0]
            classification.category = 'network'
            classification.forceDeny = true
            classification.reason +=
              ` [static-script-egress: ${egress.hits.length} network hit(s) at ` +
              `${h.where} (${h.language}): ${h.snippet}]`
            if (config.verbose) {
              console.warn(`[tm-guard] STATIC-EGRESS ${toolName}: ${h.where} — ${h.snippet}`)
            }
          } else if (egress.unverifiable) {
            classification.category = 'unknown'
            classification.reason +=
              ' [static-script-egress: dynamic eval/exec/__import__ — cannot verify no network egress]'
          }
        }
      }

      // Config overrides for network/system
      if (!config.denyNetwork && classification.category === 'network') {
        classification.category = 'file_write'
        classification.reason += ' [network denial disabled by config]'
      }
      if (!config.denySystem && classification.category === 'process') {
        classification.category = 'file_write'
        classification.reason += ' [system denial disabled by config]'
      }

      // Check path protection for file writes
      let pathsProtected = true
      if (classification.category === 'file_write' && classification.targetPaths.length > 0) {
        const checks = await Promise.all(
          classification.targetPaths.map((p) =>
            isPathProtected(p, config.protectedPaths),
          ),
        )
        pathsProtected = checks.every(Boolean)
        if (!pathsProtected) {
          const unprotected = classification.targetPaths.filter(
            (_p, i) => !checks[i],
          )
          classification.reason += ` [unprotected: ${unprotected.join(', ')}]`
        }
      }

      const decision: GateDecision = decide(classification, pathsProtected)

      const isTmInternalTool = toolName.startsWith('tm_')
      const isFileWrite = decision.allow && decision.category === 'file_write'
      const isReadOp = decision.category === 'read'

      /*
       * Tool-layer rollback net for file writes. Local git is the PRIMARY
       * mechanism (instant, offline, root-free); ensure a committed baseline
       * exists (auto-create one if needed). Only if git can't be established do
       * we fall back to Time Machine's health as the backstop. A write proceeds
       * as long as ONE of the two nets is in place; if neither is, it is denied.
       */
      let gitNetReady = false
      if (isFileWrite && !isTmInternalTool) {
        const dirs = new Set<string>()
        for (const p of classification.targetPaths) {
          const abs = p.startsWith('/') ? p : resolve(process.cwd(), p)
          dirs.add(dirname(abs))
        }
        if (dirs.size === 0) dirs.add(process.cwd())
        const dirList = [...dirs]
        if (config.requireGitBaseline) {
          const results = await Promise.all(dirList.map((d) => ensureGitBaseline(d)))
          gitNetReady = results.every((r) => r.ok)

          // Precise rollback: commit any pending work as a checkpoint BEFORE
          // the new write, so `git reset --hard` returns to this exact point.
          for (const r of results) {
            if (r.ok && r.root) {
              await commitCheckpoint(r.root, toolName)
            }
          }

          if (config.verbose) {
            for (let i = 0; i < results.length; i++) {
              if (results[i].ok) {
                console.log(`[tm-guard] git baseline ready: ${results[i].root ?? dirList[i]}`)
              } else {
                console.warn(`[tm-guard] git baseline unavailable in ${dirList[i]}: ${results[i].reason} — relying on Time Machine backstop`)
              }
            }
          }
        }
      }

      /* --- Fail-closed: when git net is absent, a write needs a healthy TM backstop --- */
      const needsTmBackstop = isFileWrite && !gitNetReady
      const blockReads = isReadOp && config.failClosedBlockReads
      if (
        config.failClosed &&
        !isTmInternalTool &&
        (needsTmBackstop || blockReads)
      ) {
        const health = await getTmHealth(config.protectedPaths)
        if (!health.healthy) {
          const issueList = health.issues.join('; ')
          const denyReason = gitNetReady === false && isFileWrite
            ? `TM-Guard: no rollback net — a local-git baseline could not be created AND Time Machine is unhealthy (${issueList}). Write denied so the change stays reversible. Fix git or TM (see tm_status), then retry.`
            : `TM-Guard FAIL-CLOSED: Time Machine is unhealthy, operations blocked. Issues: ${issueList}. Run tm_status, fix Time Machine, then retry.`

          if (config.verbose) {
            console.warn(`[tm-guard] FAIL-CLOSED [${decision.category}] ${toolName}: ${issueList}`)
          }
          audit.record({
            tool: toolName,
            category: 'fail-closed',
            decision: 'deny',
            reason: denyReason,
            targetPaths: classification.targetPaths,
            args,
          })
          return { kind: 'deny', reason: denyReason }
        }
      }

      if (config.verbose) {
        const tag = decision.allow ? 'ALLOW' : 'BLOCK'
        console.log(`[tm-guard] ${tag} [${decision.category}] ${toolName}: ${decision.reason}`)
      }

      if (!decision.allow) {
        audit.record({
          tool: toolName,
          category: decision.category,
          decision: 'deny',
          reason: decision.reason,
          targetPaths: classification.targetPaths,
          args,
        })
        return {
          kind: 'deny',
          reason: `TM-Guard: ${decision.reason}`,
        }
      }

      // Pre-mutation checkpoint, enforced at the TOOL layer (the agent cannot
      // bypass this hook). In strict mode it covers file writes AND state-
      // changing local VCS ops (git commit/reset/checkout/clean can discard
      // work); read-only git (status/log/diff) does not need a restore point.
      const isMutation = decision.shouldSnapshot || classification.mutates === true
      let snapshotId: string | undefined
      if (isMutation) {
        if (config.blockingBackupBeforeWrite) {
          // User's chosen mode: a BLOCKING full backup to the TM disk before
          // every state-changing op, so a pre-change backup definitely exists
          // on the backup disk. If the backup COMMAND fails, deny the op
          // (fail-closed). On success we record the matching local snapshot id
          // (listable root-free). NOTE: macOS does not leave the just-finished
          // backup mounted for the shell, and the browsable library is mounted
          // lazily (may lag), so immediate command-line restore from this exact
          // point can briefly need the Time Machine UI / root; it becomes
          // root-free once macOS mounts it.
          try {
            await startBackup(true)
            invalidateHealthCache()
            const snap = await latestSnapshot('/')
            snapshotId = snap?.date
            if (config.verbose) {
              console.log(`[tm-guard] Pre-write blocking backup done (checkpoint ${snapshotId ?? 'unknown'})`)
            }
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err)
            if (config.verbose) {
              console.warn(`[tm-guard] Pre-write blocking backup FAILED: ${msg} — denying write`)
            }
            audit.record({
              tool: toolName, category: 'fail-closed', decision: 'deny',
              reason: `Blocking backup failed: ${msg}`,
              targetPaths: classification.targetPaths, args,
            })
            return {
              kind: 'deny',
              reason: `TM-Guard: a blocking Time Machine backup is required before each write but ` +
                `it failed (${msg}). The write is denied so it stays rollback-able. Check the ` +
                `backup disk (SD) with tm_status, then retry.`,
            }
          }
        } else if (config.snapshotCooldownSeconds >= 0) {
          // Default mode: instant local APFS snapshot (sub-second). Reading it
          // back needs root/the TM UI; completed hourly backups are root-free.
          snapshotId = (await maybeSnapshot(config.snapshotCooldownSeconds)) ?? undefined
          if (snapshotId && config.verbose) {
            console.log(`[tm-guard] Pre-op snapshot created: ${snapshotId}`)
          }
        }
      }

      // Audit the allowed operation
      audit.record({
        tool: toolName,
        category: decision.category,
        decision: 'allow',
        reason: decision.reason,
        targetPaths: classification.targetPaths,
        snapshotId,
        args,
      })

      return next()
    },
    // prepend: run the gate FIRST. If a later gate (e.g. the sandbox
    // escalation policy) would return an 'ask', our deny/allow decision is
    // already made — dangerous ops are denied here before any approval prompt
    // can short-circuit, and only ops we allowed can flow to approval.
    true,
  )

  /* -------------------------------------------------------------- */
  /* Feedback layer 1: turn completion reports                       */
  /* -------------------------------------------------------------- */

  // Track how many audit records have already been consumed by previous
  // reports so each report covers exactly one turn's activity. Initialized to
  // the record count already on disk at boot so a restarted harness does not
  // fold pre-restart history into the first report.
  let lastReportedCount = audit.readAll().length

  ctx.on(
    'agent/turn-stopping',
    async (payload: { agent?: unknown; turn?: number }) => {
      if (!config.turnReports) return
      try {
        const all = audit.readAll()
        const activity = all.slice(lastReportedCount)
        lastReportedCount = all.length

        // Plugin self-test / boot records (explicit-allow) are noise here;
        // report only real gate decisions.
        const real = activity.filter(
          (r) => r.decision === 'allow' || r.decision === 'deny',
        )
        if (real.length === 0) return

        // Best-effort environment context (failures are non-fatal).
        let gitStatus = ''
        try {
          gitStatus = execSync('git status --short', {
            cwd: process.cwd(),
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 8000,
          })
        } catch {
          // Not a git work tree or git missing — omit from report.
        }

        let snapshotCount: number | undefined
        try {
          const out = execSync('tmutil listlocalsnapshots /', {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 8000,
          })
          snapshotCount = out
            .split('\n')
            .filter((l) => l.includes('.local')).length
        } catch {
          // tmutil unavailable — omit from report.
        }

        const report = buildTurnReport({
          turn: payload.turn ?? 0,
          now: new Date().toISOString(),
          cwd: process.cwd(),
          records: real,
          gitStatus,
          snapshotCount,
        })

        // Feedback layer 3: independent acceptance check (artifacts exist,
        // writes inside protected paths, denials left no side effects,
        // rollback net in place). Verdict is appended to the report.
        const verification = verifyTurn({
          records: real,
          artifacts: report.artifacts,
          protectedPaths: config.protectedPaths,
          snapshotCount,
        })

        const reportDir = join(audit.dirPath, 'reports')
        mkdirSync(reportDir, { recursive: true })
        const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
        const file = join(reportDir, `turn-${stamp}.md`)
        writeFileSync(file, `${report.md}\n${verification.markdown}`, 'utf8')

        console.log(`[tm-guard] Turn ${payload.turn ?? 0} report: ${file}`)
        for (const s of report.summary) {
          console.log(`[tm-guard]   ${s}`)
        }
        console.log(
          `[tm-guard]   verification: ${verification.ok ? 'OK (verified)' : 'ISSUES — see report'}`,
        )
      } catch (err) {
        console.warn(
          `[tm-guard] Turn report generation failed: ${err instanceof Error ? err.message : String(err)}`,
        )
      }
    },
  )

  /* -------------------------------------------------------------- */
  /* Zero-intervention auto-approval                                 */
  /* -------------------------------------------------------------- */

  if (config.autoApprove) {
    ctx.on(
      'approval/request',
      // The approval request carries only tool identity, no arguments; that's
      // fine — the prepended pre-execute gate above already classified and
      // allowed/denied the call. Anything reaching this stage was allowed by
      // the gate, so grant it once. Never call next(): the default fallback is
      // 'unavailable' which denies (fail-closed); we answer explicitly.
      (req: { toolName?: string; reason?: string; callId?: unknown }): string => {
        if (config.verbose) {
          console.log(`[tm-guard] AUTO-APPROVE: ${req.toolName ?? 'unknown'}${req.reason ? ` (${req.reason})` : ''}`)
        }
        audit.record({
          tool: req.toolName ?? 'unknown',
          category: 'auto-approve',
          decision: 'allow',
          reason: req.reason ? `auto-approved: ${req.reason}` : 'auto-approved (passed pre-execute gate)',
          targetPaths: [],
        })
        return 'allowed-once'
      },
      true, // prepend: answer before any human-approval listener
    )
  }

  /* -------------------------------------------------------------- */
  /* Registered tools                                               */
  /* -------------------------------------------------------------- */

  // --- tm_snapshot: create a checkpoint ---
  ctx.tools.register(
    defineTool({
      name: 'tm_snapshot',
      description:
        'Create a macOS Time Machine local APFS snapshot as a rollback checkpoint. ' +
        'MANDATORY before making any file modifications. Returns the snapshot date ID. ' +
        'Always pass a descriptive "note" so you can identify this checkpoint later.',
      parameters: {
        note: {
          type: 'string',          description:
            'Label for this checkpoint, e.g. "before-auth-refactor" or "pre-deployment".',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [
          { type: 'text', text: `Time Machine snapshot created: ${value}` },
        ],
      },
      async execute(args: { note?: string }) {
        const date = await createSnapshot()
        lastSnapshotTime = Date.now()
        consecutiveSnapshotFailures = 0
        invalidateHealthCache()
        audit.record({
          tool: 'tm_snapshot',
          category: 'snapshot',
          decision: 'allow',
          reason: `Manual checkpoint${args.note ? ': ' + args.note : ''}`,
          targetPaths: [],
          snapshotId: date,
        })
        return args.note ? `${date} (${args.note})` : date
      },
    }),
  )

  // --- tm_list_snapshots ---
  ctx.tools.register(
    defineTool({
      name: 'tm_list_snapshots',
      description:
        'List all available macOS Time Machine local snapshots with dates. ' +
        'Use to find a rollback point before calling tm_rollback.',
      parameters: {},
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute() {
        const snaps: SnapshotInfo[] = await listSnapshots('/')
        if (snaps.length === 0) return 'No local Time Machine snapshots found.'
        return snaps
          .map((s) => `  ${s.date}  (${s.createdAt.toLocaleString()})`)
          .join('\n')
      },
    }),
  )

  // --- tm_rollback: restore files ---
  ctx.tools.register(
    defineTool({
      name: 'tm_rollback',
      description:
        'Roll back files to a previous Time Machine snapshot state. ' +
        'Use when verification fails and you need to undo changes. ' +
        'Provide either a specific "path" + optional "snapshot_date", ' +
        'or set "last_operation=true" to roll back the most recent file modification ' +
        'recorded in the audit log.',
      parameters: {
        path: {
          type: 'string',          description:
            'Absolute path of the file or directory to restore. ' +
            'Required unless last_operation is true.',
        },
        snapshot_date: {
          type: 'string',          description:
            'Snapshot date string from tm_list_snapshots (e.g. 2026-09-06-120000). ' +
            'Omit to use the latest snapshot.',
        },
        last_operation: {
          type: 'boolean',          description:
            'If true, roll back the paths from the most recent file-modification ' +
            'operation in the audit log. Ignores "path" when set.',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args: {
        path?: string
        snapshot_date?: string
        last_operation?: boolean
      }) {
        // Roll back last operation via audit log
        if (args.last_operation) {
          const writes = audit.writeOperations()
          if (writes.length === 0) {
            return 'No file-modification operations found in audit log. Nothing to roll back.'
          }
          const lastWrite = writes[writes.length - 1]
          const paths = lastWrite.targetPaths
          if (paths.length === 0) {
            return `Last operation (${lastWrite.tool}) had no target paths recorded. ` +
              `Use tm_rollback with an explicit path instead.`
          }
          // Prefer the restore point from a completed blocking tm_backup
          // (root-free, browsable). The localsnapshot id on a write is not
          // readable without sudo, so the backup point is what actually works.
          const backupPoint = audit
            .readAll()
            .filter((r) => r.tool === 'tm_backup' && r.snapshotId)
            .pop()?.snapshotId
          const snapDate = backupPoint ?? args.snapshot_date ?? lastWrite.snapshotId
          const results: RollbackResult[] = await rollbackPaths(paths, snapDate)
          const summary = results
            .map((r) => `  ${r.success ? 'OK' : 'FAIL'}: ${r.message}`)
            .join('\n')
          audit.record({
            tool: 'tm_rollback',
            category: 'rollback',
            decision: 'allow',
            reason: `Rolled back last operation (${lastWrite.tool})`,
            targetPaths: paths,
            snapshotId: snapDate,
          })
          return `Rolled back ${paths.length} path(s) from last operation:\n${summary}`
        }

        // Roll back explicit path
        if (!args.path) {
          return 'Error: either "path" or "last_operation=true" must be provided.'
        }
        const result: RollbackResult = await rollbackPath(
          args.path,
          args.snapshot_date,
        )
        audit.record({
          tool: 'tm_rollback',
          category: 'rollback',
          decision: 'allow',
          reason: result.message,
          targetPaths: [args.path],
          snapshotId: result.snapshotUsed,
        })
        return result.message
      },
    }),
  )

  // --- tm_audit: review operation history ---
  ctx.tools.register(
    defineTool({
      name: 'tm_audit',
      description:
        'Review the TM-Guard audit log — every tool call that was allowed or blocked, ' +
        'with target paths and snapshot IDs. Use to trace what changes were made, ' +
        'find the snapshot ID for a specific operation, or verify what was blocked.',
      parameters: {
        limit: {
          type: 'number',          description:
            'Number of recent records to show (default 20, max 100).',
        },
        only_writes: {
          type: 'boolean',          description:
            'If true, only show file-modification operations (for rollback targeting).',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args: { limit?: number; only_writes?: boolean }) {
        const limit = Math.min(args.limit ?? 20, 100)
        const records = args.only_writes
          ? audit.writeOperations().slice(-limit)
          : audit.recent(limit)

        if (records.length === 0) {
          return 'No audit records found.'
        }

        const lines = records.map((r) => {
          const time = new Date(r.ts).toLocaleTimeString()
          const decision = r.decision === 'allow' ? 'ALLOW' : 'BLOCK'
          const paths = r.targetPaths.length > 0
            ? ` [${r.targetPaths.join(', ')}]`
            : ''
          const snap = r.snapshotId ? ` snap=${r.snapshotId}` : ''
          return `  ${time} ${decision} [${r.category}] ${r.tool}${paths}${snap}`
        })

        const header = `=== TM-Guard Audit Log (${records.length} records, log: ${audit.path}) ===`
        return `${header}\n${lines.join('\n')}`
      },
    }),
  )

  // --- tm_status: system health check ---
  ctx.tools.register(
    defineTool({
      name: 'tm_status',
      description:
        'Check Time Machine configuration, available snapshots, workspace protection ' +
        'status, and current TM-Guard policy. Run this first to confirm the safety net is active.',
      parameters: {},
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute() {
        const status = await getTmStatus()
        const latest = await latestSnapshot('/')
        const health = await getTmHealth(config.protectedPaths, true)
        const auditCount = audit.readAll().length
        const writeCount = audit.writeOperations().length

        const lines = [
          '=== TM-Guard Status ===',
          '',
          `TM Health (fail-closed)  : ${health.healthy ? 'HEALTHY ✅' : 'UNHEALTHY 🚫 — writes BLOCKED'}`,
        ]
        if (!health.healthy) {
          for (const issue of health.issues) {
            lines.push(`  ⚠️  ${issue}`)
          }
        }
        lines.push(
          '',
          `Time Machine destination : ${status.destinationConfigured ? 'configured' : 'NOT configured ⚠️'}`,
          `Local snapshots          : ${status.snapshotCount} available`,
          `Latest snapshot          : ${latest ? latest.date + ' (' + latest.createdAt.toLocaleString() + ')' : 'none ⚠️'}`,
          `Workspace                : ${process.cwd()}`,
          `Workspace protected      : ${health.workspaceProtected ? 'YES ✅' : 'NO ⚠️'}`,
          `Protected path prefixes  : ${config.protectedPaths.join(', ')}`,
          `Sensitive read paths     : ${config.denyReadPaths.join(', ') || '(none)'}`,
          '',
          `Snapshot cooldown        : ${config.snapshotCooldownSeconds}s`,
          `Network ops              : ${config.denyNetwork ? 'BLOCKED' : 'allowed'}`,
          `System/process ops       : ${config.denySystem ? 'BLOCKED' : 'allowed'}`,
          `Fail-closed              : ${config.failClosed ? 'YES (block writes if TM unhealthy)' : 'no'}`,
          `Require task snapshot    : ${config.requireTaskSnapshot ? 'YES' : 'no'}`,
          `Audit log                : ${auditCount} records (${writeCount} write ops) at ${audit.path}`,
          `Health checked at        : ${health.checkedAt.toLocaleString()}`,
        )
        return lines.join('\n')
      },
    }),
  )

  // --- tm_backup: trigger a backup to the TM disk (SD) ---
  ctx.tools.register(
    defineTool({
      name: 'tm_backup',
      description:
        'Start a Time Machine backup to the configured backup disk (e.g. the SD card). ' +
        'Finishing a backup creates a fresh, browsable restore point — call this after a ' +
        'batch of changes if you want a newer rollback point than the hourly automatic one. ' +
        'By default starts in the BACKGROUND and returns immediately; set wait=true to block ' +
        'until the backup completes (may take minutes).',
      parameters: {
        wait: {
          type: 'boolean',
          description:
            'If true, block until the backup finishes before returning. Default false (fire and forget).',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args: { wait?: boolean }) {
        const wait = args.wait === true
        try {
          await startBackup(wait)
          if (wait) {
            invalidateHealthCache()
            const snap = await latestSnapshot('/')
            const restoreId = snap?.date
            audit.record({
              tool: 'tm_backup',
              category: 'snapshot',
              decision: 'allow',
              reason: 'Blocking backup completed — rollback restore point',
              targetPaths: [],
              snapshotId: restoreId,
            })
            return restoreId
              ? `Time Machine backup completed. Checkpoint: ${restoreId} (on the backup disk). ` +
                `You can now modify files. If verification fails, call tm_rollback to recover; command-line ` +
                `restore from this exact point may briefly need the Time Machine UI (macOS mounts completed ` +
                `backups lazily), after which it is root-free.`
              : 'Time Machine backup completed. Use tm_list_snapshots / tm_audit to find a point to roll back to.'
          }
          audit.record({
            tool: 'tm_backup',
            category: 'snapshot',
            decision: 'allow',
            reason: 'Backup triggered (background)',
            targetPaths: [],
          })
          return 'Time Machine backup started in the background. Use tm_backup_status to watch progress; ' +
            'a browsable restore point appears once it finishes (then tm_rollback can use it).'
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          audit.record({
            tool: 'tm_backup',
            category: 'snapshot',
            decision: 'allow',
            reason: `Backup trigger failed: ${msg}`,
            targetPaths: [],
          })
          return `Failed to start Time Machine backup: ${msg}. Check the backup disk (SD) is connected (see tm_status).`
        }
      },
    }),
  )

  // --- tm_backup_status: backup progress ---
  ctx.tools.register(
    defineTool({
      name: 'tm_backup_status',
      description:
        'Show the current Time Machine backup progress — whether a backup is running, ' +
        'the percent complete, and the current phase. Use after tm_backup to confirm it finished.',
      parameters: {},
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute() {
        try {
          const st = await getBackupStatus()
          audit.record({
            tool: 'tm_backup_status',
            category: 'read',
            decision: 'allow',
            reason: `Backup status: running=${st.running}`,
            targetPaths: [],
          })
          if (st.running) {
            const pct = st.percent >= 0 ? `${st.percent}%` : 'progress unknown'
            const phase = st.phase ? `, phase: ${st.phase}` : ''
            return `Backup in progress: ${pct}${phase}.`
          }
          return 'No backup currently running. The last backup has completed (a browsable restore point is available).'
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          return `Could not read backup status: ${msg}`
        }
      },
    }),
  )

  if (config.verbose) {
    console.log(
      `[tm-guard] Loaded. Protected paths: ${config.protectedPaths.join(', ')}. ` +
      `Audit log: ${audit.path}. ` +
      `Deny-read paths: ${config.denyReadPaths.join(', ') || '(none)'}`,
    )
  }
}
