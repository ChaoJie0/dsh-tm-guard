/**
 * dsh-agent-flow-viz — real-time Agent tool-call flow visualizer.
 *
 * Monitoring-only MVP. It never allows or denies anything: both event hooks
 * observe the call and pass straight through to `next()`. It records:
 *
 *   - tools/pre-execute  → open a "running" node (tool name + args summary)
 *   - tools/post-execute → settle that node (success / error + duration)
 *
 * and serves a live canvas at http://127.0.0.1:<port> (default 3100).
 *
 * Extension points used:
 *   - ctx.on('tools/pre-execute',  observer)
 *   - ctx.on('tools/post-execute', observer)
 */

import type { Context } from '@deepseek-ai/cordis'
import type {
  ToolExecution,
  ToolExecutionResult,
  PreToolDecision,
  PostToolDecision,
} from '@deepseek-ai/dsh-tools'

import { CallStore, summarizeArgs, summarizeResult } from './store.ts'
import { startServer, type VizServerHandle } from './server.ts'

/* ------------------------------------------------------------------ */
/* Plugin configuration                                                */
/* ------------------------------------------------------------------ */

export interface AgentFlowVizConfig {
  /** HTTP port for the local visualization panel. Default 3100. */
  port: number
  /** Log the panel URL and lifecycle events to the harness console. */
  verbose: boolean
  /**
   * Tool names to ignore entirely (no node is drawn). Useful for hiding
   * very chatty internal tools. Defaults to an empty list.
   */
  ignoreTools: string[]
}

const DEFAULT_CONFIG: AgentFlowVizConfig = {
  port: 3100,
  verbose: true,
  ignoreTools: [],
}

/* ------------------------------------------------------------------ */
/* Plugin definition                                                   */
/* ------------------------------------------------------------------ */

export const name = 'agent-flow-viz'
export const inject = ['tools']

export function apply(ctx: Context, rawConfig?: Partial<AgentFlowVizConfig>) {
  const config: AgentFlowVizConfig = { ...DEFAULT_CONFIG, ...rawConfig }
  const store = new CallStore()
  const ignore = new Set(config.ignoreTools)

  let server: VizServerHandle | null = null

  // Start the panel asynchronously; a busy port must not crash plugin load.
  startServer(store, config.port)
    .then((handle) => {
      // If the fiber already unloaded while binding, shut it back down.
      if (disposed) {
        void handle.close()
        return
      }
      server = handle
      if (config.verbose) {
        console.log(`[agent-flow-viz] Panel ready at http://127.0.0.1:${handle.port}`)
      }
    })
    .catch((err) => {
      console.warn(
        `[agent-flow-viz] Failed to start panel on port ${config.port}: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      )
    })

  // Close the HTTP server when the plugin fiber unloads. ctx.effect runs the
  // returned disposer automatically on teardown (and HMR reload).
  let disposed = false
  ctx.effect(() => () => {
    disposed = true
    if (server) void server.close()
  })

  /* ---------------- pre-execute: open a running node ---------------- */

  ctx.on(
    'tools/pre-execute',
    async (
      exec: ToolExecution,
      next: () => Promise<PreToolDecision>,
    ): Promise<PreToolDecision> => {
      try {
        const tool = exec.name ?? 'unknown'
        if (!ignore.has(tool)) {
          const { preview, json } = summarizeArgs(exec.arguments)
          store.recordStart({
            id: String(exec.callId),
            tool,
            argsPreview: preview,
            argsJson: json,
            startedAt: Date.now(),
          })
        }
      } catch {
        // Visualization must never interfere with the call.
      }
      return next()
    },
  )

  /* ---------------- post-execute: settle the node ------------------- */

  ctx.on(
    'tools/post-execute',
    async (
      exec: ToolExecution,
      result: Readonly<ToolExecutionResult>,
      next: () => Promise<PostToolDecision>,
    ): Promise<PostToolDecision> => {
      try {
        const tool = exec.name ?? 'unknown'
        if (!ignore.has(tool)) {
          const { preview, error } = summarizeResult(result)
          store.recordEnd(String(exec.callId), {
            status: result.isError ? 'error' : 'success',
            error,
            resultPreview: preview,
          })
        }
      } catch {
        // Never interfere with the pipeline.
      }
      return next()
    },
  )

  /* ---------------- teardown ---------------------------------------- */

  ctx.on('dispose', () => {
    stopped = true
    if (server) void server.close()
  })

  if (config.verbose) {
    console.log(
      `[agent-flow-viz] Loaded. Starting visualization panel on port ${config.port}…`,
    )
  }
}
