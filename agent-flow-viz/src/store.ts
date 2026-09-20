/**
 * agent-flow-viz — in-memory call recorder.
 *
 * A tiny ring buffer of every observed tool call. The Cordis plugin writes
 * here from tools/pre-execute (open) and tools/post-execute (settle); the
 * Express server reads from here to serve /api/events and long-poll clients.
 *
 * No persistence on purpose — this is the monitoring MVP. A bounded buffer
 * keeps a long-running session from growing without limit.
 */

export type CallStatus = 'running' | 'success' | 'error'

export interface FlowCall {
  /** Stable per-call id (we derive it from the registry callId). */
  id: string
  /** Tool name, e.g. "bash", "read". */
  tool: string
  /** Short, single-line argument preview for the node card. */
  argsPreview: string
  /** Truncated JSON of the arguments for the detail panel. */
  argsJson: string
  /** epoch ms when pre-execute fired. */
  startedAt: number
  /** epoch ms when post-execute fired (undefined while running). */
  endedAt?: number
  /** Duration in ms (undefined while running). */
  durationMs?: number
  status: CallStatus
  /** Error message when status === 'error'. */
  error?: string
  /** Short preview of the successful/result content. */
  resultPreview?: string
}

export interface FlowSnapshot {
  calls: FlowCall[]
  /** Monotonic version; bumps on every mutation so clients can long-poll. */
  version: number
}

const MAX_CALLS = 1000
const PREVIEW_LIMIT = 160

/** Make a compact, safe one-line summary of arbitrary tool arguments. */
export function summarizeArgs(args: unknown): { preview: string; json: string } {
  let json = ''
  try {
    json = JSON.stringify(args) ?? ''
  } catch {
    json = String(args)
  }

  // Pick a human-meaningful field for the headline, falling back to the JSON.
  let preview = ''
  if (args && typeof args === 'object') {
    const a = args as Record<string, unknown>
    const key = ['command', 'cmd', 'input', 'file_path', 'path', 'pattern', 'url', 'query', 'description', 'name', 'prompt']
      .find((k) => typeof a[k] === 'string' && (a[k] as string).length > 0)
    if (key) preview = String(a[key])
  }
  if (!preview) preview = json

  preview = preview.replace(/\s+/g, ' ').trim()
  if (preview.length > PREVIEW_LIMIT) preview = preview.slice(0, PREVIEW_LIMIT) + '…'
  return { preview: preview || '(no arguments)', json }
}

/** Pull a short, safe preview out of a post-execute result. */
export function summarizeResult(result: unknown): { preview: string; error?: string } {
  const r = (result ?? {}) as Record<string, unknown>
  if (r.isError === true) {
    const err = r.error
    let message = 'tool error'
    if (typeof err === 'string') message = err
    else if (err && typeof err === 'object') {
      const e = err as Record<string, unknown>
      message = String(e.message ?? e.name ?? JSON.stringify(err))
    }
    return { preview: '', error: message.slice(0, PREVIEW_LIMIT) }
  }
  // Success — prefer rendered content text, else the canonical value.
  let text = ''
  const content = r.content
  if (Array.isArray(content)) {
    text = content
      .map((b) => {
        const block = (b ?? {}) as Record<string, unknown>
        return typeof block.text === 'string' ? block.text : ''
      })
      .filter(Boolean)
      .join(' ')
  }
  if (!text && r.value !== undefined) {
    try {
      text = typeof r.value === 'string' ? r.value : JSON.stringify(r.value)
    } catch {
      text = String(r.value)
    }
  }
  text = text.replace(/\s+/g, ' ').trim()
  if (text.length > PREVIEW_LIMIT) text = text.slice(0, PREVIEW_LIMIT) + '…'
  return { preview: text }
}

export class CallStore {
  private calls: FlowCall[] = []
  private version = 0
  /** Long-poll waiters notified on every mutation. */
  private waiters = new Set<() => void>()

  recordStart(call: Omit<FlowCall, 'status'>): void {
    this.calls.push({ ...call, status: 'running' })
    if (this.calls.length > MAX_CALLS) this.calls.shift()
    this.bump()
  }

  recordEnd(
    id: string,
    outcome: { status: 'success' | 'error'; error?: string; resultPreview?: string },
  ): void {
    const call = this.calls.find((c) => c.id === id)
    if (!call) return
    call.status = outcome.status
    call.endedAt = Date.now()
    call.durationMs = call.endedAt - call.startedAt
    call.error = outcome.error
    call.resultPreview = outcome.resultPreview
    this.bump()
  }

  /** Snapshot for the API. Returns a shallow copy safe to serialize. */
  snapshot(): FlowSnapshot {
    return { version: this.version, calls: this.calls.slice() }
  }

  /** @returns version >= since, or null if it would resolve immediately. */
  waitForChange(since: number, timeoutMs: number): Promise<number | null> {
    if (this.version > since) return Promise.resolve(this.version)
    return new Promise((resolve) => {
      let done = false
      const finish = (val: number | null) => {
        if (done) return
        done = true
        this.waiters.delete(wake)
        clearTimeout(timer)
        resolve(val)
      }
      const wake = () => finish(this.version > since ? this.version : null)
      const timer = setTimeout(() => finish(null), timeoutMs)
      this.waiters.add(wake)
    })
  }

  clear(): void {
    this.calls = []
    this.bump()
  }

  private bump(): void {
    this.version++
    for (const wake of this.waiters) wake()
  }
}
