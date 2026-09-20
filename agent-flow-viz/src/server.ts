/**
 * agent-flow-viz — local visualization server.
 *
 * A minimal Express app that:
 *   - serves the single-page canvas UI from ../public
 *   - GET  /api/events          → current snapshot { version, calls }
 *   - GET  /api/events?since=N  → long-poll, resolves when version > N
 *   - POST /api/clear           → reset the buffer (dev convenience)
 *
 * The server binds 127.0.0.1 only — the data shown includes real tool
 * arguments and result previews, so it must never be exposed on a LAN.
 */

import express from 'express'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Server } from 'node:http'
import { type CallStore } from './store.ts'

export interface VizServerHandle {
  port: number
  close: () => Promise<void>
}

const here = dirname(fileURLToPath(import.meta.url))
// lib/server.js → ../public ; src/server.ts (strip-types dev) → ../public too.
const PUBLIC_DIR = join(here, '..', 'public')

export function startServer(store: CallStore, port = 3100): Promise<VizServerHandle> {
  const app = express()
  app.use(express.json({ limit: '1mb' }))

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, version: store.snapshot().version })
  })

  app.get('/api/events', async (req, res) => {
    const since = Number(req.query.since ?? 0)
    // Long-poll: hold up to 25s for a change; otherwise return current state.
    if (Number.isFinite(since) && since > 0) {
      await store.waitForChange(since, 25_000)
    }
    res.json(store.snapshot())
  })

  app.post('/api/clear', (_req, res) => {
    store.clear()
    res.json({ ok: true })
  })

  app.use(express.static(PUBLIC_DIR))

  return new Promise((resolve, reject) => {
    const server: Server = app.listen(port, '127.0.0.1', () => {
      resolve({
        port,
        close: () =>
          new Promise<void>((r, rej) =>
            server.close((err) => (err ? rej(err) : r())),
          ),
      })
    })
    server.on('error', reject)
  })
}
