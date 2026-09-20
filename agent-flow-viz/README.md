# dsh-agent-flow-viz

Real-time **Agent tool-call flow visualizer** for [DeepSeek Harness (dsh)](https://www.npmjs.com/package/@deepseek-ai/dsh).

It is a read-only monitoring plugin: it listens to the harness tool pipeline and
renders every tool call as a node on a local web canvas, in call order, with
live **running / success / error** status, duration, arguments and result
preview. It never allows, denies or modifies a call.

![flow](https://img.shields.io/badge/dsh--plugin-agent--flow--viz-38bdf8)

## How it works

| Harness event | What the plugin records |
| --- | --- |
| `tools/pre-execute`  | opens a **running** node: tool name, argument summary, start time |
| `tools/post-execute` | settles the node: **success / error**, duration, error/result preview |

The panel polls a small local Express API (long-polling) and redraws an SVG
timeline of connected nodes. Click a node to inspect its full arguments and
result in the side panel.

- Binds **127.0.0.1 only** (default port `3100`) — tool arguments can contain
  sensitive values, so the panel is never exposed on the network.
- In-memory ring buffer (last 1000 calls); nothing is persisted to disk.

## Install

```bash
cd agent-flow-viz
npm install        # installs express
npm run build      # src/*.ts -> lib/*.js (Node strip-types; Node >= 22.6)
```

> The dsh Host loads TypeScript directly, so `npm run build` is optional for
> source-loading — but `npm install` is required so `express` resolves.

## Load it in dsh

### Option A — direct source load (development)

Point a patch file at the absolute source path, e.g. `agent-flow-viz.local.yml`:

```yaml
- insert:
    - id: agent-flow-viz
      name: '/absolute/path/to/agent-flow-viz/src/index.ts'
      config:
        port: 3100
        verbose: true
        ignoreTools: []
```

Then run:

```bash
dsh web --patch "/absolute/path/to/agent-flow-viz.local.yml"
```

### Option B — installed bundle

```bash
dsh plugin --profile <name> add dsh-agent-flow-viz
```

The shipped `cordis.patch.yml` registers the plugin by package name.

Open **http://127.0.0.1:3100** in a browser. As the agent calls tools, nodes
stream onto the canvas top-to-bottom in call order.

## Preview the UI without dsh

A standalone dev server seeds a handful of demo calls:

```bash
npm install && npm run build
npm run start:server          # http://127.0.0.1:3100
PORT=3200 npm run start:server
```

## Configuration

| Key           | Type       | Default | Description |
| ------------- | ---------- | ------- | ----------- |
| `port`        | `number`   | `3100`  | Local panel HTTP port. |
| `verbose`     | `boolean`  | `true`  | Log the panel URL / lifecycle to the harness console. |
| `ignoreTools` | `string[]` | `[]`    | Tool names that should not produce a node. |

## HTTP API

| Method | Path | Description |
| --- | --- | --- |
| `GET`  | `/api/health` | Liveness + current buffer version. |
| `GET`  | `/api/events` | Full snapshot `{ version, calls[] }`. |
| `GET`  | `/api/events?since=N` | Long-poll; resolves when `version > N` (25 s timeout). |
| `POST` | `/api/clear` | Reset the in-memory buffer. |

## Layout

```
agent-flow-viz/
├── src/
│   ├── index.ts     # Cordis plugin: pre/post-execute hooks
│   ├── server.ts    # Express API + static panel
│   └── store.ts     # In-memory call recorder + arg/result summarizers
├── public/
│   └── index.html   # Self-contained SVG node-flow UI (no build step)
├── scripts/
│   ├── build/build.mjs     # Zero-dep TypeScript -> lib build
│   └── run-server.mjs      # Standalone demo server
├── cordis.patch.yml
├── package.json
└── README.md
```

## Roadmap (post-MVP)

- Parent/child edges for sub-agent and nested tool dispatches (`rootCallId`).
- Parallel-execution lanes and zoom/pan over a large graph.
- WebSocket push instead of long-polling.
- Optional JSONL persistence and per-turn grouping.
- Argument/result diffing and search/filter by tool or status.

## License

MIT
