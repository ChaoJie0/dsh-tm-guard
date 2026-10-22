#!/usr/bin/env bash
# L4 isolated host smoke harness — hard-isolated dsh profile + separate host
# on a non-production port, then collects live evidence.
#
# Scope (matches TESTING.md L4 hard-isolation rules):
#   - own profile dir under $DSH_HOME/profiles/<name>, only this plugin mounted
#   - own non-production port (3080 production must stay untouched)
#   - own cwd/workspace; audit lands at <cwd>/.tm-guard, never production audit
#   - protectedPaths points only at the isolated workspace
#   - no copied ark baseURL/apiKey; the instance inherits its default model
#
# This script PREPARES the environment and COLLECTS evidence. It cannot drive a
# model turn (the host has no unary tool-execute channel) and does NOT declare
# PASS; the turn commands, live BLOCK observation, and final verdict stay manual.
#
# Usage:
#   scripts/l4-isolated-smoke.sh setup   --version <ver> --tgz <file.tgz> [opts]
#   scripts/l4-isolated-smoke.sh start   --profile <name> --port <p> --workspace <dir>
#   scripts/l4-isolated-smoke.sh collect --profile <name> --port <p> --workspace <dir>
#   scripts/l4-isolated-smoke.sh stop    --profile <name>
#
# Common opts:
#   --profile <name>      profile under $DSH_HOME/profiles (default tm-live)
#   --port <p>            isolated port; must not be 3080 (default 3091)
#   --workspace <dir>     isolated cwd under $HOME (default ~/dsh-live/<profile>)
#   --base-ver <ver>      dsh-base / dsh-web-app version (default 0.2.0-rc.2)
set -euo pipefail

DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
PROFILES_DIR="$DSH_HOME/profiles"
PROD_PORT=3080
DEFAULT_BASE_VER="0.2.0-rc.2"

PROFILE="tm-live"
PORT="3091"
WORKSPACE=""
VERSION=""
TGZ=""
BASE_VER="$DEFAULT_BASE_VER"
NO_INSTALL=""
CMD=""

# Standard deny-read set copied from the verified isolated patch (tm-live-028).
DENY_READ=(
  '~/.ssh' '~/.aws' '~/.gnupg' '~/.kube' '~/.docker'
  '~/.netrc' '~/.git-credentials' '~/.npmrc' '~/.pypirc'
  '~/.config' '~/Library/Keychains' '~/Library/Cookies'
)

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[l4] $*"; }

need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

parse() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --profile) [ $# -ge 2 ] || die "--profile requires a name"; PROFILE="$2"; shift 2 ;;
      --port) [ $# -ge 2 ] || die "--port requires a number"; PORT="$2"; shift 2 ;;
      --workspace) [ $# -ge 2 ] || die "--workspace requires a path"; WORKSPACE="$2"; shift 2 ;;
      --version) [ $# -ge 2 ] || die "--version requires a value"; VERSION="$2"; shift 2 ;;
      --tgz) [ $# -ge 2 ] || die "--tgz requires a path"; TGZ="$2"; shift 2 ;;
      --base-ver) [ $# -ge 2 ] || die "--base-ver requires a value"; BASE_VER="$2"; shift 2 ;;
      --no-install) NO_INSTALL=1; shift ;;
      *) die "unknown arg: $1" ;;
    esac
  done
}

# Canonicalize the isolated workspace: reject traversal/symlink escape BEFORE
# comparing, so a lexical glob cannot be bypassed with '..' or a symlink.
normalize_workspace() {
  [ -n "$WORKSPACE" ] || die "--workspace required"
  case "$WORKSPACE" in *..*) die "no '..' in --workspace: $WORKSPACE" ;; esac
  # Expand a leading '~' to $HOME before resolving.
  case "$WORKSPACE" in "~"/*) WORKSPACE="$HOME/${WORKSPACE#'~/'}" ;; esac
  mkdir -p "$WORKSPACE" 2>/dev/null || true
  local real realhome
  real="$(cd -P "$WORKSPACE" 2>/dev/null && pwd -P)" || die "workspace not resolvable: $WORKSPACE"
  realhome="$(cd -P "$HOME" 2>/dev/null && pwd -P || echo "$HOME")"
  case "$real" in
    "$realhome"/*|"$HOME"/*) ;;
    *) die "resolved workspace not under \$HOME: $real" ;;
  esac
  # $TMPDIR (/private/var/folders) and /tmp are Time-Machine [Excluded]; reject the
  # resolved path (covers symlinks and '..' that land there).
  case "$real" in
    /tmp/*|/private/tmp/*|/var/folders/*|/private/var/folders/*)
      die "workspace resolves into a TM-[Excluded] area: $real" ;;
  esac
  # Resolved path must not alias a real project / DSH_Work / study tree.
  case "$real" in
    *Self_Work*|*DSH_Work*|*"Claude Code"*|*Study*)
      die "workspace resolves to a real project; keep it isolated: $real" ;;
  esac
  WORKSPACE="$real"
}

# Fail-closed isolation guards shared by setup/start/collect.
guard_isolation() {
  [ "$PORT" != "$PROD_PORT" ] || die "refusing production port $PROD_PORT"
  case "$PORT" in (*[!0-9]*) die "port must be numeric: $PORT" ;; esac
  normalize_workspace
}

# Production 3080 pid captured before we touch anything; must be identical after.
prod_pid() {
  lsof -tiTCP:"$PROD_PORT" -sTCP:LISTEN 2>/dev/null | head -1 || true
}

cmd_setup() {
  [ -n "$VERSION" ] || die "setup requires --version <ver>"
  [ -n "$TGZ" ] || die "setup requires --tgz <file.tgz>"
  [ -f "$TGZ" ] || die "tgz not found: $TGZ"
  case "$TGZ" in (/*) ;; *) die "tgz must be an absolute path: $TGZ" ;; esac
  WORKSPACE="${WORKSPACE:-$HOME/dsh-live/$PROFILE/workspace}"

  local pdir="$PROFILES_DIR/$PROFILE"

  # Never clobber a shipped/reserved profile or silently overwrite an existing
  # one — checked BEFORE guard_isolation (which mkdirs the workspace) so a
  # rejected profile leaves no stray directory and touches no existing file.
  case "$PROFILE" in
    web|desktop|default|headless|acp|sdk|sdk-minimal|node_modules)
      die "reserved/shipped profile name, refusing to overwrite: $PROFILE" ;;
  esac
  if [ -e "$pdir/package.json" ] || [ -e "$pdir/cordis.patch.yml" ]; then
    die "profile $PROFILE already exists at $pdir; reuse it or pass a fresh name (no silent overwrite)"
  fi

  guard_isolation
  mkdir -p "$WORKSPACE" "$pdir"

  info "profile  = $pdir"
  info "workspace= $WORKSPACE"
  info "port     = $PORT (production $PROD_PORT pid: $(prod_pid || echo none))"

  cat > "$pdir/package.json" <<EOF
{
  "name": "dsh-profile-$PROFILE",
  "private": true,
  "dependencies": {
    "@deepseek-ai/dsh-base": "$BASE_VER",
    "@deepseek-ai/dsh-web-app": "$BASE_VER",
    "dsh-tm-guard": "file:$TGZ"
  },
  "dsh": {
    "profile": {
      "bundles": [
        "@deepseek-ai/dsh-base",
        "@deepseek-ai/dsh-web-app",
        "dsh-tm-guard"
      ],
      "patchReload": "live"
    }
  }
}
EOF

  cat > "$pdir/cordis.patch.yml" <<EOF
# Isolated L4 live-smoke patch for dsh-tm-guard $VERSION (profile $PROFILE).
# Only tm-guard is mounted; no production patch and no copied model credentials.
- id: tm-guard
  config:
    protectedPaths:
      - '$WORKSPACE'
    extraAllowTools:
      - 'guard_check'
      - 'guard_list'
      - 'when'
      - 'web_search'
      - 'web_fetch'
      - 'skill'
      - 'job_kill'
      - 'todo_write'
    denyReadPaths:
$(printf "      - '%s'\n" "${DENY_READ[@]}")
    turnReports: true
    snapshotCooldownSeconds: 30
    denyNetwork: true
    denySystem: true
    requireTaskSnapshot: true
    failClosed: true
    failClosedBlockReads: false
    verbose: true
EOF

  cat > "$pdir/pnpm-workspace.yaml" <<'EOF'
allowBuilds:
  '@deepseek-ai/dsh-subprocess-local': true
  '@google/genai': true
  koffi: true
  node-pty: true
  protobufjs: true
EOF

  # No secret leak guard on the generated patch itself.
  if grep -qE "baseURL|apiKey|sk-|Bearer " "$pdir/cordis.patch.yml"; then
    die "generated patch contains a credential field; abort"
  fi

  if [ -n "$NO_INSTALL" ]; then
    info "--no-install: skipped pnpm install, version check, git baseline (config-only dry run)"
  else
    info "installing profile deps (pnpm)..."
    need pnpm
    (cd "$pdir" && pnpm install --prefer-offline)

    # Verify installed bundle version matches the requested version.
    local installed
    installed="$(node -p "require('$pdir/node_modules/dsh-tm-guard/package.json').version" 2>/dev/null || echo unknown)"
    [ "$installed" = "$VERSION" ] || die "installed tm-guard $installed != requested $VERSION"
    info "installed dsh-tm-guard $installed"

    # Fresh git baseline in the isolated workspace (checkpoint recovery target).
    (cd "$WORKSPACE" && git init -q 2>/dev/null || true
     git -C "$WORKSPACE" config user.email l4@local 2>/dev/null || true
     git -C "$WORKSPACE" config user.name l4 2>/dev/null || true
     [ -f "$WORKSPACE/.gitignore" ] || printf '# L4 scratch\n' > "$WORKSPACE/.gitignore")
  fi

  cat <<EOF

SETUP READY. Start the isolated host with:
  scripts/l4-isolated-smoke.sh start --profile $PROFILE --port $PORT --workspace $WORKSPACE

Then open the printed URL and run ONE minimal turn with these three requests:
  1) read-only allow : ls
  2) sensitive deny  : cat ~/.ssh/config
  3) recoverable write: rm <an untracked file you create in the workspace>
Plus this version's own forked destructive command as the release-specific case.
EOF
}

cmd_start() {
  WORKSPACE="${WORKSPACE:-$HOME/dsh-live/$PROFILE/workspace}"
  guard_isolation
  need dsh
  local pdir="$PROFILES_DIR/$PROFILE"
  [ -d "$pdir" ] || die "profile not set up; run setup first: $pdir"

  # Reject an already-busy isolated port before launch (clean fail-closed message).
  if lsof -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    die "port $PORT already in use; pick another free port"
  fi

  local log="$HOME/dsh-live/$PROFILE/host.log"
  mkdir -p "$(dirname "$log")"
  local before_pid; before_pid="$(prod_pid)"

  info "starting isolated host profile=$PROFILE port=$PORT (prod $PROD_PORT pid=${before_pid:-none})"
  # cwd = isolated workspace so audit lands at <cwd>/.tm-guard
  (cd "$WORKSPACE" && nohup dsh --profile "$PROFILE" --no-open --port "$PORT" \
      >"$log" 2>&1 & echo $! > "$HOME/dsh-live/$PROFILE/host.pid")

  # Poll for BOTH Loaded and TM health (do not sleep blindly).
  local i=0
  while [ "$i" -lt 60 ]; do
    if grep -q "TM health check passed" "$log" 2>/dev/null && grep -q "\[tm-guard\] Loaded" "$log" 2>/dev/null; then
      break
    fi
    sleep 1; i=$((i+1))
  done
  grep -E "\[tm-guard\] Loaded|TM health check passed|dsh web: http" "$log" 2>/dev/null || true

  local after_pid; after_pid="$(prod_pid)"
  if [ -n "$before_pid" ] && [ "$before_pid" != "$after_pid" ]; then
    die "production $PROD_PORT pid changed ($before_pid -> $after_pid)! abort"
  fi

  # Hard readiness gate: require Loaded, TM health, and an actual bind on $PORT.
  grep -q "\[tm-guard\] Loaded" "$log" || die "isolated host did not load tm-guard; see $log"
  grep -q "TM health check passed" "$log" || die "TM health check never passed; see $log"
  lsof -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1 || die "host did not bind $PORT; see $log"

  if [ -n "$before_pid" ]; then
    info "production $PROD_PORT unchanged (pid $after_pid)"
  else
    info "production $PROD_PORT was not running at start (nothing to perturb)"
  fi
  info "isolated host listening on $PORT; log: $log"
}

cmd_collect() {
  WORKSPACE="${WORKSPACE:-$HOME/dsh-live/$PROFILE/workspace}"
  guard_isolation
  local pdir="$PROFILES_DIR/$PROFILE"
  local log="$HOME/dsh-live/$PROFILE/host.log"

  echo "=== installed bundle version ==="
  node -p "require('$pdir/node_modules/dsh-tm-guard/package.json').version" 2>/dev/null || echo unknown
  echo "=== Loaded / TM health (host log) ==="
  grep -E "\[tm-guard\] Loaded|TM health check passed" "$log" 2>/dev/null || echo "MISSING"
  echo "=== isolated audit: $WORKSPACE/.tm-guard/audit.jsonl ==="
  local audit="$WORKSPACE/.tm-guard/audit.jsonl"
  [ -f "$audit" ] && { wc -l "$audit"; grep -E "ALLOW|BLOCK" "$audit" | tail -20; } || echo "audit not found: $audit"
  echo "=== production $PROD_PORT still on original pid ==="
  echo "prod pid: $(prod_pid || echo none)"
}

cmd_stop() {
  local pidfile="$HOME/dsh-live/$PROFILE/host.pid"
  [ -f "$pidfile" ] || die "no pid file for $PROFILE (already stopped?)"
  local pid; pid="$(cat "$pidfile")"
  # Verify the recorded pid still belongs to THIS profile before signaling;
  # never kill by stale pid and never touch production 3080.
  local cmdline; cmdline="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  case "$cmdline" in
    *"--profile $PROFILE "*|*"--profile $PROFILE") ;;
    *) die "pid $pid no longer matches profile $PROFILE (cmdline: ${cmdline:-none}); refusing to kill" ;;
  esac
  kill "$pid" 2>/dev/null || true
  rm -f "$pidfile"
  info "stopped isolated pid $pid; production $PROD_PORT left alone"
}

case "${1:-}" in
  setup) shift; parse "$@"; cmd_setup ;;
  start) shift; parse "$@"; cmd_start ;;
  collect) shift; parse "$@"; cmd_collect ;;
  stop) shift; parse "$@"; cmd_stop ;;
  *) sed -n '1,30p' "$0"; exit 2 ;;
esac
