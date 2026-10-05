/**
 * Default sensitive-path list for the read-side restriction (`denyReadPaths`).
 *
 * Why this is its own module: the list is DATA, not logic. Keeping it next to
 * the gate made it easy to forget when the ecosystem grew new credential
 * locations — and the two years since v0.2.0 produced a lot of them (agent
 * CLIs, package-manager tokens, cloud CLIs). Every entry here is a path whose
 * *default* exposure is a credential leak, so the list belongs in one place
 * that a reviewer can audit in isolation.
 *
 * Matching semantics (see `denyHitFor` in classifier.ts): each entry is a
 * PREFIX. `~/.ssh` therefore covers `~/.ssh/id_rsa`, `~/.ssh/config`, and any
 * other file directly under it. Entries are `~`-prefixed (expanded against
 * `$HOME` at match time) so the default list is portable across machines and
 * does not leak the maintainer's username into the shipped artifact.
 *
 * Both read AND write targets matching a prefix are denied — the gate treats a
 * path under a sensitive prefix as untouchable in either direction, so this
 * list also protects the credential files from being overwritten.
 */

/**
 * Cloud / CLI credentials and shell secrets.
 *
 * Note `~/.aws/credentials` is deliberately accompanied by the broader
 * `~/.aws` prefix: the narrower entry documents the specific high-value file,
 * while the prefix catches `~/.aws/config`, `~/.aws/sso/cache/*`, and the
 * CLI's newer `.aws/cli/cache` token store.
 */
const CLOUD_AND_SHELL_CREDENTIALS = [
  '~/.ssh', // private keys, config, known_hosts, authorized_keys
  '~/.ssh/config', // explicit: documents the highest-value ssh target
  '~/.aws', // credentials, config, SSO token cache
  '~/.aws/credentials', // explicit: the long-lived access-key file
  '~/.gnupg', // GPG keyrings + private keys
  '~/.kube', // kubeconfig (cluster-admin bearer tokens)
  '~/.docker', // registry auth in config.json
  '~/.netrc', // legacy FTP/HTTP basic-auth store
  '~/.git-credentials', // plaintext HTTPS tokens
  '~/.npmrc', // npm registry _authToken
  '~/.pypirc', // PyPI upload tokens
  '~/.config', // XDG base: gh, gcloud, heroku, … (see note below)
]

/**
 * Credential stores belonging to the agent/CLI tools this plugin itself runs
 * alongside. These are newer than the original list and were the concrete gap
 * that motivated pulling the list out of index.ts: an autonomous agent reading
 * `~/.codex/auth.json` or `~/.cursor/mcp.json` obtains long-lived tokens for
 * other execution surfaces.
 *
 * `~/.config/gh/hosts.yml` is listed explicitly even though `~/.config` is a
 * broader prefix above: the narrower entry is documentation for reviewers
 * asking "where is the GitHub token?", and it keeps the protection meaningful
 * if a user overrides `denyReadPathsReplace` with a hand-picked list.
 */
const AGENT_AND_CLI_CREDENTIALS = [
  '~/.config/gh/hosts.yml', // GitHub CLI OAuth token
  '~/.cursor', // Cursor IDE / agent MCP + auth state
  '~/.codex', // Codex CLI auth.json + session state
  '~/.claude.json', // Claude Code CLI account + project trust state
  '~/.claude', // Claude Code CLI credentials + history
  '~/.gemini', // Gemini CLI oauth_creds.json
  '~/.aider.conf.yml', // Aider API keys (plaintext)
  '~/.continue', // Continue extension config (may hold API keys)
]

/** Platform keystores holding OS-level secrets. */
const PLATFORM_KEYSTORES = [
  '~/Library/Keychains', // macOS login/System keychain databases
  '~/Library/Cookies', // browser session cookies (auth tokens)
]

/**
 * The default `denyReadPaths` value.
 *
 * Ordering is meaningful only for the `tm_status` display and for the README
 * cross-check test, which asserts every entry appears in the documented list.
 */
export const DEFAULT_SENSITIVE_PATHS: string[] = [
  ...CLOUD_AND_SHELL_CREDENTIALS,
  ...AGENT_AND_CLI_CREDENTIALS,
  ...PLATFORM_KEYSTORES,
]

/**
 * Merge a user-supplied `denyReadPaths` with the defaults.
 *
 * Semantics (U-18c): ADDITIVE by default. The previous behaviour replaced the
 * whole list, which meant a profile that appended one project-specific path
 * silently dropped every cloud/agent credential entry — a fail-open change
 * disguised as a small config tweak. Adding is the safe direction: a user can
 * only ever widen the deny set unless they explicitly opt into replacement.
 *
 * @param userPaths  Raw `config.denyReadPaths` (already normalized to strings).
 * @param replace    When true, `userPaths` replaces the defaults outright.
 * @returns          Deduplicated list; defaults first, then user additions.
 */
export function mergeDenyReadPaths(
  userPaths: string[] | undefined,
  replace: boolean,
): string[] {
  if (userPaths === undefined) return [...DEFAULT_SENSITIVE_PATHS]
  if (replace) return [...new Set(userPaths)]
  // Defaults first so the documented base list is always present and the
  // user's additions read as additions in tm_status.
  return [...new Set([...DEFAULT_SENSITIVE_PATHS, ...userPaths])]
}
