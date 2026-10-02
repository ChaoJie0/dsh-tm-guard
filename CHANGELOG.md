# Changelog

All notable changes to dsh-tm-guard will be documented in this file.

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
