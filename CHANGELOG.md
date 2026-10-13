# Changelog

All notable changes to dsh-tm-guard will be documented in this file.

## [Unreleased]

## [0.2.5] - 2026-10-13

### Security (important)
- **解释器内联代码全链进危险网（R10–R15）**。十五轮独立对抗复核驱动下的
  allow 侧封口，全部为真实 fail-open 修复：
  - 版本化/ABI 解释器名（`python3.12`、`python3.12m/t/d`、`pypy3`、
    `-dbg`）与裸名共享 `-c` 内联代码的危险网与敏感路径扫描，不再因名单
    缺字面量而漏（R10/R11）。
  - `uv run <解释器> -c "<危险码>"` 递归进入解释器危险网：`python`/`node`/
    `ruby`/`bash` 等包装均不再整体放行（R12/R13）。
  - uv flag 按真实语法 token 化：布尔 flag（`--no-sync/--frozen/--locked/
    --offline/--no-dev/--no-project` 等）不再吞掉解释器名；`--x=y`、`-p 3.12`、
    `--` 分隔符全部正确处理；`uv run <伪造解释器名>` fail-closed（R13 阻断）。
  - `denyReadPaths`（敏感路径 forceDeny）沿全部递归边界透传：uv、bash -c、
    xargs、nohup/env/管道/子 shell/裸赋值前缀，`-c` 代码内读
    `.ssh/id_rsa` 等一律 forceDeny（R13/R14 阻断 + W1）。
  - 转义感知引号提取：`bash -c "python3 -c \"…\""` 双层嵌套不再被 `\"`
    截断而漏敏感扫描。
  - 仓库卫生：文档与源码清除本机用户名路径，host 矩阵脚本移出版本库，
    dsh 复核工作目录 ignore（发布物隐私净化延续）。

### Added
- **First-run safety baseline report (U-27)**. The first `apply()` in a
  workspace writes `.tm-guard/baseline-report.md` and prints a one-line pointer
  to it. The report probes *this* machine — TM destination and health, the
  effective writable scope, whether `git` is on PATH and the directory is a work
  tree, the effective `denyReadPaths` count and merge semantics, the platform
  mode — and closes with the residual risks from README § Limitations, so the
  honest boundaries are facts on the user's machine rather than a README section
  they may never scroll to. Previously `tm_status` was the only source of these
  facts, it had to be asked, and it left nothing behind.
  - **First run is detected by the absence of the file**, not by a flag in
    `state.json`: self-describing, survives a wiped state file, and lets a user
    regenerate by deleting the report. Later `apply()`s cost one `existsSync`.
  - **Strictly read-only, and it says so.** The git probe is `git rev-parse`
    and stops — it does **not** call `ensureGitBaseline` (which runs `git init`
    + a baseline commit) during plugin load. The report states that the baseline
    is created lazily at the first write. No snapshot, no config change.
  - **Published synchronously.** The report exists when `apply()` returns; the
    (async) tmutil section is filled in afterwards and renders as an explicit
    "unknown — check `tm_status`" until it lands, never as a false "configured".
  - **Never fatal**: an unwritable report degrades to a `console.warn` and the
    gate still loads (a display artifact never stops the safety mechanism).
  - `tm_status` 【Data sources】 now echoes the report path so it is discoverable
    from the diagnostic tool. New `src/baseline-report.ts`; new
    `probeGitSync` in `src/git.ts` (sync, read-only, test-seamed).

### Changed
- **`autoApprove` risk made explicit (U-25)**. `autoApprove` defaults to `true`,
  which means the plugin answers DSH approval prompts on the user's behalf; its
  safety depends on this plugin's `prepend` registration order relative to any
  other permission plugin. `apply()` now prints a startup warning stating this,
  with a README pointer. A second warning fires for the combination
  `failClosed=false` + `autoApprove=true`, which leaves no human confirmation
  step and no rollback gate. No behaviour change — announcements only.

### Known UX notes（发布说明，非缺陷）
- **解释器内联代码里再包本地开发命令会被拦（R15 起新增 deny 面）**：
  `python3 -c "import subprocess; subprocess.run(['npm','test'])"`、
  `node -e "execFileSync('git',['status'])"` 这类写法会按
  package/vcs_remote/unknown 类别拒绝——请**直接运行** `npm test`/`git status`/
  `cargo test`/`go run` 等命令，或写成脚本文件执行（`node x.js`/`python x.py`
  文件形态不受内联码网限制）。直接形式不受影响。
- **`uv run --with <pkg> script.py` / `--with-requirements` 按包操作拒绝**：
  属于既有"包操作默认拒绝"立场（profile 定向放行即可）；可先 `uv sync` 再
  `uv run`，或去掉 `--with` 直接运行。`--with` 精确 token 化留待下个版本。
- 上述均为安全方向的收紧，被拦命令不会执行；误拦面估计为全量命令的
  1–3%，均有低成本改写。

## [0.2.4] - 2026-10-03

### Changed
- **发布物隐私净化**：清除包内所有本机用户名路径——源码注释与 README
  文档示例路径统一中性化为 \`/Users/alice\`；测试文件改用 os.homedir()
  动态构造（无本机用户名硬编码）。无代码逻辑变更。

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
