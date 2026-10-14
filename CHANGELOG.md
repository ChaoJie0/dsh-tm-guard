# Changelog

All notable changes to dsh-tm-guard will be documented in this file.

## [Unreleased]

## [0.2.7] - 2026-10-14

### Keep-all 定稿（0.2.6 废弃说明）
- **0.2.6（npm 已发布版）为有界默认版，已废弃（deprecated）**：npm 0.2.6 发布于
  keep-all 定稿前，审计日志默认 10MiB 轮转、物理删最老代——与最终拍板相反。
  **请升级 0.2.7**；`npm view dsh-tm-guard deprecated` 可看到废弃提示。
- **审计日志默认保留全部（keep-all）随 0.2.7 定稿**：默认 `auditMaxBytes: 0`——
  不轮转、不生成任何 `.N` 代、记录全量保留；轮转为 opt-in（配置 `auditMaxBytes` 启用，
  `auditRetainFiles` 控制代数，`auditTotalMaxBytes` 设硬顶）。基线报告版本 `3`。
- **市场措辞最终形态**：README/description 明确"写操作自动放行并**自动打快照**
  （本地 git 基线 / Time Machine）"、"审计日志默认保留全部，可配置启用**自动清理
  最旧审计记录**"——无参数名/术语噪音，参数细节见正文 Configuration 与 § Audit log
  rotation。

### Fixed / Test
- **真机 TM 测试断言双布局**：回滚源接受外部盘 `.previous` 完成备份或本地快照树
  （`Backups.backupdb`）任一合法 TM 源，对齐 `src/tm.ts` 既有枚举+最新优先行为
  （`src/tm.ts` 零改动）。
- 门禁：300/300 测试、verify:fast exit 0（peer 19/19、18 files byte-identical）。

## [0.2.6] - 2026-10-14

> ⚠️ **废弃**：npm 0.2.6 为有界默认版（审计默认 10MiB 轮转、物理删最老代），
> 与 keep-all 定稿相反。请使用 **0.2.7**（本条目内容为发布时的代码状态，随 0.2.7
> 的 keep-all 反转在下方 [0.2.7] 描述）。

### Disclosure & hardening (review-gap fill)
- **auditMaxBytes:0 关闭轮转契约补测**：`auditMaxBytes: 0`（及负值）短路
  轮转（`maybeRotate()` 返回 false、`record()` 永不触发轮转、不生成任何 `.N` 代）。
  **0 现为默认值**——0.2.6 定稿将默认反转为保留全部（见下方 Changed）。
- **基线报告版本化重生成（存量升级用户可见披露）**：报告此前"存在即跳过"，
  0.2.5 老用户升级后永远看不到 §6 新增的审计保留窗口披露。报告现在带 schema 版本
  （`报告版本 | 3 |`），版本不匹配自动重新生成；稳态成本仍是一次 `existsSync` +
  ~512B 头部读。补 2 条测试（旧报告重生成 / 当前版本不重写）。
- **轮转日志按实际删除区分措辞**：此前每次轮转都打印 "physically deleted"，
  但前 `retainFiles` 次轮转实际没有删除任何文件（窗口未满）。`RotateInfo` 新增
  `evicted` 计数，日志改为：未满窗口时明说 "no file evicted yet — retention window
  just shifted"，真删除时报告 "physically deleted N generation(s)"。补 evicted 两条测试（窗口驱逐 evicted=1、总字节顶 backstop 删除计入 evicted）。

### Fixed (edges promised in 0.2.5)
- **存量边界 1 修复（temp 前缀穿越）**：写门控的 temp 豁免现在与敏感读/写保护
  使用同一规范化（`normalizeForMatch` 折叠 `//`、`.`、`..` 并 lowercase）。
  `echo x > /tmp/../etc/evil.txt` 之前被按 temp 放行（实际落点在 `/tmp` 之外），
  现在正确解析为 `/etc/evil.txt` → 非 temp、非保护 → BLOCKED。补穿越单测。
- **存量边界 2 修复（curl 捆绑短选项）**：curl 判定新增短选项簇展开
  （`-sLk` → `-s -L -k`），`curl -sLk -o a …` / `-sLd x=y` / `-sLH "X:y"` 中的
  `-k`/`-d`/`-H` 不再被捆绑隐藏 → 恢复 network/deny（不再降级为 file_write）。
- **误拦修复（curl -o 分离值提取）**：`curl -o /tmp/x https://…` 的下载目标路径
  之前提取为空（temp 豁免不触发 → 合法下载被 BLOCKED）；现在提取 `-o/--output`
  分离值，合法 `/tmp` 下载恢复 temp 豁免放行。
- **回归封口（curl -K/--config 配置注入）**：独立对抗复查发现 `-K/--config`
  配置文件注入可携带 `-k/-d/-H/--output` 任意参数（配置内容 curl 真实执行）；
  `-K`/`--config` 已加入危险 flag 表 → `curl -K cfg / -K - / -Kcfg` 一律
  network/deny（不再降级为只读下载）。
- **误拦封口（curl -o 粘值误拆）**：`-o` 是带参短选项，`curl -oout`/`-odata`
  是「选项+文件名」而非 flag 簇——簇展开对 `-o` 开头的粘值不展开，避免从
  文件名拆出虚构的 `-u`/`-d` 等 blocked flag 把合法下载误判为 network。
- **放行封口（危险短选项任意位置）**：危险短选项识别改为 **token 级任意位置**
  ——危险字母前粘良性簇前缀（`-sHX:y`、`-sLdsecret=1`、`-suadmin:pw`、
  `-sFkey=@f`、`-sehttp://r`、`-sK./cfg`、`-sk./x`、`-XPOST`）同样
  network/deny（含 `-K` 配置注入与 `-k` TLS 绕过形态）；**引号整体包裹的
  选项**（`"-HX:y"`、`"--insecure"`、`"--config"`）检测前统一剥引号，短/长
  选项均不因引号逃逸。`-o` 在任意位置（token 首位或簇中段）均视为带参选项、
  其余为本地文件名（`-oT`/`-odata`/`-sodata`/`-soxH:y`），不参与危险判定、
  不误拦合法下载。分隔/粘连/簇内/任意前缀/引号包裹形态全部 network/deny。

### Changed
- **审计日志默认反转为保留全部（0.2.6 定稿）**：默认 `auditMaxBytes: 0`——不轮转、
  完整留痕（磁盘无界增长由用户自行管理，README Limitations 已如实披露）；有界轮转
  改为 **opt-in**（显式设 `auditMaxBytes` + `auditRetainFiles`）。同步反转 README
  开头段/配置表/轮转章节/Limitations、npm description、基线报告 §6
  （`报告版本 | 3 |`，升级用户自动重生成）、轮转日志文案
  （"rotation is opt-in; default keeps all"）。
- **审计轮转披露补强（B1/B2/O1/O2）**——轮转对用户数据保留有实质影响（窗口外
  最老代被物理删除、不可恢复），披露从"深渠道"补齐到"用户必经渠道"：
  - 运行时轮转日志点明后果：`audit rotated → .1; oldest generation beyond N
    retained (~X MiB/file, Y MiB cap) physically deleted — forensics reach back
    only this far (rotation is opt-in; default keeps all)`（之前只说
    rotated/retained，没说删除与取证窗口；无宿主 logger 时回退 console 同款文案）。
  - 首次基线报告第 6 节披露本机审计数据保留事实（0.2.6 起默认保留全部；显式配置
    才启用有界轮转；窗口满后最老代物理删除不可恢复；看当前窗口的方法）——把深
    README 事实落到用户最可能打开的持久产物。
  - README § Limitations 更新为 **The audit log keeps everything by default
    (since 0.2.6)** 条目（与其它 since 0.2.5/0.2.6 条目同格式，链接 § Audit log
    rotation）。
  - npm/market 包描述（description）同步为：审计默认保留全部、可选启用
    有界轮转——命中安装前唯一几乎必读的渠道。

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
- **Audit log rotation (new default behaviour)**. `audit.jsonl` now rotates at
  10 MiB, keeps 5 generations, total ≈ 50 MiB (100 MiB hard cap), with a
  cross-process lock. **The oldest generation is physically deleted once the
  retained window is full** — rollback/forensics reach back only as far as the
  window. This replaces 0.2.4's unbounded log, so the audit can never silently
  fill the disk (which would break the write path rollback depends on). Tune
  via `auditMaxBytes`/`auditRetainFiles`/`auditTotalMaxBytes`; set
  `auditMaxBytes: 0` to disable rotation entirely. See README § Audit log
  rotation.

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
- 上述均为安全方向的收紧，被拦命令不会执行。真实生产语料回放显示内联
  解释器写法（`python/node -c/-e`）会大幅收紧，具体踩不踩中取决于内联码
  里是否出现高危 import/原语——请以内联码改写指引为准，而非一个固定
  百分比（既有 "1–3%" 估算无干净语料支撑，已撤回）。
- **audit 自动轮转（升级须知）**：默认 10MiB/5 代/100MiB，保留窗口填满后
  最旧审计会被**物理删除**——若你需要更长回滚/取证历史，用
  `auditMaxBytes`/`auditRetainFiles` 调大窗口，或 `auditMaxBytes: 0` 完全
  关闭轮转（回到无界增长）。
- **已知边界**：纯 socket 外联（`socket.create_connection(...)`，无 URL
  字面量）静态扫描不识别；0.2.5 起版本化解释器名（`python3.12`/`pypy3`）
  与裸名共享此边界（非回归，两版一致）。高需求用户可从可信工具移除内联
  解释器，或配出口防火墙（见 README § Limitations）。
- **存量边界 1（temp 前缀未规范化）**：写门控的 temp 豁免对**未规范化的
  `/tmp/../` 前缀**误判——`echo x > /tmp/../etc/evil.txt` 会按 temp 放行，
  而 OS 实际落点在 `/tmp` 之外。0.2.4 行为相同（非 0.2.5 回归），且外层
  沙箱/git-net 实测兜底；计划 0.2.6 让 temp 判定与受保护路径判定使用同一
  规范化逻辑并补穿越单测。
- **存量边界 2（curl 捆绑短选项）**：curl 只读下载的危险 flag 以**独立
  token** 匹配，`curl -sLk -o a https://…`、`-sLd x=y`（POST body）、
  `-sLH "X:y"`（任意头）等捆绑短选项可绕过检测、被降级为 file_write 判定
  （受保护路径/`/tmp` 下会放行落地，但远端内容不执行、仍受写门控+快照
  约束）。0.2.4 行为相同（非回归）；计划 0.2.6 短选项簇展开解析。

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
