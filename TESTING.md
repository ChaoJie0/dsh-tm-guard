# dsh-tm-guard — 测试机制

本文件定义插件的分层测试机制：**哪些层自动跑、哪些发布前手动跑、历史问题如何固化为用例、发布门禁长什么样**。发布新版本前必须读完本文件与本地发布规范 `RELEASE.md`（私有文档，不收录于公开仓库），并逐项执行。

## 分层架构

> 注：L0–L6 以本文件为**唯一事实源**（测试机制分层）。`RELEASE.md`（本地私有）沿用同一套编号，不另立体系：L0–L3 自动门禁、L4 实机 host 冒烟、L5 独立复核（L5-a MainAgent / L5-b dsh）、L6 内容隐私审查（L6-a Git 树 / L6-b 历史 / L6-c 发布物）。`DEV.md` 为日常开发，只引用本编号。

| 层 | 名称 | 命令 | 耗时 | 时机 | 自动化 |
|---|---|---|---|---|---|
| L0 | 单元测试 | `npm test` | ~20s | 每次提交 / 发布前 | CI + 本地 |
| L1 | 构建可复现 | `npm run verify:build` | <1s | 发布前 / 工作树变更后 | CI + 本地 |
| L2 | 包内容审计 | `npm run verify:pack` | <1s | 发布前 / 推送前 | CI + 本地 |
| L3 | peer 兼容矩阵 | `npm run verify:peer` | <1s | 发布前 / 改动声明后 | CI + 本地 |
| L4 | 隔离 host 进程内活体冒烟（全版本矩阵 + 本版分叉命令经真实 harness 被门控） | 见下方 L4 段 / RELEASE §2 | ~10min | **发布前（手动，强制）** | 本地（需 macOS + TM + dsh host，硬隔离生产） |
| L5 | 独立复核 | 委派 dsh 会话 | ~3min | **发布前（手动）** | 本地（需 dsh 会话） |
| L6 | 内容隐私审查（树/发布物自动；已 push 污染应急重写人工） | `npm run verify:hygiene` + `npm run verify:pack` | ~1min | 推送前（自动门；§6 应急手动） | CI + 本地 |

> 耗时实测（2026-10-20，本机）：L0 ≈ 18s（TAP duration），L1 ≈ 0.7s，L2 ≈ 0.2s，L3 ≈ 0.25s。L1/L2 因无子进程/增量构建而为亚秒级。

`npm run verify:fast` = L0+L1+L2+L3+L6 一键全跑（发布门禁的自动部分；L4/L5 仍手动）；`npm run release:check` 为 `verify:fast` 的别名，`prepublishOnly` 同样强制它。

### 量化发布记分卡 `npm run release:gate`

`release:check` 只保证自动门通过；`release:gate` 在其之上输出一张量化记分卡并直接给 GO/NO-GO。**所有自动门阈值都是"违规数 = 0"**，展示性计数（pass 数、文件数、WARN 数）不是放行线。

| 门 | 硬阈值（必须为 0） | 展示（非阈值） |
|---|---|---|
| L0 单元测试 | `# fail = 0` | `# pass` 数（随版本增长，不设下限） |
| L3 peer 矩阵 | violated expectations = 0 | `N/N` 命中 |
| L1 可复现构建 | differ files = 0 | 逐字节一致文件数 |
| L2 发布物审计 | leak violation = 0 | 白名单打包文件数 |
| L6 树+历史卫生 | hard violation = 0 | WARN 计数（非阻断） |

退出码与结论：
- `0` = **RELEASE GO**：自动门全绿且 L4/L5 已显式确认；
- `1` = **NO-GO**：任一自动门失败，修完再跑；
- `2` = **AUTOMATIC GREEN, MANUAL PENDING**：自动门全绿但 L4/L5 未确认，尚不可发布。

L4/L5 脚本无法自证，绝不自动判定；完成后用显式 flag 计入：
`npm run release:gate -- --confirm-l4 --confirm-l5`。缺任一 flag，结论停在 PENDING（exit 2）。
这两个 flag 只是人工 attestation（声明你已完成 L4/L5），脚本本身不连接 host、不复核 dsh 结论，
不能替代真实实机与独立审查。push/tag/publish 始终由人在终端执行。

## 各层说明

### L0 单元测试（`npm test`）
`node --test test-*.mts test-*.mjs`，**37 个测试文件（36 .mts + 1 .mjs）、333 用例**（2026-10-20 实测 333/333/0），纯逻辑 + 真实文件系统，不依赖 dsh/tmutil。覆盖分类器、决策真值表、路径变体、敏感路径、对抗回归、fuzz、扫描脚本与配额、验证器、报告、hook、运行时、git 回滚与恢复、tm 快照、审计/配置故障注入、ignored 恢复门、平台探测、watermark 等。**任何 src/ 改动必须保持此层全绿。**

**测试文件地图**（按主题分组；新用例就近加入，新增特性测试建 `test-<特性>.mts`）：

| 主题 | 文件 |
|---|---|
| 分类与决策 | `test-classifier.mts`、`test-classifier-edge.mts`、`test-decide-matrix.mts`、`test-path-variants.mts`、`test-sensitive-paths.mts`、`test-fuzz-classifier.mts`、`test-bypass-regression.mts`、`test-fp-verdict-regression.mts`、`test-adversarial.mts`、`test-round9.mjs` |
| 门控与自动放行 | `test-gate-prod.mts`、`test-auto-approve-warn.mts` |
| 扫描脚本 | `test-scan-scripts.mts`、`test-scan-quota.mts`、`test-fuzz-scan.mts` |
| git 恢复/回滚 | `test-git-real.mts`、`test-git-rollback.mts`、`test-git-recovery.mts`、`test-git-faults.mts` |
| ignored 恢复门（0.2.8） | `test-ignored-recovery-gate.mts`、`test-ignored-recovery-render.mts` |
| tm 快照 | `test-tm-real.mts`、`test-tm-faults.mts`、`test-rollback.mts` |
| 故障注入 | `test-audit-faults.mts`、`test-config-faults.mts` |
| 集成/报告/状态 | `test-index.mts`、`test-report.mts`、`test-baseline-report.mts`、`test-status.mts`、`test-verify.mts`、`test-hook.mts`、`test-runtime.mts` |
| 平台/元数据 | `test-platform-detect.mts`、`test-readme.mts`、`test-watermark.mts`、`test-perf.mts` |

注：`test-rollback.mts` 是需真实 TM 备份的条件自跳过脚本（前置不满足时 `process.exit(0)` 跳过，不注册 node:test 用例、不贡献 `# tests` 计数）。

### L1 构建可复现（`npm run verify:build`）
从 `git HEAD`（将要发布的提交）用 `git archive` 导出干净工作树 → 重新构建 → 与当前 `lib/` + 随包文件逐文件比对 SHA-256。**阻止「未提交改动 + 陈旧 lib/ 被发布」**。工作树有任何未提交改动时此层会正确失败（门禁在起作用）。

### L2 包内容审计（`npm run verify:pack`）
按 package.json `files` 白名单**进程内递归展开**（无子进程，等价于实际 tarball 清单；仓库根存在同名 `<pkg>-<ver>.tgz` 时追加逐字节新鲜度比对）审计：
- 无本地绝对路径（`/Users/`、`/private/`、`/tmp/`）、无 session id
- 无源码/测试/临时残留（`src/`、`test-*.mts`、`test-*.mjs`、`.smoke-out/`、`.tm-*`、`.git/`、`node_modules/`）
- 顶层条目仅限白名单（`lib` + `cordis.patch.yml` + 3 文档 `README.md`/`CHANGELOG.md`/`LICENSE` + `package.json`，共 18 文件）

这是 0.2.0 推送前那次人工隐私审查的机器化版本（当时抓出 3 份本地报告 + 2 个测试残留）。

### L3 peer 兼容矩阵（`npm run verify:peer`）
用真实 `semver` 引擎（devDependency）对**全部候选 dsh 版本**验证 `peerDependencies` 与 `engines.dsh`：

| dsh 版本 | 必须 |
|---|---|
| 0.1.0-rc.1 / 0.1.0 / 0.1.1 / 0.1.2-rc.1 | ✅ 匹配（0.1.x 全段） |
| 0.2.0-0 / 0.2.0-rc.2 / 0.2.0 / 0.2.9 | ✅ 匹配（0.2.x 全段） |
| 0.3.0 / 1.0.0 / 0.1.0-rc.0 / 0.0.9 | ❌ 不匹配 |

同时强制 `engines.dsh == peerDependencies["@deepseek-ai/dsh-tools"]`（单一事实来源）。
**为什么必须有这层**：npm semver 对 prerelease 的规则（同主次补丁三元组 comparator 才生效）极容易手工推导出错——0.1.1 事件（`<0.2.0-0` 挡 0.1.x 线）、0.2.0 三段式（漏 0.1.0/0.1.1 stable）都是手工推导的产物。任何声明改动必须让此矩阵全绿。

### L4 全版本 host 矩阵冒烟（发布前手动）
在**每个实际存在的 dsh host 版本**上起隔离实例验证。npm 实测版本集合 = 0.1.x 线（0.1.0-rc.2 ~ 0.1.7-rc.2）+ 0.2.x 线（0.2.0-rc.1/rc.2）。0.2.3 发布前全矩阵实测（2026-10-01）：

| host 版本 | 插件加载 | TM health check | API 响应 | tm_status 冒烟 | 端到端拦截 |
|---|---|---|---|---|---|
| 0.1.0-rc.2 | ✅ Loaded | ✅ passed | —（host web boot 缺内置插件，host 自身缺陷） | — | — |
| 0.1.2-rc.1 | ✅ Loaded | ✅ passed | ✅ 200 | ⚠️ host agent turn 崩溃（`reading 'length'`，host 自身缺陷） | — |
| 0.1.7-rc.2 | ✅ Loaded | ✅ passed | ✅ 200 | ✅ HEALTHY / protected | — |
| 0.2.0-rc.1 | ✅ Loaded | ✅ passed | ✅ 200 | ✅ HEALTHY / protected | — |
| 0.2.0-rc.2 | ✅ Loaded | ✅ passed | ✅ 200 | ✅ HEALTHY / protected | ✅ `cat ~/.ssh/config` → `BLOCKED (read, forced deny)`，命令未执行 |

验证项：
1. 加载：启动日志含 `[tm-guard] Loaded` + 无 peer skip（host 0.2.0 会打印各 bundle peer 检查，tm-guard 不在 skip 列表即兼容）
2. 工具注册：会话内 agent 调 `tm_status` 成功返回 HEALTHY / workspace protected / deny 路径列表
3. 门控拦截：agent 调 bash 执行敏感读 → 门控 `BLOCKED (forced deny)`，命令未执行
4. host 自身缺陷（0.1.0-rc.2 web boot 缺插件、0.1.2-rc.1 agent turn 崩溃）**不属于插件问题**——插件在两线加载与初始化均正常

环境：每版本 = npm tgz 解压 + pnpm 装依赖（`allowBuilds` 白名单 6 项）+ 独立 profile（dsh-base/web-app 同版本 + 插件 tarball）+ 独立端口实例。0.1.2-rc.1 会话为 v3 格式（`session.jsonl.zstd`），0.1.7+ 为 v4（`session.v4.jsonl.zstd`）。冒烟 RPC 脚本见 `.smoke-out/verify-host-matrix-023.md` 附注（/tmp/tm-rpc.py + tm-gate-smoke.py，端口参数化认证）。

**写门控端到端补测（2026-10-02）**：3 个可端到端 host（0.1.7-rc.2/0.2.0-rc.1/0.2.0-rc.2）全部通过受保护内写放行、越界写拒（非临时路径）、敏感路径写拒三场景，行为一致。驱动为一次性临时脚本（记录于 gitignored 报告 `.smoke-out/verify-host-matrix-write-023.md`，不随仓库存档）。注意：`/tmp`/`/var/tmp`/`/var/folders` 是设计内一次性临时区放行（classifier.ts），越界写测试须用非临时路径。

**发布前强制：隔离 host 进程内活体分叉命令冒烟（不可由单测或隔离脚本替代）**
单测（mock/注入 tm 层）与 `/tmp` 隔离脚本（直接调 build 后的门控函数）只证明**函数本身正确**，不等于"命令经过真实 harness、在 host 进程内被门控拦住"。因此每个版本发布前必须：

1. **硬隔离（5 条，缺一不可）**：
   - 独立 profile 目录，**只挂本插件一个 bundle**；不加载生产 patch（模型桥 / atoll 灵动岛 / provider-failover / 真实模型 baseURL / 状态上报桥一律不带）。
   - 独立新端口，避开生产端口（生产 3080）；**生产 host 不重启、不断连、不改任何配置文件**。
   - 独立 cwd 专用测试目录；审计落 `<cwd>/.tm-guard`，绝不写生产审计（audit 按 workspaceDir/cwd 解析）。
   - `protectedPaths` 只指向隔离测试目录，不指向真实项目 / 学科目录 / DSH_Work。
   - 门控钩子只在一次 agent turn 由模型发起工具调用时触发；host 没有不经模型直接 POST 工具的 unary 通道（`tools/list/execute` 是事件名而非 RPC），catalog 无免费/本地 provider。因此触发方式为：隔离实例用其继承的默认轻量模型跑一次极简 turn（只读 allow + 敏感读 deny + 可恢复写放行各一条）；**不复制生产方舟配置、不把付费 key 写进任何文件、不碰生产额度以外的资源**。若环境完全无任何可用模型，则只记录 host 加载/钩子注册/TM health 证据，命令拦截层由单测 + `/tmp` 隔离脚本承担，并在报告中如实标注该边界，不得冒充 host 内拦截通过。
2. **通过标准（host 进程内实测）**：启动日志含 `[tm-guard] Loaded`、`tm_status` 返回 HEALTHY、TM health passed；本版新增/改动的分叉破坏性命令在 harness 内真 `BLOCKED` 且命令未执行、审计落盘；同时一条良性只读命令仍 allow。
3. **非目录隔离项（如实记录）**：`tmutil localsnapshot` 是 APFS 卷级 purgeable 快照，非目录级；隔离实例创建的快照由系统自动回收，不复制、不修改生产文件。
4. 报告写入 gitignored `docs/`，不进公开仓库。

#### 可复用隔离脚本（替代手动搭 profile）

`scripts/l4-isolated-smoke.sh`（`npm run l4 -- <subcmd>`）把每次手动建 profile、选端口、写 patch、装依赖、抓证据的步骤固化；**只做环境准备与证据采集，不驱动模型 turn、不自动判 PASS**（host 无 unary 工具通道，模型 turn 与最终判定仍人工）。

```bash
# 1) 准备隔离 profile（生成 package.json/cordis.patch.yml、装依赖、建 git 基线）
npm run l4 -- setup --version 0.2.8 --tgz "$PWD/dsh-tm-guard-0.2.8.tgz" \
  --profile tm-live --port 3091 --workspace "$HOME/dsh-live/tm-live/workspace"
# 2) 启动隔离 host（空闲端口预检，轮询 Loaded+TM health，校验实际绑定该端口，比对生产 3080 pid 不变）
npm run l4 -- start --profile tm-live --port 3091 --workspace "$HOME/dsh-live/tm-live/workspace"
# 3) 会话内跑一次极简 turn 后，采集证据（版本/Loaded/TM health/隔离 audit/生产 pid）
npm run l4 -- collect --profile tm-live --port 3091 --workspace "$HOME/dsh-live/tm-live/workspace"
# 4) 收尾：只杀本实例（按 cmdline 校验，绝不碰 3080）
npm run l4 -- stop --profile tm-live
```

脚本 fail-closed 自动保证上面「硬隔离 5 条」中的可机检项：拒绝生产 3080 与非数字端口；workspace 先展开前导 `~` 再 `cd -P` 规范化解析，拒绝字面 `..`、拒绝解析后逃逸出 `$HOME`（含 symlinked `$HOME` 也按解析后真实家目录比较）、拒绝落到 `/tmp`/`/private/var/folders`（TM Excluded）、拒绝指向真实项目/DSH_Work/学科目录；保留名/已存在 profile 检查先于建目录执行，拒绝时不写任何文件、不留残留空目录，也不静默覆盖；生成 patch 不含模型凭据字段；启动前预检端口空闲，启动就绪门要求 `Loaded` + `TM health check passed` + 实际绑定该端口，启动前后生产 3080 pid 必须一致；stop 按锚定 cmdline 只杀本实例，绝不碰 3080。`--no-install` 仅用于干跑生成配置（不联网、不建基线）。

仍需人工：在隔离会话里发「只读 allow / 敏感读 deny / 可恢复写 allow」三条 + 本版分叉破坏性命令，观察真 `BLOCKED` 且命令未执行；模型继承默认轻量模型，不复制方舟配置。

**0.2.8 特性实机验证（git-ignored 删除兜底，2026-10-20）**：
在真实 APFS + Time Machine 配置上验证新增的「被 `.gitignore` 忽略、git 无法恢复的删除目标」处理：
- 场景：目标文件 git 探针 `state=no`（git-ignored，git 无法恢复）→ 绕过冷却**强制创建恰好 1 张新鲜 APFS 快照**兜底；**始终 allow 绝不 deny**（零干预哲学，默认决策不变）；`warnOnIgnoredDelete` 默认 false（仅 console.warn 不改决策）；`requireGitBaseline:false` 同时关闭探针与强制快照。
- 驱动与报告（`docs/` 已 gitignore，仅本地）：`docs/live-verification-ignored-20261020.md`（实机报告）、`docs/review-live-ignored-20261020.md`（dsh 实机独立复核 PASS）、`docs/review-l5-0.2.8.md`（dsh L5 对抗复核 PASS）。
- 环境坑位（实测）：`$TMPDIR`（`/var/folders`）被 Time Machine `[Excluded]`，写操作会 fail-closed BLOCK——实机脚本必须建在 `$HOME`（`[Included]`）下；普通用户 `tmutil localsnapshot` 无需 sudo。

### L5 独立复核（发布前委派）
委派 dsh 独立会话（不采信本文件/此前结论）：对 **npm 发布物**（安装目录 + registry 元数据）验证——peer 严格语义、发布物与 gitHead 重建 SHA 一致、函数级门控全量用例、生产审计活性。0.2.5/0.2.6/0.2.7/0.2.8 发布前均执行并 PASS；0.2.8 重写历史后 tarball SHA-256 与 dsh L5 记录逐字节一致（`c1e021af…`），证明裁剪历史未改发布物、dsh 审查直接成立。

### L6 内容隐私审查（推送前）
分层：可确定性判断的部分已自动化进 `verify:fast`（=`release:check`=`prepublishOnly`），剩余需人工判断的应急动作保留。

**自动门（`npm run verify:hygiene`，已并入 verify:fast 末尾）**：
- L6-a 树卫生：porcelain 干净（先 commit/stash，与 L1 同前置）、无跟踪的 `docs/`/`research-proposal/`/`.smoke-out/` 目录与 `scratch-*.mts`/`*.log`/审查产物 basename、HEAD blob 无真实本机路径/会话 id/密钥。
- L6-b 推送主线历史：扫 `origin/main` 基线树 + `origin/main..HEAD` 新提交（禁止路径与敏感串）；legacy 本地 author 身份与 orphan/backup 历史仅 WARN 不阻断。
- L6-c 发布物内容：`verify:pack` 在白名单文件内进程内扫密钥/真实本机路径/审查 token（无 tar、无网络）。

**仍需人工（脚本不代做）**：
- 已 push 的污染：按 `RELEASE.md` 第 6 节应急流程（先备份，再重写，最后 force push）——破坏性历史重写不进自动门。
- 未 push 本地污染的重写决策、bundle 备份与 `filter-branch`/reflog/gc 清理由人判断执行。
- 发布相关报告（guide/测试报告/实机报告）留在 `docs/` / `.smoke-out/`（已 gitignore），不进公开仓库。

## 用例注册表（历史问题 → 固化用例）

| 历史事件 | 固化位置 |
|---|---|
| H1：`subagent` 白名单短路绕过 mixed 拒绝（生产 1682 条 explicit-allow 实证） | `test-gate-prod.mts` F 组（工具层分类/越界/敏感路径；t7 迁移）+ README ⚠️ 警示。注：短路本身是**显式放权设计**，靠 README 警示约束而非用例禁止，全仓无"白名单内必须拒绝"回归用例 |
| 敏感读经重定向渗漏（`cat ~/.ssh/id_rsa > 保护区`） | `test-classifier.mts` Sensitive-read 节 + `test-gate-prod.mts` C 组（forceDeny 优先于路径豁免） |
| 灾难模式 `rm -rf /` | `test-classifier.mts` Catastrophic 节（decide 强拒） |
| 0.1.1 声明 `<0.2.0-0` 挡掉全部 0.2.x 用户 | `verify-peer-matrix.mjs`（0.2.0-rc.2 必须 PASS） |
| 0.2.0 三段式漏配 0.1.0/0.1.1 stable | `verify-peer-matrix.mjs`（0.1.0/0.1.1 必须 PASS，四段式） |
| **`$HOME` 变量展开绕过敏感读**（`cat $HOME/.ssh/id_rsa` 曾放行；0.2.3 修复：expandHome/toAbsolute 归一化 `$HOME`/`${HOME}`） | `test-adversarial.mts` GAP 组（先红后绿） |
| **`cd` 上下文绕过**（`cd ~/.ssh && cat id_rsa` 曾放行；0.2.3 修复：cd 后敏感目录内 read 类 segment 即 deny） | `test-adversarial.mts` GAP 组（先红后绿） |
| **git-ignored 删除目标 git 无法恢复**（0.2.8：探针 `state=no`，删除后 git 无法还原；修复：绕过冷却强制恰好 1 张新鲜 APFS 快照兜底，始终 allow 绝不 deny） | `test-ignored-recovery-gate.mts`（14）+ `test-ignored-recovery-render.mts`（2）+ `test-git-recovery.mts`（17） |
| **审查/研究/外部资料被 checkpoint 误收录**（0.2.8：`research-proposal/`、`ha-mcp-README.md`、第三方 PDF 混入未 push 提交） | `.gitignore` 红线（`docs/`、`RELEASE.md`、`research-proposal/`、`ha-mcp-README.md`、`100 问 PDF`）+ L2 历史检查（`origin/main..HEAD`） |
| 发布物与提交漂移 / 未提交改动混入 | `verify-reproducible-build.mjs` |
| 本地路径/测试残留进公开仓库 | `verify-pack-audit.mjs` + `.gitignore` 锁定 |

**规则**：任何新发现的缺陷，修复时**先固化用例再修代码**（先让用例红，再让用例绿）。

## 环境要求

- L0/L1/L2/L3/L6：Node ≥ 20 + npm + git（L6 仅需 git 只读，可进 CI）；其中 L1（verify:build）在本机构建需 Node ≥ 22.6 或 ≥ 20.19 LTS（stripTypeScriptTypes）。CI 用 macOS runner 可全跑。
- L4/L5：macOS + APFS + Time Machine 配置 + 本地 dsh 安装（需真实 host 与会话，不能进 CI）

## CI

`.github/workflows/test.yml`：push/PR 自动跑 L0+L1+L2+L3+L6（`npm run verify:fast`，checkout `fetch-depth:0` 供 L6-b 历史扫描）。L4/L5 因需真实 TM 与 dsh 会话，保持本地手动（发布前执行）。
