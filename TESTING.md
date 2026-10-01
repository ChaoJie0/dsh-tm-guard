# dsh-tm-guard — 测试机制

本文件定义插件的分层测试机制：**哪些层自动跑、哪些发布前手动跑、历史问题如何固化为用例、发布门禁长什么样**。发布新版本前必须读完并逐项执行 [RELEASE.md](./RELEASE.md)。

## 分层架构

| 层 | 名称 | 命令 | 耗时 | 时机 | 自动化 |
|---|---|---|---|---|---|
| L0 | 单元测试 | `npm test` | ~5s | 每次提交 / 发布前 | CI + 本地 |
| L1 | 构建可复现 | `npm run verify:build` | ~15s | 发布前 / 工作树变更后 | CI + 本地 |
| L2 | 包内容审计 | `npm run verify:pack` | ~10s | 发布前 / 推送前 | CI + 本地 |
| L3 | peer 兼容矩阵 | `npm run verify:peer` | ~1s | 发布前 / 改动声明后 | CI + 本地 |
| L4 | 双线隔离冒烟 | 见 [RELEASE.md] 步骤 5 | ~10min | **发布前（手动）** | 本地（需 macOS + TM + dsh host） |
| L5 | 独立复核 | 委派 dsh 会话 | ~3min | **发布前（手动）** | 本地（需 dsh 会话） |
| L6 | 内容隐私审查 | `npm run verify:pack` + 清单 | ~1min | **推送前（手动）** | 本地 |

`npm run verify:fast` = L0+L1+L2+L3 一键全跑（发布门禁的自动部分）；`npm run release:check` 为 `verify:fast` 的别名。

## 各层说明

### L0 单元测试（`npm test`）
`node --test test-*.mts`，8 个测试文件、208+ 用例，纯逻辑 + 真实文件系统，不依赖 dsh/tmutil。覆盖分类器（116 用例）、扫描脚本、验证器、报告、hook、运行时、git 回滚。**任何 src/ 改动必须保持此层全绿。**

### L1 构建可复现（`npm run verify:build`）
从 `git HEAD`（将要发布的提交）用 `git archive` 导出干净工作树 → 重新构建 → 与当前 `lib/` + 随包文件逐文件比对 SHA-256。**阻止「未提交改动 + 陈旧 lib/ 被发布」**。工作树有任何未提交改动时此层会正确失败（门禁在起作用）。

### L2 包内容审计（`npm run verify:pack`）
`npm pack --dry-run --json` 实际 tarball 内容审计：
- 无本地绝对路径（`/Users/`、`/private/`、`/tmp/`）、无 session id
- 无源码/测试/临时残留（`src/`、`test-*.mts`、`.smoke-out/`、`.tm-*`、`.git/`、`node_modules/`）
- 顶层条目仅限白名单（`lib` + 4 文档 + `package.json`）

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
在**每个实际存在的 dsh host 版本**上起隔离实例验证。npm 实测版本集合 = 0.1.x 线（0.1.0-rc.2 ~ 0.1.7-rc.2）+ 0.2.x 线（0.2.0-rc.1/rc.2）。0.2.3 发布前全矩阵实测（2026-10-01）：| host 版本 | 插件加载 | TM health check | API 响应 | tm_status 冒烟 | 端到端拦截 |
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

**写门控端到端补测（2026-10-02）**：3 个可端到端 host（0.1.7-rc.2/0.2.0-rc.1/0.2.0-rc.2）全部通过受保护内写放行、越界写拒（非临时路径）、敏感路径写拒三场景，行为一致。驱动脚本 `scripts/verify-host-matrix-write.py`，报告 `.smoke-out/verify-host-matrix-write-023.md`。注意：`/tmp`/`/var/tmp`/`/var/folders` 是设计内一次性临时区放行（classifier.ts），越界写测试须用非临时路径。

### L5 独立复核（发布前委派）
委派 dsh 独立会话（不采信本文件/此前结论）：对 **npm 发布物**（安装目录 + registry 元数据）验证——peer 严格语义、发布物与 gitHead 重建 SHA 一致、函数级门控 40+208 用例、生产审计活性。0.2.0/0.2.1 发布均执行并 PASS。

### L6 内容隐私审查（推送前）
除 L2 机器扫描外，人工检查：
- `git log` 无本地路径/会话 id/端口/token 字样
- 历史 blob 无敏感残留（必要时 `git reset --soft origin/main` 压缩）
- 发布相关报告（guide/测试报告）留在 `.smoke-out/`（已 gitignore），不进公开仓库

## 用例注册表（历史问题 → 固化用例）

| 历史事件 | 固化位置 |
|---|---|
| H1：`subagent` 白名单短路绕过 mixed 拒绝（生产 1682 条 explicit-allow 实证） | `test-gate-prod.mts` F 组（t7 迁移）+ README ⚠️ 警示 |
| 敏感读经重定向渗漏（`cat ~/.ssh/id_rsa > 保护区`） | `test-classifier.mts` C 组 + `test-gate-prod.mts` C 组（forceDeny 优先于路径豁免） |
| 灾难模式 `rm -rf /` | `test-classifier.mts` H 组（decide 强拒） |
| 0.1.1 声明 `<0.2.0-0` 挡掉全部 0.2.x 用户 | `verify-peer-matrix.mjs`（0.2.0-rc.2 必须 PASS） |
| 0.2.0 三段式漏配 0.1.0/0.1.1 stable | `verify-peer-matrix.mjs`（0.1.0/0.1.1 必须 PASS，四段式） |
| **`$HOME` 变量展开绕过敏感读**（`cat $HOME/.ssh/id_rsa` 曾放行；0.2.3 修复：expandHome/toAbsolute 归一化 `$HOME`/`${HOME}`） | `test-adversarial.mts` GAP 组（先红后绿） |
| **`cd` 上下文绕过**（`cd ~/.ssh && cat id_rsa` 曾放行；0.2.3 修复：cd 后敏感目录内 read 类 segment 即 deny） | `test-adversarial.mts` GAP 组（先红后绿） |
| 发布物与提交漂移 / 未提交改动混入 | `verify-reproducible-build.mjs` |
| 本地路径/测试残留进公开仓库 | `verify-pack-audit.mjs` + `.gitignore` 锁定 |

**规则**：任何新发现的缺陷，修复时**先固化用例再修代码**（先让用例红，再让用例绿）。

## 环境要求

- L0/L1/L2/L3：Node ≥ 20 + npm + git（CI 用 macOS runner 可全跑）
- L4/L5/L6：macOS + APFS + Time Machine 配置 + 本地 dsh 安装（不能进 CI）

## CI

`.github/workflows/test.yml`：push/PR 自动跑 L0+L1+L2+L3（`npm run verify:fast`）。L4/L5 因需真实 TM 与 dsh 会话，保持本地手动（发布前执行）。
