# dsh-tm-guard — 发布门禁（RELEASE.md）

每次发布新版本，**按顺序**执行以下清单。任何一步失败 → 停止，修复后从失败步骤重跑。全部通过才允许 `npm publish`。

> 先决：确认要发布的版本号（`package.json version`）与 `CHANGELOG.md` 新条目一致。

## 自动门禁（L0–L3，一条命令）

```bash
npm run release:check    # = verify:fast = test + verify:peer + verify:build + verify:pack
```

| 层 | 通过标准 |
|---|---|
| `npm test` | 8 测试文件全过（pass ≥ 8 / fail 0） |
| `verify:peer` | 矩阵 12/12 期望全中（含 0.1.0/0.1.1/0.1.2-rc.1/0.2.0-rc.2 必须匹配） |
| `verify:build` | lib/ + 随包文件与 git HEAD 重建逐字节一致（**先 commit 再跑**） |
| `verify:pack` | 14 文件、无本地路径、无源码/测试/scratch 泄漏 |

## 手动门禁（L4–L6，发布前必做）

### 步骤 5 — 双线隔离冒烟（L4）

**0.1.x 线**（profile `tm-01`，端口 3091，dsh 备份二进制 `0.1.2-rc.1`）：
1. `dsh --profile tm-01` 起实例（用 `/opt/homebrew/lib/node_modules/@deepseek-ai/dsh.bak-0.1.2-rc.1/lib/bin.js`）
2. 验证：加载无 skip · 7 个 tm_* 工具注册 · 写受保护放行 · 越界写拒绝（文件未产生）· 敏感读 forced deny · 审计一一对应 · `tm_status` HEALTHY

**0.2.x 线**（隔离 profile `tm-test`，端口 3090，生产同款配置）：
1. 起实例 → 重复上述 6 项验证
2. 白名单短路（H1）：对照审计 `explicit-allow` 计数与对照组 `send_message` 拒绝

### 步骤 6 — 独立复核（L5）

委派 dsh 独立会话（cwd = 插件仓库），目标 = **npm 发布物**（发布后执行，或 `npm pack` 产物预演）：
- peer 严格语义成立（对当前 dsh 版本）
- 发布物 14 文件与 gitHead 提交重建 SHA 逐字节一致
- 函数级门控 40 自建用例 + 厂商 208 用例全过
- 生产审计活性（若生产已升级）

### 步骤 7 — 内容隐私审查（L6）

- `git log --oneline -10` 检查无本地路径/session id/端口/token
- `npm run verify:pack`（L2 已覆盖机器扫描）
- 本地报告（guide/测试报告）确认留在 `.smoke-out/`（gitignore），不进提交
- 历史 blob 无敏感残留（必要时 `git reset --soft origin/main` 压缩）

## 发布执行

```bash
git push origin main
git tag v<version> && git push origin v<version>
npm publish                      # 本机终端（2FA 认证流）
npm view dsh-tm-guard dist-tags  # 确认 latest = <version>
gh release create v<version> --generate-notes --repo ChaoJie0/dsh-tm-guard
```

## 发布后验证

1. registry API：`curl -s https://registry.npmjs.org/dsh-tm-guard` → `dist-tags.latest` 正确、`gitHead` 与本地提交一致
2. 生产升级（可选）：`cd ~/.dsh/profiles/web && pnpm add dsh-tm-guard@<version>` → 重启 web → `tm_status` 冒烟 HEALTHY
3. 发布物独立复核（L5，对已发布版本执行）

## 发布后回滚预案（从未使用过，保留）

- npm：`npm publish` 不可撤回 → 回滚策略 = 发布修复版 `<version>.1`；`npm deprecate` 标注旧版
- GitHub：删除 tag/release（`gh release delete` + `git push origin :refs/tags/v<version>`）
- 生产：`pnpm add dsh-tm-guard@<上一版>` 降级 + 重启
