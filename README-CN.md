# misteye-security-check

GitHub repository: [https://github.com/slowmist/misteye-skills](https://github.com/slowmist/misteye-skills)

[中文版](README-CN.md) | [English](README.md)

MistEye 安全前置闸门 Skill。

核心目标：把“依赖安装”和“外部 URL/域名访问”变成**先检测再执行**的硬门禁流程，并提供每日巡检能力（OpenClaw/Hermes）。

## 1. 功能概览

- 唯一检测接口：`POST https://app-api.misteye.io/functions/v1/detect`
- 官方文档：`https://app.misteye.io/api-docs`
- 检测类型：`ip` / `ip:port` / `domain` / `url` / `email` / `file_hash` / `md5` / `sha1` / `sha256` / `package:*`
- 高优先级门禁：
  - 依赖安装前检测
  - URL/域名访问前检测
  - Skill/MCP 安装前依赖声明扫描
- 阻断策略：
  - API `safe=false` 或 `matches` 非空 -> 已拦截
  - `error` / `no_check` -> 已拦截（未完成检测）
  - API `safe=true` 且 `matches=[]` -> 可继续但必须带风险提示

## 2. 前置检测触发规则（防漏检）

以下任一情况，必须先做 MistEye 检测，再进入正文回答：

- 用户输入包含 URL（`http://` 或 `https://`）
- 用户输入包含域名（如 `example.com`）
- 用户要求“看一下/分析/检查/访问/打开/下载”某个地址或链接

URL 场景必须：

1. 同时检测 `url` 与 `domain`
2. 先输出前置检测结论
3. 只有“可继续”才允许输出网站信息/HTTP 状态/功能分析

## 3. Skill/MCP 依赖扫描边界

该 Skill 在安装场景中只扫描“依赖安装库相关对象”，**不判定 Skill/MCP 本体是否恶意**。

- 扫描对象来源：依赖声明文件（`requirements*.txt`、`package.json`、`go.mod`、`Cargo.toml` 等）
- 提取对象：供应链包（优先 `package:*`）以及原文显式出现的 `url` / `domain` / `email` / `hash`
- 不扫描对象：`SKILL.md` 文本内容、提示词文案、脚本业务逻辑本体
- 安装阶段必须“逐项解析依赖条目”（dependency_id），不能只检测公共仓库域名替代依赖扫描

## 4. 每日巡检（首次安装时提醒开启）

提醒策略：

- 仅首次安装完成（或首次启用）时提醒开启巡检
- 默认建议每天 1 次
- 后续常规使用不重复提醒（除非用户主动要求查看巡检配置）

每日巡检固定顺序：

1. 网络连通性预检（`app-api.misteye.io`、`raw.githubusercontent.com`）
2. 凭据预检（`MISTEYE_API_KEY`）
3. 版本检查（上游仓库）
4. 已安装 Skill/MCP 依赖对象巡检（必须）
5. 新版本提醒（如有）
6. 常规巡检摘要

巡检覆盖率要求（防漏扫）：

- 必须先枚举全部已安装 Skill/MCP 目录，再逐目录扫描依赖文件
- 报告中必须给出：安装目录总数、已扫描目录数、依赖文件总数、成功解析文件数、失败文件数
- 若覆盖不足或解析失败，必须输出告警

## 5. 网络受限与降级策略（重点）

如果你在 `isolated` 会话里运行 cron，经常会遇到网络或环境变量不继承问题。

本 Skill 的标准处理是：

- 网络不通 -> 输出 `【网络连通性告警】`，标记 `degraded`
- 凭据缺失 -> 输出 `【凭据缺失告警】`，标记 `degraded`
- `degraded` 下允许继续做本地依赖文件统计，但**禁止伪造“检测成功”**
- API `safe=true` 且 `matches=[]` 仅表示未命中情报库，禁止写成“Clean/无风险/安全通过”
- 供应链包未命中时可提示用户是否到对应生态的官方包源/注册表查看包元数据（如 npm registry、PyPI、NuGet、RubyGems、pkg.go.dev、crates.io）；未经用户同意不自动打开或查询

OpenClaw 默认推荐用 `--session "shared"` 跑该任务，`isolated` 仅作为备选模式。OpenClaw 和 Hermes 只作为定时任务执行器，不作为 MistEye API key 的主存储位置。

## 6. 凭据管理（禁止明文硬编码）

禁止把 API Key 明文写进 cron payload/message/聊天日志/命令历史。

如果没有 API key：

- 打开 `https://app.misteye.io/api-keys` 获取或管理 key
- 如果没有 MistEye 账号，先注册，再创建 API key

推荐一次性初始化：

```bash
mkdir -p "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}"
read -s MISTEYE_API_KEY && echo
printf '%s' "$MISTEYE_API_KEY" > "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}/api_key"
chmod 600 "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}/api_key"
unset MISTEYE_API_KEY
```

巡检时凭据加载顺序：

1. 环境变量 `MISTEYE_API_KEY`
2. `${MISTEYE_CONFIG_DIR}/api_key`（当 `MISTEYE_CONFIG_DIR` 已设置）
3. `$HOME/.config/misteye/api_key`

## 7. 提取规则（防误检）

- 检测对象只能从“实际扫描到的依赖文件原文”提取
- 每个对象必须有来源证据（文件路径 + 行号或字段路径）
- 禁止用预置生态域名清单补全（例如默认加入 `pypi.org`、`npmjs.org` 等）
- 禁止只检测 `pypi.org/files.pythonhosted.org` 这类公共域名来宣称“依赖已扫描”
- 每个依赖条目都必须先做一次供应链包直查；可识别生态时使用 `package:npm` / `package:pypi` / `package:nuget` / `package:rubygems` / `package:go` / `package:cratesio`
- 只有依赖原文存在显式 url/domain/email/hash 时，才追加这些对象检测（不能替代供应链包直查）
- 硬约束：`dependency_package_detect_count >= dependency_item_count`，否则必须输出 `【巡检覆盖不足告警】`
- 只有空值/注释/异常损坏等无法形成有效依赖字符串时，才计入 `unresolved_source`

## 8. 任务模板（简版）

### OpenClaw（推荐 shared）

```bash
openclaw cron add \
  --name "misteye-dependency-patrol" \
  --description "每晚安全巡检" \
  --cron "0 3 * * *" \
  --tz "Asia/Shanghai" \
  --session "shared" \
  --message "先做网络连通性预检和 MISTEYE_API_KEY 凭据预检；再做版本检查；再巡检已安装 Skill/MCP 的依赖声明。必须逐项解析 dependency_id，并对每个依赖先执行供应链包直查（优先 package:* 类型）；若依赖原文存在显式 url/domain/email/hash 再追加检测。仅检测公共仓库域名不算完成。输出 dependency_item_count 与 dependency_package_detect_count；若前者大于后者，输出【巡检覆盖不足告警】并标记 degraded。网络或凭据不可用时输出告警并标记 degraded。" \
  --announce \
  --channel <channel> \
  --to <your-chat-id> \
  --timeout-seconds 300 \
  --thinking off
```

### Hermes

```bash
hermes cron create "0 3 * * *" \
  "先做网络连通性预检和 MISTEYE_API_KEY 凭据预检；再做版本检查；再巡检已安装 Skill/MCP 的依赖声明。必须逐项解析 dependency_id，并对每个依赖先执行供应链包直查（优先 package:* 类型）；若依赖原文存在显式 url/domain/email/hash 再追加检测。仅检测公共仓库域名不算完成。输出 dependency_item_count 与 dependency_package_detect_count；若前者大于后者，输出【巡检覆盖不足告警】并标记 degraded。网络或凭据不可用时输出告警并标记 degraded。" \
  --name "misteye-dependency-patrol" \
  --deliver origin
```

## 9. 相关文件

- 规则主文件：`SKILL.md`
- API 说明：`references/api.md`
- UI 元数据：`agents/openai.yaml`
