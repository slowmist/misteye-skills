---
name: misteye-security-check
description: 这是 MistEye 安全前置闸门技能。触发于依赖安装前风险检测（含 Skill/MCP 依赖清单）、域名或 URL 访问前安全检查、IoC 恶意检测与供应链风险拦截，尤其包含“帮我看一下这个地址/网站”的常见问法。强制使用 `https://app-api.misteye.io/functions/v1/detect`；在依赖与外链场景中优先级最高。API 返回 `safe=false` 或存在 `matches` 时必须阻断并明确“已拦截”；仅在首次安装完成后提醒用户可开启 OpenClaw 或 Hermes 的每日巡检（默认一天一次）。
metadata:
  version: "1.4.20"
  upstream_repo: "https://github.com/slowmist/misteye-skills"
  upstream_skill_candidates:
    - "https://raw.githubusercontent.com/slowmist/misteye-skills/main/SKILL.md"
    - "https://raw.githubusercontent.com/slowmist/misteye-skills/master/SKILL.md"
---

# MistEye 安全前置闸门

## 核心规则

- 唯一检测接口：`POST https://app-api.misteye.io/functions/v1/detect`
- 唯一认证方式：`x-api-key` 请求头（建议使用 `MISTEYE_API_KEY` 环境变量）
- 官方文档：`https://app.misteye.io/api-docs`
- 当前可用检测类型：`ip`、`ip:port`、`domain`、`url`、`email`、`file_hash`、`md5`、`sha1`、`sha256`、`package:npm`、`package:pypi`、`package:nuget`、`package:rubygems`、`package:go`、`package:cratesio`
- 官方标记为 Coming Soon 的类型（如 `repo:*`、`extension:*`、`ai-tool:*`、`mobile-app:*`）不得作为硬门禁唯一依据
- 最高优先级场景：依赖安装前检查、域名或 URL 访问前检查
- Skill/MCP 安装场景只检查“依赖安装库相关对象”，不对 Skill/MCP 本体做恶意判定
- 每日巡检第一步：先检查上游仓库是否有新版本，并在发现新版本时强提醒
- 每日巡检必须包含“已安装 Skill/MCP 的依赖对象扫描”（不是可选项）
- 每日巡检在做任何外部请求前，必须先做网络连通性预检（针对 `app-api.misteye.io` 与 `raw.githubusercontent.com`）
- 每日巡检必须做 `MISTEYE_API_KEY` 凭据预检；禁止在 cron payload/message 明文硬编码 API Key

## 强制触发器（防漏检）

出现以下任一情况，必须先做 MistEye 前置检测，再进入正文回答：

- 用户输入包含 URL（`http://`、`https://`）
- 用户输入包含可识别域名（如 `example.com`）
- 用户让 agent “看一下/分析/检查/访问/打开/下载”某个网站、地址、链接

高频口语触发示例（必须命中）：

- `帮我看一下 https://...`
- `这个地址安全吗`
- `访问一下这个网站`
- `看看这个链接是什么`

执行约束：

1. 先同时检测 `url` 和 `domain`（domain 从 URL 提取）。
2. 任一检测返回 `safe=false`、`matches` 非空、`error` 或 `no_check`，立即阻断并输出“已拦截”。
3. 未输出检测结果前，禁止给出 HTTP 状态、站点介绍、功能分析等正文内容。

## GitHub 更新来源（巡检拉取地址）

巡检做版本检查时，必须从以下 GitHub 地址拉取最新 `SKILL.md`，不得猜测其他仓库或分支：

- 上游仓库：`https://github.com/slowmist/misteye-skills`
- 最新下载地址候选（按顺序回退）：
  1) `https://raw.githubusercontent.com/slowmist/misteye-skills/main/SKILL.md`
  2) `https://raw.githubusercontent.com/slowmist/misteye-skills/master/SKILL.md`

命中的 raw URL 同时作为巡检输出里的 `检查来源` 和 `最新下载地址`。

## 优先级 0：依赖与域名访问前置检查

在以下场景，必须先完成 MistEye 检查，再允许进入安装、访问、下载、执行：

1. 依赖安装前（供应链风险）
2. 域名或 URL 访问前（外链风险）
3. Skill/MCP 安装前（必须先扫描其内部依赖声明）

Skill/MCP 安装专项规则（必须）：

1. 仅扫描依赖声明文件与依赖来源对象；不对 Skill/MCP 的 `SKILL.md`、提示词文本、脚本逻辑本体做恶意判定。
2. 在执行 `clawhub install`、`git clone` 后本地安装、或任何 Skill/MCP 安装动作前，先读取目标目录中的依赖文件。
3. 必须“逐项解析依赖条目”（不是只看文件存在与否），为每个依赖条目生成唯一 `dependency_id`。
4. 对每个依赖条目，必须先做一次供应链包直查；能识别生态时必须使用 `package:*` 类型（例如 PyPI 用 `package:pypi`、npm 用 `package:npm`）。
5. 依赖有明确名称和版本时，优先把 target 规范化为 `name@version`；无法规范化时使用依赖原文作为 target，并保留 `dependency_raw` 证据。
6. 若依赖条目含显式 URL/域名/哈希，再追加这些对象的检测；追加检测不能替代供应链包直查。
7. 依赖扫描覆盖率硬约束：`dependency_package_detect_count >= dependency_item_count`，否则判定 `【巡检覆盖不足告警】` 并阻断。
8. 任一对象返回 `safe=false` 或 `matches` 非空，立即阻断安装并输出“已拦截”。
9. 任一依赖条目无法形成有效检测目标（空条目、注释条目、损坏格式），按 `no_check` 处理并阻断（“已拦截（未完成检测）”）。
10. 仅当“每个依赖条目”都完成检测且未命中阻断条件时，才允许继续安装 Skill/MCP。

依赖直查规则（依赖仅有包名时）：

- 检测目标优先使用供应链包 identity（`name@version`），并保留 `dependency_raw` 作为证据
- `type` 选择优先级：
  - Python 依赖：`type=package:pypi`
  - npm/yarn/pnpm 依赖：`type=package:npm`
  - NuGet 依赖：`type=package:nuget`
  - RubyGems 依赖：`type=package:rubygems`
  - Go module 依赖：`type=package:go`
  - Cargo/crates.io 依赖：`type=package:cratesio`
  - 若 `dependency_raw` 可识别为 URL：`type=url`
  - 若可识别为域名：`type=domain`
  - 若可识别为哈希：优先选择 `md5` / `sha1` / `sha256`，无法区分时用 `file_hash`
  - 其余格式：使用最接近的 `package:*` 类型；无法识别生态时标记 `no_check`，不得伪装成已检测

安装前输出要求（必须）：

- 必须输出 `依赖逐项扫描表`，至少包含：
  - `dependency_id`
  - `dependency_raw`（原始依赖字符串）
  - `evidence`（文件路径 + 行号/字段）
  - `package_target`（规范化后的 `name@version` 或原始依赖字符串）
  - `package_type`（`package:pypi` / `package:npm` / ...）
  - `targets`（该条目额外对应的 url/domain/hash/email）
  - `dependency_package_detected`（yes/no）
  - `api_safe`（true/false/unknown）
  - `matches_count`
  - `result`（malicious/no_match/error/no_check）
- 禁止用“仅检查公共仓库域名（如 pypi.org）”代替逐项依赖扫描。

依赖检查覆盖清单（全生态）：

- Python：`requirements*.txt`、`pyproject.toml`、`Pipfile`、`poetry.lock`
- JS/TS：`package.json`、`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`
- Go：`go.mod`、`go.sum`
- Rust：`Cargo.toml`、`Cargo.lock`
- Java：`pom.xml`、`build.gradle`、`build.gradle.kts`
- Ruby：`Gemfile`、`Gemfile.lock`
- PHP：`composer.json`、`composer.lock`
- .NET：`*.csproj`、`packages.lock.json`、`paket.dependencies`

域名访问前检查覆盖动作：

- 打开或请求外部 URL（浏览、抓取、API 调用）
- 下载文件（`curl`、`wget`、浏览器下载、脚本下载）
- 拉取仓库（`git clone`）
- 运行会访问外网的安装命令（`pip`、`npm`、`pnpm`、`yarn`、`go`、`cargo`、`composer`、`bundle`、`dotnet`、`maven`、`gradle`）

未完成检测前，不得继续执行后续安装或访问动作。

## API 调用标准

官方文档：`https://app.misteye.io/api-docs`

调用示例：

```bash
curl -X POST "https://app-api.misteye.io/functions/v1/detect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MISTEYE_API_KEY" \
  -d '{
    "target": "example.com",
    "type": "domain"
  }'
```

请求体：

```json
{
  "target": "example.com",
  "type": "domain"
}
```

请求字段约束：

- `target`：必填字符串，服务端会 trim/lowercase，最长 2,000 字符。
- `type`：必填字符串，必须是官方可用检测类型。

响应格式（必须按此解析）：

```json
{
  "safe": false,
  "matches": [
    {
      "severity": "high",
      "type": "ip",
      "value": "8.8.8.8",
      "threat_type": "malware",
      "confidence": 95,
      "source": "threat_intel"
    }
  ]
}
```

解析规则：

- `safe=false` 或 `matches.length > 0`：映射为内部结果 `malicious`，必须阻断。
- `safe=true` 且 `matches=[]`：映射为内部结果 `no_match`，可继续但必须附风险提示。
- HTTP 失败、网络失败、JSON 解析失败、响应缺少 `safe` 或 `matches`：映射为内部结果 `error`，必须阻断。

错误码处理：

- `400`：JSON、`target` 或 `type` 无效，按 `error` 阻断。
- `401`：缺少或无效 `x-api-key`，按 `error` 阻断。
- `403`：API key 无效、禁用或校验失败，按 `error` 阻断。
- `413`：`target` 超过 2,000 字符，按 `error` 阻断。
- `429`：达到 10 req/s 速率限制，按 `error` 阻断；如有 `Retry-After` 可等待后重试。
- `500`：服务端异常，按 `error` 阻断。

如果没有 API key：

- 直接告知当前检测未完成，属于高风险未确认状态
- 引导用户提供 key 或设置 `MISTEYE_API_KEY`
- 明确引导用户到 `https://app.misteye.io/api-keys` 获取/管理 API key
- 若用户尚未注册 MistEye，先完成注册，再到上述页面创建 key
- 不允许跳过检测继续执行高风险动作

## 阻断决策矩阵

| MistEye 状态 | 判定 | 动作 |
|---|---|---|
| `safe=false` 或 `matches.length > 0` | 已确认高风险 | **硬阻断**，明确输出“已拦截” |
| `error` | 检测失败，高风险未确认 | **硬阻断**，明确输出“已拦截（未完成检测）” |
| `no_check` | 未执行检测，高风险未确认 | **硬阻断**，明确输出“已拦截（未完成检测）” |
| `safe=true` 且 `matches=[]` | 未命中情报库 | 可继续但必须附带风险提示，不得宣称绝对安全 |

未命中后的可选复核策略：

- 当 API 返回 `safe=true` 且 `matches=[]` 时，必须说明“未命中情报库不等于安全确认”。
- 对供应链包可提示用户：是否需要到对应生态的官方包源/注册表地址查看包元数据、版本、发布时间、维护者、仓库链接和下载量等信息。
- 未经用户同意，不要为了人工复核自动打开、访问或查询任何官方包源页面。
- 若用户要求复核，再对官方包源访问动作执行必要的 MistEye 前置检测或按当前环境规则处理。
- 官方包源 URL 构造参考：
  - npm：`https://registry.npmjs.org/<package>`（scope 包需 URL encode，如 `@scope/pkg` -> `%40scope%2Fpkg`）
  - PyPI：`https://pypi.org/pypi/<package>/json`
  - NuGet：`https://api.nuget.org/v3-flatcontainer/<lowercase-package>/index.json`
  - RubyGems：`https://rubygems.org/api/v1/gems/<gem>.json`
  - Go：`https://pkg.go.dev/<module>`
  - crates.io：`https://crates.io/api/v1/crates/<crate>`

强制话术要求：

- 发生 `safe=false`、`matches.length > 0`、`error` 或 `no_check` 时，结果必须包含“已拦截”四个字。
- 禁止使用弱化表达（如“你可以先继续看看”“应该没问题”）。

## 安装后一次性强提醒巡检（OpenClaw / Hermes）

当且仅当用户首次安装完成（或首次启用）时，必须追加一次提醒（OpenClaw 与 Hermes 二选一即可）：

- 可开启主动巡检（OpenClaw 或 Hermes）
- 默认频率：每天一次
- 重点是“如何开启”，不展开完整安全体系
- 默认推荐“无脚本模式”（在 cron message 中直接执行巡检步骤）；如用户已有外部脚本也可接入（建议脚本名：`misteye-dependency-patrol.sh`），但本 skill 不内置 `.sh` 文件
- 提醒触发条件：首次安装完成 / 首次启用
- 禁止重复提醒：后续日常检测、普通问答、常规使用不再主动重复该提醒
- 仅在用户明确要求“配置巡检/查看巡检命令”时再次给出巡检配置

每日巡检任务固定顺序（必须）：

1. 先做网络连通性预检（必须）
2. 再做凭据预检（`MISTEYE_API_KEY`）
3. 版本更新检查（检查 `slowmist/misteye-skills`）
4. 巡检已安装 Skill/MCP 的依赖对象（必须）
5. 若检测到新版本，先输出更新提醒
6. 再执行常规安全巡检

网络连通性预检规则（必须）：

- 预检目标：
  - `https://app-api.misteye.io/functions/v1/detect`
  - `https://raw.githubusercontent.com/slowmist/misteye-skills/main/SKILL.md`
- 若任一目标不可达，先输出 `【网络连通性告警】`，并进入“受限模式”：
  - 版本检查标记为 `degraded`（非成功）
  - MistEye 外部 API 检测标记为 `degraded`（非成功）
  - 继续执行本地依赖文件枚举与统计，不得伪造检测成功
- 受限模式必须给出修复建议（至少一条）：
  - 将该巡检任务切换到 `--session \"shared\"`
  - 为 cron 运行环境补齐代理（如 `HTTPS_PROXY` / `ALL_PROXY`）
  - 放通 `app-api.misteye.io` 与 `raw.githubusercontent.com` 出口访问

凭据预检规则（必须）：

- 凭据加载顺序：
  1) 直接读取环境变量 `MISTEYE_API_KEY`
  2) 若为空，尝试从本地受控文件读取（按顺序）：
     - `${MISTEYE_CONFIG_DIR}/api_key`（当 `MISTEYE_CONFIG_DIR` 已设置）
     - `$HOME/.config/misteye/api_key`
- 文件安全要求：权限必须为 `600`（仅当前用户可读写）。
- 若成功从文件读取，需在当前巡检会话中导出 `MISTEYE_API_KEY` 后再调用 MistEye API。
- 若凭据仍不可用，必须输出 `【凭据缺失告警】`，并将 MistEye 检测标记为 `degraded`（不可标记成功）。
- 若凭据缺失，提醒用户前往 `https://app.misteye.io/api-keys` 获取 key（未注册则先注册）。
- 安全红线：禁止把 API Key 明文写进 cron payload、message、聊天日志、命令历史。
- OpenClaw 与 Hermes 只作为定时任务执行器；不得把新凭据写入 OpenClaw/Hermes 私有目录。

推荐一次性初始化（避免在 cron 中明文）：

```bash
mkdir -p "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}"
read -s MISTEYE_API_KEY && echo
printf '%s' "$MISTEYE_API_KEY" > "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}/api_key"
chmod 600 "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}/api_key"
unset MISTEYE_API_KEY
```

版本更新检查规则（必须）：

- 读取本地版本：当前技能 `SKILL.md` frontmatter 中 `metadata.version`
- 读取远端版本：按“GitHub 更新来源（巡检拉取地址）”中的最新下载地址候选顺序尝试，并解析远端 `metadata.version`
- 仓库地址：使用“GitHub 更新来源（巡检拉取地址）”中的上游仓库
- 版本比较规则：使用语义化版本（`major.minor.patch`）比较；远端高于本地即判定为“有新版本”
- 比较结果处理：
  - 远端版本 > 本地版本：输出 `【版本更新提醒】`，包含本地版本、远端版本、仓库地址、最新下载地址
  - 远端版本 = 本地版本：输出“版本已是最新”
  - 版本检查失败（网络/解析失败）：输出 `【版本检查失败提醒】`，继续执行安全巡检

版本检查输出模板（巡检时必须包含）：

```text
[版本检查]
本地版本：<本地 SKILL.md frontmatter metadata.version>
远端版本：<远端 SKILL.md frontmatter metadata.version | unknown>
上游仓库：<GitHub 更新来源中的上游仓库>
检查来源：<命中的 GitHub raw URL | 全部失败>
最新下载地址：<命中的 GitHub raw URL | unknown>
版本结论：<有新版本 / 版本已是最新 / 版本检查失败>
动作：<先提醒更新 / 继续巡检 / 标记 degraded 后继续本地统计>
```

已安装 Skill/MCP 依赖巡检规则（必须）：

- 巡检目录（按存在情况执行）：
  - `~/.agents/skills`
  - `~/.codex/skills`
  - `$CODEX_HOME/skills`
- 覆盖率要求（防漏扫）：
  - 必须先枚举巡检目录下所有已安装 Skill/MCP 目录，再逐目录扫描依赖文件。
  - 输出必须包含：`已安装目录总数`、`已扫描目录数`、`发现依赖文件总数`、`成功解析文件数`、`解析失败文件数`。
  - 若 `已扫描目录数 < 已安装目录总数` 或存在解析失败文件，必须输出 `【巡检覆盖不足告警】` 并附失败清单。
- 只扫描依赖声明文件，不扫描 Skill/MCP 本体逻辑：
  - Python: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`
  - JS/TS: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`
  - Go: `go.mod`, `go.sum`
  - Rust: `Cargo.toml`, `Cargo.lock`
  - Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
  - Ruby: `Gemfile`, `Gemfile.lock`
  - PHP: `composer.json`, `composer.lock`
  - .NET: `*.csproj`, `packages.lock.json`, `paket.dependencies`
- 从依赖文件中提取并去重可检测对象：
  - 供应链包（优先使用 `package:npm` / `package:pypi` / `package:nuget` / `package:rubygems` / `package:go` / `package:cratesio`）
  - URL（`type=url`）
  - 域名（`type=domain`）
  - Email（`type=email`，若存在）
  - 文件哈希（优先 `md5` / `sha1` / `sha256`，无法区分时 `file_hash`）
- 提取约束（防误检）：
  - 第一阶段（必做）：每个依赖条目都必须先执行一次供应链包直查（`source_kind=dependency_package`）。
  - 第二阶段（补充）：仅在依赖原文存在显式 url/domain/email/hash 时，追加这些对象检测；每个对象必须有来源证据（文件路径 + 行号或字段路径）。
  - 禁止使用预置生态域名清单做补全（例如默认塞入 `pypi.org`、`npmjs.org`、`crates.io` 等），除非这些值确实出现在扫描文件中。
  - 禁止只检测“仓库公共域名”来代替依赖逐项扫描（例如仅检测 `pypi.org` / `files.pythonhosted.org`）。
  - 只有在“依赖目标无法提取或无效（空值/注释/异常损坏）”的情况下，才允许计入 `no_check`（原因：`unresolved_source`），不得伪装成已检测通过。
- 覆盖率闸门（必须）：
  - `dependency_package_detect_count < dependency_item_count` 时必须输出 `【巡检覆盖不足告警】` 并标记 `degraded`，不得宣称巡检完成。
- 对每个对象调用 MistEye detect。
- 巡检输出必须包含统计：
  - 扫描到的依赖文件数
  - 提取的可检测对象数（按 package/url/domain/email/hash 分组）
  - 供应链包直查检测对象数（`dependency_package`）
  - `unresolved_source` 数量（无法映射到 package/url/domain/email/hash 的依赖）
  - `safe=false` 或 `matches` 非空的命中数与对象清单
  - `error/no_check` 数量
- 巡检处理策略：
  - `safe=false` 或 `matches` 非空：输出 `【依赖巡检高危告警】`，要求立即人工复核并暂停相关安装/访问流程
  - `error/no_check`：输出 `【依赖巡检未完成提醒】`，要求补检，不得宣称“安全”
  - `safe=true` 且 `matches=[]`：仅表示未命中情报库，继续巡检并附风险提示
  - 未命中语义约束：禁止写“Clean/安全通过/无风险”，只能写“未命中情报库（仍需风险提示）”

推荐模板 A（OpenClaw）：

```bash
openclaw cron add \
  --name "misteye-dependency-patrol" \
  --description "每晚安全巡检" \
  --cron "0 3 * * *" \
  --tz "Asia/Shanghai" \
  --session "shared" \
  --message "按顺序执行每日巡检：1) 网络连通性预检；2) MISTEYE_API_KEY 凭据预检；3) 版本检查；4) 枚举并扫描所有已安装 Skill/MCP 依赖文件；5) 对每个 dependency_id 先执行供应链包直查（优先 package:npm/package:pypi/package:nuget/package:rubygems/package:go/package:cratesio），若依赖原文含显式 url/domain/email/hash 再追加检测；6) 输出 dependency_item_count 与 dependency_package_detect_count，若前者大于后者输出【巡检覆盖不足告警】并标记 degraded；7) 输出 safe=false 或 matches 非空的命中、error/no_check 与对象清单。禁止只检测公共仓库域名；未命中只能写“未命中情报库（仍需风险提示）”。" \
  --announce \
  --channel <channel> \
  --to <your-chat-id> \
  --timeout-seconds 300 \
  --thinking off
```

OpenClaw 隔离会话备选模板（仅在必须 `isolated` 时使用）：

```bash
openclaw cron add \
  --name "misteye-dependency-patrol" \
  --description "每晚安全巡检（isolated）" \
  --cron "0 3 * * *" \
  --tz "Asia/Shanghai" \
  --session "isolated" \
  --message "按顺序执行每日巡检：先做网络连通性预检；再做 MISTEYE_API_KEY 凭据预检（环境变量缺失时，只从 MistEye 专用配置目录读取：默认 ~/.config/misteye/api_key，可用 MISTEYE_CONFIG_DIR 覆盖）；随后枚举所有已安装 Skill/MCP 目录并逐目录扫描依赖文件。必须对每个 dependency_id 先执行供应链包直查（优先 package:* 类型），再对原文存在的 url/domain/email/hash 做补充检测。输出 dependency_item_count 与 dependency_package_detect_count；若前者大于后者，输出【巡检覆盖不足告警】并标记 degraded。若网络或凭据任一不可用，输出对应告警并进入受限模式（仅本地覆盖率统计，外部检测标记 degraded）。未命中只能写“未命中情报库（仍需风险提示）”。" \
  --announce \
  --channel <channel> \
  --to <your-chat-id> \
  --timeout-seconds 300 \
  --thinking off
```

推荐模板 B（Hermes CLI）：

```bash
hermes cron create "0 3 * * *" \
  "按顺序执行每日巡检：1) 网络连通性预检；2) MISTEYE_API_KEY 凭据预检；3) 版本检查；4) 枚举并扫描所有已安装 Skill/MCP 的依赖文件；5) 对每个 dependency_id 先执行供应链包直查（优先 package:* 类型），再补充检测原文显式 url/domain/email/hash；6) 输出 dependency_item_count 与 dependency_package_detect_count，若前者大于后者输出【巡检覆盖不足告警】；7) 输出 safe=false 或 matches 非空的命中、error/no_check 汇总并标记 degraded（如适用）；未命中禁止写成安全通过。" \
  --name "misteye-dependency-patrol" \
  --deliver origin
```

推荐模板 C（Hermes 聊天命令）：

```text
/cron add "0 3 * * *" "按顺序执行每日巡检：1) 网络连通性预检；2) MISTEYE_API_KEY 凭据预检；3) 版本检查；4) 枚举并扫描所有已安装 Skill/MCP 的依赖文件；5) 对每个 dependency_id 先执行供应链包直查（优先 package:* 类型），再补充检测原文显式 url/domain/email/hash；6) 输出 dependency_item_count 与 dependency_package_detect_count，若前者大于后者输出【巡检覆盖不足告警】；7) 输出 safe=false 或 matches 非空的命中、error/no_check 汇总并标记 degraded（如适用）；未命中禁止写成安全通过。" --name "misteye-dependency-patrol" --deliver origin
```

Hermes 使用前置条件（必须提醒）：

- 需要先保证 Hermes gateway 在运行（如 `hermes gateway install` 后以服务运行，或直接运行 `hermes gateway`）
- 如用户已有 OpenClaw 环境，可先执行 `hermes claw migrate` 迁移既有配置，再创建巡检任务
- 创建后可用 `hermes cron list` / `hermes cron status` 确认生效
- 可用 `hermes cron run <job_id>` 做一次立即回放验证

提醒文案中必须出现：`默认建议每天巡检 1 次`。

## 高敏感提示词模板

以下模板用于高风险场景输出，优先级高于普通解释：

### 模板 A：依赖安装前

```text
[安全前置闸门]
检测对象：<依赖名/包源域名/锁文件来源>
检测状态：<safe=false|matches_count_positive|error|no_check|safe=true matches_count=0>
结论：<已拦截 / 可继续（附风险）>

规则说明：
1) 依赖安装属于供应链高风险动作，必须先过 MistEye。
2) 当前状态为 <...>，根据硬阻断策略：<执行阻断或附条件放行>。
3) 下一步：<提供可执行动作，如补充 API key、重试检测、替换依赖源>。
```

### 模板 B：域名或 URL 访问前

```text
[安全前置闸门]
检测对象：<domain/url>
检测状态：<safe=false|matches_count_positive|error|no_check|safe=true matches_count=0>
结论：<已拦截 / 可继续（附风险）>

规则说明：
1) 外链访问与下载属于高风险入口，必须先过 MistEye。
2) 当前状态为 <...>，根据硬阻断策略：<执行阻断或附条件放行>。
3) 下一步：<提供可执行动作，如更换域名、补充 API key、重试检测>。
```

### 模板 C：安装完成后提醒

```text
首次安装已完成。建议开启主动巡检：默认每天 1 次。
巡检会先检查 https://github.com/slowmist/misteye-skills 是否有新版本；如有更新会先提醒你再继续巡检。
巡检主要会做三件事：1) 检查版本更新；2) 扫描你已安装 Skill/MCP 的依赖声明并优先用 package:* 做供应链包直查，再对提取的 url/domain/email/hash 做 MistEye 检测；3) 把结果集中汇报。
主要作用：把“手动才会做”的安全检查变成“每天自动做”，更早发现供应链投毒、恶意外链和规则失效导致的漏检风险。
```

## 输出格式

```text
MistEye API：safe=<true|false|unknown>, matches_count=<n>
内部结果：malicious | no_match | error | no_check
检测对象：<target>
类型：<ip|ip:port|domain|url|email|file_hash|md5|sha1|sha256|package:*>
证据：<matches[].severity/type/value/threat_type/confidence/source 等返回字段>
动作：<已拦截 / 可继续（附风险）>
可选复核：<若 safe=true 且 matches_count=0，提示是否去对应官方包源/注册表地址核对包元数据>
```

针对 URL/域名问答，必须先输出可见化前置检测块（不允许省略）：

```text
[前置检测]
URL 检测：<safe=false|matches_count_positive|safe=true matches_count=0|error|no_check>
Domain 检测：<safe=false|matches_count_positive|safe=true matches_count=0|error|no_check>
前置结论：<已拦截 / 可继续（附风险）>
```

只有 `前置结论=可继续` 时，才允许继续输出“网站信息/HTTP 状态/功能介绍”等正文。

针对“每日依赖巡检”输出，必须额外包含以下两块：

1. 覆盖率块

```text
[巡检覆盖率]
已安装目录总数：<n>
已扫描目录数：<n>
依赖文件总数：<n>
成功解析文件数：<n>
解析失败文件数：<n>
覆盖结论：<正常 / 巡检覆盖不足>
```

2. 检测对象证据块（至少列出前若干条）

```text
[检测对象证据]
<type> <target> <- <file_path>:<line_or_field> [source_kind=dependency_package|raw]
...
```
