# misteye-security-check

GitHub repository: [https://github.com/slowmist/misteye-skills](https://github.com/slowmist/misteye-skills)

[中文版](README-CN.md) | [English](README.md)

MistEye security gate skill.

Purpose: make dependency installation and external URL or domain access follow a strict "detect first, execute second" flow, and provide daily patrol support for OpenClaw and Hermes.

## 1. Overview

- Single detection endpoint: `POST https://app-api.misteye.io/functions/v1/detect`
- Official docs: `https://app.misteye.io/api-docs`
- Supported detection types: `ip`, `ip:port`, `domain`, `url`, `email`, `file_hash`, `md5`, `sha1`, `sha256`, `package:*`
- High-priority gates:
  - Detect before installing dependencies
  - Detect before opening URLs or domains
  - Scan dependency declarations before Skill/MCP installation
- Blocking logic:
  - `safe=false` or a non-empty `matches` array means the target is blocked
  - `error` or `no_check` means the detection was not completed, so treat it as blocked
  - `safe=true` with `matches=[]` means the target may continue, but a risk warning is still required

## 2. Pre-check Triggers

Run MistEye detection before answering if any of the following is true:

- The user message contains a URL such as `http://` or `https://`
- The user message contains a domain name such as `example.com`
- The user asks to inspect, analyze, check, visit, open, or download a specific address or link

For URL-related requests:

1. Detect both `url` and `domain`
2. Report the pre-check result first
3. Only continue with website details, HTTP status, or feature analysis if the result says it may continue

## 3. Skill/MCP Dependency Scan Scope

In installation workflows, this skill only scans dependency-related objects. It does **not** judge whether the Skill or MCP itself is malicious.

- Scan inputs: dependency declaration files such as `requirements*.txt`, `package.json`, `go.mod`, `Cargo.toml`, and similar files
- Scan outputs: supply-chain packages, preferably as `package:*`, plus any explicit `url`, `domain`, `email`, or `hash` values found in the source
- Do not scan: the text inside `SKILL.md`, prompt wording, or the internal business logic of scripts
- Parse dependency items one by one using `dependency_id`; do not replace dependency scanning with a scan of the public repository domain

## 4. Daily Patrol

Reminder policy:

- After the first installation completes, remind the user to configure the MistEye API key
- Remind the user to enable patrol only on the first successful installation or the first activation
- The default recommendation is once per day
- Do not repeat the reminder during normal use unless the user explicitly asks about patrol settings

Fixed patrol order:

1. Network reachability pre-check for `app-api.misteye.io` and `raw.githubusercontent.com`
2. Credential pre-check for `MISTEYE_API_KEY`
3. Upstream version check
4. Required patrol of installed Skill/MCP dependency objects
5. New version notice, if any
6. Standard patrol summary

Coverage requirements:

- Enumerate all installed Skill/MCP directories first, then scan dependency files directory by directory
- The report must include total installed directories, scanned directories, total dependency files, successfully parsed files, and failed files
- If coverage is incomplete or parsing fails, emit an alert

## 5. Network Restrictions and Degraded Mode

If cron runs in an `isolated` session, network access or environment variable inheritance may fail.

Standard handling:

- No network access -> output `【network connectivity alert】` and mark the result as `degraded`
- Missing credentials -> output `【credential missing alert】` and mark the result as `degraded`
- In `degraded` mode, local dependency file statistics are still allowed, but do not claim a successful detection
- `safe=true` with `matches=[]` only means there was no intelligence match; do not describe it as "clean", "risk-free", or "safe"
- If a supply-chain package does not match, you may ask the user whether they want to check metadata in the official ecosystem source, such as npm, PyPI, NuGet, RubyGems, pkg.go.dev, or crates.io; do not query it automatically without consent

OpenClaw defaults to `--session "shared"` for this task. Use `isolated` only as a fallback. OpenClaw and Hermes are task executors only; they are not the primary storage location for the MistEye API key.

## 6. Credential Management

Do not hardcode the API key in cron payloads, messages, chat logs, or command history.

If you do not have an API key:

- Open `https://app.misteye.io/api-keys` to get or manage one
- If you do not have a MistEye account, register first and then create an API key
- After the first installation completes, remind the user to configure the MistEye API key before enabling patrol

Recommended one-time setup:

```bash
mkdir -p "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}"
read -s MISTEYE_API_KEY && echo
printf '%s' "$MISTEYE_API_KEY" > "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}/api_key"
chmod 600 "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}/api_key"
unset MISTEYE_API_KEY
```

Credential lookup order during patrol:

1. Environment variable `MISTEYE_API_KEY`
2. `${MISTEYE_CONFIG_DIR}/api_key` when `MISTEYE_CONFIG_DIR` is set
3. `$HOME/.config/misteye/api_key`

## 7. Extraction Rules

- Detection targets must come only from the raw text of files that were actually scanned
- Every target must have source evidence, such as a file path plus a line number or field path
- Do not fill gaps with a predefined list of ecosystem domains
- Do not claim dependency scanning is complete by checking only public domains such as `pypi.org` or `npmjs.org`
- Each dependency item must first receive a direct supply-chain package lookup; when the ecosystem is identifiable, use `package:npm`, `package:pypi`, `package:nuget`, `package:rubygems`, `package:go`, or `package:cratesio`
- Only add `url`, `domain`, `email`, or `hash` detections when they appear explicitly in the dependency source text; they do not replace package lookup
- Hard rule: `dependency_package_detect_count >= dependency_item_count`; otherwise output `【coverage insufficient alert】`
- Only empty values, comments, or invalid broken input should count as `unresolved_source`

## 8. Task Template

### OpenClaw

```bash
openclaw cron add \
  --name "misteye-dependency-patrol" \
  --description "Nightly security patrol" \
  --cron "0 3 * * *" \
  --tz "Asia/Shanghai" \
  --session "shared" \
  --message "Run the network reachability pre-check and the MISTEYE_API_KEY credential pre-check first. Then run the version check. Then patrol the dependency declarations of installed Skill/MCP items. Parse dependency_id one by one, and for each dependency run a direct supply-chain package lookup first, preferably with a package:* type. If the dependency source contains explicit url, domain, email, or hash values, add those detections afterward. Checking only the public repository domain is not enough. Output dependency_item_count and dependency_package_detect_count. If dependency_item_count is greater than dependency_package_detect_count, output 【coverage insufficient alert】 and mark the result as degraded. If network or credentials are unavailable, output the corresponding alert and mark the result as degraded." \
  --announce \
  --channel <channel> \
  --to <your-chat-id> \
  --timeout-seconds 300 \
  --thinking off
```

### Hermes

```bash
hermes cron create "0 3 * * *" \
  "Run the network reachability pre-check and the MISTEYE_API_KEY credential pre-check first. Then run the version check. Then patrol the dependency declarations of installed Skill/MCP items. Parse dependency_id one by one, and for each dependency run a direct supply-chain package lookup first, preferably with a package:* type. If the dependency source contains explicit url, domain, email, or hash values, add those detections afterward. Checking only the public repository domain is not enough. Output dependency_item_count and dependency_package_detect_count. If dependency_item_count is greater than dependency_package_detect_count, output 【coverage insufficient alert】 and mark the result as degraded. If network or credentials are unavailable, output the corresponding alert and mark the result as degraded." \
  --name "misteye-dependency-patrol" \
  --deliver origin
```

## 9. Related Files

- Main rules file: `SKILL.md`
- API docs: `references/api.md`
- UI metadata: `agents/openai.yaml`
