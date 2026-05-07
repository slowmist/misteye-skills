---
name: misteye-security-check
description: This is the MistEye security gate skill. It is triggered by pre-installation risk checks (including Skill/MCP dependency manifests), pre-access security checks for domains or URLs, IoC malicious detection, and supply-chain risk blocking, especially for common requests such as "take a look at this address/website." It must use `https://app-api.misteye.io/functions/v1/detect`; in dependency and external-link scenarios it has the highest priority. If the API returns `safe=false` or any `matches`, the action must be blocked and explicitly reported as "blocked". Only after the first installation is complete should the user be reminded that daily patrols can be enabled with OpenClaw or Hermes (default once per day).
metadata:
  version: "1.4.21"
  upstream_repo: "https://github.com/slowmist/misteye-skills"
  upstream_skill_candidates:
    - "https://raw.githubusercontent.com/slowmist/misteye-skills/main/SKILL.md"
    - "https://raw.githubusercontent.com/slowmist/misteye-skills/master/SKILL.md"
---

# MistEye Security Gate

## Core Rules

- Single detection endpoint: `POST https://app-api.misteye.io/functions/v1/detect`
- Single authentication method: the `x-api-key` request header (the `MISTEYE_API_KEY` environment variable is recommended)
- Official docs: `https://app.misteye.io/api-docs`
- Currently available detection types: `ip`, `ip:port`, `domain`, `url`, `email`, `file_hash`, `md5`, `sha1`, `sha256`, `package:npm`, `package:pypi`, `package:nuget`, `package:rubygems`, `package:go`, `package:cratesio`
- Types officially marked as Coming Soon (for example `repo:*`, `extension:*`, `ai-tool:*`, `mobile-app:*`) must not be used as the sole basis for a hard gate
- Highest-priority scenarios: dependency installation pre-checks, and domain or URL access pre-checks
- In Skill/MCP installation scenarios, only inspect "dependency-installation related objects" and do not classify the Skill/MCP itself as malicious
- First step of daily patrol: check whether the upstream repository has a new version, and strongly remind the user when one is found
- Daily patrol must include "scanning the dependencies of installed Skill/MCP items" (this is mandatory, not optional)
- Before any external request during daily patrol, a network reachability pre-check must be performed first (for `app-api.misteye.io` and `raw.githubusercontent.com`)
- Daily patrol must also perform an `MISTEYE_API_KEY` credential pre-check; never hardcode the API key in cron payloads or messages

## Trigger Rules (Prevent Missed Checks)

If any of the following appear, MistEye detection must be performed before answering the main request:

- The user input contains a URL (`http://` or `https://`)
- The user input contains a recognizable domain name, such as `example.com`
- The user asks the agent to "take a look at", "analyze", "check", "visit", "open", or "download" a website, address, or link

Common spoken trigger examples that must match:

- `take a look at https://...`
- `is this address safe`
- `visit this website`
- `what is this link`

Execution constraints:

1. Detect `url` and `domain` together first (extract the domain from the URL).
2. If any detection returns `safe=false`, a non-empty `matches`, `error`, or `no_check`, immediately block and output "blocked".
3. Before the detection result is shown, do not provide HTTP status, site introduction, feature analysis, or any other main content.

## GitHub Update Source (Patrol Download Locations)

When performing version checks during patrol, the latest `SKILL.md` must be fetched from the following GitHub locations. Do not guess any other repository or branch:

- Upstream repository: `https://github.com/slowmist/misteye-skills`
- Latest download candidates (fallback in order):
  1. `https://raw.githubusercontent.com/slowmist/misteye-skills/main/SKILL.md`
  2. `https://raw.githubusercontent.com/slowmist/misteye-skills/master/SKILL.md`

The matched raw URL must also be used as `check source` and `latest download URL` in patrol output.

## Priority 0: Dependency and Domain Access Pre-checks

In the following scenarios, MistEye checks must be completed before installation, access, download, or execution is allowed:

1. Before dependency installation (supply-chain risk)
2. Before domain or URL access (external-link risk)
3. Before Skill/MCP installation (its internal dependency declarations must be scanned first)

Skill/MCP installation dedicated rules (mandatory):

1. Only scan dependency declaration files and dependency source objects. Do not classify the Skill/MCP's `SKILL.md`, prompt text, or script logic itself as malicious.
2. Before any `clawhub install`, local installation after `git clone`, or any other Skill/MCP installation action, read the dependency files in the target directory first.
3. Dependency items must be parsed one by one, not merely by checking whether a file exists. Create a unique `dependency_id` for each dependency item.
4. For each dependency item, a supply-chain package direct lookup must be performed first. When the ecosystem can be identified, a `package:*` type must be used (for example, `package:pypi` for PyPI and `package:npm` for npm).
5. If a dependency has a clear name and version, prefer normalizing the target to `name@version`. If normalization is not possible, use the raw dependency text as the target and keep `dependency_raw` as evidence.
6. If the dependency item contains an explicit URL, domain, or hash, add those objects as additional detections; these additional detections do not replace the supply-chain package lookup.
7. Hard coverage rule: `dependency_package_detect_count >= dependency_item_count`; otherwise determine `[coverage insufficient alert]` and block.
8. If any object returns `safe=false` or a non-empty `matches`, immediately block installation and output "blocked".
9. If any dependency item cannot produce a valid detection target (empty item, comment-only item, corrupted format), treat it as `no_check` and block with "blocked (detection incomplete)".
10. Only when every dependency item has been checked and none of the blocking conditions are triggered may Skill/MCP installation continue.

Direct lookup rules (when the dependency has only a package name):

- Prefer the supply-chain package identity (`name@version`) as the target, and keep `dependency_raw` as evidence
- `type` priority:
  - Python dependencies: `type=package:pypi`
  - npm/yarn/pnpm dependencies: `type=package:npm`
  - NuGet dependencies: `type=package:nuget`
  - RubyGems dependencies: `type=package:rubygems`
  - Go module dependencies: `type=package:go`
  - Cargo/crates.io dependencies: `type=package:cratesio`
  - If `dependency_raw` can be recognized as a URL: `type=url`
  - If it can be recognized as a domain: `type=domain`
  - If it can be recognized as a hash: prefer `md5`, `sha1`, or `sha256`; if it cannot be distinguished, use `file_hash`
  - For all other formats: use the closest `package:*` type; if the ecosystem cannot be identified, mark it as `no_check` and do not pretend a check was performed

Pre-install output requirements (mandatory):

- The output must include a `dependency scan table`, containing at least:
  - `dependency_id`
  - `dependency_raw` (original dependency string)
  - `evidence` (file path + line number/field)
  - `package_target` (normalized `name@version` or raw dependency string)
  - `package_type` (`package:pypi` / `package:npm` / ...)
  - `targets` (the url/domain/hash/email values additionally associated with this item)
  - `dependency_package_detected` (`yes`/`no`)
  - `api_safe` (`true`/`false`/`unknown`)
  - `matches_count`
  - `result` (`malicious`/`no_match`/`error`/`no_check`)
- Do not use "public repository domain only" checks (for example, only checking `pypi.org`) as a substitute for per-item dependency scanning.

Dependency check coverage list (full ecosystem):

- Python: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`
- JS/TS: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`
- Go: `go.mod`, `go.sum`
- Rust: `Cargo.toml`, `Cargo.lock`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
- Ruby: `Gemfile`, `Gemfile.lock`
- PHP: `composer.json`, `composer.lock`
- .NET: `*.csproj`, `packages.lock.json`, `paket.dependencies`

Coverage for pre-access domain checks:

- Opening or requesting external URLs (browsing, scraping, API calls)
- Downloading files (`curl`, `wget`, browser downloads, script downloads)
- Cloning repositories (`git clone`)
- Running install commands that access the external network (`pip`, `npm`, `pnpm`, `yarn`, `go`, `cargo`, `composer`, `bundle`, `dotnet`, `maven`, `gradle`)

Do not continue with later installation or access actions before detection is complete.

## API Call Standard

Official docs: `https://app.misteye.io/api-docs`

Example call:

```bash
curl -X POST "https://app-api.misteye.io/functions/v1/detect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MISTEYE_API_KEY" \
  -d '{
    "target": "example.com",
    "type": "domain"
  }'
```

Request body:

```json
{
  "target": "example.com",
  "type": "domain"
}
```

Request field constraints:

- `target`: required string; the service trims/lowercases it; maximum 2,000 characters
- `type`: required string; must be an officially available detection type

Response format (must be parsed exactly):

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

Parsing rules:

- `safe=false` or `matches.length > 0`: map to internal result `malicious`; must block
- `safe=true` and `matches=[]`: map to internal result `no_match`; it may continue, but a risk warning must be attached
- HTTP failure, network failure, JSON parsing failure, or a response missing `safe` or `matches`: map to internal result `error`; must block

Error code handling:

- `400`: invalid JSON, `target`, or `type`; block as `error`
- `401`: missing or invalid `x-api-key`; block as `error`
- `403`: invalid, disabled, or failed API key validation; block as `error`
- `413`: `target` exceeds 2,000 characters; block as `error`
- `429`: rate limit of 10 req/s reached; block as `error`; if `Retry-After` is present, wait and retry
- `500`: server exception; block as `error`

If there is no API key:

- Directly tell the user that the detection is incomplete and therefore in a high-risk unconfirmed state
- Guide the user to provide a key or set `MISTEYE_API_KEY`
- Clearly direct the user to `https://app.misteye.io/api-keys` to obtain/manage an API key
- If the user is not yet registered with MistEye, they must register first, then create a key on the page above
- Do not skip detection and continue with a high-risk action

## Blocking Decision Matrix

| MistEye state | Decision | Action |
|---|---|---|
| `safe=false` or `matches.length > 0` | Confirmed high risk | **Hard block**, explicitly output "blocked" |
| `error` | Detection failed, high risk remains unconfirmed | **Hard block**, explicitly output "blocked (detection incomplete)" |
| `no_check` | Detection was not performed, high risk remains unconfirmed | **Hard block**, explicitly output "blocked (detection incomplete)" |
| `safe=true` and `matches=[]` | No intelligence hit | It may continue, but a risk warning must be attached; do not claim absolute safety |

Unmatched follow-up review strategy:

- When the API returns `safe=true` and `matches=[]`, you must state that "no intelligence hit does not mean confirmed safety."
- For supply-chain packages, you may suggest the user check the official package source or registry for metadata such as version, publish time, maintainer, repository link, and download counts
- Do not automatically open, visit, or query any official package source page without user consent
- If the user asks for a review, perform the necessary MistEye pre-checks before accessing the official package source, or follow the current environment rules
- Official package source URL reference:
  - npm: `https://registry.npmjs.org/<package>` (scope packages must be URL-encoded, for example `@scope/pkg` -> `%40scope%2Fpkg`)
  - PyPI: `https://pypi.org/pypi/<package>/json`
  - NuGet: `https://api.nuget.org/v3-flatcontainer/<lowercase-package>/index.json`
  - RubyGems: `https://rubygems.org/api/v1/gems/<gem>.json`
  - Go: `https://pkg.go.dev/<module>`
  - crates.io: `https://crates.io/api/v1/crates/<crate>`

Mandatory wording:

- When `safe=false`, `matches.length > 0`, `error`, or `no_check` occurs, the result must contain the exact phrase "blocked"
- Do not use softened expressions such as "you can continue for now" or "it should be fine"

## One-Time Strong Patrol Reminder After Installation (OpenClaw / Hermes)

When and only when the user completes the first installation (or first enablement), one reminder must be added (either OpenClaw or Hermes is sufficient):

- Active patrol can be enabled (OpenClaw or Hermes)
- Default cadence: once per day
- The focus is on "how to enable it"; do not expand into the full security system
- Default recommendation: "no script mode" (the patrol steps are written directly in the cron message); if the user already has an external script, it may also be integrated (suggested script name: `misteye-dependency-patrol.sh`), but this skill does not include a `.sh` file
- Trigger condition: first installation completed / first enablement
- Do not repeat the reminder: later daily checks, normal Q&A, and ordinary use should not trigger the reminder again
- Only provide patrol configuration again when the user explicitly asks to "configure patrol" or "view patrol commands"

Daily patrol task order (mandatory):

1. First perform the network reachability pre-check (mandatory)
2. Then perform the credential pre-check (`MISTEYE_API_KEY`)
3. Version update check (check `slowmist/misteye-skills`)
4. Patrol the dependencies of installed Skill/MCP items (mandatory)
5. If a new version is detected, output the update reminder first
6. Then perform the normal security patrol

Network reachability pre-check rules (mandatory):

- Pre-check targets:
  - `https://app-api.misteye.io/functions/v1/detect`
  - `https://raw.githubusercontent.com/slowmist/misteye-skills/main/SKILL.md`
- If either target is unreachable, output `[network connectivity alert]` first, then enter "restricted mode":
  - Version checks are marked `degraded` (not successful)
  - MistEye external API detections are marked `degraded` (not successful)
  - Continue local dependency file enumeration and statistics, but do not fake a successful detection
- Restricted mode must provide at least one recovery suggestion:
  - Switch the patrol task to `--session "shared"`
  - Add proxy settings for the cron runtime, such as `HTTPS_PROXY` / `ALL_PROXY`
  - Allow outbound access to `app-api.misteye.io` and `raw.githubusercontent.com`

Credential pre-check rules (mandatory):

- Credential loading order:
  1. Read the `MISTEYE_API_KEY` environment variable directly
  2. If empty, try reading from the local controlled file in order:
     - `${MISTEYE_CONFIG_DIR}/api_key` (when `MISTEYE_CONFIG_DIR` is set)
     - `$HOME/.config/misteye/api_key`
- File security requirement: permissions must be `600` (read/write for the current user only)
- If the key is successfully read from file, export `MISTEYE_API_KEY` in the current patrol session before calling the MistEye API
- If credentials are still unavailable, output `[credential missing alert]` and mark the MistEye check as `degraded` (it cannot be marked successful)
- If credentials are missing, remind the user to go to `https://app.misteye.io/api-keys` to obtain the key (register first if not registered)
- Security red line: do not write the API key in plain text into cron payloads, messages, chat logs, or command history
- OpenClaw and Hermes are only cron executors; do not write the new credential into their private directories

Recommended one-time initialization (to avoid plain text in cron):

```bash
mkdir -p "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}"
read -s MISTEYE_API_KEY && echo
printf '%s' "$MISTEYE_API_KEY" > "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}/api_key"
chmod 600 "${MISTEYE_CONFIG_DIR:-$HOME/.config/misteye}/api_key"
unset MISTEYE_API_KEY
```

Version update check rules (mandatory):

- Read local version: `metadata.version` in the current skill's `SKILL.md` frontmatter
- Read remote version: try the latest download candidates in the "GitHub Update Source (Patrol Download Locations)" section in order, and parse the remote `metadata.version`
- Repository URL: use the upstream repository from the "GitHub Update Source (Patrol Download Locations)" section
- Version comparison rule: use semantic versioning (`major.minor.patch`); if the remote version is greater than the local version, treat it as "a new version is available"
- Result handling:
  - Remote version > local version: output `[version update reminder]`, including the local version, remote version, repository URL, and latest download URL
  - Remote version = local version: output "version is already up to date"
  - Version check failure (network or parsing failure): output `[version check failed reminder]` and continue the security patrol

Version check output template (must be included during patrol):

```text
[Version Check]
Local version: <local SKILL.md frontmatter metadata.version>
Remote version: <remote SKILL.md frontmatter metadata.version | unknown>
Upstream repository: <upstream repository from GitHub Update Source (Patrol Download Locations)>
Check source: <matched GitHub raw URL | all failed>
Latest download URL: <matched GitHub raw URL | unknown>
Version conclusion: <new version available / version is already up to date / version check failed>
Action: <warn first / continue patrol / mark degraded and continue local statistics>
```

Installed Skill/MCP dependency patrol rules (mandatory):

- Patrol directories (depending on what exists):
  - `~/.agents/skills`
  - `~/.codex/skills`
  - `$CODEX_HOME/skills`
- Coverage requirements (prevent missed scans):
  - First enumerate all installed Skill/MCP directories under the patrol roots, then scan dependency files directory by directory
  - The output must include: `total installed directories`, `scanned directories`, `total dependency files found`, `successfully parsed files`, and `failed files`
  - If `scanned directories < total installed directories` or any file fails to parse, output `[coverage insufficient alert]` and attach the failure list
- Only scan dependency declaration files, not the Skill/MCP implementation itself:
  - Python: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`
  - JS/TS: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`
  - Go: `go.mod`, `go.sum`
  - Rust: `Cargo.toml`, `Cargo.lock`
  - Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
  - Ruby: `Gemfile`, `Gemfile.lock`
  - PHP: `composer.json`, `composer.lock`
  - .NET: `*.csproj`, `packages.lock.json`, `paket.dependencies`
- Extract and deduplicate detectable objects from the dependency files:
  - Supply-chain packages (prefer `package:npm`, `package:pypi`, `package:nuget`, `package:rubygems`, `package:go`, `package:cratesio`)
  - URL (`type=url`)
  - Domain (`type=domain`)
  - Email (`type=email`, if present)
  - File hashes (prefer `md5`, `sha1`, `sha256`; if the type cannot be distinguished, use `file_hash`)
- Extraction constraints (prevent false positives):
  - First stage (mandatory): every dependency item must first perform a supply-chain package direct lookup (`source_kind=dependency_package`)
  - Second stage (supplementary): only when the raw dependency text explicitly contains url/domain/email/hash, add those detections; each object must have source evidence (file path + line number or field path)
  - Do not use a preset ecosystem domain list to fill gaps (for example, do not auto-insert `pypi.org`, `npmjs.org`, `crates.io`) unless those values actually appear in the scanned file
  - Do not replace per-item dependency scanning with checking only a public repository domain (for example, only `pypi.org` / `files.pythonhosted.org`)
  - Only when the dependency target cannot be extracted or is invalid (empty value / comment / corrupted input) may it be counted as `no_check` (reason: `unresolved_source`); do not pretend a check was completed
- Coverage gate (mandatory):
  - When `dependency_package_detect_count < dependency_item_count`, output `[coverage insufficient alert]` and mark `degraded`; do not claim the patrol is complete
- Call MistEye detect for every object
- Patrol output must include statistics:
  - Number of dependency files scanned
  - Number of detectable objects extracted (grouped by package/url/domain/email/hash)
  - Number of direct supply-chain lookup objects (`dependency_package`)
  - Number of `unresolved_source` items (dependencies that cannot be mapped to package/url/domain/email/hash)
  - Number of hits with `safe=false` or non-empty `matches`, plus the object list
  - Number of `error/no_check` items
- Patrol handling:
  - `safe=false` or non-empty `matches`: output `[high-risk dependency patrol alert]`, require immediate manual review, and pause the related installation/access flow
  - `error/no_check`: output `[dependency patrol incomplete reminder]`, request a re-check, and do not claim it is "safe"
  - `safe=true` and `matches=[]`: indicates only that no intelligence hit was found; continue the patrol and attach a risk warning
  - No-hit wording constraint: do not write "Clean / passed safe / no risk"; only write "no intelligence hit (risk warning still required)"

Recommended template A (OpenClaw):

```bash
openclaw cron add \
  --name "misteye-dependency-patrol" \
  --description "Nightly security patrol" \
  --cron "0 3 * * *" \
  --tz "Asia/Shanghai" \
  --session "shared" \
  --message "Execute the daily patrol in order: 1) network reachability pre-check; 2) MISTEYE_API_KEY credential pre-check; 3) version check; 4) enumerate and scan all installed Skill/MCP dependency files; 5) for each dependency_id, first perform a supply-chain package direct lookup (prefer package:npm/package:pypi/package:nuget/package:rubygems/package:go/package:cratesio), and if the raw dependency contains explicit url/domain/email/hash, add those detections; 6) output dependency_item_count and dependency_package_detect_count, and if the former is greater than the latter, output [coverage insufficient alert] and mark degraded; 7) output hits with safe=false or non-empty matches, and list error/no_check objects. Do not replace per-item dependency scanning with a public-domain-only check; when there is no hit, only write 'no intelligence hit (risk warning still required)'." \
  --announce \
  --channel <channel> \
  --to <your-chat-id> \
  --timeout-seconds 300 \
  --thinking off
```

OpenClaw isolated-session fallback template (use only when `isolated` is required):

```bash
openclaw cron add \
  --name "misteye-dependency-patrol" \
  --description "Nightly security patrol (isolated)" \
  --cron "0 3 * * *" \
  --tz "Asia/Shanghai" \
  --session "isolated" \
  --message "Execute the daily patrol in order: first the network reachability pre-check; then the MISTEYE_API_KEY credential pre-check (if the environment variable is missing, read only from the MistEye dedicated config directory: default ~/.config/misteye/api_key, overridable with MISTEYE_CONFIG_DIR); then enumerate all installed Skill/MCP directories and scan dependency files directory by directory. You must first perform a supply-chain package direct lookup for each dependency_id (prefer package:* types), and then add checks for url/domain/email/hash only when they appear in the raw text. Output dependency_item_count and dependency_package_detect_count; if the former is greater than the latter, output [coverage insufficient alert] and mark degraded. If either network or credentials are unavailable, output the corresponding alert and enter restricted mode (local coverage statistics only, external detection marked degraded). When there is no hit, only write 'no intelligence hit (risk warning still required)'." \
  --announce \
  --channel <channel> \
  --to <your-chat-id> \
  --timeout-seconds 300 \
  --thinking off
```

Recommended template B (Hermes CLI):

```bash
hermes cron create "0 3 * * *" \
  "Execute the daily patrol in order: 1) network reachability pre-check; 2) MISTEYE_API_KEY credential pre-check; 3) version check; 4) enumerate and scan all installed Skill/MCP dependency files; 5) for each dependency_id, first perform a supply-chain package direct lookup (prefer package:* types), then add checks for explicit url/domain/email/hash from the raw text; 6) output dependency_item_count and dependency_package_detect_count, and if the former is greater than the latter output [coverage insufficient alert]; 7) output hits with safe=false or non-empty matches, plus error/no_check summaries, and mark degraded when applicable; do not describe no hits as safe." \
  --name "misteye-dependency-patrol" \
  --deliver origin
```

Recommended template C (Hermes chat command):

```text
/cron add "0 3 * * *" "Execute the daily patrol in order: 1) network reachability pre-check; 2) MISTEYE_API_KEY credential pre-check; 3) version check; 4) enumerate and scan all installed Skill/MCP dependency files; 5) for each dependency_id, first perform a supply-chain package direct lookup (prefer package:* types), then add checks for explicit url/domain/email/hash from the raw text; 6) output dependency_item_count and dependency_package_detect_count, and if the former is greater than the latter output [coverage insufficient alert]; 7) output hits with safe=false or non-empty matches, plus error/no_check summaries, and mark degraded when applicable; do not describe no hits as safe." --name "misteye-dependency-patrol" --deliver origin
```

Hermes prerequisites (must be reminded):

- Hermes gateway must be running first (for example, run `hermes gateway install` and then run the service, or run `hermes gateway` directly)
- If the user already has an OpenClaw environment, they may first run `hermes claw migrate` to migrate existing configuration, then create the patrol task
- After creation, use `hermes cron list` / `hermes cron status` to confirm it is active
- Use `hermes cron run <job_id>` for an immediate replay verification

The reminder text must include: `default recommendation is once per day`.

## High-Sensitivity Prompt Templates

The following templates are used for high-risk scenarios and have higher priority than ordinary explanations:

### Template A: Before dependency installation

```text
[Security Gate]
Detection target: <dependency name / package registry domain / lockfile source>
Detection status: <safe=false|matches_count_positive|error|no_check|safe=true matches_count=0>
Conclusion: <blocked / continue (with risk)>

Rules:
1) Dependency installation is a high-risk supply-chain action and must pass MistEye first.
2) The current status is <...>. According to the hard-block policy: <block or allow with conditions>.
3) Next step: <provide an actionable step, such as adding an API key, retrying detection, or replacing the dependency source>.
```

### Template B: Before domain or URL access

```text
[Security Gate]
Detection target: <domain/url>
Detection status: <safe=false|matches_count_positive|error|no_check|safe=true matches_count=0>
Conclusion: <blocked / continue (with risk)>

Rules:
1) External links and downloads are high-risk entry points and must pass MistEye first.
2) The current status is <...>. According to the hard-block policy: <block or allow with conditions>.
3) Next step: <provide an actionable step, such as changing the domain, adding an API key, or retrying detection>.
```

### Template C: Reminder after installation

```text
The first installation has completed. You should enable active patrol: the default recommendation is once per day.
The patrol will first check whether https://github.com/slowmist/misteye-skills has a new version; if there is an update, it will warn you before continuing the patrol.
The patrol mainly does three things: 1) checks for version updates; 2) scans the dependency declarations of installed Skill/MCP items and first uses package:* supply-chain direct lookup, then runs MistEye detection on extracted url/domain/email/hash items; 3) summarizes the results centrally.
The main purpose is to turn "manual-only" security checks into a daily automatic process, so that supply-chain poisoning, malicious external links, and missed detections caused by rule failures can be found earlier.
```

## Output Format

```text
MistEye API: safe=<true|false|unknown>, matches_count=<n>
Internal result: malicious | no_match | error | no_check
Detection target: <target>
Type: <ip|ip:port|domain|url|email|file_hash|md5|sha1|sha256|package:*>
Evidence: <returned fields such as matches[].severity/type/value/threat_type/confidence/source>
Action: <blocked / continue (with risk)>
Optional review: <when safe=true and matches_count=0, suggest checking metadata in the corresponding official package source or registry>
```

For URL/domain questions, a visible pre-check block must be output first and may not be omitted:

```text
[Pre-check]
URL detection: <safe=false|matches_count_positive|safe=true matches_count=0|error|no_check>
Domain detection: <safe=false|matches_count_positive|safe=true matches_count=0|error|no_check>
Pre-check conclusion: <blocked / continue (with risk)>
```

Only when `Pre-check conclusion=continue (with risk)` may "website info / HTTP status / feature introduction" be continued.

For "daily dependency patrol" output, the following two blocks are additionally required:

1. Coverage block

```text
[Patrol Coverage]
Total installed directories: <n>
Scanned directories: <n>
Dependency files found: <n>
Successfully parsed files: <n>
Failed files: <n>
Coverage conclusion: <normal / patrol coverage insufficient>
```

2. Detection evidence block (list at least the first several items)

```text
[Detection Evidence]
<type> <target> <- <file_path>:<line_or_field> [source_kind=dependency_package|raw]
...
```
