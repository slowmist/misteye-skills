# MistEye Detect API (Single Allowed Endpoint)

The only allowed detection endpoint is:

```text
POST https://app-api.misteye.io/functions/v1/detect
```

Official documentation entry:

```text
https://app.misteye.io/api-docs
```

Request headers:

```text
Content-Type: application/json
x-api-key: <MistEye API key>
```

If there is no API key:

- Go to `https://app.misteye.io/api-keys` to obtain or manage a key
- If you do not yet have an account, register with MistEye first, then create an API key
- Before a key is available, treat detection as high-risk and unconfirmed (`error/no_check` -> block)

Request body:

```json
{
  "target": "example.com",
  "type": "domain"
}
```

Field constraints:

- `target`: required string; the detection target; the service trims and lowercases it; maximum 2,000 characters
- `type`: required string; must use an officially supported detection type

Currently available `type` values:

Network and identity:

- `ip`
- `ip:port`
- `domain`
- `url`
- `email`

File hashes:

- `file_hash`
- `md5`
- `sha1`
- `sha256`

Supply-chain packages:

- `package:npm`
- `package:pypi`
- `package:nuget`
- `package:rubygems`
- `package:go`
- `package:cratesio`

Types marked as Coming Soon in the official docs, and which must not be used as the sole basis for a hard gate:

- `repo:github` / `repo:gitlab` / `repo:bitbucket`
- `extension:chrome` / `extension:firefox` / `extension:vscode`
- `ai-tool:mcp` / `ai-tool:skill`
- `mobile-app:apk` / `mobile-app:ipa`

Response format:

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

No-match example:

```json
{
  "safe": true,
  "matches": []
}
```

Per-item dependency direct lookup constraints (mandatory):

- Every dependency item must trigger at least one supply-chain package direct lookup
- When the ecosystem can be identified, a `package:*` type must be preferred, for example `package:pypi` for PyPI and `package:npm` for npm
- If a dependency item has a clear name and version, prefer normalizing the target to `name@version`; if normalization is not possible, use the raw dependency string as the `target`
- Checking only public repository domains such as `pypi.org` / `files.pythonhosted.org` does not count as a complete dependency check

Examples:

```bash
curl -X POST "https://app-api.misteye.io/functions/v1/detect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MISTEYE_API_KEY" \
  -d '{"target":"https://example.com","type":"url"}'
```

Supply-chain package example:

```bash
curl -X POST "https://app-api.misteye.io/functions/v1/detect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MISTEYE_API_KEY" \
  -d '{"target":"requests@2.32.3","type":"package:pypi"}'
```

## Blocking Mapping (Mandatory)

- `safe=false` or `matches.length > 0`: threat-intel hit; block immediately and output "blocked"
- `safe=true` and `matches=[]`: no intelligence hit; it may continue, but a risk warning must be attached, and absolute safety must not be claimed
- `error`: detection failed; treat as high-risk and unconfirmed; block immediately and output "blocked (detection incomplete)"
- `no_check`: no detection was performed; treat as high-risk and unconfirmed; block immediately and output "blocked (detection incomplete)"

Optional review when there is no match:

- When `safe=true` and `matches=[]`, you may ask the user whether they want to check the official package source or registry for metadata
- Do not automatically open or visit official package source pages without user consent
- Common official package source URLs:
  - npm: `https://registry.npmjs.org/<package>`
  - PyPI: `https://pypi.org/pypi/<package>/json`
  - NuGet: `https://api.nuget.org/v3-flatcontainer/<lowercase-package>/index.json`
  - RubyGems: `https://rubygems.org/api/v1/gems/<gem>.json`
  - Go: `https://pkg.go.dev/<module>`
  - crates.io: `https://crates.io/api/v1/crates/<crate>`

Internal output labels may continue to be used:

- `malicious` = API `safe=false` or `matches.length > 0`
- `no_match` = API `safe=true` and `matches=[]`

## Common Failure Handling

- `401/403`: API key missing or invalid; treat as `error` and block
- `400`: invalid JSON, `target`, or `type`; treat as `error` and block
- `413`: `target` exceeds 2,000 characters; treat as `error` and block
- `429`: rate limit of 10 req/s reached; treat as `error` and block; if the response headers include `Retry-After`, you may wait and retry
- `500`: server exception; treat as `error` and block
- Network timeout or parse failure: treat as `error` and block
- Unsupported `type` or malformed request body: treat as `error` and block
