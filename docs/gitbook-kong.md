---
hidden: true
---

# Kong AI Gateway

Add Lasso guardrails to **Kong Gateway** with the **`ai-lasso-guardrail`** plugin. Prompts
(and optionally completions) flowing through Kong's AI Proxy are classified by Lasso;
jailbreaks and policy violations are blocked, and PII can be masked — inline.

## What it is

A native Kong plugin (Lua) that runs in the request and response path, calls Lasso
`POST /gateway/v3/classify` (or `/classifix` for masking), and enforces the verdict using
Kong's PDK.

- **Host gateway:** Kong Gateway (OSS or Enterprise) 3.x; Konnect via Custom Plugin Streaming.
- **Archetype:** in-process Lua plugin (installed via LuaRocks / `KONG_PLUGINS`).

## Install

```bash
luarocks install ai-lasso-guardrail
export KONG_PLUGINS=bundled,ai-lasso-guardrail
kong reload
```

On Kong Konnect, upload it through **Custom Plugin Streaming**.

## Configuration

Attach the plugin to your AI Proxy route or service:

```yaml
plugins:
  - name: ai-lasso-guardrail
    config:
      lasso_api_key: "{vault://env/lasso-api-key}"
      lasso_api_base: https://server.lasso.security/gateway/v3
      guard_request: true      # scan prompts
      guard_response: false    # scan completions (buffers body; off for streaming)
      masking: false           # true = mask PII via /classifix
      fail_open: true          # allow if Lasso is unreachable; auth errors always surface
```

| Field | Default | Description |
|---|---|---|
| `lasso_api_key` | — (required) | Your Lasso API key (use a Vault reference). |
| `lasso_api_base` | `https://server.lasso.security/gateway/v3` | Lasso v3 base URL. |
| `masking` | `false` | Mask PII by rewriting the body via `/classifix`. |
| `guard_request` / `guard_response` | `true` / `false` | Which directions to scan. |
| `fail_open` | `true` | Allow traffic when Lasso is unreachable/5xx; a bad key is always surfaced. |
| `source_type` | `kong` | Attribution shown in Lasso's "Used By" view. |
| `user_header` | `x-lasso-user-id` | Header carrying a stable end-user id. |
| `block_status_code` / `block_message` | `400` / … | Response returned when content is blocked. |

## What's enforced

- **Input and output** scanning (output is opt-in).
- **Block:** any finding with action `BLOCK` (jailbreak, policy, unsafe content) returns the
  configured status with the block reason.
- **Mask:** with `masking: true`, `AUTO_MASKING` findings (e.g. PII) are redacted in the
  request/response body before it continues.
- **Alerts:** `USER_ALERT` / `ADMIN_ALERT` are logged, not blocked.
- **Fail mode:** on Lasso timeout/5xx, allow (`fail_open: true`) or block; a bad API key is
  always surfaced.

## Limitations

- **Streaming responses are not scanned.** Response scanning buffers the upstream body, which
  disables SSE streaming for the route — leave `guard_response` off for streaming clients.
- PII mask offsets are byte-based; for multi-byte text, Lasso's returned masked messages are
  used when available.
