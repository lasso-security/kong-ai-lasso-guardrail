# ai-lasso-guardrail (Kong plugin)

A custom **Kong Gateway** plugin that classifies AI chat traffic with **Lasso Security** and
blocks or masks it inline — in the request path (prompts) and, optionally, the response path
(completions).

```
client ──▶ Kong ──[ai-lasso-guardrail]──▶ ai-proxy ──▶ LLM provider
                        │ POST /gateway/v3/classify|classifix
                        ▼
                   Lasso Security
```

Unlike wiring Lasso behind Kong's generic **AI Custom Guardrail** plugin (which is limited to
block/allow on extracted text), a native plugin has full request/response body access — so it
forwards the structured `messages` + `tools`, sends `source`, reuses one ULID `sessionId`
across both phases, and can **mask** by rewriting the body. That reaches full parity with the
other Lasso gateway integrations.

Archetype: **in-process Lua plugin**. Delivery: **Lasso-owned repo** (LuaRocks rock);
self-serve install, no Kong partnership required.

## Why native Lua (vs. the AI Custom Guardrail sidecar)

Kong's `ai-custom-guardrail` plugin can only block/allow and forwards only concatenated text
— so masking, tools, and per-request identity are impossible through it. A custom plugin runs
in the `access` / `response` phases with full PDK access and closes all of those gaps. It also
runs on **Kong OSS** (no Enterprise 3.14 requirement).

| Capability | This plugin |
|---|---|
| Scan prompts (input) | ✅ `access` |
| Scan completions (output) | ✅ buffered `response` phase |
| Block (`findings[].action == BLOCK`) | ✅ `kong.response.exit` |
| Mask (`AUTO_MASKING`, `/classifix`) | ✅ rewrites body via PDK |
| Forward `tools`, `source`, ULID `sessionId`, `userId` | ✅ |
| Configurable base URL + fail-mode | ✅ |
| Streaming output | ❌ out of scope (response scanning buffers → disables SSE) |

## Install

Self-hosted Kong (OSS or Enterprise):

```bash
luarocks make            # or: luarocks install ai-lasso-guardrail
# enable it
export KONG_PLUGINS=bundled,ai-lasso-guardrail
kong reload
```

**Konnect** dedicated cloud gateways: upload via **Custom Plugin Streaming** (the plugin is
self-contained in `schema.lua` + `handler.lua` + two local modules — within Konnect's custom
plugin limits).

## Configure

Attach to an AI Proxy route (see `kong/kong.yml` for a full decK example):

| Field | Default | Purpose |
|---|---|---|
| `lasso_api_key` | — (required) | Lasso API key. Use a Vault reference; never hardcode. |
| `lasso_api_base` | `https://server.lasso.security/gateway/v3` | Lasso v3 base URL. |
| `masking` | `false` | `true` → `/classifix` + body rewrite; `false` → `/classify` only. |
| `guard_request` | `true` | Scan prompts. |
| `guard_response` | `false` | Scan completions (buffers the body — off for streaming). |
| `fail_open` | `true` | Allow on Lasso timeout/5xx. Auth errors always surface. |
| `timeout` | `10000` | Lasso call timeout (ms). |
| `source_type` | `kong` | `source.type` for the "Used By" badge. |
| `user_header` | `x-lasso-user-id` | Header to read a stable end-user id from (→ `userId`). |
| `session_header` | `x-session-id` | Header carrying a client-supplied conversation id; reused across turns → one Lasso dialogue. Kong has no native session, so this comes from the caller (Langfuse/Fiddler convention). Falls back to a generated ULID. |
| `intent` | `false` | Intent double-duty. When on **and** a request carries `intent_trace_header`, the existing `access`/`response` classify calls also feed the intent pipeline. Auto-masking body-rewrite is not applied in intent mode (detect/block still enforced). |
| `intent_trace_header` | `x-lasso-trace-id` | Per-turn ULID `traceId` the app seeds (see the lasso-sdk `GatewayIntent` helper). Its presence activates intent for that request. |
| `intent_app_intent_header` | `x-lasso-application-intent` | Application intent (the baseline the trace is scored against); upserted as session info. |
| `intent_app_name_header` | `x-lasso-application-name` | Application display name; upserted as session info so the trace shows up named in the intent UI. |
| `intent_encoding_header` | `x-lasso-encoding` | When `pct`, the plugin percent-decodes the intent/name headers (the seeder sets it only when they contain non-ASCII, e.g. Hebrew/emoji). |
| `intent_finalize_on_stop` | `true` | Finalize + score the trace immediately on a turn's terminal answer (completion `finish_reason` `stop`) instead of waiting the server's 10-min silence timer. Tool-call turns keep accumulating. |
| `block_status_code` / `block_message` | `400` / … | Response when blocked. |

### Intent double-duty (single-egress)

When an app funnels its LLM calls through Kong, this plugin can feed the Lasso **intent
pipeline** off the *same* classify calls it already makes for content-safety — no separate
call, no assembled trace (RND-6372 "Suggestion 2"). The only thing the gateway can't know is
the turn boundary, so the app seeds a per-turn `traceId` header; Kong turns each phase's
messages into intent events with stable ids (`traceId`/`eventId`/`eventIndex`) and the server
dedups the re-sent history by `eventId`. Captured signals: user / model / tool-input /
tool-output, plus reasoning when the provider echoes it (retriever and error are out of scope).

Seed the header from the app with the [lasso-sdk](https://github.com/lasso-security/lasso-sdk)
`GatewayIntent` helper, and enable the mode on the route:

```yaml
plugins:
  - name: ai-lasso-guardrail
    config:
      lasso_api_key: "{vault://env/lasso-api-key}"
      intent: true
```

## Test

```bash
# Pure logic (runs anywhere with Lua/busted; verified via Docker):
docker run --rm -v "$PWD":/data -w /data imega/busted busted spec/    # 19 passing

# End-to-end against a real Kong (CI): needs Pongo/Docker
pongo run spec/ai-lasso-guardrail/integration_spec.lua
```

`spec/ai-lasso-guardrail/lasso_spec.lua` covers the translation logic (payload, block/mask,
ULID, span application). `integration_spec.lua` proves the PDK wiring end-to-end under Pongo.

## Layout

```
kong/plugins/ai-lasso-guardrail/
  handler.lua   access + response orchestration (PDK)
  schema.lua    plugin config
  lasso.lua     pure translation logic (block/mask/ulid) — unit-tested
  client.lua    resty.http + cjson transport
kong/kong.yml   example decK config
spec/           busted unit tests + Pongo integration spec
dev/            local Kong e2e harness (docker-compose + mock)
```
