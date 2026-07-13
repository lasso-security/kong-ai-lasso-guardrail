local typedefs = require "kong.db.schema.typedefs"

return {
  name = "ai-lasso-guardrail",
  fields = {
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          -- Lasso API. `referenceable` lets the key come from a Vault reference
          -- ({vault://...}); never hardcode it in the declarative config.
          { lasso_api_key = { type = "string", required = true, referenceable = true } },
          -- `referenceable` so the base can also come from a Vault/env reference
          -- ({vault://...}) rather than being written into declarative config.
          { lasso_api_base = {
              type = "string",
              default = "https://server.lasso.security/gateway/v3",
              referenceable = true,
          } },
          -- /classifix (mask) when true, else /classify (detect+block only).
          { masking = { type = "boolean", default = false } },
          -- Which directions to scan.
          { guard_request = { type = "boolean", default = true } },
          -- Intent double-duty (single-egress): when true AND a request carries the trace
          -- header, the plugin's existing access/response classify calls also feed the intent
          -- pipeline — the app only seeds a per-turn traceId. Auto-
          -- masking body-rewrite is not applied in intent mode (detect/block still enforced).
          { intent = { type = "boolean", default = false } },
          -- Header the app stamps with a per-turn ULID traceId (see lasso-sdk KongIntent).
          { intent_trace_header = { type = "string", default = "x-lasso-trace-id" } },
          -- Header carrying the application intent (baseline the trace is scored against).
          { intent_app_intent_header = { type = "string", default = "x-lasso-application-intent" } },
          -- Header carrying the application display name, so the trace shows up named in the UI.
          { intent_app_name_header = { type = "string", default = "x-lasso-application-name" } },
          -- Marker ("pct") the seeder sets when the intent/name headers are percent-encoded; gates decoding.
          { intent_encoding_header = { type = "string", default = "x-lasso-encoding" } },
          -- Send the finalize marker (isLastEventInTrace) on a turn's terminal answer (completion
          -- finish_reason "stop") so the server finalizes + scores the trace immediately instead of
          -- waiting out the server's inactivity timeout. Turns still in a tool loop are left to accumulate.
          { intent_finalize_on_stop = { type = "boolean", default = true } },
          -- Response scanning buffers the upstream body (disables SSE streaming for the
          -- route) — leave off for streaming clients.
          { guard_response = { type = "boolean", default = false } },
          -- Fail-open: allow traffic on Lasso timeout/5xx (default). Auth errors always
          -- surface regardless.
          { fail_open = { type = "boolean", default = true } },
          { timeout = { type = "number", default = 10000 } },  -- ms
          { source_type = { type = "string", default = "kong" } },
          -- Header carrying a stable end-user id to forward as userId.
          { user_header = { type = "string", default = "x-lasso-user-id" } },
          -- Header carrying a client-supplied conversation/session id, reused across turns
          -- to aggregate a multi-turn dialogue. Kong has no native session concept, so this
          -- must come from the caller (the Kong AI ecosystem convention, e.g. Langfuse's
          -- X-Session-Id). When absent, a per-request ULID is generated instead.
          { session_header = { type = "string", default = "x-session-id" } },
          { block_status_code = {
              type = "integer", default = 400, between = { 100, 599 },
          } },
          { block_message = {
              type = "string", default = "Request blocked by Lasso guardrail",
          } },
          { ssl_verify = { type = "boolean", default = true } },
        },
      },
    },
  },
}
