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
          { lasso_api_base = {
              type = "string",
              default = "https://server.lasso.security/gateway/v3",
          } },
          -- /classifix (mask) when true, else /classify (detect+block only).
          { masking = { type = "boolean", default = false } },
          -- Which directions to scan.
          { guard_request = { type = "boolean", default = true } },
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
