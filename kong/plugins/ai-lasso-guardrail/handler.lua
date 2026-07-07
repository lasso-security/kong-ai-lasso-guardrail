-- ai-lasso-guardrail — Kong plugin that classifies chat traffic with Lasso and blocks or
-- masks it inline. Runs in the request path (access) and, optionally, buffers the response
-- (response phase) to scan completions.
--
-- Full body access means real parity with the other Lasso integrations: it forwards the
-- structured `messages` + `tools`, sends `source`, reuses one ULID `sessionId` across both
-- phases (kong.ctx.shared), and — unlike the generic ai-custom-guardrail plugin — can MASK
-- by rewriting the body via the PDK.

local lasso = require "kong.plugins.ai-lasso-guardrail.lasso"
local client = require "kong.plugins.ai-lasso-guardrail.client"
local cjson = require "cjson.safe"

local AiLassoGuardrail = {
  -- Above ai-proxy (770) so we see and can mutate the original chat body before it proxies.
  PRIORITY = 772,
  VERSION = "1.0.0",
}

-- Flatten OpenAI multimodal content (string | array of blocks) to text for classification.
local function flatten_content(content)
  if type(content) == "string" then
    return content, true       -- maskable: it's a plain string we can write back to
  end
  if type(content) == "table" then
    local parts = {}
    for _, block in ipairs(content) do
      if type(block) == "table" and block.type == "text" and block.text then
        parts[#parts + 1] = block.text
      end
    end
    return table.concat(parts, " "), false  -- non-string content: scan text, don't mask back
  end
  return "", false
end

-- Build the scan list (what we send to Lasso) from OpenAI-style messages, remembering which
-- original entries are plain strings so masks can be written back only to those.
local function scan_messages_from_request(messages)
  local scan, meta = {}, {}
  for i, m in ipairs(messages or {}) do
    if type(m) == "table" and m.role and m.content ~= nil then
      local text, maskable = flatten_content(m.content)
      scan[#scan + 1] = { role = tostring(m.role), content = text }
      meta[#scan] = { orig = i, maskable = maskable }
    end
  end
  return scan, meta
end

local function scan_messages_from_response(choices)
  local scan, meta = {}, {}
  for i, c in ipairs(choices or {}) do
    local msg = type(c) == "table" and c.message or nil
    if type(msg) == "table" and msg.content ~= nil then
      scan[#scan + 1] = { role = msg.role or "assistant", content = tostring(msg.content) }
      meta[#scan] = { orig = i }
    end
  end
  return scan, meta
end

local function session_id(conf)
  local shared = kong.ctx.shared
  if not shared.lasso_session_id then
    -- Prefer a client-supplied conversation id (Kong has none of its own), so multi-turn
    -- calls sharing that header aggregate into one Lasso dialogue. Fall back to a generated
    -- ULID, which still groups the prompt+completion of this single request.
    local from_header
    if conf.session_header and conf.session_header ~= "" then
      from_header = kong.request.get_header(conf.session_header)
    end
    if from_header and from_header ~= "" then
      shared.lasso_session_id = from_header
    else
      shared.lasso_session_id = lasso.gen_ulid()
    end
  end
  return shared.lasso_session_id
end

local function resolve_user_id(conf)
  if conf.user_header and conf.user_header ~= "" then
    local hv = kong.request.get_header(conf.user_header)
    if hv and hv ~= "" then
      return hv
    end
  end
  local consumer = kong.client.get_consumer()
  if consumer then
    return consumer.username or consumer.id
  end
  return nil
end

-- Run one classify/classifix call. Returns a decision table from lasso.decide, or one of
-- the control strings "allow" / "surface-auth" / "fail". Mutates `scan` on mask.
local function classify(conf, scan, tools, source)
  if #scan == 0 then
    return { action = "allow" }        -- nothing to classify; must not error
  end
  local dir = lasso.direction(source)
  local payload = lasso.build_payload({
    messages = scan,
    message_type = dir.message_type,
    session_id = session_id(conf),
    user_id = resolve_user_id(conf),
    tools = tools,
    source_type = conf.source_type,
  })
  local endpoint = conf.masking and "classifix" or "classify"
  local data, err_kind = client.call(conf, endpoint, payload)
  if err_kind == "auth" then
    return { action = "surface-auth" }
  elseif err_kind then
    return { action = "fail", err = err_kind }
  end
  return lasso.decide(data, scan, conf.masking)
end

local function fail_or_allow(conf, err)
  if conf.fail_open then
    kong.log.warn("lasso guardrail: Lasso unavailable (", err, ") — fail-open, allowing")
    return  -- pass through
  end
  kong.log.err("lasso guardrail: Lasso unavailable (", err, ") — fail-closed, blocking")
  return kong.response.exit(503, { message = "Guardrail unavailable" })
end

local function surface_auth()
  -- A bad/expired key is a misconfiguration; surface it (block) regardless of fail-mode so
  -- fail-open can't silently disable the guardrail forever.
  kong.log.err("lasso guardrail: Lasso auth error — check lasso_api_key")
  return kong.response.exit(500, { message = "Guardrail misconfigured" })
end

function AiLassoGuardrail:access(conf)
  if not conf.guard_request then
    return
  end
  local body = kong.request.get_body()
  if type(body) ~= "table" or type(body.messages) ~= "table" then
    return  -- not a chat body we understand; let ai-proxy handle it
  end

  local scan, meta = scan_messages_from_request(body.messages)
  local decision = classify(conf, scan, body.tools, "INPUT")

  if decision.action == "surface-auth" then
    return surface_auth()
  elseif decision.action == "fail" then
    return fail_or_allow(conf, decision.err)
  elseif decision.action == "block" then
    return kong.response.exit(conf.block_status_code,
      { message = conf.block_message, reason = decision.detail })
  elseif decision.action == "mask" then
    for i, m in ipairs(scan) do
      if meta[i] and meta[i].maskable then
        body.messages[meta[i].orig].content = m.content
      end
    end
    local ok, encoded = pcall(cjson.encode, body)
    if ok then
      kong.service.request.set_raw_body(encoded)
    else
      kong.log.err("lasso guardrail: failed to re-encode masked request body")
    end
  end
end

-- Defining :response triggers buffered proxying (disables streaming for the route), which is
-- what lets us read + rewrite the full completion. Streaming output is therefore out of scope.
function AiLassoGuardrail:response(conf)
  if not conf.guard_response then
    return
  end
  local raw = kong.service.response.get_raw_body()
  if not raw then
    return
  end
  local body = cjson.decode(raw)
  if type(body) ~= "table" or type(body.choices) ~= "table" then
    return
  end

  local scan, meta = scan_messages_from_response(body.choices)
  local decision = classify(conf, scan, nil, "OUTPUT")

  if decision.action == "surface-auth" then
    return surface_auth()
  elseif decision.action == "fail" then
    return fail_or_allow(conf, decision.err)
  elseif decision.action == "block" then
    return kong.response.exit(conf.block_status_code,
      { message = conf.block_message, reason = decision.detail })
  elseif decision.action == "mask" then
    for i, m in ipairs(scan) do
      local choice = body.choices[meta[i].orig]
      if choice and choice.message then
        choice.message.content = m.content
      end
    end
    local ok, encoded = pcall(cjson.encode, body)
    if ok then
      -- Replace the buffered response with the masked body. We use kong.response.exit
      -- (allowed in the response phase) rather than set_raw_body (body_filter-only), so
      -- the whole rewrite happens in one phase before headers are flushed.
      return kong.response.exit(kong.response.get_status(), encoded,
        { ["Content-Type"] = "application/json" })
    else
      kong.log.err("lasso guardrail: failed to re-encode masked response body")
    end
  end
end

return AiLassoGuardrail
