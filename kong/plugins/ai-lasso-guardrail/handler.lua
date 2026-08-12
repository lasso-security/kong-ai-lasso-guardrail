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

-- Free-text headers are percent-encoded only when non-ASCII (flagged by the marker header);
-- decode iff flagged, since a raw ASCII value may legitimately contain '%'. Same convention the
-- intent/name headers use.
local function pct_decoded(conf, value)
  if value and kong.request.get_header(conf.intent_encoding_header) == "pct" then
    return ngx.unescape_uri(value)
  end
  return value
end

-- Resolve one agent-identity field for the classify payload: the per-request header (name is
-- configurable, like user_header/session_header) over the static config value, sanitized.
-- Returns nil when neither yields a usable value, so the field is omitted.
local function agent_identity(conf, header_name, conf_value)
  local raw
  if header_name and header_name ~= "" then
    raw = pct_decoded(conf, kong.request.get_header(header_name))
  end
  local value, header_rejected = lasso.resolve_agent_identity(raw, conf_value)
  if header_rejected then
    kong.log.warn("lasso guardrail: ignoring ", header_name, " — not a valid agent identity (max ",
      lasso.AGENT_IDENTITY_MAX_LENGTH, " chars, no control or formatting characters)")
  end
  return value
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
    agent_id = agent_identity(conf, conf.agent_id_header, conf.agent_id),
    agent_name = agent_identity(conf, conf.agent_name_header, conf.agent_name),
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

-- ── Intent double-duty ──────────────────────────────────────────────────────
-- When intent mode is on and the app seeded a per-turn traceId header, the
-- existing access/response classify calls also feed the intent trace. The app
-- contributes only the traceId; Kong turns each phase's messages into intent
-- events (stable ids via lasso.to_intent_messages) on the SAME classify that
-- enforces content-safety. No separate call, no assembled trace.

-- The per-turn traceId the app seeded, or nil when intent is off / not seeded.
local function intent_trace_id(conf)
  if not conf.intent then
    return nil
  end
  local tid = kong.request.get_header(conf.intent_trace_header)
  if tid and tid ~= "" then
    return tid
  end
  return nil
end

local function intent_session_information(conf)
  local app_intent = kong.request.get_header(conf.intent_app_intent_header)
  -- applicationIntent is required for sessionInformation, so it gates the whole block.
  if not app_intent or app_intent == "" then
    return nil
  end
  -- Free-text headers are percent-encoded only when non-ASCII (flagged by the marker);
  -- decode iff flagged (a raw ASCII value may legitimately contain '%').
  local encoded = kong.request.get_header(conf.intent_encoding_header) == "pct"
  local function decode(value)
    if encoded and value then
      return ngx.unescape_uri(value)
    end
    return value
  end
  local info = { applicationIntent = decode(app_intent) }
  -- Optional display name so the trace shows up named in the intent UI (else it's unnamed).
  local app_name = kong.request.get_header(conf.intent_app_name_header)
  if app_name and app_name ~= "" then
    info.agenticAppName = decode(app_name)
  end
  return info
end

-- Run one intent-enriched classify (content-safety + intent) for a set of intent
-- messages. Returns a control string when the caller must exit, else nil (allow).
local function classify_intent(conf, messages, message_type, session_information, tools)
  if #messages == 0 then
    return nil
  end
  local payload = lasso.build_payload({
    messages = messages,
    message_type = message_type,
    session_id = session_id(conf),
    user_id = resolve_user_id(conf),
    tools = tools,
    source_type = conf.source_type,
    session_information = session_information,
    agent_id = agent_identity(conf, conf.agent_id_header, conf.agent_id),
    agent_name = agent_identity(conf, conf.agent_name_header, conf.agent_name),
  })
  -- Always /classify in intent mode: masking body-rewrite is out of scope here
  -- (detect/block still enforced from the findings).
  local data, err_kind = client.call(conf, "classify", payload)
  if err_kind == "auth" then
    return surface_auth()
  elseif err_kind then
    return fail_or_allow(conf, err_kind)
  end
  local decision = lasso.decide(data, messages, false)
  if decision.action == "block" then
    return kong.response.exit(conf.block_status_code,
      { message = conf.block_message, reason = decision.detail })
  end
  return nil
end

local function access_intent(conf, body, trace_id)
  local messages, count = lasso.to_intent_messages(body.messages, trace_id, 0, cjson.decode)
  -- The response phase continues the event index right after the request's events.
  kong.ctx.shared.lasso_intent_count = count
  return classify_intent(conf, messages, "PROMPT", intent_session_information(conf),
    lasso.to_intent_tools(body.tools))
end

local function response_intent(conf, trace_id)
  local raw = kong.service.response.get_raw_body()
  if not raw then
    return nil
  end
  local body = cjson.decode(raw)
  if type(body) ~= "table" or type(body.choices) ~= "table" then
    return nil
  end
  local completion = {}
  local terminal = false
  for _, c in ipairs(body.choices) do
    if type(c) == "table" and type(c.message) == "table" then
      completion[#completion + 1] = c.message
      -- finish_reason "stop" = a plain answer with no further tool calls: the turn is done.
      if c.finish_reason == "stop" then
        terminal = true
      end
    end
  end
  local start = kong.ctx.shared.lasso_intent_count or 0
  local messages = lasso.to_intent_messages(completion, trace_id, start, cjson.decode)
  -- Finalize the trace the moment the turn produces its terminal answer, so the server scores it
  -- now instead of after the server's inactivity timeout. Tool-call turns (finish_reason "tool_calls")
  -- are not marked, so a trace still mid-loop keeps accumulating.
  if conf.intent_finalize_on_stop ~= false and terminal and #messages > 0 then
    messages[#messages].isLastEventInTrace = true
  end
  return classify_intent(conf, messages, "COMPLETION", nil, nil)
end

function AiLassoGuardrail:access(conf)
  -- Intent double-duty: when seeded, this replaces the plain content-safety call
  -- (it enforces block AND feeds intent on one classify).
  local trace_id = intent_trace_id(conf)
  if trace_id then
    local ibody = kong.request.get_body()
    if type(ibody) == "table" and type(ibody.messages) == "table" then
      return access_intent(conf, ibody, trace_id)
    end
    return
  end

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
  -- Intent double-duty: capture the completion (the final answer + any tool-call
  -- decision) as intent events, continuing the request phase's event index.
  local trace_id = intent_trace_id(conf)
  if trace_id then
    return response_intent(conf, trace_id)
  end

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
