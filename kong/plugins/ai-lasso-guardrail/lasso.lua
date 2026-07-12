-- Pure translation logic for the ai-lasso-guardrail plugin.
--
-- Deliberately free of `resty.*`, `cjson`, and `kong.*` requires so it can be unit-tested
-- with busted on a plain Lua interpreter. Everything that touches the network or the Kong
-- PDK lives in client.lua / handler.lua; the bug-prone table transforms live here.
--
-- Mirrors the field names + block/mask semantics of the other Lasso integrations
-- (TrueFoundry `lasso.py`, Envoy `client.go`) so a shared contract stays recognizable.

local M = {}

-- INPUT/OUTPUT (the phase) -> Lasso messageType + the role we wrap content as.
local DIRECTION = {
  INPUT  = { message_type = "PROMPT",     role = "user" },
  OUTPUT = { message_type = "COMPLETION", role = "assistant" },
}

M.USER_ID_MAX_LENGTH = 128

local CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
local seeded = false

-- A ULID-shaped 26-char Crockford-base32 id. Not cryptographically strict, but time-ordered
-- + random, which is all sessionId aggregation needs. Kong seeds math.random per worker; we
-- seed defensively for the plain-Lua test environment.
function M.gen_ulid(now_ms, rand)
  if not seeded then
    math.randomseed((now_ms or (os.time() * 1000)) + (os.clock() * 1000000))
    seeded = true
  end
  rand = rand or math.random
  local chars = {}
  -- 10 chars (50 bits) of timestamp, then 16 chars (80 bits) of randomness.
  local ms = math.floor(now_ms or (os.time() * 1000))
  for i = 10, 1, -1 do            -- 10 chars (50 bits) of timestamp
    local idx = (ms % 32) + 1
    chars[i] = CROCKFORD:sub(idx, idx)
    ms = math.floor(ms / 32)
  end
  for i = 11, 26 do               -- 16 chars (80 bits) of randomness
    local idx = rand(1, 32)
    chars[i] = CROCKFORD:sub(idx, idx)
  end
  return table.concat(chars)
end

function M.direction(source)
  return DIRECTION[(source or "INPUT"):upper()] or DIRECTION.INPUT
end

-- Build the InvokeDeputiesRequest body (a Lua table; client.lua serializes it).
function M.build_payload(opts)
  local payload = {
    messages    = opts.messages,
    messageType = opts.message_type,
    sessionId   = opts.session_id,
    source      = { type = opts.source_type or "kong" },
  }
  if opts.user_id and opts.user_id ~= "" then
    payload.userId = string.sub(opts.user_id, 1, M.USER_ID_MAX_LENGTH)
  end
  if opts.tools and #opts.tools > 0 then
    payload.tools = opts.tools
  end
  -- Intent double-duty: session baseline the trace is scored against (upserted server-side).
  if opts.session_information then
    payload.sessionInformation = opts.session_information
  end
  return payload
end

-- ── Intent double-duty (native pre/post-LLM) ────────────────────────────────
-- When the app funnels LLM calls through Kong and seeds a per-turn `traceId`
-- header, the plugin's existing `access`/`response` classify calls double as
-- intent ingestion. These pure helpers turn OpenAI-wire messages into the
-- server's intent `Message` shape (role x single content-block) with stable
-- ids, so the server derives signals and dedups re-sent history by `eventId`.

-- Flatten OpenAI content (string | array of {type=text,text=...}) to plain text.
function M.flatten_text(content)
  if type(content) == "string" then
    return content
  end
  if type(content) == "table" then
    local parts = {}
    for _, block in ipairs(content) do
      if type(block) == "table" and block.type == "text" and type(block.text) == "string" then
        parts[#parts + 1] = block.text
      end
    end
    return table.concat(parts, " ")
  end
  return ""
end

-- Deterministic ULID-shaped event id: stable for a (trace_id, event_index) pair
-- across re-sends and unique within the trace, so the server's eventId-keyed cache
-- collapses the conversation history re-sent on every call. Keeps the 26-char
-- Crockford shape (passes the server's ULID validation): the trace_id's high 20
-- chars + 6 chars of base32 index (supports 32^6 ≈ 1e9 events per trace).
function M.derive_event_id(trace_id, event_index)
  local prefix = tostring(trace_id or ""):sub(1, 20)
  while #prefix < 20 do prefix = prefix .. "0" end
  local n = math.floor(tonumber(event_index) or 0)
  local suffix = {}
  for i = 6, 1, -1 do
    local idx = (n % 32) + 1
    suffix[i] = CROCKFORD:sub(idx, idx)
    n = math.floor(n / 32)
  end
  return prefix .. table.concat(suffix)
end

-- Parse an OpenAI tool-call `arguments` into the object the server's tool_use block requires.
-- Arguments arrive as a JSON string on the wire; `decode_json` (injected so this module stays
-- pure/cjson-free) turns it into a table. Already-decoded tables pass through; anything that
-- fails to decode becomes an empty object — still a valid tool_use input for the server.
local function tool_input_object(arguments, decode_json)
  if type(arguments) == "table" then
    return arguments
  end
  if type(arguments) == "string" and type(decode_json) == "function" then
    local decoded = decode_json(arguments)
    if type(decoded) == "table" then
      return decoded
    end
  end
  return {}
end

-- Transform OpenAI-wire messages into intent Messages with stable
-- traceId/eventId/eventIndex. `start_index` offsets the (0-based) event index so
-- the response phase continues after the request phase's events. Deterministic +
-- append-only ⟹ re-sent history yields identical ids ⟹ server-side idempotency.
-- `decode_json` (e.g. cjson.decode) parses tool-call arguments into the object the
-- server's tool_use block requires. Returns (intent_messages, produced_count).
function M.to_intent_messages(messages, trace_id, start_index, decode_json)
  local out = {}
  local base = math.floor(tonumber(start_index) or 0)
  local function push(role, content)
    local index = base + #out
    out[#out + 1] = {
      role = role,
      content = content,
      traceId = trace_id,
      eventId = M.derive_event_id(trace_id, index),
      eventIndex = index,
    }
  end

  for _, m in ipairs(messages or {}) do
    if type(m) == "table" and m.role then
      local role = tostring(m.role)
      if role == "tool" and m.tool_call_id then
        -- OpenAI tool result -> tool_result block (TOOL_OUTPUT_TEXT). The server derives the
        -- signal from the block type, but rejects role "tool"; tool results ride under `developer`.
        push("developer", { type = "tool_result", tool_use_id = m.tool_call_id,
                            content = M.flatten_text(m.content) })
      else
        -- Text first (USER_MESSAGE / MODEL_RESPONSE), then any tool calls.
        local text = M.flatten_text(m.content)
        if text ~= nil and text ~= "" then
          push(role, text)
        end
        if type(m.tool_calls) == "table" then
          for _, tc in ipairs(m.tool_calls) do
            local fn = type(tc) == "table" and tc["function"] or nil
            if type(fn) == "table" and fn.name then
              -- OpenAI tool call -> tool_use block (TOOL_INPUT_TEXT) under role `model`.
              -- `arguments` is a JSON string on the wire; the server's tool_use block requires
              -- an object, so decode it.
              push("model", { type = "tool_use", id = tc.id, name = fn.name,
                              input = tool_input_object(fn.arguments, decode_json) })
            end
          end
        end
      end
    end
  end
  return out, #out
end

-- Convert OpenAI tool definitions ({type="function", function={name,description,parameters}})
-- into the server's flat AvailableTool shape ({name, description, parameters}). Tools already in
-- the flat shape pass through; entries without a string name are dropped. Returns nil when there
-- is nothing to forward, so build_payload omits the field.
function M.to_intent_tools(tools)
  if type(tools) ~= "table" then
    return nil
  end
  local out = {}
  for _, t in ipairs(tools) do
    if type(t) == "table" then
      local fn = type(t["function"]) == "table" and t["function"] or t
      if type(fn.name) == "string" and fn.name ~= "" then
        out[#out + 1] = { name = fn.name, description = fn.description, parameters = fn.parameters }
      end
    end
  end
  if #out == 0 then
    return nil
  end
  return out
end

-- Block if any finding across any deputy has action == "BLOCK". Returns (blocked, detail).
function M.extract_block(findings)
  local details = {}
  for deputy, list in pairs(findings or {}) do
    if type(list) == "table" then
      for _, f in ipairs(list) do
        if type(f) == "table" and f.action == "BLOCK" then
          local name = f.name or "violation"
          local sev = f.severity and (" (" .. f.severity .. ")") or ""
          details[#details + 1] = deputy .. "/" .. name .. sev
        end
      end
    end
  end
  if #details > 0 then
    return true, table.concat(details, "; ")
  end
  return false, nil
end

-- Apply masking spans to a single content string. Lasso start/end are 0-based, end-exclusive
-- byte offsets; apply highest-first so earlier offsets stay valid.
local function apply_spans_to_text(content, spans)
  table.sort(spans, function(a, b) return a.start > b.start end)
  for _, s in ipairs(spans) do
    if s.start >= 0 and s["end"] > s.start and s["end"] <= #content then
      content = content:sub(1, s.start) .. s.mask .. content:sub(s["end"] + 1)
    end
  end
  return content
end

-- Redact AUTO_MASKING findings in-place on the messages table.
-- Prefers Lasso's top-level masked `messages` (authoritative) when present and shaped the
-- same; otherwise applies per-finding start/end/mask spans. Only AUTO_MASKING findings are
-- masked — alert/off findings can carry span metadata but must not be redacted.
-- Returns (messages, transformed).
function M.apply_masks(messages, resp)
  resp = resp or {}

  -- 1) authoritative masked messages from /classifix
  local masked = resp.messages
  if type(masked) == "table" and #masked == #messages and #messages > 0 then
    local transformed = false
    for i = 1, #messages do
      local new_content = masked[i] and masked[i].content
      if new_content ~= nil and tostring(new_content) ~= tostring(messages[i].content) then
        messages[i].content = new_content
        transformed = true
      end
    end
    if transformed then
      return messages, true
    end
  end

  -- 2) fall back to per-finding spans
  local by_index = {}
  for _, list in pairs(resp.findings or {}) do
    if type(list) == "table" then
      for _, f in ipairs(list) do
        if type(f) == "table" and f.action == "AUTO_MASKING"
           and f.start ~= nil and f["end"] ~= nil and f.mask then
          local mi = (f.message_index or 0) + 1  -- Lasso is 0-based; Lua is 1-based
          by_index[mi] = by_index[mi] or {}
          local spans = by_index[mi]
          spans[#spans + 1] = { start = f.start, ["end"] = f["end"], mask = f.mask }
        end
      end
    end
  end

  local transformed = false
  for mi, spans in pairs(by_index) do
    local msg = messages[mi]
    if msg and msg.content ~= nil then
      local original = tostring(msg.content)
      local updated = apply_spans_to_text(original, spans)
      if updated ~= original then
        msg.content = updated
        transformed = true
      end
    end
  end
  return messages, transformed
end

-- Decide the outcome of a classify/classifix response given the plugin config.
-- Returns a table: { action = "allow"|"block"|"mask", detail = <string?>, transformed = <bool> }
-- `messages` is mutated in place when action == "mask".
function M.decide(resp, messages, masking)
  resp = resp or {}
  if not resp.violations_detected then
    return { action = "allow" }
  end
  local blocked, detail = M.extract_block(resp.findings)
  if blocked then
    return { action = "block", detail = detail }   -- block trumps mask
  end
  if masking then
    local _, transformed = M.apply_masks(messages, resp)
    if transformed then
      return { action = "mask", transformed = true }
    end
  end
  -- AUTO_MASKING with masking off, or USER_ALERT / ADMIN_ALERT / OFF -> non-blocking.
  return { action = "allow" }
end

return M
