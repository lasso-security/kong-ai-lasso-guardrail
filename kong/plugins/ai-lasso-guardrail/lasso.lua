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
  return payload
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
