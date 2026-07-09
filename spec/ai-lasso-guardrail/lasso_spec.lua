-- Unit tests for the pure translation logic (kong/plugins/ai-lasso-guardrail/lasso.lua).
-- Runs on a plain Lua interpreter (no OpenResty/Kong) — that's why lasso.lua has no
-- resty/cjson/kong requires. Run with busted from the repo root.

package.path = "./?.lua;" .. package.path

local lasso = require "kong.plugins.ai-lasso-guardrail.lasso"

local CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

local function is_crockford(s)
  for i = 1, #s do
    if not CROCKFORD:find(s:sub(i, i), 1, true) then
      return false
    end
  end
  return true
end

describe("gen_ulid", function()
  it("is 26 Crockford-base32 chars", function()
    local u = lasso.gen_ulid()
    assert.equal(26, #u)
    assert.is_true(is_crockford(u))
  end)

  it("is time-ordered (earlier ms sorts before later ms)", function()
    local a = lasso.gen_ulid(1000000000000)
    local b = lasso.gen_ulid(1000000009999)
    assert.is_true(a < b)
  end)

  it("varies for the same ms (random low bits)", function()
    local a = lasso.gen_ulid(1700000000000)
    local b = lasso.gen_ulid(1700000000000)
    assert.are_not.equal(a, b)
  end)
end)

describe("direction", function()
  it("maps INPUT -> PROMPT/user and OUTPUT -> COMPLETION/assistant", function()
    assert.same({ message_type = "PROMPT", role = "user" }, lasso.direction("INPUT"))
    assert.same({ message_type = "COMPLETION", role = "assistant" }, lasso.direction("OUTPUT"))
    assert.same({ message_type = "PROMPT", role = "user" }, lasso.direction(nil))
  end)
end)

describe("build_payload", function()
  it("sets messages, messageType, sessionId, source", function()
    local p = lasso.build_payload({
      messages = { { role = "user", content = "hi" } },
      message_type = "PROMPT",
      session_id = "01J000000000000000000000AA",
      source_type = "kong",
    })
    assert.equal("PROMPT", p.messageType)
    assert.equal("01J000000000000000000000AA", p.sessionId)
    assert.same({ type = "kong" }, p.source)
    assert.is_nil(p.userId)
    assert.is_nil(p.tools)
  end)

  it("truncates userId to 128 chars and omits empty tools", function()
    local p = lasso.build_payload({
      messages = {}, message_type = "PROMPT", session_id = "s",
      user_id = string.rep("u", 200), tools = {},
    })
    assert.equal(128, #p.userId)
    assert.is_nil(p.tools)
  end)

  it("forwards tools when present", function()
    local tools = { { type = "function", ["function"] = { name = "get_weather" } } }
    local p = lasso.build_payload({
      messages = {}, message_type = "PROMPT", session_id = "s", tools = tools,
    })
    assert.same(tools, p.tools)
  end)
end)

describe("extract_block", function()
  it("blocks on any BLOCK finding with detail", function()
    local blocked, detail = lasso.extract_block({
      jailbreak = { { action = "BLOCK", name = "pi", severity = "HIGH" } },
    })
    assert.is_true(blocked)
    assert.matches("jailbreak/pi", detail)
  end)

  it("does not block on non-BLOCK actions", function()
    local blocked = lasso.extract_block({
      pii = { { action = "USER_ALERT", name = "email" } },
    })
    assert.is_false(blocked)
  end)
end)

describe("apply_masks", function()
  it("prefers authoritative masked messages", function()
    local messages = { { role = "user", content = "email a@b.com" } }
    local _, transformed = lasso.apply_masks(messages, {
      messages = { { role = "user", content = "email <EMAIL>" } },
    })
    assert.is_true(transformed)
    assert.equal("email <EMAIL>", messages[1].content)
  end)

  it("applies AUTO_MASKING spans (0-based, end-exclusive)", function()
    -- "email a@b.com": a@b.com starts at byte offset 6, ends at 13
    local messages = { { role = "user", content = "email a@b.com" } }
    local _, transformed = lasso.apply_masks(messages, {
      findings = { pii = { {
        action = "AUTO_MASKING", message_index = 0, start = 6, ["end"] = 13, mask = "<EMAIL>",
      } } },
    })
    assert.is_true(transformed)
    assert.equal("email <EMAIL>", messages[1].content)
  end)

  it("applies multiple spans in one message right-to-left", function()
    local messages = { { role = "user", content = "a@b.com and c@d.com" } }
    lasso.apply_masks(messages, {
      findings = { pii = {
        { action = "AUTO_MASKING", message_index = 0, start = 0, ["end"] = 7, mask = "<E>" },
        { action = "AUTO_MASKING", message_index = 0, start = 12, ["end"] = 19, mask = "<E>" },
      } },
    })
    assert.equal("<E> and <E>", messages[1].content)
  end)

  it("ignores non-masking findings that carry spans", function()
    local messages = { { role = "user", content = "email a@b.com" } }
    local _, transformed = lasso.apply_masks(messages, {
      findings = { pii = { {
        action = "USER_ALERT", message_index = 0, start = 6, ["end"] = 13, mask = "<EMAIL>",
      } } },
    })
    assert.is_false(transformed)
    assert.equal("email a@b.com", messages[1].content)
  end)
end)

describe("decide", function()
  it("allows when no violations", function()
    local d = lasso.decide({ violations_detected = false }, {}, false)
    assert.equal("allow", d.action)
  end)

  it("blocks on BLOCK", function()
    local d = lasso.decide({
      violations_detected = true,
      findings = { jailbreak = { { action = "BLOCK", name = "pi" } } },
    }, {}, false)
    assert.equal("block", d.action)
  end)

  it("masks on AUTO_MASKING when masking on", function()
    local messages = { { role = "user", content = "email a@b.com" } }
    local d = lasso.decide({
      violations_detected = true,
      messages = { { role = "user", content = "email <EMAIL>" } },
      findings = { pii = { { action = "AUTO_MASKING", message_index = 0 } } },
    }, messages, true)
    assert.equal("mask", d.action)
    assert.equal("email <EMAIL>", messages[1].content)
  end)

  it("does not mask (allows) when masking off", function()
    local d = lasso.decide({
      violations_detected = true,
      findings = { pii = { { action = "AUTO_MASKING", message_index = 0 } } },
    }, { { role = "user", content = "x" } }, false)
    assert.equal("allow", d.action)
  end)

  it("block trumps mask", function()
    local d = lasso.decide({
      violations_detected = true,
      findings = {
        jailbreak = { { action = "BLOCK", name = "pi" } },
        pii = { { action = "AUTO_MASKING", message_index = 0 } },
      },
    }, { { role = "user", content = "x" } }, true)
    assert.equal("block", d.action)
  end)

  it("treats alert-only as non-blocking", function()
    local d = lasso.decide({
      violations_detected = true,
      findings = { pii = { { action = "USER_ALERT", name = "email" } } },
    }, {}, false)
    assert.equal("allow", d.action)
  end)
end)

describe("derive_event_id", function()
  local tid = "01HF3Z9DEFN0SGKPVJ9BQ6RPXG"
  it("is a 26-char Crockford id", function()
    local e = lasso.derive_event_id(tid, 0)
    assert.equal(26, #e)
    assert.is_true(is_crockford(e))
  end)
  it("is deterministic for the same (trace, index)", function()
    assert.equal(lasso.derive_event_id(tid, 5), lasso.derive_event_id(tid, 5))
  end)
  it("is unique per index within a trace", function()
    assert.are_not.equal(lasso.derive_event_id(tid, 0), lasso.derive_event_id(tid, 1))
  end)
end)

describe("to_intent_messages", function()
  local tid = "01HF3Z9DEFN0SGKPVJ9BQ6RPXG"
  local history = {
    { role = "system", content = "be helpful" },
    { role = "user", content = "where is order 123?" },
    { role = "assistant", content = "", tool_calls = {
        { id = "call_1", ["function"] = { name = "get_order", arguments = '{"id":123}' } } } },
    { role = "tool", tool_call_id = "call_1", content = '{"status":"shipped"}' },
  }

  it("maps user/tool_use/tool_result with monotonic 0-based eventIndex", function()
    local out, n = lasso.to_intent_messages(history, tid, 0)
    assert.equal(4, n)
    assert.equal("user", out[2].role)
    assert.equal(1, out[2].eventIndex)
    assert.equal("tool_use", out[3].content.type)
    assert.equal("get_order", out[3].content.name)
    assert.equal(2, out[3].eventIndex)
    assert.equal("tool_result", out[4].content.type)
    assert.equal("call_1", out[4].content.tool_use_id)
    assert.equal(3, out[4].eventIndex)
  end)

  it("stamps traceId + a derived eventId on every event", function()
    local out = lasso.to_intent_messages(history, tid, 0)
    for _, e in ipairs(out) do
      assert.equal(tid, e.traceId)
      assert.equal(26, #e.eventId)
    end
  end)

  it("is stable across re-sends (idempotent history)", function()
    local a = lasso.to_intent_messages(history, tid, 0)
    local b = lasso.to_intent_messages(history, tid, 0)
    for i = 1, #a do
      assert.equal(a[i].eventId, b[i].eventId)
      assert.equal(a[i].eventIndex, b[i].eventIndex)
    end
  end)

  it("continues the index from start_index (response phase)", function()
    local out = lasso.to_intent_messages({ { role = "assistant", content = "done" } }, tid, 4)
    assert.equal(4, out[1].eventIndex)
    assert.equal(lasso.derive_event_id(tid, 4), out[1].eventId)
  end)
end)

describe("flatten_text", function()
  it("returns a plain string as-is", function()
    assert.equal("hi", lasso.flatten_text("hi"))
  end)
  it("joins text blocks and ignores non-text blocks", function()
    assert.equal("a b", lasso.flatten_text({ { type = "text", text = "a" }, { type = "image" }, { type = "text", text = "b" } }))
  end)
end)
