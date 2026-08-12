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

  it("forwards agentId/agentName when resolved", function()
    local p = lasso.build_payload({
      messages = {}, message_type = "PROMPT", session_id = "s",
      agent_id = "svc-support-bot", agent_name = "Support Bot",
    })
    assert.equal("svc-support-bot", p.agentId)
    assert.equal("Support Bot", p.agentName)
  end)

  it("omits agentId/agentName when absent or empty", function()
    local p = lasso.build_payload({
      messages = {}, message_type = "PROMPT", session_id = "s", agent_name = "",
    })
    assert.is_nil(p.agentId)
    assert.is_nil(p.agentName)
  end)

  it("forwards agentId while agentName is absent (independent fields)", function()
    local p = lasso.build_payload({
      messages = {}, message_type = "PROMPT", session_id = "s", agent_id = "svc-support-bot",
    })
    assert.equal("svc-support-bot", p.agentId)
    assert.is_nil(p.agentName)
  end)
end)

describe("sanitize_agent_identity", function()
  it("trims and keeps a valid value", function()
    assert.equal("svc-support-bot", lasso.sanitize_agent_identity("  svc-support-bot \t"))
  end)

  it("keeps non-ASCII names", function()
    assert.equal("סוכן תמיכה", lasso.sanitize_agent_identity("סוכן תמיכה"))
  end)

  it("drops a non-string / empty / whitespace-only value", function()
    assert.is_nil(lasso.sanitize_agent_identity(nil))
    assert.is_nil(lasso.sanitize_agent_identity(42))
    assert.is_nil(lasso.sanitize_agent_identity(""))
    assert.is_nil(lasso.sanitize_agent_identity("   "))
  end)

  it("keeps a value at the cap and drops one over it", function()
    assert.equal(128, #lasso.sanitize_agent_identity(string.rep("a", 128)))
    assert.is_nil(lasso.sanitize_agent_identity(string.rep("a", 129)))
  end)

  it("drops control characters (Cc)", function()
    assert.is_nil(lasso.sanitize_agent_identity("bot\nname"))
    assert.is_nil(lasso.sanitize_agent_identity("bot\0name"))
    assert.is_nil(lasso.sanitize_agent_identity("bot\127name"))
    assert.is_nil(lasso.sanitize_agent_identity("bot\194\133name"))    -- U+0085 (C1)
  end)

  it("drops format characters (Cf) — bidi overrides and zero-width", function()
    assert.is_nil(lasso.sanitize_agent_identity("bot\226\128\174name"))  -- U+202E RLO
    assert.is_nil(lasso.sanitize_agent_identity("bot\226\128\139name"))  -- U+200B ZWSP
    assert.is_nil(lasso.sanitize_agent_identity("bot\239\187\191"))      -- U+FEFF BOM
    assert.is_nil(lasso.sanitize_agent_identity("bot\243\160\128\160"))  -- U+E0020 TAG SPACE
  end)

  it("keeps a high-plane codepoint that is not Cc/Cf", function()
    assert.equal("bot\240\159\164\150", lasso.sanitize_agent_identity("bot\240\159\164\150")) -- 🤖
  end)

  it("drops malformed UTF-8 (unknowable server-side, and unencodable by cjson)", function()
    assert.is_nil(lasso.sanitize_agent_identity("bot\255name"))
    assert.is_nil(lasso.sanitize_agent_identity("bot\226\128"))          -- truncated sequence
    assert.is_nil(lasso.sanitize_agent_identity("bot\128name"))          -- lone continuation byte
    assert.is_nil(lasso.sanitize_agent_identity("bot\192\175"))          -- overlong 2-byte '/'
    assert.is_nil(lasso.sanitize_agent_identity("bot\224\128\175"))      -- overlong 3-byte '/'
    assert.is_nil(lasso.sanitize_agent_identity("bot\240\128\128\175"))  -- overlong 4-byte '/'
    assert.is_nil(lasso.sanitize_agent_identity("bot\237\160\128"))      -- U+D800 surrogate half
    assert.is_nil(lasso.sanitize_agent_identity("bot\244\144\128\128"))  -- above U+10FFFF
  end)
end)

describe("resolve_agent_identity", function()
  it("uses the configured value when there is no header", function()
    local v, rejected = lasso.resolve_agent_identity(nil, "svc-support-bot")
    assert.equal("svc-support-bot", v)
    assert.is_false(rejected)
  end)

  it("lets the header override the configured value", function()
    local v, rejected = lasso.resolve_agent_identity("hdr-bot", "svc-support-bot")
    assert.equal("hdr-bot", v)
    assert.is_false(rejected)
  end)

  it("returns nil when neither source has a value", function()
    assert.is_nil((lasso.resolve_agent_identity(nil, nil)))
  end)

  it("falls back to config and flags rejection for an over-cap header", function()
    local v, rejected = lasso.resolve_agent_identity(string.rep("a", 129), "svc-support-bot")
    assert.equal("svc-support-bot", v)
    assert.is_true(rejected)
  end)

  it("drops a control-character header with no config to fall back to", function()
    local v, rejected = lasso.resolve_agent_identity("hdr\226\128\174bot", nil)
    assert.is_nil(v)
    assert.is_true(rejected)
  end)

  it("drops an invalid configured value", function()
    assert.is_nil((lasso.resolve_agent_identity(nil, string.rep("a", 200))))
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

  -- Stub JSON decoder (busted runs plain Lua without cjson): turns the wire arguments
  -- string into the object the server's tool_use block requires.
  local function decode(_)
    return { id = 123 }
  end

  it("maps user/tool_use/tool_result with stride-spaced eventIndex", function()
    local out, n = lasso.to_intent_messages(history, tid, 0, decode)
    assert.equal(4, n)                       -- n counts reproducible events (unmultiplied)
    assert.equal("user", out[2].role)
    assert.equal(10, out[2].eventIndex)      -- position 1 * STRIDE(10)
    assert.equal("tool_use", out[3].content.type)
    assert.equal("get_order", out[3].content.name)
    assert.equal(20, out[3].eventIndex)
    assert.equal("tool_result", out[4].content.type)
    assert.equal("call_1", out[4].content.tool_use_id)
    assert.equal(30, out[4].eventIndex)
  end)

  it("emits tool_use under role 'model' and tool_result under role 'developer'", function()
    local out = lasso.to_intent_messages(history, tid, 0, decode)
    assert.equal("model", out[3].role)      -- tool_use
    assert.equal("developer", out[4].role)  -- tool_result (server rejects role 'tool')
  end)

  it("decodes tool_use arguments into an object (server rejects a raw string)", function()
    local out = lasso.to_intent_messages(history, tid, 0, decode)
    assert.equal("table", type(out[3].content.input))
    assert.equal(123, out[3].content.input.id)
  end)

  it("falls back to an empty object when arguments cannot be decoded", function()
    local out = lasso.to_intent_messages(history, tid, 0) -- no decoder
    assert.equal("table", type(out[3].content.input))
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
    assert.equal(40, out[1].eventIndex)                    -- (start 4 + pos 0) * STRIDE
    assert.equal(lasso.derive_event_id(tid, 40), out[1].eventId)
  end)

  it("emits a reasoning block (role 'model') strictly BEFORE the answer it precedes", function()
    local out = lasso.to_intent_messages(
      { { role = "assistant", reasoning_content = "let me think", content = "the answer" } }, tid, 2)
    local reason, ans = out[1], out[2]
    assert.equal("reasoning", reason.content.type)
    assert.equal("let me think", reason.content.content)
    assert.equal("model", reason.role)
    assert.equal("the answer", ans.content)
    assert.equal(20, ans.eventIndex)                       -- answer at pos 2 * STRIDE, unshifted
    assert.equal(lasso.derive_event_id(tid, 20), ans.eventId)
    assert.equal(11, reason.eventIndex)                    -- reasoning in the gap (10,20) → before the answer
    assert.is_true(reason.eventIndex < ans.eventIndex)
    assert.not_equal(ans.eventId, reason.eventId)          -- distinct index → distinct id, no collision
  end)

  it("reasoning does not shift following tool_use, keeping the history re-send idempotent", function()
    -- turn 1 COMPLETION: model reasons, then calls 2 tools (base = 2 after system + user)
    local comp = lasso.to_intent_messages({ { role = "assistant", content = "", reasoning_content = "r",
      tool_calls = { { id = "c1", ["function"] = { name = "a", arguments = "{}" } },
                     { id = "c2", ["function"] = { name = "b", arguments = "{}" } } } } }, tid, 2, decode)
    -- turn 2 PROMPT re-sends that same assistant turn; history carries NO reasoning_content
    local hist = lasso.to_intent_messages({ { role = "assistant", content = "",
      tool_calls = { { id = "c1", ["function"] = { name = "a", arguments = "{}" } },
                     { id = "c2", ["function"] = { name = "b", arguments = "{}" } } } } }, tid, 2, decode)
    -- comp = [reasoning@11, tool_use@20, tool_use@30]; hist = [tool_use@20, tool_use@30]
    assert.equal("reasoning", comp[1].content.type)
    assert.equal(11, comp[1].eventIndex)                   -- in the gap, strictly before the first tool_use
    assert.equal(20, comp[2].eventIndex)
    assert.equal(30, comp[3].eventIndex)
    assert.is_true(comp[1].eventIndex < comp[2].eventIndex)
    assert.equal(hist[1].eventId, comp[2].eventId)         -- tool_use #1 id matches across phases
    assert.equal(hist[2].eventId, comp[3].eventId)         -- tool_use #2 id matches across phases
    assert.not_equal(comp[1].eventId, comp[2].eventId)     -- reasoning collides with neither tool_use
    assert.not_equal(comp[1].eventId, comp[3].eventId)
  end)

  it("falls back to thinking_blocks when reasoning_content is absent", function()
    local out = lasso.to_intent_messages(
      { { role = "assistant", content = "done", thinking_blocks = {
          { type = "thinking", thinking = "step 1" }, { type = "thinking", thinking = " step 2" } } } }, tid, 2)
    assert.equal("reasoning", out[1].content.type)
    assert.equal("step 1 step 2", out[1].content.content)
  end)

  it("emits no reasoning block when the message carries none", function()
    local out = lasso.to_intent_messages({ { role = "assistant", content = "plain" } }, tid, 0)
    assert.equal(1, #out)
    assert.equal("plain", out[1].content)
  end)

  it("gives consecutive reasoning-only messages distinct, ordered ids", function()
    -- two back-to-back reasoning-only messages (e.g. an n>1 completion) must not collide,
    -- even though neither advances the reproducible index.
    local out = lasso.to_intent_messages({
      { role = "assistant", reasoning_content = "first thought" },
      { role = "assistant", reasoning_content = "second thought" },
    }, tid, 2)
    assert.equal(2, #out)
    assert.equal("reasoning", out[1].content.type)
    assert.equal("reasoning", out[2].content.type)
    assert.is_true(out[1].eventIndex < out[2].eventIndex)  -- ascending in-gap order
    assert.not_equal(out[1].eventId, out[2].eventId)       -- distinct ids, no collision
  end)

  it("harvests reasoning only from completion (assistant/model) messages", function()
    -- a stray reasoning field on a user/developer message must NOT synthesize a reasoning event
    local out = lasso.to_intent_messages({
      { role = "user", content = "hi", reasoning_content = "not the model's" },
    }, tid, 0)
    assert.equal(1, #out)
    assert.equal("hi", out[1].content)                     -- only the user text, no reasoning block
  end)
end)

describe("reasoning_text", function()
  it("prefers the reasoning_content string", function()
    assert.equal("cot", lasso.reasoning_text({ reasoning_content = "cot" }))
  end)
  it("joins thinking_blocks when there is no reasoning_content", function()
    assert.equal("ab", lasso.reasoning_text({ thinking_blocks = {
      { type = "thinking", thinking = "a" }, { type = "thinking", thinking = "b" } } }))
  end)
  it("returns nil when the message has no reasoning", function()
    assert.is_nil(lasso.reasoning_text({ content = "x" }))
  end)
end)

describe("to_intent_tools", function()
  it("flattens OpenAI tool defs to the server's AvailableTool shape", function()
    local out = lasso.to_intent_tools({
      { type = "function", ["function"] = { name = "get_order",
        description = "look up an order", parameters = { type = "object" } } },
    })
    assert.equal(1, #out)
    assert.equal("get_order", out[1].name)
    assert.equal("look up an order", out[1].description)
    assert.equal("object", out[1].parameters.type)
    assert.is_nil(out[1].type)      -- no OpenAI wrapper leaks through
    assert.is_nil(out[1]["function"])
  end)

  it("passes already-flat tools through and drops nameless entries", function()
    local out = lasso.to_intent_tools({
      { name = "divide", description = "math" },
      { type = "function", ["function"] = { description = "no name" } },
    })
    assert.equal(1, #out)
    assert.equal("divide", out[1].name)
  end)

  it("returns nil when there is nothing to forward", function()
    assert.is_nil(lasso.to_intent_tools(nil))
    assert.is_nil(lasso.to_intent_tools({}))
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
