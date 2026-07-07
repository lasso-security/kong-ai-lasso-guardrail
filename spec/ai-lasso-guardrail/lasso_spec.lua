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
