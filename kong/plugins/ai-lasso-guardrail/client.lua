-- Thin HTTP client for the Lasso classify/classifix API. Kept small on purpose: all the
-- logic worth testing lives in lasso.lua; this only does transport + (de)serialization,
-- which is exercised under Pongo integration rather than plain-Lua unit tests.

local http = require "resty.http"
local cjson = require "cjson.safe"

local Client = {}

-- Returns (data, err_kind, status):
--   data      decoded response table on success, else nil
--   err_kind  nil | "auth" | "http" | "conn" | "parse"
--   status    HTTP status when there was a response
function Client.call(conf, endpoint, payload)
  local httpc = http.new()
  httpc:set_timeout(conf.timeout or 10000)

  local base = (conf.lasso_api_base or ""):gsub("/+$", "")
  local res, err = httpc:request_uri(base .. "/" .. endpoint, {
    method = "POST",
    body = cjson.encode(payload),
    headers = {
      ["Content-Type"] = "application/json",
      ["lasso-api-key"] = conf.lasso_api_key,
    },
    ssl_verify = conf.ssl_verify ~= false,
    keepalive_timeout = 60000,
  })

  if not res then
    return nil, "conn", nil, err
  end
  -- Auth/config errors are surfaced regardless of fail-mode (see handler): a bad key must
  -- not be silently swallowed by fail-open.
  if res.status == 401 or res.status == 403 then
    return nil, "auth", res.status
  end
  if res.status < 200 or res.status >= 300 then
    return nil, "http", res.status
  end

  local data = cjson.decode(res.body or "")
  if type(data) ~= "table" then
    return nil, "parse", res.status
  end
  return data, nil, res.status
end

return Client
