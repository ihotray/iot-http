--- place this file as /usr/share/iot/rpc/plugin/unicom/handler.lua
local cjson = require 'cjson.safe'

local header =
    "Host: iot-web\r\nCache-Control: no-cache, no-store, max-age=0\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Type: application/json\r\n"

local plugin_name = "unicom"

local M = {}

--- TODO: add your handler function here
function M.handler(args)
    if args == nil then
        return cjson.encode({
            plugin = plugin_name,
            code = 200,
            header = header,
            body = "bad request"
        })
    end
    return cjson.encode({
        plugin = plugin_name,
        code = 200,
        header = header,
        body = cjson.encode(args)
    })
end

return M
