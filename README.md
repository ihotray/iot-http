# iot-http
 A http server base libiot



# plugin机制
- 内置接口的URI为/api或/deive/{devid}/api固定格式, HTTP method为POST. 为了第三方对接，可通过插件机制灵活添加其他URI和HTTP method的响应接口。


## 概述

HTTP 插件系统允许通过编写 Lua 插件来扩展 HTTP 服务器的功能。插件系统主要由以下部分组成：

1. 插件注册机制
2. 路由配置
3. 请求处理

## 插件目录结构

每个插件需要遵循以下目录结构:

```
plugin/
  └── your_plugin_name/
      ├── routes.json    # 路由配置文件
      └── handler.lua    # 请求处理程序
```

## 创建插件

### 1. 路由配置 (routes.json)

在 `routes.json` 中定义插件需要处理的 HTTP 路径:

```json
[
    "/api/your/path1",
    "/api/your/path2"
]

* 路径支持通配符#，如/api/your/path#
```

### 2. 处理程序 (handler.lua)

创建处理程序文件 `handler.lua`:

```lua
local cjson = require 'cjson.safe'

local plugin_name = "your_plugin_name"

local header = "Host: iot-web\r\nCache-Control: no-cache, no-store, max-age=0\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Type: application/json\r\n"

local M = {}
--- handler 总入口，可以根据uri实现对应的业务处理逻辑
function M.handler(args)
    -- args 包含以下字段:
    -- method: HTTP 方法 (GET/POST 等)
    -- uri: 请求路径
    -- body: 请求体内容
    -- query: URL 查询参数数组
    -- header: HTTP 头部数组
    -- client: 客户端IP
    -- logined: 是否通过了/api接口登录（携带对应的access_token时）
    
    return cjson.encode({
        plugin = plugin_name,
        code = 200,
        header = header,
        body = "your response"
    })
end

return M
```

handler收到的请求数据示例：
```
{
    "method": "POST",
    "query": [
        {
            "keytest1": "valuetest1"
        },
        {
            "keytest2": "valuetest2"
        }
    ],
    "header": [
        {
            "test": "1"
        },
        {
            "User-Agent": "Apifox/1.0.0 (https://apifox.com)"
        },
        {
            "Content-Type": "application/json"
        },
        {
            "Accept": "*/*"
        },
        {
            "Host": "10.5.2.47:8080"
        },
        {
            "Accept-Encoding": "gzip, deflate, br"
        },
        {
            "Connection": "keep-alive"
        },
        {
            "Content-Length": "20"
        }
    ],
    "logined": false,
    "client": "10.5.2.30",
    "uri": "/api/system/user_login_nonce",
    "body": "post data, post data"
}
```

登录校验：可以使用/api接口的登录结果（即logined字段），也可以自建登录校验逻辑。

## 插件响应格式

插件必须返回以下 JSON 格式的响应:

```json
{
    "plugin": "插件名称",
    "code": HTTP状态码,
    "header": "HTTP响应头",
    "body": "响应内容"
}

*plugin字段为必须项
```


## 插件加载流程

1. 系统启动时会扫描配置的插件目录, 目前仅支持`/usr/share/iot/rpc/plugin/`
2. 加载每个插件目录下的 `routes.json`
3. 注册插件的路由
4. 当请求匹配到插件路由时,调用对应的 `handler.lua`

## 注意事项

1. handler.lua 文件需要放置在 `/usr/share/iot/rpc/plugin/your_plugin_name/` 目录下
2. 插件响应必须是有效的 JSON 格式
3. 处理函数应该进行适当的错误处理
4. 建议在响应头中设置正确的 Content-Type

## 示例插件

参考 `plugin/unicom` 目录下的示例插件实现:

1. routes.json:
```json
[
    "/api/system/user_login_nonce",
    "/api/ntwk/wan"
]
```

2. handler.lua:
```lua
local cjson = require 'cjson.safe'

local plugin_name = "unicom"

local header = "Host: iot-web\r\nCache-Control: no-cache, no-store, max-age=0\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Type: application/json\r\n"


local M = {}

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
