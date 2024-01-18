#include <iot/cJSON.h>
#include <iot/mongoose.h>
#include "session.h"
#include "http.h"
#include "middleware.h"

struct middleware {
    char method[MAX_API_LEN];
    handler pre_hook;   //请求到达，发送到rpcd前调用
    handler post_hook;  //回复到达，发送给请求者前调用
    bool no_auth;       //无需登录也能访问的接口
};

static struct middleware s_middlewares[] = { //调用优先级，和数组下标一致，下标越小，优先级越高
    {
        .method = "*",  //匹配所有
        .pre_hook = pre_session_get,
        .no_auth = true,
    }, {
        .method = "challenge",
        .pre_hook = pre_session_challenge,
        .post_hook = post_session_challenge,
        .no_auth = true,
    }, {
        .method = "login",
        .pre_hook = pre_session_login,
        .post_hook = post_session_login,
        .no_auth = true,
    }, {
        .method = "logout",
        .pre_hook = pre_session_logout,
    }, {
        .method = "is_inited", //是否初始化
        .no_auth = true,
    }, {
        .method = "get_locale", //获取语言
        .no_auth = true,
    }, {
        .method = "set_locale", //设置语言
        .no_auth = true,
    }, {
        .method = "board_info", //board info
        .no_auth = true,
    }, {
        .method = "init_password", //初始化密码
        .no_auth = true,
        .post_hook = post_session_login,
    },
};


/*
return:
true: 拦截
*/
bool cb_pre_hooks(struct rpc_call_context *ctx) {
    bool no_auth = false;
    bool is_remote = true;
    if ( ctx->c->rem.ip == 0x0100007f ) { // 本地调用
        is_remote = false;
    }

    struct http_private *priv = (struct http_private *)ctx->c->mgr->userdata;

    for (int i = 0; i < sizeof(s_middlewares)/sizeof(s_middlewares[0]); i++) {
        struct middleware *m = &s_middlewares[i];
        if (m->method[0] != '*' && (!ctx->method || mg_casecmp(cJSON_GetStringValue(ctx->method), m->method) )) { //not matched
            continue;
        }

        if (!priv->cfg.opts->devel_mode && is_remote && !m->no_auth && !ctx->s) { // 未登陆
            mg_http_reply(ctx->c, 401, IOT_SDK_HOST, "{\"code\": -10000}\n");
            return true;
        }
        if (m->no_auth && m->method[0] != '*' ) {
            no_auth = true;
        }

        if (m->pre_hook && m->pre_hook(ctx)) {
            return true;
        }
    }

    if (!priv->cfg.opts->devel_mode && is_remote && !no_auth && !ctx->s) {
        mg_http_reply(ctx->c, 401, IOT_SDK_HOST, "{\"code\": -10000}\n");
        return true;
    }

    return false;
}

/*
return:
true: 拦截
*/
bool cb_post_hooks(struct rpc_call_context *ctx) {
    for (int i = 0; i < sizeof(s_middlewares)/sizeof(s_middlewares[0]); i++) {
        struct middleware *m = &s_middlewares[i];
        if (m->method[0] != '*' && mg_casecmp(cJSON_GetStringValue(ctx->method), m->method)) { //not matched
            continue;
        }

        if (m->post_hook && m->post_hook(ctx)) {
            return true;
        }
    }

    return false;
}