#ifndef __IOT_SESSION_H__
#define __IOT_SESSION_H__

#include <iot/mongoose.h>
#include <iot/iot.h>

struct challenge {
    struct challenge *next;
    uint64_t expire; //超时时间
    int tries; //尝试次数
    struct mg_str username;
    struct mg_str nonce;
};

struct session {
    struct session *next;
    uint64_t expire;
    uint64_t timeout;
    struct mg_str token;
    struct mg_str username;
};

struct rpc_call_context;
bool pre_session_challenge(struct rpc_call_context *ctx);
bool post_session_challenge(struct rpc_call_context *ctx);

bool pre_session_login(struct rpc_call_context *ctx);
bool post_session_login(struct rpc_call_context *ctx);

bool pre_session_get(struct rpc_call_context *ctx);
bool pre_session_logout(struct rpc_call_context *ctx);

void timer_session_fn(void *arg);


#endif