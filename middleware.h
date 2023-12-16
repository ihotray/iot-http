#ifndef __IOT_MIDDLEWARE_H__
#define __IOT_MIDDLEWARE_H__

#include <iot/cJSON.h>
#include <iot/mongoose.h>
#include <iot/iot.h>


struct session;
struct rpc_call_context {
    struct mg_connection *c;
    cJSON *method;
    cJSON *root;
    void *ev_data;
    struct session *s;  //pre_hook使用该值
};

typedef bool (*handler)(struct rpc_call_context *ctx);


bool cb_pre_hooks(struct rpc_call_context *ctx);
bool cb_post_hooks(struct rpc_call_context *ctx);

#endif