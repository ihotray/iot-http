
#include <iot/cJSON.h>
#include <iot/mongoose.h>
#include <iot/iot.h>
#include "middleware.h"
#include "http.h"


static void mqtt_ev_open_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    MG_INFO(("mqtt client connection created"));
}

static void mqtt_ev_error_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    MG_ERROR(("%p %s", c->fd, (char *) ev_data));
    c->is_closing = 1;
}

static void mqtt_ev_poll_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct http_private *priv = (struct http_private*)c->mgr->userdata;
    if (!priv->cfg.opts->mqtt_keepalive) //no keepalive
        return;

    uint64_t now = mg_millis();

    if (priv->pong_active && now > priv->pong_active &&
        now - priv->pong_active > (priv->cfg.opts->mqtt_keepalive + 3)*1000) { //TODO
        MG_INFO(("mqtt client connction timeout"));
        c->is_draining = 1;
    }

}

static void mqtt_ev_close_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct http_private *priv = (struct http_private*)c->mgr->userdata;
    MG_INFO(("mqtt client connection closed"));
    priv->mqtt_conn = NULL; // Mark that we're closed

}

static void mqtt_ev_mqtt_open_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mg_str subt_resp_rpcd = mg_str(IOT_HTTP_TOPIC);
    struct mg_str subt_resp_proxy = mg_str(IOT_HTTP_PROXY_RESP_TOPIC);

    struct http_private *priv = (struct http_private*)c->mgr->userdata;

    MG_INFO(("connect to mqtt server: %s", priv->cfg.opts->mqtt_serve_address));
    struct mg_mqtt_opts sub_opts;
    memset(&sub_opts, 0, sizeof(sub_opts));
    sub_opts.topic = subt_resp_rpcd;
    sub_opts.qos = MQTT_QOS;
    mg_mqtt_sub(c, &sub_opts);
    MG_INFO(("subscribed to %.*s", (int) subt_resp_rpcd.len, subt_resp_rpcd.ptr));

    sub_opts.topic = subt_resp_proxy;
    mg_mqtt_sub(c, &sub_opts);

    MG_INFO(("subscribed to %.*s", (int) subt_resp_proxy.len, subt_resp_proxy.ptr));

}

static void mqtt_ev_mqtt_cmd_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    struct http_private *priv = (struct http_private*)c->mgr->userdata;

    if (mm->cmd == MQTT_CMD_PINGRESP) {
        priv->pong_active = mg_millis();
    }
}

/*
mg/iot-http/123
device/+/rpc/response/iot-http/123
*/
static struct mg_str connection_id(struct mg_str topic) {
    struct mg_str sub_topic_prefix = mg_str(IOT_HTTP_TOPIC_PREFIX);
    const char *p = mg_strstr(topic, sub_topic_prefix);
    if (p == NULL) {
        return mg_str("0");
    }

    struct mg_str topic_prefix = mg_str_n(p, topic.len - (p - topic.ptr));

    struct mg_str cid = mg_str_n(topic_prefix.ptr + sub_topic_prefix.len, topic_prefix.len - sub_topic_prefix.len);
    MG_DEBUG(("topic: %.*s, topic: %.*s, cid: %.*s", (int)topic.len, topic.ptr, (int)topic_prefix.len, topic_prefix.ptr, (int)cid.len, cid.ptr));
    return cid;
}

static void mqtt_ev_mqtt_msg_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mg_mqtt_message *mm = (struct mg_mqtt_message *)ev_data;
    MG_DEBUG(("received %.*s <- %.*s", (int) mm->data.len, mm->data.ptr,
        (int) mm->topic.len, mm->topic.ptr));
        
    //从topic解析客户端connection id
    struct mg_str cid = connection_id(mm->topic);

    struct mg_connection *dst = NULL;
    cJSON *root = cJSON_ParseWithLength(mm->data.ptr, mm->data.len);
    cJSON *method = cJSON_GetObjectItem(root, FIELD_METHOD);

    //查找客户端连接
    for (dst = c->mgr->conns; dst != NULL; dst = dst->next) {
        char id[32] = {0};
        mg_snprintf(id, sizeof(id) - 1, "%lu", dst->id);
        if (mg_strcmp(cid, mg_str(id)) == 0) {
            break;
        }
    }

    if (!dst) {
        MG_ERROR(("http dst connection [%lu] not found", cid));
        goto end;
    }

    if ( !cJSON_IsString(method) ) {
        MG_ERROR(("no method field found"));
        goto cb_end;
    }

    struct rpc_call_context ctx = {
        dst, method, root, ev_data, NULL
    };

    if ( cb_post_hooks(&ctx) ) {//丢弃或更改
        goto end;
    }

cb_end:

    //直接将结果发送给请求端
    MG_DEBUG(("send %.*s -> connection: [%lu], websocket: [%d]", (int) mm->data.len, mm->data.ptr, cid, dst->is_websocket ? 1 : 0));
    if (dst->is_websocket) {
        mg_ws_send(dst, mm->data.ptr, mm->data.len, WEBSOCKET_OP_TEXT);
    } else {
        mg_http_reply(dst, 200, IOT_SDK_HOST, "%.*s", (int) mm->data.len, mm->data.ptr);
    }

end:
    cJSON_Delete(root);
}

static void mqtt_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    switch (ev) {
        case MG_EV_OPEN:
            mqtt_ev_open_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_ERROR:
            mqtt_ev_error_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_OPEN:
            mqtt_ev_mqtt_open_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_CMD:
            mqtt_ev_mqtt_cmd_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_MSG:
            mqtt_ev_mqtt_msg_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_POLL:
            mqtt_ev_poll_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_CLOSE:
            mqtt_ev_close_cb(c, ev, ev_data, fn_data);
            break;
    }
}


// Timer function - recreate client connection if it is closed
void timer_mqtt_fn(void *arg) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct http_private *priv = (struct http_private*)mgr->userdata;
    uint64_t now = mg_millis();

    if (priv->mqtt_conn == NULL) {
        struct mg_mqtt_opts opts = { 0 };

        opts.clean = true;
        opts.qos = MQTT_QOS;
        opts.message = mg_str("goodbye");
        opts.keepalive = priv->cfg.opts->mqtt_keepalive;

        priv->mqtt_conn = mg_mqtt_connect(mgr, priv->cfg.opts->mqtt_serve_address, &opts, mqtt_cb, NULL);
        priv->ping_active = now;
        priv->pong_active = now;

    } else if (priv->cfg.opts->mqtt_keepalive) { //need keep alive
        
        if (now < priv->ping_active) {
            MG_INFO(("system time loopback"));
            priv->ping_active = now;
            priv->pong_active = now;
        }
        if (now - priv->ping_active >= priv->cfg.opts->mqtt_keepalive * 1000) {
            mg_mqtt_ping(priv->mqtt_conn);
            priv->ping_active = now;
        }
    }
}