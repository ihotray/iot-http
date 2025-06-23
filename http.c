#include <iot/iot.h>
#include "mqtt.h"
#include "http.h"
#include "session.h"
#include "middleware.h"
#include "plugin.h"


static int s_signo;
static void signal_handler(int signo) {
    s_signo = signo;
}

static void http_ev_accept_cb(struct mg_connection *c, int ev, void *ev_data) {

    if (c->fn_data) {
        MG_ERROR(("bad logic error"));
        exit(EXIT_FAILURE);
    }

    c->fn_data = calloc(1, sizeof(struct http_session));
    if (!c->fn_data) {
        MG_ERROR(("OOM"));
        exit(EXIT_FAILURE);
    }

    struct http_session *s = (struct http_session*)c->fn_data;
    s->active = mg_millis();

}

static void http_ev_read_cb(struct mg_connection *c, int ev, void *ev_data) {

    if (!c->fn_data)
        return;

    struct http_session *s = (struct http_session*)c->fn_data;
    s->active = mg_millis();

}

static void http_ev_poll_cb(struct mg_connection *c, int ev, void *ev_data) {

    if (!c->fn_data)
        return;

    struct http_session *s = (struct http_session*)c->fn_data;
    if (!c->is_websocket) {
        struct http_private *priv = (struct http_private *)c->mgr->userdata;
        uint64_t now = mg_millis();
        if (s->active > now || now - s->active > priv->cfg.opts->http_timeout *1000 ) { //http_timeout
            MG_INFO(("http connection %lu timeout", c->id));
            c->is_closing = 1;
        }
    }
}

static void http_ev_close_cb(struct mg_connection *c, int ev, void *ev_data) {

    struct http_private *priv = (struct http_private *)c->mgr->userdata;

    if ( c == priv->http_1st_listener ) {
        MG_INFO(("http listener %lu closed", c->id));
        priv->http_1st_listener = NULL;
    } else if ( c == priv->http_2nd_listener ) {
        MG_INFO(("http listener %lu closed", c->id));
        priv->http_2nd_listener = NULL;
    } else if ( c == priv->https_1st_listener ) {
        MG_INFO(("https listener %lu closed", c->id));
        priv->https_1st_listener = NULL;
    } else if ( c == priv->https_2nd_listener ) {
        MG_INFO(("https listener %lu closed", c->id));
        priv->https_2nd_listener = NULL;
    }

    if (!c->fn_data)
        return;

    struct http_session *s = (struct http_session*)c->fn_data;

    if (s->fd)
        priv->fs->cl(s->fd);

    if (s->filepath.buf)
        free((void*)s->filepath.buf);

    free(s);

}

static void http_alive_handler(struct mg_connection *c, int ev, void *ev_data) {
    mg_http_reply(c, 200, HTTP_DEFAULT_HEADER, "true");
}

static void http_websocket_handler(struct mg_connection *c, int ev, void *ev_data) {

    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct rpc_call_context ctx = {
            c, NULL, NULL, ev_data, NULL
    };
    if ( cb_pre_hooks(&ctx) ) { //登录授权检查
        c->is_draining = 1;
        return;
    }

    MG_INFO(("upgrade connection %lu to websocket", c->id));
    mg_ws_upgrade(c, hm, NULL);

}

static void http_serve_dir_handler(struct mg_connection *c, int ev, void *ev_data) {

    struct http_private *priv = (struct http_private*)c->mgr->userdata;
    struct mg_http_serve_opts opts = { 0 };
    opts.root_dir = priv->cfg.opts->http_serve_dir;
    opts.extra_headers = HTTP_DEFAULT_HEADER;
    opts.page404 = priv->cfg.opts->http_404_page;
    opts.fs = priv->fs;
    mg_http_serve_dir(c, ev_data, &opts);

}


static void http_api_handler(struct mg_connection *c, int ev, void *ev_data) {

    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct mg_str devid = mg_str(NULL);
    struct mg_str pub_topic = mg_str(NULL);
    struct http_private *priv = (struct http_private *)c->mgr->userdata;

    cJSON *root = cJSON_ParseWithLength(hm->body.buf, hm->body.len);

    //parse method name
    cJSON *method = cJSON_GetObjectItem(root, FIELD_METHOD);

    MG_DEBUG(("received %.*s <- %.*s", (int)hm->body.len, hm->body.buf, (int)hm->uri.len, hm->uri.buf));

    if ( !cJSON_IsString(method) ) {
        MG_ERROR(("no method found"));
        mg_http_reply(c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10001}\n");
        goto end;
    }

    //pub to iot-rpcd
    if (!priv->mqtt_conn) {
        MG_ERROR(("mqtt connection lost"));
        mg_http_reply(c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10002}\n");
        goto end;
    }

    struct mg_str caps[2] = { mg_str(NULL), mg_str(NULL) };
    if ( mg_match(hm->uri, mg_str("/device/#/api"), caps) ) {
        MG_DEBUG(("match /device/#/api"));
        devid = caps[0]; //devid is the first capture group
    }

    //通过topic传递客户端connection id，后面用
    struct mg_str mg_method_prefix = mg_str(MQTT_METHOD_PREFIX);
    struct mg_str mg_method = mg_str(cJSON_GetStringValue(method));
    if (mg_method.len > mg_method_prefix.len && !mg_strcasecmp(mg_str_n(mg_method.buf, mg_method_prefix.len), mg_method_prefix)) {
        //to mqtt server
        pub_topic = mg_str(mg_mprintf(IOT_HTTP_MQTT_TOPIC, c->id));
    } else if (devid.len > 0) {
        //to agent
        pub_topic = mg_str(mg_mprintf(IOT_HTTP_PROXY_REQ_TOPIC, (int)devid.len, devid.buf, c->id));
    } else {
        //to rpcd
        pub_topic = mg_str(mg_mprintf(IOT_HTTP_RPCD_TOPIC, c->id));
    }

    // add remote client ip
    const char *ip = mg_mprintf("%M", mg_print_ip, &c->rem);
    cJSON_AddItemToObject(root, FIELD_CLIENT, cJSON_CreateString(ip));
    free((void *)ip);

    struct rpc_call_context ctx = {
        c, method, root, ev_data, NULL
    };
    if ( cb_pre_hooks(&ctx) ) { //本地处理
        c->is_draining = 1;
        goto end;
    }

    char *printed = cJSON_Print(ctx.root); // data maybe modified by pre hooks

    MG_DEBUG(("pub %s -> %.*s", printed, (int) pub_topic.len, pub_topic.buf));

    struct mg_mqtt_opts pub_opts;
    memset(&pub_opts, 0, sizeof(pub_opts));
    pub_opts.topic = pub_topic;
    pub_opts.message = mg_str(printed);
    pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
    mg_mqtt_pub(priv->mqtt_conn, &pub_opts);

    cJSON_free(printed);

end:
    cJSON_Delete(root);

    if (pub_topic.buf)
        free((void*)pub_topic.buf);

}

static void http_ev_http_msg_cb(struct mg_connection *c, int ev, void *ev_data) {

    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    MG_DEBUG(("%.*s %.*s", (int) hm->method.len, hm->method.buf,
        (int) hm->uri.len, hm->uri.buf));

    //alive request
    if ( mg_strcasecmp(hm->uri, mg_str("/alive")) == 0 ) {
        http_alive_handler(c, ev, ev_data);
        return;
    }

    //websocket
    if ( mg_strcasecmp(hm->uri, mg_str("/websocket")) == 0 ) {
        http_websocket_handler(c, ev, ev_data);
        return;
    }

    //handled by plugin
    if ( http_plugin_handler(c, ev, ev_data) ) {
        return;
    }

    //not post, as serve files
    if ( mg_strcasecmp(hm->method, mg_str("POST")) ) {
        http_serve_dir_handler(c, ev, ev_data);
        return;
    }

    //post /api
    if ( mg_strcasecmp(hm->uri, mg_str("/api")) == 0 || mg_match(hm->uri, mg_str("/device/#/api"), NULL) ) {
        http_api_handler(c, ev, ev_data);
        return;
    }

    //default
    mg_http_reply(c, 404, HTTP_DEFAULT_HEADER, "request not supported\n");

}

static void http_ev_http_upload_cb(struct mg_connection *c, int ev, void *ev_data) {

    struct http_private *priv = (struct http_private *)c->mgr->userdata;

    if ( !c->fn_data ) {
        MG_ERROR(("no fn_data found"));
        return;
    }

    struct http_session *s = (struct http_session*)c->fn_data;

    if (s->is_upload && c->recv.len > 0) {
        s->filesize_recv += c->recv.len;
        if ( s->fd ) {
            priv->fs->wr(s->fd, c->recv.buf, c->recv.len);
            mg_sha256_update(&s->sha256_ctx, (const unsigned char *)c->recv.buf, c->recv.len);
        }
        c->recv.len = 0;
    }
    if (s->is_upload && s->filesize_recv >= s->filesize_expt) {
        unsigned char sha256_digest[32] = {0};
        char sha256sum[sizeof(sha256_digest)*2+1] = {0};
        if ( s->fd && s->filesize_recv) {
            mg_sha256_final(sha256_digest, &s->sha256_ctx);
            for (int i=0; i<sizeof(sha256_digest); i++) {
                mg_snprintf(&sha256sum[i*2], 3, "%02x", sha256_digest[i]);
            }
        }
        mg_http_reply(c, 200, HTTP_DEFAULT_HEADER, "{\"code\": 0, \"data\": {\"filepath\": \"%.*s\", \"sha256sum\": \"%s\"}}\n", (int)s->filepath.len, s->filepath.buf, sha256sum);
        c->is_draining = 1;
    }
}

static void http_ev_http_hdrs_cb(struct mg_connection *c, int ev, void *ev_data) {

    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct http_private *priv = (struct http_private *)c->mgr->userdata;

    if ( !c->fn_data ) {
        MG_ERROR(("no fn_data found"));
        return;
    }

    if ( mg_strcasecmp(hm->uri, mg_str("/upload")) ) { //not upload request
        return;
    }

    //auth check
    struct rpc_call_context ctx = {
        c, NULL, NULL, ev_data, NULL
    };

    if ( cb_pre_hooks(&ctx) ) { //登录授权检查
        mg_http_reply(c, 401, HTTP_DEFAULT_HEADER, "{\"code\": -10000}\n");
        return;
    }

    struct http_session *s = (struct http_session*)c->fn_data;

    s->is_upload = true;  // Mark this session as an upload session
    s->filesize_expt = hm->body.len;  // Store number of bytes we expect
    mg_iobuf_del(&c->recv, 0, hm->head.len);  // Delete HTTP headers
    c->pfn = NULL;  // Silence HTTP protocol handler, we'll use MG_EV_READ

    if ( s->filesize_expt && !s->fd ) {
        //创建目录
        priv->fs->mkd(priv->cfg.opts->http_upload_dir);

        struct mg_str filename = mg_http_var(hm->query, mg_str("name"));
        if (filename.len == 0) {
            filename = mg_str("upload.dat");
        }
        char *filepath = mg_mprintf("%s/%.*s", priv->cfg.opts->http_upload_dir, (int)filename.len, filename.buf);
        s->filepath = mg_str(filepath);
        //删除已有文件
        priv->fs->rm(filepath);
        //创建新文件
        s->fd = priv->fs->op(filepath, MG_FS_WRITE);
        if (!s->fd) {
            MG_ERROR(("cannot open file %s for writing", filepath));
            mg_http_reply(c, 500, HTTP_DEFAULT_HEADER, "{\"code\": -10002}\n");
            c->is_draining = 1;
            return;
        }
        mg_sha256_init(&s->sha256_ctx);
    }

    http_ev_http_upload_cb(c, ev, ev_data);
}


static void http_ev_ws_cb(struct mg_connection *c, int ev, void *ev_data) {

    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
    struct mg_str devid = mg_str(NULL);
    struct mg_str data = mg_str(NULL);
    struct mg_str pub_topic = mg_str(NULL);
    struct http_private *priv = (struct http_private *)c->mgr->userdata;

    struct mg_str caps[3] = { mg_str(NULL), mg_str(NULL), mg_str(NULL) };

    // [devid]data
    if ( !mg_match(wm->data, mg_str("[#]#"), caps) /*|| caps[0].len == 0 || caps[1].len == 0*/ ) {
        MG_ERROR(("websocket msg: %.*s format([devid]data) is wrong", wm->data.len, wm->data.buf));
        goto end;
    }
    devid = caps[0];
    data = caps[1];

    //parse json from body
    MG_DEBUG(("received %.*s over websocket", (int)wm->data.len, wm->data.buf));

    //pub to iot-rpcd
    if (!priv->mqtt_conn) {
        MG_ERROR(("mqtt connection lost"));
        goto end;
    }

    //通过topic传递客户端connection id，后面用
    if ( !mg_strcasecmp(devid, mg_str("$mqtt")) ) {
        // to mqtt server
        pub_topic = mg_str(mg_mprintf(IOT_HTTP_MQTT_TOPIC, c->id));
    } else if ( !mg_strcasecmp(devid, mg_str("$rpcd")) ) {
        // to rpcd
        pub_topic = mg_str(mg_mprintf(IOT_HTTP_RPCD_TOPIC, c->id));
    } else {
        // to agent
        pub_topic = mg_str(mg_mprintf(IOT_HTTP_PROXY_REQ_TOPIC, (int)devid.len, devid.buf, c->id));
    }

    MG_DEBUG(("pub %.*s -> %.*s", (int)data.len, data.buf, (int)pub_topic.len, pub_topic.buf));

    struct mg_mqtt_opts pub_opts;
    memset(&pub_opts, 0, sizeof(pub_opts));
    pub_opts.topic = pub_topic;
    pub_opts.message = data;
    pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
    mg_mqtt_pub(priv->mqtt_conn, &pub_opts);

end:
    if (pub_topic.buf)
        free((void*)pub_topic.buf);
}


// Event handler for the listening connection.
static void http_cb(struct mg_connection *c, int ev, void *ev_data) {
    switch (ev) {
        case MG_EV_ACCEPT:
            http_ev_accept_cb(c, ev, ev_data);
            break;

        case MG_EV_READ:
            http_ev_read_cb(c, ev, ev_data);
            http_ev_http_upload_cb(c, ev, ev_data);
            break;

        case MG_EV_POLL:
            http_ev_poll_cb(c, ev, ev_data);
            break;

        case MG_EV_CLOSE:
            http_ev_close_cb(c, ev, ev_data);
            break;

        case MG_EV_HTTP_MSG:
            http_ev_http_msg_cb(c, ev, ev_data);
            break;

        case MG_EV_HTTP_HDRS:
            http_ev_http_hdrs_cb(c, ev, ev_data);
            break;

        case MG_EV_WS_MSG: //websocket msg
            http_ev_ws_cb(c, ev, ev_data);
            break;

    }
}


static void https_accept_cb(struct mg_connection *c, int ev, void *ev_data) {

    struct http_private *priv = (struct http_private*)c->mgr->userdata;
    struct mg_tls_opts opts = { 0 };
    opts.cert = mg_str(priv->cfg.opts->https_cert);
    opts.key = mg_str(priv->cfg.opts->https_key);
    mg_tls_init(c, &opts);

}

static void https_cb(struct mg_connection *c, int ev, void *ev_data) {

    if (ev == MG_EV_ACCEPT)
        https_accept_cb(c, ev, ev_data);

    http_cb(c, ev, ev_data);
}

void timer_http_fn(void *arg) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct http_private *priv = (struct http_private *)mgr->userdata;

    if (priv->cfg.opts->http_mode != 2) { //http
        if ( !priv->http_1st_listener ) {
            struct mg_connection *c = mg_http_listen(&priv->mgr, priv->cfg.opts->http_listening_address, http_cb, NULL);
            if ( !c ) {
                MG_ERROR(("Cannot listen on %s. Use http://ADDR:PORT or :PORT", priv->cfg.opts->http_listening_address));
            } else {
                MG_INFO(("listen on %s", priv->cfg.opts->http_listening_address));
                priv->http_1st_listener = c;
            }
        }
        if ( priv->http_1st_listener && priv->http_1st_listener->loc.is_ip6 && !priv->http_2nd_listener) { //已监听ipv6，还需要监听ipv4
            unsigned short port = mg_url_port(priv->cfg.opts->http_listening_address);
            const char *address = mg_mprintf("http://0.0.0.0:%d", port);
            struct mg_connection *c = mg_http_listen(&priv->mgr, address, http_cb, NULL);
            free((void*)address);
            if ( !c ) {
                MG_ERROR(("Cannot listen on %s. Use http://ADDR:PORT or :PORT", address));
            } else {
                MG_INFO(("listen on %s", address));
                priv->http_2nd_listener = c;
            }
        }
    }

    if (priv->cfg.opts->http_mode > 1) { //https
        if ( !priv->https_1st_listener ) {
            struct mg_connection *c = mg_http_listen(&priv->mgr, priv->cfg.opts->https_listening_address, https_cb, NULL);
            if ( !c ) {
                MG_ERROR(("Cannot listen on %s. Use https://ADDR:PORT or :PORT", priv->cfg.opts->https_listening_address));
            } else {
                MG_INFO(("listen on %s", priv->cfg.opts->https_listening_address));
                priv->https_1st_listener = c;
            }
        }
        if ( priv->https_1st_listener && priv->https_1st_listener->loc.is_ip6 && !priv->https_2nd_listener ) { //已监听ipv6，还需要监听ipv4
            unsigned short port = mg_url_port(priv->cfg.opts->https_listening_address);
            const char *address = mg_mprintf("https://0.0.0.0:%d", port);
            struct mg_connection *c = mg_http_listen(&priv->mgr, address, https_cb, NULL);
            free((void*)address);
            if ( !c ) {
                MG_ERROR(("Cannot listen on %s. Use https://ADDR:PORT or :PORT", address));
            } else {
                MG_INFO(("listen on %s", address));
                priv->https_2nd_listener = c;
            }
        }
    }
}

int http_init(void **priv, void *opts) {

    struct http_private *p;
    int timer_opts = MG_TIMER_REPEAT | MG_TIMER_RUN_NOW;

    signal(SIGINT, signal_handler);   // Setup signal handlers - exist event
    signal(SIGTERM, signal_handler);  // manager loop on SIGINT and SIGTERM

    *priv = NULL;
    p = calloc(1, sizeof(struct http_private));
    if (!p)
        return -1;
    
    p->cfg.opts = opts;
    mg_log_set(p->cfg.opts->debug_level);

    p->fs = &mg_fs_posix;

    mg_mgr_init(&p->mgr);

    //load plugins
    http_plugin_load(p);

    p->mgr.userdata = p;

    mg_timer_add(&p->mgr, 1000, timer_opts, timer_mqtt_fn, &p->mgr);
    mg_timer_add(&p->mgr, 1000, timer_opts, timer_session_fn, &p->mgr);
    mg_timer_add(&p->mgr, 1000, timer_opts, timer_http_fn, &p->mgr);

    *priv = p;

    return 0;

}

void http_run(void *handle) {
    struct http_private *priv = (struct http_private *)handle;
    while (s_signo == 0) mg_mgr_poll(&priv->mgr, 1000);  // Event loop, 1000ms timeout
}

void http_exit(void *handle) {
    struct http_private *priv = (struct http_private *)handle;

    // free plugins
    http_plugin_free(handle);

    mg_mgr_free(&priv->mgr);
    free(handle);
}

int http_main(void *user_options) {

    struct http_option *opts = (struct http_option *)user_options;
    void *http_handle;
    int ret;

    ret = http_init(&http_handle, opts);
    if (ret)
        exit(EXIT_FAILURE);

    http_run(http_handle);

    http_exit(http_handle);

    return 0;

}