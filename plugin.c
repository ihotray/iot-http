#include <iot/mongoose.h>
#include <iot/cJSON.h>
#include <iot/iot.h>
#include "http.h"
#include "session.h"
#include "middleware.h"


static void load_plugin(const char *name, void *handle) {
    struct http_private *priv = (struct http_private *)handle;
    struct mg_str dir = mg_str(priv->cfg.opts->http_plugin_dir);
    char *path = NULL;
    if (dir.len > 0 && dir.ptr[dir.len-1] == '/') {
        path = mg_mprintf("%.*s%s/routes.json", (int)dir.len, dir.ptr, name);
    } else {
        path = mg_mprintf("%.*s/%s/routes.json", (int)dir.len, dir.ptr, name);
    }

    MG_INFO(("find plugin: %s", name));
    size_t file_size = 0;
    priv->fs->st(path, &file_size, NULL);
    size_t align_file_size = ((file_size + 1) / 64 + 1) * 64; //align 64 bytes
    MG_INFO(("open plugin file: %s, size: %d(%d)", path, file_size, align_file_size));
    void *fp = priv->fs->op(path, MG_FS_READ);
    if (fp) {
        char *buf = calloc(1, align_file_size);
        size_t size = priv->fs->rd(fp, buf, align_file_size - 1);
        cJSON *root = cJSON_ParseWithLength(buf, size);
        if (root && cJSON_IsArray(root)) {
            struct http_plugin *plugin = calloc(1, sizeof(struct http_plugin));
            plugin->name = mg_strdup(mg_str(name));
            plugin->routes = root;
            LIST_ADD_TAIL(struct http_plugin, &priv->http_plugins, plugin);
            MG_INFO(("load plugin: %s", name));
        } else {
            MG_ERROR(("plugin file %s format is wrong", path));
            if (root)
                cJSON_Delete(root);
        }
        free(buf);
        priv->fs->cl(fp);

    } else {
        MG_ERROR(("cannot open plugin file: %s", path));
    }

    free(path);

}

void http_plugin_load(void *handle) {
    struct http_private *priv = (struct http_private *)handle;
    //load plugins
    priv->fs->ls(priv->cfg.opts->http_plugin_dir, load_plugin, handle);
}

void http_plugin_free(void *handle) {
    struct http_private *priv = (struct http_private *)handle;
    // free plugins
    for (struct http_plugin *next, *p = priv->http_plugins; p != NULL; p = next) {
        next = p->next;
        LIST_DELETE(struct http_plugin, &priv->http_plugins, p);
        if (p->name.ptr)
            free((void*)p->name.ptr);
        cJSON_Delete(p->routes);
        free(p);
    }
}

/*
{
	"method": "call",
	"param": ["plugin/xxx/handler", "handler", {"method": "POST/GET", "uri": "/api/system/user_login_nonce", "query": "", body: "", "header": []}]
}

/usr/share/iot/rpc/plugin/xxx/handler.lua
*/

static void call_handler(struct mg_str plugin, struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct http_private *priv = (struct http_private *)c->mgr->userdata;
    struct mg_str pub_topic = mg_str(mg_mprintf(IOT_HTTP_RPCD_TOPIC, c->id));
    cJSON *root = NULL;

    struct mg_http_message *hm = (struct mg_http_message *)ev_data;
    MG_DEBUG(("match plugin %.*s's uri: %.*s", plugin.len, plugin.ptr, hm->uri.len, hm->uri.ptr));

    if (!priv->mqtt_conn) {
        MG_ERROR(("mqtt connection lost"));
        mg_http_reply(c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10002}\n");
        goto end;
    }

    //create json
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, FIELD_METHOD, "call");

    struct rpc_call_context ctx = {
        c, NULL, NULL, ev_data, NULL
    };
    pre_session_get(&ctx); //get session by /api login token

    cJSON *args = cJSON_CreateObject();
    if (ctx.s) {
        cJSON_AddItemToObject(args, "logined", cJSON_CreateBool(true));
        if (ctx.s->username.ptr) {
            cJSON_AddItemToObject(args, FIELD_USERNAME, cJSON_CreateString(ctx.s->username.ptr));
        }
    } else {
        cJSON_AddItemToObject(args, "logined", cJSON_CreateBool(false));
    }

    char ip[16] = {0};
    mg_snprintf(ip, sizeof(ip)-1, "%M", mg_print_ip, c->rem);
    cJSON_AddItemToObject(args, "client", cJSON_CreateString(ip));

    char *value = mg_mprintf("%.*s",hm->method.len, hm->method.ptr);
    cJSON_AddStringToObject(args, "method", value);
    free(value);
    value = mg_mprintf("%.*s",hm->uri.len, hm->uri.ptr);
    cJSON_AddStringToObject(args, "uri", value);
    free(value);
    value = mg_mprintf("%.*s",hm->body.len, hm->body.ptr);
    cJSON_AddStringToObject(args, "body", value);
    free(value);


    //add query
    cJSON *querys = cJSON_CreateArray();
    struct mg_str k, v;
    while (mg_split(&hm->query, &k, &v, '&')) {
        if (k.len > 0) {
            char *key = mg_mprintf("%.*s", k.len, k.ptr);
            char *val = mg_mprintf("%.*s", v.len, v.ptr);
            cJSON *query = cJSON_CreateObject();
            cJSON_AddStringToObject(query, key, val);
            cJSON_AddItemToArray(querys, query);
            free(key);
            free(val);
        }
    }
    cJSON_AddItemToObject(args, "query", querys);

    //add hearders
    cJSON *headers = cJSON_CreateArray();
    for (int i = 0; i < sizeof(hm->headers) / sizeof(hm->headers[0]) && hm->headers[i].name.len > 0; i++) {
        struct mg_str *k = &hm->headers[i].name, *v = &hm->headers[i].value;
        char *key = mg_mprintf("%.*s", k->len, k->ptr);
        char *val = mg_mprintf("%.*s", v->len, v->ptr);
        cJSON *header = cJSON_CreateObject();
        cJSON_AddStringToObject(header, key, val);
        cJSON_AddItemToArray(headers, header);
        free(key);
        free(val);
    }
    cJSON_AddItemToObject(args, "header", headers);

    cJSON *param = cJSON_CreateArray();
    char *handler = mg_mprintf("plugin/%.*s/handler", plugin.len, plugin.ptr);
    cJSON_AddItemToArray(param, cJSON_CreateString(handler));
    free(handler);
    cJSON_AddItemToArray(param, cJSON_CreateString("handler"));
    cJSON_AddItemToArray(param, args);
    cJSON_AddItemToObject(root, FIELD_PARAM, param);

    char *printed = cJSON_Print(root);
    MG_DEBUG(("pub %s -> %.*s", printed, (int) pub_topic.len, pub_topic.ptr));

    struct mg_mqtt_opts pub_opts;
    memset(&pub_opts, 0, sizeof(pub_opts));
    pub_opts.topic = pub_topic;
    pub_opts.message = mg_str(printed);
    pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
    mg_mqtt_pub(priv->mqtt_conn, &pub_opts);

    cJSON_free(printed);

end:
    if (root)
        cJSON_Delete(root);

    if (pub_topic.ptr)
        free((void*)pub_topic.ptr);
}

bool http_plugin_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct http_private *priv = (struct http_private *)c->mgr->userdata;
    struct mg_http_message *hm = (struct mg_http_message *)ev_data;

    for (struct http_plugin *plugin = priv->http_plugins; plugin != NULL; plugin = plugin->next) {
        if (plugin->routes && cJSON_IsArray(plugin->routes)) {
            cJSON *routes = (cJSON *)plugin->routes;
            cJSON *route = NULL;
            cJSON_ArrayForEach(route, routes) {
                if (cJSON_IsString(route) && mg_http_match_uri(hm, cJSON_GetStringValue(route))) { //matched route, handle by plugin
                    call_handler(plugin->name, c, ev, ev_data, fn_data);
                    return true;
                }
            }
        }
    }

    return false;
}