#ifndef __IOT_HTTP_H__
#define __IOT_HTTP_H__

#include <iot/mongoose.h>

#define HTTP_DEFAULT_HEADER "Host: iot-web\r\nCache-Control: no-cache, no-store, max-age=0\r\nX-Frame-Options: SAMEORIGIN\r\n"

struct http_option {
    const char *http_listening_address;  //http 监听端口
    const char *https_listening_address; //https 监听端口
    const char *https_ca;                //https ca
    const char *https_cert;              //https cert
    const char *https_certkey;           //https certkey
    const char *http_serve_dir;          //http serve dir, static resource
    const char *http_plugin_dir;         //http plugin dir
    const char *http_upload_dir;         //upload file store in

    const char *http_404_page;         //http 404 page

    int http_timeout;                    //http connection timeout
    int http_mode;                       //http mode, 1: http, 2: https, 3: http+https

    const char *mqtt_serve_address;      //mqtt 服务端口
    int mqtt_keepalive;                  //mqtt 保活间隔

    int devel_mode; //开发模式，不用鉴权
    int debug_level;

};

struct http_config {
    struct http_option *opts;
};

struct http_session {
    uint64_t active;
    mg_sha256_ctx sha256_ctx;
    struct mg_str filepath;
    struct mg_str ws_uri;
    void *fd;
    int filesize;
};


struct http_plugin {
    struct http_plugin *next;
    struct mg_str name;
    void *routes;
};

struct http_private {
    struct http_config cfg;
    struct http_plugin *http_plugins;

    struct mg_mgr mgr;
    struct mg_fs *fs;

    struct mg_connection *mqtt_conn;
    uint64_t ping_active;
    uint64_t pong_active;

    struct session *sessions;
    struct challenge *challenges;

    struct mg_connection *http_1st_listener;
    struct mg_connection *http_2nd_listener;
    struct mg_connection *https_1st_listener;
    struct mg_connection *https_2nd_listener;

};


int http_main(void *user_options);

#endif
