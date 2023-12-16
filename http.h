#ifndef __IOT_HTTP_H__
#define __IOT_HTTP_H__

#include <iot/mongoose.h>

struct http_option {
    const char *http_listening_address;  //http 监听端口
    const char *https_listening_address; //https 监听端口
    const char *https_ca;                //https ca
    const char *https_cert;              //https cert
    const char *https_certkey;           //https certkey
    const char *http_serve_dir;          //http serve dir, static resource
    const char *http_upload_dir;         //upload file store in

    int http_timeout;                    //http connection timeout
    int https_enable;                    //是否开启https端口

    const char *mqtt_serve_address;      //mqtt 服务端口
    int mqtt_keepalive;                  //mqtt 保活间隔

    int development_mode; //开发模式，不用鉴权
    int debug_level;

};

struct http_config {
    struct http_option *opts;
};

struct http_session {
    uint64_t active;
    mg_md5_ctx md5_ctx;
    struct mg_str filepath;
    struct mg_str ws_uri;
    void *fd;
    int filesize;
};

struct http_private {
    struct http_config cfg;

    struct mg_mgr mgr;
    struct mg_fs *fs;

    struct mg_connection *mqtt_conn;
    uint64_t ping_active;
    uint64_t pong_active;

    struct session *sessions;
    struct challenge *challenges;

};


int http_main(void *user_options);

#endif