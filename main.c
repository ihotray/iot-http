#include <iot/mongoose.h>
#include <iot/iot.h>
#include "http.h"


#define CERT "/www/iot/certs/server.cert"
#define KEY "/www/iot/certs/server.key"

static void usage(const char *prog, struct http_option *default_opts) {
    struct http_option *opts = default_opts;
    fprintf(stderr,
            "IoT-SDK v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -l ADDR     - http listening address, default: '%s'\n"
            "  -L ADDR     - https listening address, default: '%s'\n"
            "  -e 1|2|3    - http server mode, 1: http, 2: https, 3: http+https, default: %d\n"
            "  -c CERT     - cert content or file path for https, default: '%s'\n"
            "  -k KEY      - key content or file path for https, default: '%s'\n"
            "  -t n        - http timeout, default: %d seconds\n"
            "  -d DIR      - web file dir, default: '%s'\n"
            "  -D DIR      - upload file dir, default: '%s'\n"
            "  -s ADDR     - local mqtt server address, default: '%s'\n"
            "  -a n        - local mqtt keepalive, default: %d\n"
            "  -m prod|dev - running mode, default: '%s'\n"
            "  -v LEVEL    - debug level, from 0 to 4, default: %d\n",
            MG_VERSION, prog, opts->http_listening_address, opts->https_listening_address,
                        opts->http_mode, opts->https_cert, opts->https_certkey, opts->http_timeout, opts->http_serve_dir, opts->http_upload_dir,
                        opts->mqtt_serve_address, opts->mqtt_keepalive, "prod", opts->debug_level);

    exit(EXIT_FAILURE);
}

static void parse_args(int argc, char *argv[], struct http_option *opts) {
    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            opts->http_listening_address = argv[++i];
        } else if (strcmp(argv[i], "-L") == 0) {
            opts->https_listening_address = argv[++i];
        } else if (strcmp(argv[i], "-e") == 0) {
            opts->http_mode = atoi(argv[++i]);
            if (opts->http_mode < 1 || opts->http_mode > 3) {
                opts->http_mode = 1;
            }
        } else if (strcmp(argv[i], "-c") == 0) {
            opts->https_cert = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            opts->https_certkey = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0) {
            opts->http_timeout = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0) {
            opts->http_serve_dir = argv[++i];
        } else if (strcmp(argv[i], "-D") == 0) {
            opts->http_upload_dir = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0) {
            opts->mqtt_serve_address = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0) {
            opts->mqtt_keepalive = atoi(argv[++i]);
            if (opts->mqtt_keepalive < 6) {
                opts->mqtt_keepalive = 6;
            }
        } else if (strcmp(argv[i], "-m") == 0) {
            char *running_mode = argv[++i];
            opts->devel_mode = 0;
            if (strcmp(running_mode, "dev") == 0) {
                opts->devel_mode = 1;
            }
        } else if (strcmp(argv[i], "-v") == 0) {
            opts->debug_level = atoi(argv[++i]);
        } else {
            usage(argv[0], opts);
        }
    }

}

int main(int argc, char *argv[]) {

    struct http_option opts = {
        .http_listening_address = "http://0.0.0.0:8080",
        .https_listening_address = "https://0.0.0.0:8443",
        .https_ca = NULL,
        .https_cert = CERT,
        .https_certkey = KEY,
        .http_serve_dir = "/www/iot/web_root",
        .http_upload_dir = "/tmp/upload",

        .http_timeout = 60,
        .http_mode = 1,

        .mqtt_serve_address = MQTT_LISTEN_ADDR,
        .mqtt_keepalive = 6,
        .debug_level = MG_LL_INFO,
        .devel_mode  = 0
    };

    parse_args(argc, argv, &opts);

    MG_INFO(("IoT-SDK version         : v%s", MG_VERSION));
    if (opts.http_mode != 2)
        MG_INFO(("HTTP listening on       : %s", opts.http_listening_address));
    if (opts.http_mode > 1 )
        MG_INFO(("HTTPS Listening on      : %s", opts.https_listening_address));
    MG_INFO(("Development mode        : %d", opts.devel_mode));

    http_main(&opts);

    return 0;
}
