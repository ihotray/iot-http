#include <iot/mongoose.h>
#include <iot/iot.h>
#include "http.h"

static const char *s_cert = "-----BEGIN CERTIFICATE-----\n"
"MIIDMzCCAhsCFDkAgEpMXOjrLNnbytaj/XjCwgs1MA0GCSqGSIb3DQEBCwUAMFQx\n"
"CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
"LweJGbpA3N1NeImZ0sFTztlfrQrh3CIpUOzSY59KiiX6ZYX3Xh/yMOOlBXVO5wb9\n"
"b0QpXuWEwLRVzyS6RwGz9Qtes1wqRn3Lgf9JjgWBq7QwTd4bdf3s3xLJCbdO9qa5\n"
"DIdZAgkbC+lyPDkWfobSg2t/VHnPkQu3FyXpqpq3BEyzUHMV9nw6NuHdybE2b6TZ\n"
"M7xH9SwR4AMTxjcG0QzsK0hEYtq3c9LS2HrpR01EKwgjdlJF09l6p/c5H/tYksg5\n"
"Jo96rkD25KwpYgTlYW8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAhZRJeN60Hsjs\n"
"gHJ7iEDOGioJ1DlmAC3dKpkbHnQSIwrKt191xJyh6K3z4Zc1KyGWpH9Ivj7AEacm\n"
"/7GYIeJuxBTvajy8VPlW0Lrkbc9ADJl0h+MiqPe23kRfkAPGYOB8pH+OTjfz7BO1\n"
"KrJ1k9GyO6YdX13gnQ9u5eIZTzjI8Tmt1egs+bNfkw903vgkvq6DmI/LfG4YzUMC\n"
"KvhTgvJVaeoWQe17fK3JMmppfCNzkZlBiiZn4dO0M8B8FtY1fkBDF/P7uMMkE3j7\n"
"I0VutKd95w==\n"
"-----END CERTIFICATE-----\n";

static const char *s_certkey = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEArSM1XBqSPC5LMe0HiFOtPR1MJmXqDg7otJOtPWphUEb5ci6f\n"
"u8iNIIFKC2GzmgP9TZzORS8lqiZqouM9OlNYt428/E5ElqfqJlTkB3n0x7kniWsF\n"
"ugRcwj/r1XR2hQFPUUcZrb/ggsIHfakcr20cRL4wWjNqKkppGlonlRJMmkuNiLBE\n"
"n/QzIUcFpmNBSMgkVX3+zOyJ/1cBnAIhZnraNmq8k/2AQbv/e/21gyhzw1JGzNtP\n"
"4ZvDFSwmjXKOQn2ZJU2gcHYHVNxfvZCemYsLIVl+V66kwvBO9pDKTb5bQ74gGcmQ\n"
"SWTLu7W4tw7Rip0JJG14hnTJAzBKwUcZazmTQVSpAoGAWXiZlQN8cXm+V594JwFL\n"
"dMEVpYTcloJw1NvtCV+wRsKRQH8K4podbJ1Wk8tG1K4AsRJgAHwK+dgHPRtIm3/Q\n"
"AKCs3HAc1DIqBTPmgb0rmjRrtpia8IhP3ZZwo4+pSCKI7xUXAhpRB5uGXoM0MR16\n"
"NfWvaNgJd2RqpROL1YzPlykCgYBoEG//++vWn7ucJwhwCYwDTLjLMGxIdh61Tux5\n"
"iuN49Tj/Hepd2sOsc3SnYHLGw3LtuX3ziJeHH4YjmyJddgnSC8CzT0r0N1HNHfO4\n"
"pgeXeHorQQe8zID7+WJb/E1T0hKO8xKpjG3JIZM/+/i/VA81KT/usKAoGUDgRj0W\n"
"27KbCQKBgAFglZ/jSgcAxORknm4e75eGfExmY7VKF1yCzUBQ1IYoAAhEJQdmEEsj\n"
"C/YkFnxAyFCFomxQadiWNYy7Z7IyATZ6RlhHqx4wouHGYHXqSk+0iySxiWkJCyYB\n"
"1PZ5VvU83vu8ciHQi1qZF6qtmwgMS/EhXkWyrDU6KBzWjR2YsUjF\n"
"-----END RSA PRIVATE KEY-----\n";

static void usage(const char *prog, struct http_option *default_opts) {
    struct http_option *opts = default_opts;
    fprintf(stderr,
            "IoT-SDK v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -l ADDR     - http listening address, default: '%s'\n"
            "  -L ADDR     - https listening address, default: '%s'\n"
            "  -e 0|1      - https enable, default: %d\n"
            "  -t n        - http timeout, default: %d seconds\n"
            "  -d DIR      - web file dir, default: '%s'\n"
            "  -D DIR      - upload file dir, default: '%s'\n"
            "  -s ADDDR    - mqtt server address, default: '%s'\n"
            "  -k n        - mqtt timeout, default: '%d'\n"
            "  -m prod|dev - running mode, default: '%s'\n"
            "  -v LEVEL    - debug level, from 0 to 4, default: %d\n",
            MG_VERSION, prog, opts->http_listening_address, opts->https_listening_address,
                        opts->https_enable, opts->http_timeout, opts->http_serve_dir, opts->http_upload_dir,
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
            opts->https_enable = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0) {
            opts->http_timeout = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0) {
            opts->http_serve_dir = argv[++i];
        } else if (strcmp(argv[i], "-D") == 0) {
            opts->http_upload_dir = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0) {
            opts->mqtt_serve_address = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            opts->mqtt_keepalive = atoi(argv[++i]);
            if (opts->mqtt_keepalive < 6) {
                opts->mqtt_keepalive = 6;
            }
        } else if (strcmp(argv[i], "-m") == 0) {
            char *running_mode = argv[++i];
            opts->development_mode = 0;
            if (strcmp(running_mode, "dev") == 0) {
                opts->development_mode = 1;
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
        .https_cert = s_cert,
        .https_certkey = s_certkey,
        .http_serve_dir = "/www/iot/web_root",
        .http_upload_dir = "/tmp/upload",

        .http_timeout = 60,
        .https_enable = 0,

        .mqtt_serve_address = MQTT_LISTEN_ADDR,
        .mqtt_keepalive = 6,
        .debug_level = MG_LL_INFO,
        .development_mode  = 0
    };

    parse_args(argc, argv, &opts);

    MG_INFO(("IoT-SDK version        : v%s", MG_VERSION));
    MG_INFO(("HTTP listening on      : %s", opts.http_listening_address));
    if (opts.https_enable)
        MG_INFO(("HTTPS Listening on     : %s", opts.http_listening_address));
    MG_INFO(("Development mode        : %d", opts.development_mode));

    http_main(&opts);

    return 0;
}
