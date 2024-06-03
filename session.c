#include <iot/cJSON.h>
#include <iot/mongoose.h>
#include <iot/iot.h>
#include "session.h"
#include "middleware.h"
#include "http.h"

bool pre_session_challenge(struct rpc_call_context *ctx) {

    struct http_private *priv = (struct http_private*)ctx->c->mgr->userdata;

    if (ctx->s) { //已登录用户
        MG_INFO(("token %.*s is logined", ctx->s->token.len, ctx->s->token.ptr));
        mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10003}\n");
        return true;
    }

    cJSON *username = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_PARAM), FIELD_USERNAME);
    if (!cJSON_IsString(username)) {
        MG_DEBUG(("username is null"));
        mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10001}\n");
        return true;
    }

#ifdef ONE_DEVICE_LOGGED_IN_LIMIT
    for (struct session *s = priv->sessions; s != NULL; s = s->next) {
        if (!mg_strcmp(s->username, mg_str(cJSON_GetStringValue(username))) ) {
            MG_INFO(("user %.*s is logged in", s->username.len, s->username.ptr));
            mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10006}\n");
            return true;
        }
    }
#endif

    for (struct challenge *c = priv->challenges; c != NULL; c = c->next) {
        if (!mg_strcmp(c->username, mg_str(cJSON_GetStringValue(username)))) { //found exist challenge
            MG_INFO(("nonce %.*s  user %.*s is exist", c->nonce.len, c->nonce.ptr, c->username.len, c->username.ptr));
            mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"data\":{\"username\":\"%.*s\",\"nonce\":\"%.*s\"},\"method\":\"challenge\",\"code\":0}", c->username.len, c->username.ptr, c->nonce.len, c->nonce.ptr);
            return true;
        }
    }

    return false;
}

bool post_session_challenge(struct rpc_call_context *ctx) {

    cJSON *code = cJSON_GetObjectItem(ctx->root, FIELD_CODE);
    cJSON *username = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_DATA), FIELD_USERNAME);
    cJSON *nonce = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_DATA), FIELD_NONCE);
    cJSON *timeout = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_DATA), FIELD_TIMEOUT);
    cJSON *tries = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_DATA), FIELD_TRIES);

    struct http_private *priv = (struct http_private*)ctx->c->mgr->userdata;

    int n_timeout = DEFALUT_NONCE_TIMEOUT;
    int n_tries = DEFAULT_NONCE_TRIES;
    
    if (!cJSON_IsNumber(code) || (int)cJSON_GetNumberValue(code) != 0) {
        goto end;
    }

    if ( !cJSON_IsString(username) || !cJSON_IsString(nonce) ) {
        mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10004}\n");
        MG_ERROR(("bad rpc challenge resp"));
        return true;
    }

    if ( cJSON_IsNumber(timeout) && \
            (int)cJSON_GetNumberValue(timeout) > 0 && \
            (int)cJSON_GetNumberValue(timeout) < MAX_NONCE_TIMEOUT ) {
        n_timeout = (int)cJSON_GetNumberValue(timeout);
    }

    if ( cJSON_IsNumber(tries) && \
            (int)cJSON_GetNumberValue(tries) > 0 && \
            (int)cJSON_GetNumberValue(tries) < MAX_NONCE_TRIES ) {
        n_tries = (int)cJSON_GetNumberValue(tries);
    }

    struct challenge *c = (struct challenge *) calloc(1, sizeof(struct challenge));
    if (!c) {
        MG_ERROR(("OOM"));
        mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10002}\n");
        return true;
    }

    c->expire = mg_millis() + n_timeout * 1000;
    c->tries = n_tries;
    c->username = mg_strdup(mg_str(cJSON_GetStringValue(username)));
    c->nonce = mg_strdup(mg_str(cJSON_GetStringValue(nonce)));

    LIST_ADD_TAIL(struct challenge, &priv->challenges, c);
    MG_INFO(("nonce %.*s challenge", c->nonce.len, c->nonce.ptr));

end:
    return false;
}

bool pre_session_login(struct rpc_call_context *ctx) {

    cJSON *username = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_PARAM), FIELD_USERNAME);
    cJSON *password = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_PARAM), FIELD_PASSWORD);

    struct http_private *priv = (struct http_private*)ctx->c->mgr->userdata;

    if ( !cJSON_IsString(username) || !cJSON_IsString(password) ) {
        MG_INFO(("some param miss"));
        mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10003}\n");
        return true;
    }

    struct challenge *c;
    for (c = priv->challenges; c != NULL; c = c->next) {
        if (!mg_strcmp(c->username, mg_str(cJSON_GetStringValue(username)))) { //found exist nonce
            char *nonce = mg_mprintf("%.*s", c->nonce.len, c->nonce.ptr);
            cJSON_AddItemToObject(cJSON_GetObjectItem(ctx->root, FIELD_PARAM), FIELD_NONCE, cJSON_CreateString(nonce));
            free(nonce);
            MG_INFO(("nonce %.*s of user %.*s is exist", c->nonce.len, c->nonce.ptr, c->username.len, c->username.ptr));
            c->tries--;
            break;
        }
    }
    if (!c || c->tries < 0) {
        MG_INFO(("no challenge found or try too many times"));
        mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10005}\n");
        return true;
    }

    return false;
}

bool post_session_login(struct rpc_call_context *ctx) {

    cJSON *code = cJSON_GetObjectItem(ctx->root, FIELD_CODE);
    cJSON *token = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_DATA), FIELD_TOKEN);
    cJSON *timeout = cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_DATA), FIELD_TIMEOUT);
    cJSON *username =  cJSON_GetObjectItem(cJSON_GetObjectItem(ctx->root, FIELD_DATA), FIELD_USERNAME);

    struct http_private *priv = (struct http_private*)ctx->c->mgr->userdata;


    int n_timeout = DEFAULT_TOKEN_TIMEOUT;

    if (!cJSON_IsNumber(code) || (int)cJSON_GetNumberValue(code) != 0) { //todo add retry times left
        goto end;
    }

    if ( !cJSON_IsString(token) ) {
        mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10004}\n");
        MG_ERROR(("bad rpc login resp"));
        return true;
    }
    if ( cJSON_IsNumber(timeout) && \
            (int)cJSON_GetNumberValue(timeout) > 0 && \
            (int)cJSON_GetNumberValue(timeout) < MAX_TOKEN_TIMEOUT ) {
        n_timeout = (int)cJSON_GetNumberValue(timeout);
    }

    struct session *s = (struct session *) calloc(1, sizeof(struct session));
    if (!s) {
        MG_ERROR(("OOM"));
        mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": -10002}\n");
        return true;
    }

    s->timeout = n_timeout;
    s->expire = mg_millis() + s->timeout * 1000;
    s->token = mg_strdup(mg_str(cJSON_GetStringValue(token)));
    LIST_ADD_HEAD(struct session, &priv->sessions, s);

    MG_INFO(("token %.*s login", s->token.len, s->token.ptr));

    if ( cJSON_IsString(username) ) {
        s->username = mg_strdup(mg_str(cJSON_GetStringValue(username)));
        for (struct challenge *c = priv->challenges; c != NULL; c = c->next ) {
            if (!mg_strcmp(c->username, mg_str(cJSON_GetStringValue(username)))) { //found exist nonce
                MG_INFO(("delete nonce %.*s because of user %.*s logined", c->nonce.len, c->nonce.ptr, c->username.len, c->username.ptr));
                LIST_DELETE(struct challenge, &priv->challenges, c);
                if (c->username.ptr)
                    free((void*)c->username.ptr);
                if (c->nonce.ptr)
                    free((void*)c->nonce.ptr);
                free(c);
                break;
            }
        }
    }

end:

    return false;
}

/*
Cookie: access_token: token
Authorization: Bearer token
*/
bool pre_session_get(struct rpc_call_context *ctx) {
    
    struct mg_http_message *hm = (struct mg_http_message *) ctx->ev_data;
    struct http_private *priv = (struct http_private*)ctx->c->mgr->userdata;

    char user[MAX_USERNAME_LEN] = {0}, token[MAX_TOKEN_LEN] = {0};
    
    mg_http_creds(hm, user, sizeof(user), token, sizeof(token));
    
    for (struct session *s = priv->sessions; s != NULL; s = s->next) {
        if (!mg_strcmp(s->token, mg_str(token))) { //match
            uint64_t now = mg_millis();
            if (now > s->expire) {
                MG_INFO(("token %s is timeout: %llu-%llu=%llu", token, now, s->expire, now - s->expire));
                break;
            }

            if (s->username.ptr) {
                cJSON_AddItemToObject(ctx->root, FIELD_USERNAME, cJSON_CreateString(s->username.ptr));
            }

            s->expire = now + s->timeout * 1000;
            ctx->s = s;
            
            break;
        }
    }

    return false;
}

bool pre_session_logout(struct rpc_call_context *ctx) {
    struct http_private *priv = (struct http_private*)ctx->c->mgr->userdata;
    if (ctx->s) {
        MG_INFO(("token %.*s logout", ctx->s->token.len, ctx->s->token.ptr));
        LIST_DELETE(struct session, &priv->sessions, ctx->s);
        if (ctx->s->token.ptr)
            free((void*)ctx->s->token.ptr);
        if (ctx->s->username.ptr)
            free((void*)ctx->s->username.ptr);
        free(ctx->s);
        ctx->s = NULL;
    }

    mg_http_reply(ctx->c, 200, HTTP_DEFAULT_HEADER, "{\"code\": 0}\n");

    return true;

}

void timer_session_fn(void *arg) {

    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct http_private *priv = (struct http_private*)mgr->userdata;

    uint64_t now = mg_millis();

    for (struct session *next, *s = priv->sessions; s != NULL; s = next) {

        next = s->next;

        if (now > s->expire) { //timeout
            MG_INFO(("session token %.*s timeout: %llu-%llu=%llu", s->token.len, s->token.ptr, now, s->expire, now - s->expire));
            LIST_DELETE(struct session, &priv->sessions, s);
            if (s->token.ptr)
                free((void*)s->token.ptr);
            if (s->username.ptr)
                free((void*)s->username.ptr);
            free(s);
        }
    }

    for (struct challenge *next, *c = priv->challenges; c != NULL; c = next) {

        next = c->next;

        if (now > c->expire) {
            MG_INFO(("nonce %.*s of user %.*s timeout: %llu-%llu=%llu", c->nonce.len, c->nonce.ptr, c->username.len, c->username.ptr, now, c->expire, now - c->expire));
            LIST_DELETE(struct challenge, &priv->challenges, c);
            if (c->username.ptr)
                free((void*)c->username.ptr);
            if (c->nonce.ptr)
                free((void*)c->nonce.ptr);
            free(c);
        }

    }

}

