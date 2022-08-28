#define MAX_DISCOVERY_NAME_SIZE 256

static ngx_int_t
ngx_http_upsync_discovery_parse_init(void *data)
{
    char                                  *buf;
    size_t                                 parsed;
    ngx_http_upsync_ctx_t                 *ctx;
    ngx_http_upsync_server_t              *upsync_server = data;

    ctx = &upsync_server->ctx;

    if (ngx_http_parser_init() == NGX_ERROR) {
        return NGX_ERROR;
    }

    buf = (char *)ctx->recv.pos;
    ctx->body.pos = ctx->body.last = NULL;

    parsed = http_parser_execute(parser, &settings, buf, ngx_strlen(buf));
    if (parsed != ngx_strlen(buf)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_discovery_parse_init: parsed upstream \"%V\" wrong",
                      &upsync_server->host);

        if (parser != NULL) {
            ngx_free(parser);
            parser = NULL;
        }

        return NGX_ERROR;
    }

    if (ngx_strncmp(state.status, "OK", 2) == 0
        || ngx_strncmp(state.status, "Bad", 3) == 0) {

        if (ngx_strlen(state.http_body) != 0) {
            ctx->body.pos = state.http_body;
            ctx->body.last = state.http_body + ngx_strlen(state.http_body);

            *(ctx->body.last + 1) = '\0';
        }

    } else {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_discovery_parse_init: recv upstream \"%V\" error; "
                      "http_status: %d", &upsync_server->host, parser->status_code);

        if (parser != NULL) {
            ngx_free(parser);
            parser = NULL;
        }

        return NGX_ERROR;
    }

    if (parser != NULL) {
        ngx_free(parser);
        parser = NULL;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_upsync_discovery_parse_json(void *data)
{
    //u_char                         *p;
    ngx_buf_t                      *buf;
    ngx_int_t                       weight;
    ngx_http_upsync_ctx_t          *ctx;
    ngx_http_upsync_conf_t         *upstream_conf = NULL;
    ngx_http_upsync_server_t       *upsync_server = data;

    char                           name[MAX_DISCOVERY_NAME_SIZE];
    uint64_t                       index = 0;

    ctx = &upsync_server->ctx;
    buf = &ctx->body;

#if (NGX_DEBUG)
    ngx_str_t s;
    s.data = buf->pos;
    s.len = buf->last - buf->pos;
    ngx_log_debug0(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                  "upsync_discovery_parse_json: recv upstream \"%V\" "
                  "host: %V, port: %d, body: %V",
                  &upsync_server->host,
                  &upsync_server->upscf->upsync_host, upsync_server->upscf->upsync_port, &s);
#endif

    cJSON *root = cJSON_Parse((char *)buf->pos);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_parse_json: upstream \"%V\" root error", &upsync_server->host);
        return NGX_ERROR;
    }

    cJSON *temp0 = NULL;
    cJSON *code = cJSON_GetObjectItem(root, "code");
    if (code != NULL) {
        if (code->valueint == -304) { // no thing changed
            cJSON_Delete(root);
            return NGX_AGAIN;
        }
        if (code->valueint != 0) {
            temp0 = cJSON_GetObjectItem(root, "message");
            if (temp0 != NULL && temp0->valuestring != NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "upsync_parse_json: upstream \"%V\" error code: %d, message: %s",
                              &upsync_server->host, code->valueint, temp0->valuestring);
            } else {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "upsync_parse_json: upstream \"%V\" error code: %d",
                              &upsync_server->host, code->valueint);
            }
            temp0 = NULL;
            cJSON_Delete(root);
            return NGX_ERROR;
        }
    }

    // TODO: check error["-404"]

    cJSON *json_data = cJSON_GetObjectItem(root, "data");
    if (json_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_parse_json: upstream \"%V\" data is null, no servers",
                      &upsync_server->host);
        cJSON_Delete(root);
        return NGX_ERROR;
    }

    if (upsync_server->host.len >= MAX_DISCOVERY_NAME_SIZE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_parse_json: upstream \"%V\" name too long",
                      &upsync_server->host);
        cJSON_Delete(root);
        return NGX_ERROR;
    }
    ngx_memzero(name, MAX_DISCOVERY_NAME_SIZE);
    ngx_memcpy(name, upsync_server->host.data, upsync_server->host.len);

    cJSON *app = cJSON_GetObjectItem(json_data, name);
    if (app == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_parse_json: upstream \"%V\" app is null, no servers",
                      &upsync_server->host);
        cJSON_Delete(root);
        return NGX_ERROR;
    }

    cJSON *instances = cJSON_GetObjectItem(app, "instances");
    if (instances == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_parse_json: upstream \"%V\" instances is null, no servers",
                      &upsync_server->host);
        cJSON_Delete(root);
        return NGX_ERROR;
    }

    if (ngx_array_init(&ctx->upstream_conf, ctx->pool, 16,
                       sizeof(*upstream_conf)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_parse_json: upstream \"%V\" array init error",
                      &upsync_server->host);
        cJSON_Delete(root);
        return NGX_ERROR;
    }

    cJSON *server_next, *addrs, *addr_next;
    for (server_next = instances->child; server_next != NULL;
         server_next = server_next->next)
    {
        temp0 = cJSON_GetObjectItem(server_next, "status");
        if (temp0 == NULL || temp0->valueint != 1) {
            continue;
        }

        addrs = cJSON_GetObjectItem(server_next, "addrs");
        if (addrs == NULL) {
            continue;
        }

        temp0 = cJSON_GetObjectItem(server_next, "metadata");
        if (temp0 == NULL) {
            continue;
        }

        temp0 = cJSON_GetObjectItem(temp0, "weight");
        if (temp0 == NULL || temp0->valuestring == NULL) {
            continue;
        }

        weight = ngx_atoi((u_char *)temp0->valuestring,
                          (size_t)ngx_strlen(temp0->valuestring));
        if (weight <= 0) {
            continue;
        }

        upstream_conf = ngx_array_push(&ctx->upstream_conf);
        ngx_memzero(upstream_conf, sizeof(*upstream_conf));

        upstream_conf->weight = weight;

        /* default value, server attribute */
        upstream_conf->max_fails = 2;
        upstream_conf->fail_timeout = 10;

        upstream_conf->down = 0;
        upstream_conf->backup = 0;
        // ngx_sprintf(upstream_conf->sockaddr, "%*s", ngx_strlen(p + 1), p + 1);

        for (addr_next = addrs->child; addr_next != NULL;
             addr_next = addr_next->next)
        {
            if (addr_next->valuestring == NULL) {
                continue;
            }
            if (ngx_strncmp(addr_next->valuestring, "http://", 7) == 0) {
                ngx_sprintf(upstream_conf->sockaddr, "%*s",
                            ngx_strlen(addr_next->valuestring + 7), addr_next->valuestring + 7);
                break;
            }
        }
        if (addr_next == NULL) {
            // http server not found
            continue;
        }
    }

    temp0 = cJSON_GetObjectItem(app, "latest_timestamp_nano");
    if (temp0 == NULL || temp0->valuestring == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upsync_parse_json: upstream \"%V\" app latest_timestamp is null",
                      &upsync_server->host);
        cJSON_Delete(root);
        return NGX_ERROR;
    }
    index = ngx_strtoull((char *)temp0->valuestring, (char **)NULL, 10);
    upsync_server->index = index;

    cJSON_Delete(root);
    return NGX_OK;
}
