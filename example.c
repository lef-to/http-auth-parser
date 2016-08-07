#include "http_auth_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_STRING1 "Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\", Auth2 type=2  "
#define TEST_STRING2 "Basic cGllanJlOg== , Digest username=\"admin\", realm=\"secret\", nonce=\"35BgQjIPBQA=5014d9d750424666921e3e9007bd102dc4d3f2bc\", uri=\"/\", algorithm=MD5, response=\"afb7a95eb81ffe8a3877e968b34db8e9\", qop=auth, nc=00000001, cnonce=\"9c1d4392e7611e41\""
#define TEST_STRING3 "Digest realm=\"secret\", nonce=\"35BgQjIPBQA=5014d9d750424666921e3e9007bd102dc4d3f2bc\", algorithm=MD5, qop=\"auth\"  , "

static void on_schema(void *data, const char *at, size_t len) {
    fprintf(stdout, "schema:\n\t[");
    fwrite(at, 1, len, stdout);
    fprintf(stdout, "]\n");
}

static void on_token68(void *data, const char *at, size_t len) {
    fprintf(stdout, "token68:\n\t[");
    fwrite(at, 1, len, stdout);
    fprintf(stdout, "]\n");
}

static void on_param_field(void *data, const char *at, size_t len) {
    fprintf(stdout, "field:\n\t[");
    fwrite(at, 1, len, stdout);
    fprintf(stdout, "]\n");
}

static void on_param_value(void *data, const char *at, size_t len) {
    fprintf(stdout, "value:\n\t[");
    fwrite(at, 1, len, stdout);
    fprintf(stdout, "]\n");
}

static void on_param_quoted_value(void *data, const char *at, size_t len) {
    char *str = (char *)malloc(len);

    if (str != NULL) {
        http_auth_parser_strip_quoted_string(str, len, at, len);
        fprintf(stdout, "value:\n\t[%s]\n", str);
        free(str);
    }
}

static void on_complete(void *data, int err, size_t len) {
    int ilen = *((int *)data);
    fprintf(stdout, "complete: result=%d parsed_len=%zu input_len=%d\n", err, len, ilen);
}

int main(int argc, char **argv) {
    int rc;
    http_auth_parser_settings settings;
    int len;

    settings.on_schema = on_schema;
    settings.on_token68 = on_token68;
    settings.on_param_field = on_param_field;
    settings.on_param_value = on_param_value;
    settings.on_param_quoted_value = on_param_quoted_value;
    settings.on_complete = on_complete;

    len = strlen(TEST_STRING1);
    printf("input:%s\n", TEST_STRING1);
    rc = http_auth_parse(TEST_STRING1, len, &settings, &len);
    printf("result: %d\n\n", rc);

    len = strlen(TEST_STRING2);
    printf("input:%s\n", TEST_STRING2);
    rc = http_auth_parse(TEST_STRING2, len, &settings, &len);
    printf("result: %d\n\n", rc);

    len = strlen(TEST_STRING3);
    printf("input:%s\n", TEST_STRING3);
    rc = http_auth_parse(TEST_STRING3, len, &settings, &len);
    printf("result: %d\n\n", rc);
}

