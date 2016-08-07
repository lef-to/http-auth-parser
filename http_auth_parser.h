/*
 * http_auth_parser
 *
 * Copyright (c) 2016 Koji Ogawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef __HTTP_AUTH_PARSER_H__
#define __HTTP_AUTH_PARSER_H__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif
    typedef enum http_auth_parser_errno {
        HAP_OK = 0,
        HAP_INVALID_TOKEN,
        HAP_INVALID_QUOTED_STRING,
        HAP_INVALID_PARAM,
        HAP_INVALID_LIST
    } http_auth_parser_errno;

    typedef void (*http_auth_parser_cb)(void *data, int err, size_t length);
    typedef void (*http_auth_parser_data_cb)(void *data, const char *at, size_t length);

    typedef struct http_auth_parser_settings {
        http_auth_parser_cb on_complete;
        http_auth_parser_data_cb on_schema;
        http_auth_parser_data_cb on_token68;
        http_auth_parser_data_cb on_param_field;
        http_auth_parser_data_cb on_param_value;
        http_auth_parser_data_cb on_param_quoted_value;
    } http_auth_parser_settings;

    http_auth_parser_errno http_auth_parse(const char *at, size_t length, http_auth_parser_settings *settings, void *data);
    ssize_t http_auth_parser_strip_quoted_string(char *dst, size_t dstlen, const char *src, size_t srclen);

#ifdef __cplusplus
}
#endif

#endif /* __HTTP_AUTH_PARSER_H__ */
