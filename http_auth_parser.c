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
#include "http_auth_parser.h"
#include <string.h>

#if __STDC_VERSION__ >= 199901L || __GNUC__ >= 3
# define _INLINE static inline
#else
# define _INLINE static
#endif

#if !defined __GNUC_MINOR__ || defined __clang__
#define _GCC_VERSION(major, minor) 0
#else
#define _GCC_VERSION(major, minor) (__GNUC__ > (major) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#endif

#if __clang__ && defined __has_builtin
#define _CLANG_BUILTIN(x) __has_builtin(x)
#else
#define _CLANG_BUILTIN(x) 0
#endif

#if _GCC_VERSION(3,1) || _CLANG_BUILTIN(__builtin_expect)
#define _EXPECT_TRUE(expr)  __builtin_expect(!!(expr),1)
#define _EXPECT_FALSE(expr) __builtin_expect(!!(expr),0)
#else
#define _EXPECT_TRUE(expr)  (expr)
#define _EXPECT_FALSE(expr) (expr)
#endif

_INLINE int _is_vchar(char ch) {
    return (0x21 <= ch && ch <= 0x7e);
}

_INLINE int _is_obs_text(char ch) {
    return (0x80 <= (unsigned char )ch); /* && (unsigned char )ch <= 0xff); */
}

_INLINE int _is_qdtext(char ch) {
    return (ch == 0x9 || ch == 0x20 || ch == 0x21 || (0x23 <= ch && ch <= 0x5B) || (0x5D <= ch && ch <= 0x7E) || _is_obs_text(ch));
}

_INLINE int _is_ws(char ch) {
    return (ch == 0x20 || ch == 0x9);
}

_INLINE int _is_digit(char ch) {
    return (0x30 <= ch && ch <= 0x39);
}

_INLINE int _is_alpha(char ch) {
    return ((0x41 <= ch && ch <= 0x5a) || (0x61 <= ch && ch <= 0x7a));
}

_INLINE int _is_tchar(char ch) {
    return (ch == '!' || ch == '#' || ch == '$' || ch == '%' || ch == '&' || ch == '\'' || ch == '*' ||
            ch == '+' || ch == '-' || ch == '.' || ch == '^' || ch == '_' || ch == '`'  || ch == '|' || ch == '~' ||
            _is_digit(ch) || _is_alpha(ch));
}

_INLINE int _is_tchar68(char ch) {
    return (_is_alpha(ch) || _is_digit(ch) || ch == '-' || ch == '.' || ch ==  '_' || ch == '~' || ch == '+' || ch == '/');
}

_INLINE int _is_tchar_or_tchar68(char ch) {
    return (_is_tchar(ch) || ch == '/');
}

typedef enum hap_state {
    s_start = 1,
    s_schema_1,
    s_schema_2,
    s_schema_3,
    s_param_key,
    s_param_sep_1,
    s_param_sep_2,
    s_param_value,
    s_list_sep
} hap_state;

static size_t _is_token68(const char *at, size_t len) {
    const char *end = at + len;
    const char *ch;
    size_t ret = 0;

    for (ch = at; ch < end; ch++) {
        if (!_is_tchar68(*ch))
            break;
    }

    for (; ch < end; ch++) {
        if (*ch != '=')
            break;
    }
    ret = ch - at;

    for (; ch < end; ch++) {
        if (*ch == ',') {
            return ret;
        }
        else if (_EXPECT_FALSE(!_is_ws(*ch))) {
            return 0;
        }
    }

    return ret;
}

_INLINE int _is_quoted_half(char ch) {
    return (ch == 0x9 || ch == 0x20 || _is_vchar(ch) || _is_obs_text(ch));
}

static size_t _is_quoted_string(const char *at, size_t len) {
    const char *end = at + len;
    const char *ptr;
    register char ch;
    size_t ret = 1;

    for (ptr = at + 1; ptr < end; ptr++) {
        ch = *ptr;

        if(_is_qdtext(ch)) {
            ret++;
        }
        else if (ch == '\\') {
            ret++;
            ptr++;
            if (_EXPECT_TRUE(ptr != end && _is_quoted_half(*ptr)))
                ret++;
            else
                break;
        }
        else if (ch == '"') {
            ret++;
            return ret;
        }
        else {
            break;
        }
    }

    return 0;
}

#define CALLBACK(x) do { \
    if (_EXPECT_TRUE(settings && settings->on_ ## x != NULL)) \
        settings->on_ ## x (data, value, vlen); \
} while(0)

#define COMPLETE(x) do { \
    if (_EXPECT_TRUE(settings && settings->on_complete != NULL)) \
        settings->on_complete(data, (x), ptr - at); \
    return (x); \
} while(0)

http_auth_parser_errno http_auth_parse(const char *at, size_t len, http_auth_parser_settings *settings, void *data) {
    hap_state state = s_start;
    const char *end = at + len;
    const char *ptr = at;
    const char *value;
    ssize_t vlen = 0;
    register char ch;

    for (; ptr < end; ptr++) {
        ch = *ptr;

        switch (state) {
            case s_start:
                {
                    if (_is_tchar(ch)) {
                        value = ptr;
                        vlen = 1;
                        state = s_schema_1;
                    }
                    else if (_EXPECT_FALSE(!_is_ws(ch) && ch != ',')) {
                        COMPLETE(HAP_INVALID_TOKEN);
                    }
                }
                break;

            case s_schema_1:
                {
                    if (_is_tchar(ch)) {
                        vlen++;
                    }
                    else if (ch == 0x20) {
                        state = s_schema_2;
                    }
                    else if (_is_ws(ch)) {
                        state = s_schema_3;
                    }
                    else if (ch == '=') {
                        CALLBACK(param_field);
                        state = s_param_sep_2;
                    }
                    else if (ch == ',') {
                        CALLBACK(schema);
                        state = s_start;
                    }
                    else {
                        COMPLETE(HAP_INVALID_TOKEN);
                    }
                }
                break;

            case s_schema_2:
                {
                    if (_is_tchar_or_tchar68(ch)) {
                        CALLBACK(schema);

                        value = ptr;
                        vlen = _is_token68(value, end - ptr);

                        if (vlen > 0) {
                            ptr += vlen - 1;
                            CALLBACK(token68);
                            state = s_list_sep;
                        }
                        else {
                            vlen = 1;
                            state = s_param_key;
                        }
                        break;
                    }
                    else if (ch != 0x20 && _is_ws(ch)) {
                        state = s_schema_3;
                        break;
                    }
                }

            case s_schema_3:
                {
                    if (ch == '=') {
                        CALLBACK(param_field);
                        state = s_param_sep_2;
                    }
                    else if (ch == ',') {
                        CALLBACK(schema);
                        state = s_start;
                    }
                    else if (_EXPECT_FALSE(!_is_ws(ch))) {
                        COMPLETE(HAP_INVALID_TOKEN);
                    }
                }
                break;

            case s_param_key:
                {
                    if (_is_tchar(ch)) {
                        vlen++;
                    }
                    else if (ch == '=') {
                        CALLBACK(param_field);
                        state = s_param_sep_2;
                    }
                    else if (_is_ws(ch)) {
                        CALLBACK(param_field);
                        state = s_param_sep_1;
                    }
                    else {
                        COMPLETE(-1);
                    }
                }
                break;

            case s_param_sep_1:
                {
                    if (ch == '=') {
                        state = s_param_sep_2;
                    }
                    else if (!_EXPECT_FALSE(_is_ws(ch))) {
                        COMPLETE(HAP_INVALID_PARAM);
                    }
                }
                break;

            case s_param_sep_2:
                {
                    if (ch == '"') {
                        value = ptr;
                        vlen = _is_quoted_string(value, end - ptr);

                        if (vlen > 0) {
                            ptr += vlen - 1;
                            CALLBACK(param_quoted_value);
                            state = s_list_sep;
                        }
                        else {
                            COMPLETE(HAP_INVALID_QUOTED_STRING);
                        }
                    }
                    else if (_is_tchar(ch)) {
                        value = ptr;
                        vlen = 1;
                        state = s_param_value;
                    }
                    else if (_EXPECT_FALSE(!_is_ws(ch))) {
                        COMPLETE(HAP_INVALID_PARAM);
                    };
                }
                break;

            case s_param_value:
                {
                    if (_is_tchar(ch)) {
                        vlen++;
                    }
                    else if (ch == ',') {
                        CALLBACK(param_value);
                        state = s_start;
                    }
                    else if (_is_ws(ch)) {
                        CALLBACK(param_value);
                        state = s_list_sep;
                    }
                    else {
                        COMPLETE(HAP_INVALID_TOKEN);
                    }
                }
                break;

            case s_list_sep:
                {
                    if (ch == ',') {
                        state = s_start;
                    }
                    else if (_EXPECT_FALSE(!_is_ws(ch))) {
                        COMPLETE(HAP_INVALID_LIST);
                    }
                }
                break;
        }
    }

    if (state == s_param_value) {
        CALLBACK(param_field);
    }
    else if (state == s_schema_1 || state == s_schema_2 || state == s_schema_3) {
        CALLBACK(schema);
    }

    COMPLETE(HAP_OK);
}

ssize_t http_auth_parser_strip_quoted_string(char *dst, size_t dstlen, const char *src, size_t srclen) {
    const char *se = src + srclen;
    const char *de = dst + dstlen;
    const char *s = src;
    char *d = dst;
    ssize_t ret = 0;

    s++;
    while(s < se) {
        if (*s == '\\') {
            s++;
            if (_EXPECT_TRUE(d != de))
                *d++ = *s++;
            ret++;
        }
        else if (*s == '"') {
            if (_EXPECT_TRUE(d != de))
                *d = '\0';
            return ret;
        }
        else {
            if (_EXPECT_TRUE(d != de))
                *d++ = *s++;
            ret++;
        }
    }

    return -1;
}
