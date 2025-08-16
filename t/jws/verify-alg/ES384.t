use Test::Nginx::Socket::Lua;

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

repeat_each(1);
plan tests => repeat_each() * 3 * blocks();

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ES384 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDk3NDZ9.PO7g8wmtKMsYeDTC7k_KgQxi6dKhmF0rU9iFia3c5KR2qciZCvfLhDrVYMm-_WNMyxDP5PdBydwO2fPWSq2q3Wh0zuXWDBGh6DV434u_xxC1DfCDQeuwTG6xJ-cVecjl"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEeDLssIoGJWSpYzuIHlsMDMNHYTplFG+R\nxPqH/StkaKogfxdO2TwtA3o1bTjfKtwDO0B0kXvhhKCqoIEougojLAvw1M+P2/A1\n66kLwlRap8y2QufiOF50y7oLRPYCkzR7\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ES384 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDk3NDZ9.PO7g8wmtKMsYeDTC7k_KgQxi6dKhmF0rU9iFia3c5KR2qciZCvfLhDrVYMm-_WNMyxDP5PdBydwO2fPWSq2q3Wh0zuXWDBGh6DV434u_xxC1DfCDQeuwTG6xJ-cVecjl"
            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"eDLssIoGJWSpYzuIHlsMDMNHYTplFG-RxPqH_StkaKogfxdO2TwtA3o1bTjfKtwD","y":"O0B0kXvhhKCqoIEougojLAvw1M-P2_A166kLwlRap8y2QufiOF50y7oLRPYCkzR7","crv":"P-384"}', nil)
            if not decoded_token then
                ngx.say(err)
                return
            end
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: ES384 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDk3NDZ9.PO7g8wmtKMsYeDTC7k_KgQxi6dKhmF0rU9iFia3c5KR2qciZCvfLhDrVYMm-_WNMyxDP5PdBydwO2fPWSq2q3Wh0zuXWDBGh6DV434u_xxC1DfCDQeuwTG6xJ-cVecjl"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAELnC+Ja4kq4OJu1xbMbRjXnl4vRaVz/uV\ntJz/5QJCQGrUmvuQJPbo1M5KM2Kjj3Mm2ApJ0PeWmrMVXjxMXVEcrxVWFwTcBkNQ\nE2Wg/QcJ1ectkSuXEfP0qu3sl38ZPvmY\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
invalid jwt: signature does not match
--- error_code: 200
--- no_error_log
[error]
