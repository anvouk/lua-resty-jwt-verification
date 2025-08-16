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

=== TEST 1: RS384 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzI5Nzl9.rb0aeKNNFlpuLeVAJb1jKKlG22uMm9tTSOOFr_pn3XmgqEP1ebA8pPtokIhXaSRM5zRR_7SKh9-TicNhQ3k4TPMV-BeO91-hwcFcsesX3j7YtID8dt0cf5clNL9S4oIfk8MviM02tBWR60Yg-XQW2P7tvDYX3hCG0reYfZs7FIwLzdnvxnhNpgXEbx55WDVkek7iACZ_6CkW6Td3R0mx-KusodMNOojDJbz1_9WlEf1-p0dsHFkNmk8GrL_GcC0Yz9kocrWMUPYZ3dqhULOIapYxNOmxIWKmLjkuIH3yEwKLW-k-JwjBHwvolAD5qIa4OPDj8DsSpPk0-t50EkMe7w"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
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
RS384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: RS384 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzI5Nzl9.rb0aeKNNFlpuLeVAJb1jKKlG22uMm9tTSOOFr_pn3XmgqEP1ebA8pPtokIhXaSRM5zRR_7SKh9-TicNhQ3k4TPMV-BeO91-hwcFcsesX3j7YtID8dt0cf5clNL9S4oIfk8MviM02tBWR60Yg-XQW2P7tvDYX3hCG0reYfZs7FIwLzdnvxnhNpgXEbx55WDVkek7iACZ_6CkW6Td3R0mx-KusodMNOojDJbz1_9WlEf1-p0dsHFkNmk8GrL_GcC0Yz9kocrWMUPYZ3dqhULOIapYxNOmxIWKmLjkuIH3yEwKLW-k-JwjBHwvolAD5qIa4OPDj8DsSpPk0-t50EkMe7w"
            local decoded_token, err = jwt.verify(token, '{"kty":"RSA","e":"AQAB","kid":"90334551-d36e-4962-818e-5fd0bf79c6a8","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw"}', nil)
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
RS384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: RS384 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzMwMzZ9.mj8_9zbuR99I6li3NTmki66nO-WvPd25EIR5a2XJu4k6Rk3h_R84myipOWqF4lOEN1qvi2JoedmxGlHzH-thbnMB8lYuUDWod7MOv_qtJz2zgRYIqLsncrEnY9WlzhxUXJa_yx_cpGqgJmAeNX6qCTP3Bm7HqNaQmQqgbHGmCy4niKGkCaSgqnqdC6E_hIVRk0MICvQhLaoMxYDQy-6E0U1_zqOtmDVoS7VkEnAppFsJlTK4siz941wa5-FEmEWSsgJYuV1zY-eLIUjChXiUzWzAvkviDf16_I98U8BdgijxkwbjtnD8Pqo2Xy2qZIAGCsrm4ZMBXXEPE_rB45IZqw"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
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
