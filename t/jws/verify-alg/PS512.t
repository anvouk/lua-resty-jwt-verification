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

=== TEST 1: PS512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE2NjJ9.AgKzm-PCtwNUIvdKm7p10Z3fErwKmW28uVW6LDseVb_WaEM_DvgW1mYNT-UIl_JTly4_NLmnS3o4zAx844Q8evKx7FbleCFfXx7qCisCRoSW17fLYWFpHD6p2Mo8xNTnraWOuyboFS2T8s_fW2DchvE_FUXrVsO_I6fgQjTYRnzu2Riy5-Yp5SYgSaJUU4ddhY25mPCc7AEUvOWCZrMxurcoDodmABc0dyk2StP1EnARSxegQOj6RYGm_t6tRRH_X1Xmz4ZhJACiObdxNhCWX_FpNMtYVqTmlCip7ns-_b5xvnmkG4_tcZrG9Z9o35btxV4F1QjnJYHN88rCNEZVQA"
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
PS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: PS512 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE2NjJ9.AgKzm-PCtwNUIvdKm7p10Z3fErwKmW28uVW6LDseVb_WaEM_DvgW1mYNT-UIl_JTly4_NLmnS3o4zAx844Q8evKx7FbleCFfXx7qCisCRoSW17fLYWFpHD6p2Mo8xNTnraWOuyboFS2T8s_fW2DchvE_FUXrVsO_I6fgQjTYRnzu2Riy5-Yp5SYgSaJUU4ddhY25mPCc7AEUvOWCZrMxurcoDodmABc0dyk2StP1EnARSxegQOj6RYGm_t6tRRH_X1Xmz4ZhJACiObdxNhCWX_FpNMtYVqTmlCip7ns-_b5xvnmkG4_tcZrG9Z9o35btxV4F1QjnJYHN88rCNEZVQA"
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
PS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: PS512 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE2NjJ9.AgKzm-PCtwNUIvdKm7p10Z3fErwKmW28uVW6LDseVb_WaEM_DvgW1mYNT-UIl_JTly4_NLmnS3o4zAx844Q8evKx7FbleCFfXx7qCisCRoSW17fLYWFpHD6p2Mo8xNTnraWOuyboFS2T8s_fW2DchvE_FUXrVsO_I6fgQjTYRnzu2Riy5-Yp5SYgSaJUU4ddhY25mPCc7AEUvOWCZrMxurcoDodmABc0dyk2StP1EnARSxegQOj6RYGm_t6tRRH_X1Xmz4ZhJACiObdxNhCWX_FpNMtYVqTmlCip7ns-_b5xvnmkG4_tcZrG9Z9o35btxV4F1QjnJYHN88rCNEZVQA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAonGuwxIrRg3QcUlFdGIe\ncYuedMTLd38EaTcE48DZG+rrPPhaWA4eWr82pGrU7fV8GLCv/OKh3zOS6Lrcpuwd\nEbOBbGFFRq8DA2Ej1Np4DEt4f4bXhzLOnIkFnnhJstqboAkagA9A0bKz2w9Qj11w\nVW8K2RlC1O9Zu1lL/2FvWzEapy8AhsS34hkEe2xfBnHSZ986WWFLmJJ4+Bone0KU\ncwmttc2vCQ8Nvo/jEuZ+xIK1rDkumakawsIjq3A0ne9k/Cj7E3c0BKp9D1Zq5FGI\nzZV8tQdMZph/j0na38YJAfasbdRDYjUhyNhHIpnDY0aCRtSGt5ayw9M668SBMemV\nuQIDAQAB\n-----END PUBLIC KEY-----", nil)
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
