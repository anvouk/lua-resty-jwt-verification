use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: RS256 error, invalid public key used
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzI4NzV9.h5H6ASOTa6ws2ThZ-Hrb9ljRLLL2mSBEQgjQAm6a3E_7r2P_x4Pv-i6IzZYH5SJzw_kxqRVap4sUMMgFWZzwKyG1C4wZTdQbAFxyrAmPSX3vjrcFVlokho4TF0ymsHQm3YKRHqadtEVaxpMFvXGZmR8WdaZ4odRlS7N_9TfEphXmA-6fRC7EOx0Xdy40X4Wy84YKHquWfBeoUiO1QkUALFwkyMtkhNzqEHyxlry5UDv2TEoDs6xXszyZcPRPHfmbYPBjBIQbZzCElzfhPdDWlH68rwDvnv_wewmgNv85qRglWdIJx7RKXTI1C1TbLTbvgji3SuvAj9mlkmZZXI51cg"
            local decoded_token, err = jwt.verify(token, "invalid key", nil)
            ngx.say(decoded_token)
            if string.match(err, "invalid jwt: failed initializing openssl with public key: ") then
                ngx.say("invalid jwt: failed initializing openssl with public key")
            else
                ngx.say("unexpected error")
            end
        }
    }
--- request
    GET /t
--- response_body
nil
invalid jwt: failed initializing openssl with public key
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: RS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2Njg2Mzd9.H6PE-zLizMMqefx8DG4X5glVjyxR9UNT225Tq2yufHhu4k9K0IGttpykjMCG8Ck_4Qt2ezEWIgoiWhSn1rv_zwxe7Pv-B09fDs7h1hbASi5MZ0YVAmK9ID1RCKM_NTBEnPLot_iopKZRj2_J5F7lvXwJDZSzEAFJZdrgjKeBS4saDZAv7SIL9Nk75rdhgY-RgRwsjmTYSksj7eioRJJLHifrMnlQDbdrBD5_Qk5tD6VPcssO-vIVBUAYrYYTa7M7A_v47UH84zDtzNYBbk9NrDbyq5-tYs0lZwNhIX8t-0VAxjuCyrrGZvv8_O01pdi90kQmntFIbaiDiD-1WlGcGA"
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
RS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: RS256 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2Njg2Mzd9.H6PE-zLizMMqefx8DG4X5glVjyxR9UNT225Tq2yufHhu4k9K0IGttpykjMCG8Ck_4Qt2ezEWIgoiWhSn1rv_zwxe7Pv-B09fDs7h1hbASi5MZ0YVAmK9ID1RCKM_NTBEnPLot_iopKZRj2_J5F7lvXwJDZSzEAFJZdrgjKeBS4saDZAv7SIL9Nk75rdhgY-RgRwsjmTYSksj7eioRJJLHifrMnlQDbdrBD5_Qk5tD6VPcssO-vIVBUAYrYYTa7M7A_v47UH84zDtzNYBbk9NrDbyq5-tYs0lZwNhIX8t-0VAxjuCyrrGZvv8_O01pdi90kQmntFIbaiDiD-1WlGcGA"
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
RS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: RS256 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzI4NzV9.h5H6ASOTa6ws2ThZ-Hrb9ljRLLL2mSBEQgjQAm6a3E_7r2P_x4Pv-i6IzZYH5SJzw_kxqRVap4sUMMgFWZzwKyG1C4wZTdQbAFxyrAmPSX3vjrcFVlokho4TF0ymsHQm3YKRHqadtEVaxpMFvXGZmR8WdaZ4odRlS7N_9TfEphXmA-6fRC7EOx0Xdy40X4Wy84YKHquWfBeoUiO1QkUALFwkyMtkhNzqEHyxlry5UDv2TEoDs6xXszyZcPRPHfmbYPBjBIQbZzCElzfhPdDWlH68rwDvnv_wewmgNv85qRglWdIJx7RKXTI1C1TbLTbvgji3SuvAj9mlkmZZXI51cg"
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

