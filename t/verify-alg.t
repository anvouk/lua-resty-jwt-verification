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

=== TEST 1: HS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
HS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: HS256 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0"
            local decoded_token, err = jwt.verify(token, "invalidSecret", nil)
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

=== TEST 3: HS384 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4ODB9.B2l-OZwpiX3ftJbyYnki_NIUC4OUi_wfDMrNmOrze0SPngM0RBome3R_d14ZQnaN"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
HS384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: HS384 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4ODB9.B2l-OZwpiX3ftJbyYnki_NIUC4OUi_wfDMrNmOrze0SPngM0RBome3R_d14ZQnaN"
            local decoded_token, err = jwt.verify(token, "invalidSecret", nil)
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

=== TEST 5: HS512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4OTJ9.6v1I0CHzem8vAMpJc77Dtu7P8J7UdUj99TrL1n_WeSfmpMhSArnxLEA-OLZBpzfw3L3u3IDGzlpziHhKuFDUgg"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
HS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: HS512 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4OTJ9.6v1I0CHzem8vAMpJc77Dtu7P8J7UdUj99TrL1n_WeSfmpMhSArnxLEA-OLZBpzfw3L3u3IDGzlpziHhKuFDUgg"
            local decoded_token, err = jwt.verify(token, "invalidSecret", nil)
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

=== TEST 7: RS256 error, invalid public key used
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

=== TEST 8: RS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2Njg2Mzd9.H6PE-zLizMMqefx8DG4X5glVjyxR9UNT225Tq2yufHhu4k9K0IGttpykjMCG8Ck_4Qt2ezEWIgoiWhSn1rv_zwxe7Pv-B09fDs7h1hbASi5MZ0YVAmK9ID1RCKM_NTBEnPLot_iopKZRj2_J5F7lvXwJDZSzEAFJZdrgjKeBS4saDZAv7SIL9Nk75rdhgY-RgRwsjmTYSksj7eioRJJLHifrMnlQDbdrBD5_Qk5tD6VPcssO-vIVBUAYrYYTa7M7A_v47UH84zDtzNYBbk9NrDbyq5-tYs0lZwNhIX8t-0VAxjuCyrrGZvv8_O01pdi90kQmntFIbaiDiD-1WlGcGA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
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

=== TEST 9: RS256 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2Njg2Mzd9.H6PE-zLizMMqefx8DG4X5glVjyxR9UNT225Tq2yufHhu4k9K0IGttpykjMCG8Ck_4Qt2ezEWIgoiWhSn1rv_zwxe7Pv-B09fDs7h1hbASi5MZ0YVAmK9ID1RCKM_NTBEnPLot_iopKZRj2_J5F7lvXwJDZSzEAFJZdrgjKeBS4saDZAv7SIL9Nk75rdhgY-RgRwsjmTYSksj7eioRJJLHifrMnlQDbdrBD5_Qk5tD6VPcssO-vIVBUAYrYYTa7M7A_v47UH84zDtzNYBbk9NrDbyq5-tYs0lZwNhIX8t-0VAxjuCyrrGZvv8_O01pdi90kQmntFIbaiDiD-1WlGcGA"
            local decoded_token, err = jwt.verify(token, '{"kty":"RSA","e":"AQAB","kid":"90334551-d36e-4962-818e-5fd0bf79c6a8","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw"}', nil)
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

=== TEST 10: RS256 error, signature is invalid
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

=== TEST 11: RS384 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzI5Nzl9.rb0aeKNNFlpuLeVAJb1jKKlG22uMm9tTSOOFr_pn3XmgqEP1ebA8pPtokIhXaSRM5zRR_7SKh9-TicNhQ3k4TPMV-BeO91-hwcFcsesX3j7YtID8dt0cf5clNL9S4oIfk8MviM02tBWR60Yg-XQW2P7tvDYX3hCG0reYfZs7FIwLzdnvxnhNpgXEbx55WDVkek7iACZ_6CkW6Td3R0mx-KusodMNOojDJbz1_9WlEf1-p0dsHFkNmk8GrL_GcC0Yz9kocrWMUPYZ3dqhULOIapYxNOmxIWKmLjkuIH3yEwKLW-k-JwjBHwvolAD5qIa4OPDj8DsSpPk0-t50EkMe7w"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
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

=== TEST 12: RS384 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzI5Nzl9.rb0aeKNNFlpuLeVAJb1jKKlG22uMm9tTSOOFr_pn3XmgqEP1ebA8pPtokIhXaSRM5zRR_7SKh9-TicNhQ3k4TPMV-BeO91-hwcFcsesX3j7YtID8dt0cf5clNL9S4oIfk8MviM02tBWR60Yg-XQW2P7tvDYX3hCG0reYfZs7FIwLzdnvxnhNpgXEbx55WDVkek7iACZ_6CkW6Td3R0mx-KusodMNOojDJbz1_9WlEf1-p0dsHFkNmk8GrL_GcC0Yz9kocrWMUPYZ3dqhULOIapYxNOmxIWKmLjkuIH3yEwKLW-k-JwjBHwvolAD5qIa4OPDj8DsSpPk0-t50EkMe7w"
            local decoded_token, err = jwt.verify(token, '{"kty":"RSA","e":"AQAB","kid":"90334551-d36e-4962-818e-5fd0bf79c6a8","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw"}', nil)
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

=== TEST 13: RS384 error, signature is invalid
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

=== TEST 14: RS512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzMwODF9.CSR4yMVAcmWmn2rIoeqaM4cEZy9HgY3Y_nMARVNJFG0L2Erd45Mf26AWoo6jpg3-UOqeqVbbKAvFNrpxxJjVXHbvuH8VfS8USDm_enBsJ3WYBm2m-c98jLTVwF66Up7L5YlRL6WM6vAoeZM1PUeLcXu-5asACA-hjhE8RRuQbypapcZrO5PVpwKZ1CSPsEmJ0QXfK8laKf__Mfwak-COcqpmOeU4Hd8UTJi0q21eN7z4k_xVz34gwvOYQZITwcMuBcF1HZRM5yXTMRYA7WKMKW0zKVQEBuz4v7a5XYIwD7RhbgRaSN4RmFUNQgqaNSLmQ4pXeNoxw4IvMHMnPCJl-Q"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
RS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 15: RS512 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzMwODF9.CSR4yMVAcmWmn2rIoeqaM4cEZy9HgY3Y_nMARVNJFG0L2Erd45Mf26AWoo6jpg3-UOqeqVbbKAvFNrpxxJjVXHbvuH8VfS8USDm_enBsJ3WYBm2m-c98jLTVwF66Up7L5YlRL6WM6vAoeZM1PUeLcXu-5asACA-hjhE8RRuQbypapcZrO5PVpwKZ1CSPsEmJ0QXfK8laKf__Mfwak-COcqpmOeU4Hd8UTJi0q21eN7z4k_xVz34gwvOYQZITwcMuBcF1HZRM5yXTMRYA7WKMKW0zKVQEBuz4v7a5XYIwD7RhbgRaSN4RmFUNQgqaNSLmQ4pXeNoxw4IvMHMnPCJl-Q"
            local decoded_token, err = jwt.verify(token, '{"kty":"RSA","e":"AQAB","kid":"90334551-d36e-4962-818e-5fd0bf79c6a8","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw"}', nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
RS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 16: RS512 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzMxMTN9.PzyQhdlxGmPeymme_djQrY1p5r5jPA3nS6xOFqgX4Qi5YLwXOUW_W00bNbfEgrIqT6hjaB6OeIrIDgRoOrkZ6mBpsChQanjUVx7WWbHY7AqOT16OH4fKm1JvNCrF97KDg5Iw_dfLiK50qFLC--4r0FnFs-o9LccyXFWC4gii2jGE0BIzCwjfprs2UUYvEFBwz_btbDWzlw_Ye5CLA1lK_o2bxfitlXP_epRdfk_bl50MNt3zus1pWzoGxtfuAUPnoReMbXhIpNlbWh06gRp9kT_N-okk0Su9KOs7imVWKJpN0iIa-UuUyfHgDKoNqF4QUVzzWLXNkR6lXr2AHNfMtA"
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

=== TEST 17: ES256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDkwNzV9.JCCaBLnjxFzfigpLEocicSHbr13Dv6NS0FMVae0hhaHpIwqfvijUwHB5r51DQpnOpPEpE9Y3BOW2Gi_Hu0QAUA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5tLj4FVQLT0i2k2++Ekh+YhojZLz\n0cBsUH1T89qUbusGeS6xRKdAcDBqd23IsdxFF5tnGubORP4YvTNq76UelA==\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 18: ES256 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDkwNzV9.JCCaBLnjxFzfigpLEocicSHbr13Dv6NS0FMVae0hhaHpIwqfvijUwHB5r51DQpnOpPEpE9Y3BOW2Gi_Hu0QAUA"
            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"5tLj4FVQLT0i2k2--Ekh-YhojZLz0cBsUH1T89qUbus","y":"BnkusUSnQHAwandtyLHcRRebZxrmzkT-GL0zau-lHpQ","crv":"P-256"}', nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 19: ES256 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDkwNzV9.JCCaBLnjxFzfigpLEocicSHbr13Dv6NS0FMVae0hhaHpIwqfvijUwHB5r51DQpnOpPEpE9Y3BOW2Gi_Hu0QAUA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERyD8tb/p+eCuCqwJKxwWrH/7aQnC\nn4e+pGcC5+p+MixMmUTb0pmvc5nkQdytKJj5vYrLh0YWvdZL2ZJhlMiZeg==\n-----END PUBLIC KEY-----", nil)
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

=== TEST 20: ES384 ok
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

=== TEST 21: ES384 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDk3NDZ9.PO7g8wmtKMsYeDTC7k_KgQxi6dKhmF0rU9iFia3c5KR2qciZCvfLhDrVYMm-_WNMyxDP5PdBydwO2fPWSq2q3Wh0zuXWDBGh6DV434u_xxC1DfCDQeuwTG6xJ-cVecjl"
            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"eDLssIoGJWSpYzuIHlsMDMNHYTplFG-RxPqH_StkaKogfxdO2TwtA3o1bTjfKtwD","y":"O0B0kXvhhKCqoIEougojLAvw1M-P2_A166kLwlRap8y2QufiOF50y7oLRPYCkzR7","crv":"P-384"}', nil)
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

=== TEST 22: ES384 error, signature is invalid
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

=== TEST 23: ES512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTAwMTh9.ATocuer0f8LHzW9BhHyvVqfBpMXyyiVNpvNLJdRwG465B8lFHRhWkAPg3SufQ12YBGhxtBZtbMCqtoI_1N6GDxQGAWvjg-M95GfAKLFHmN6WVVQAXolz7FaaV-e0cJkU_pg3ZY7IVb86X-EOAYRYZCAnWDcRUxXoDxtd_v1LDoLTsrPq"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA5JkQNYNYE4R+jwvyfS4lVFm5RFxy\n1agPFoQyQg6bF15hBtDxeifR6Y887Z0C22/MRoJMITp+zcnXlZ0ChfMnbdEB9LeF\np0cv7btxGr09x9wvOqqHPC9I20bIfeqOrvmeBkqCVJ+0Rib2tRpqbgoYA1b783CM\nCGSJpnynxvcNsmIE34k=\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 24: ES512 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTAwMTh9.ATocuer0f8LHzW9BhHyvVqfBpMXyyiVNpvNLJdRwG465B8lFHRhWkAPg3SufQ12YBGhxtBZtbMCqtoI_1N6GDxQGAWvjg-M95GfAKLFHmN6WVVQAXolz7FaaV-e0cJkU_pg3ZY7IVb86X-EOAYRYZCAnWDcRUxXoDxtd_v1LDoLTsrPq"
            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"AOSZEDWDWBOEfo8L8n0uJVRZuURcctWoDxaEMkIOmxdeYQbQ8Xon0emPPO2dAttvzEaCTCE6fs3J15WdAoXzJ23R","y":"AfS3hadHL-27cRq9PcfcLzqqhzwvSNtGyH3qjq75ngZKglSftEYm9rUaam4KGANW-_NwjAhkiaZ8p8b3DbJiBN-J","crv":"P-521"}', nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 25: ES512 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTAwMTh9.ATocuer0f8LHzW9BhHyvVqfBpMXyyiVNpvNLJdRwG465B8lFHRhWkAPg3SufQ12YBGhxtBZtbMCqtoI_1N6GDxQGAWvjg-M95GfAKLFHmN6WVVQAXolz7FaaV-e0cJkU_pg3ZY7IVb86X-EOAYRYZCAnWDcRUxXoDxtd_v1LDoLTsrPq"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBLDiw68N0/CzrYOgr5fBqu6z+Vgec\nXEf2unp4fha4R8gQOEXUPCVC/DnpStMgO1FS9zE2LHz18kt9v5KaTg4tE4oB42AB\ntXX7y6b/2SPZqWoRgTeIPr1JHpScqaIqY6T/+3R3/Fw2YWEFx5D0pdj6lUx6I2oO\nhgxXFjiFJce9EviLDq4=\n-----END PUBLIC KEY-----", nil)
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

=== TEST 26: PS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE0MTh9.kXc1d1rN3RJnGcnbUSjSfh62dDihewE7Ev3CujkcSB3t3j1074aa2Ud7rmQgD5vQTLFzvDhpWaInY_DMrBYh2XtwlaTCuHkXN7OVyWzctAvDq_x5LQov5ktHvjhIWPqp1V6ty7ZRA3VIh7bmG7bFHZYwot9diCO04vPQ2u-ThpIdB_BaQdf4z54-UtyXpmVb4QVg7y24FOXXskVvybwtwbt3pmXI1RLCEDiDjIbtPeGXeHYT_Kepq-F0r6pemxOZ_iTKkzfiYMewsQwwtYB3-t9wtk8vnPqIFOZFnDEMm_Y2txMYyh_A2sBkpEHCGpzjIBSvTOONwOrUmSokl6qaSg"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
PS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 27: PS256 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE0MTh9.kXc1d1rN3RJnGcnbUSjSfh62dDihewE7Ev3CujkcSB3t3j1074aa2Ud7rmQgD5vQTLFzvDhpWaInY_DMrBYh2XtwlaTCuHkXN7OVyWzctAvDq_x5LQov5ktHvjhIWPqp1V6ty7ZRA3VIh7bmG7bFHZYwot9diCO04vPQ2u-ThpIdB_BaQdf4z54-UtyXpmVb4QVg7y24FOXXskVvybwtwbt3pmXI1RLCEDiDjIbtPeGXeHYT_Kepq-F0r6pemxOZ_iTKkzfiYMewsQwwtYB3-t9wtk8vnPqIFOZFnDEMm_Y2txMYyh_A2sBkpEHCGpzjIBSvTOONwOrUmSokl6qaSg"
            local decoded_token, err = jwt.verify(token, '{"kty":"RSA","e":"AQAB","kid":"90334551-d36e-4962-818e-5fd0bf79c6a8","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw"}', nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
PS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 28: PS256 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE0MTh9.kXc1d1rN3RJnGcnbUSjSfh62dDihewE7Ev3CujkcSB3t3j1074aa2Ud7rmQgD5vQTLFzvDhpWaInY_DMrBYh2XtwlaTCuHkXN7OVyWzctAvDq_x5LQov5ktHvjhIWPqp1V6ty7ZRA3VIh7bmG7bFHZYwot9diCO04vPQ2u-ThpIdB_BaQdf4z54-UtyXpmVb4QVg7y24FOXXskVvybwtwbt3pmXI1RLCEDiDjIbtPeGXeHYT_Kepq-F0r6pemxOZ_iTKkzfiYMewsQwwtYB3-t9wtk8vnPqIFOZFnDEMm_Y2txMYyh_A2sBkpEHCGpzjIBSvTOONwOrUmSokl6qaSg"
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

=== TEST 29: PS384 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzM4NCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE1ODl9.rq-rUcG5oqjRMVX75nRsPMXpbww5uQ7ba-RajD4VzTR9eQHhIoN5CGZZLY4NG087HUx_YEl3vO0mlcKeXZNT1gsK6W--4qEoIdczHqOTYFLsPfvJ_2Lc19bzGrUl-S6mOgbbL6a2Hg6lGRfkcNalUtFNjprdgIEdFoZWBXNeaPZvIgiVKRNsbh1voB0AMr-WgEPoxlWHuuP206Q6YmV9G7XhbL7RWt6KdcEgn3U787PJZQ4bbXdfycmWkzVP9Np5IAckrwY-JG_l8kg83D2n2BwPo7m3hheczLM7LeWYWmUrnRmpD9-vMpilQjulu9iGChfRMqStvTXMEDcAz4ZsVg"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
PS384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 30: PS384 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzM4NCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE1ODl9.rq-rUcG5oqjRMVX75nRsPMXpbww5uQ7ba-RajD4VzTR9eQHhIoN5CGZZLY4NG087HUx_YEl3vO0mlcKeXZNT1gsK6W--4qEoIdczHqOTYFLsPfvJ_2Lc19bzGrUl-S6mOgbbL6a2Hg6lGRfkcNalUtFNjprdgIEdFoZWBXNeaPZvIgiVKRNsbh1voB0AMr-WgEPoxlWHuuP206Q6YmV9G7XhbL7RWt6KdcEgn3U787PJZQ4bbXdfycmWkzVP9Np5IAckrwY-JG_l8kg83D2n2BwPo7m3hheczLM7LeWYWmUrnRmpD9-vMpilQjulu9iGChfRMqStvTXMEDcAz4ZsVg"
            local decoded_token, err = jwt.verify(token, '{"kty":"RSA","e":"AQAB","kid":"90334551-d36e-4962-818e-5fd0bf79c6a8","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw"}', nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
PS384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 31: PS384 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzM4NCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE1ODl9.rq-rUcG5oqjRMVX75nRsPMXpbww5uQ7ba-RajD4VzTR9eQHhIoN5CGZZLY4NG087HUx_YEl3vO0mlcKeXZNT1gsK6W--4qEoIdczHqOTYFLsPfvJ_2Lc19bzGrUl-S6mOgbbL6a2Hg6lGRfkcNalUtFNjprdgIEdFoZWBXNeaPZvIgiVKRNsbh1voB0AMr-WgEPoxlWHuuP206Q6YmV9G7XhbL7RWt6KdcEgn3U787PJZQ4bbXdfycmWkzVP9Np5IAckrwY-JG_l8kg83D2n2BwPo7m3hheczLM7LeWYWmUrnRmpD9-vMpilQjulu9iGChfRMqStvTXMEDcAz4ZsVg"
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

=== TEST 32: PS512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE2NjJ9.AgKzm-PCtwNUIvdKm7p10Z3fErwKmW28uVW6LDseVb_WaEM_DvgW1mYNT-UIl_JTly4_NLmnS3o4zAx844Q8evKx7FbleCFfXx7qCisCRoSW17fLYWFpHD6p2Mo8xNTnraWOuyboFS2T8s_fW2DchvE_FUXrVsO_I6fgQjTYRnzu2Riy5-Yp5SYgSaJUU4ddhY25mPCc7AEUvOWCZrMxurcoDodmABc0dyk2StP1EnARSxegQOj6RYGm_t6tRRH_X1Xmz4ZhJACiObdxNhCWX_FpNMtYVqTmlCip7ns-_b5xvnmkG4_tcZrG9Z9o35btxV4F1QjnJYHN88rCNEZVQA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
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

=== TEST 33: PS512 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJQUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTE2NjJ9.AgKzm-PCtwNUIvdKm7p10Z3fErwKmW28uVW6LDseVb_WaEM_DvgW1mYNT-UIl_JTly4_NLmnS3o4zAx844Q8evKx7FbleCFfXx7qCisCRoSW17fLYWFpHD6p2Mo8xNTnraWOuyboFS2T8s_fW2DchvE_FUXrVsO_I6fgQjTYRnzu2Riy5-Yp5SYgSaJUU4ddhY25mPCc7AEUvOWCZrMxurcoDodmABc0dyk2StP1EnARSxegQOj6RYGm_t6tRRH_X1Xmz4ZhJACiObdxNhCWX_FpNMtYVqTmlCip7ns-_b5xvnmkG4_tcZrG9Z9o35btxV4F1QjnJYHN88rCNEZVQA"
            local decoded_token, err = jwt.verify(token, '{"kty":"RSA","e":"AQAB","kid":"90334551-d36e-4962-818e-5fd0bf79c6a8","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw"}', nil)
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

=== TEST 34: PS512 error, signature is invalid
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

=== TEST 35: none error, none alg is unsafe, useless and should always return invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTUyOTh9."
            local decoded_token, err = jwt.verify(token, "doesNotExists", {
                valid_signing_algorithms = { ["none"]="none" }
            })
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
unsafe jwt with none alg will never be verifiable
--- error_code: 200
--- no_error_log
[error]