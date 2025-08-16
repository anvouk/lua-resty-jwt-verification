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

=== TEST 1: RS512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzMwODF9.CSR4yMVAcmWmn2rIoeqaM4cEZy9HgY3Y_nMARVNJFG0L2Erd45Mf26AWoo6jpg3-UOqeqVbbKAvFNrpxxJjVXHbvuH8VfS8USDm_enBsJ3WYBm2m-c98jLTVwF66Up7L5YlRL6WM6vAoeZM1PUeLcXu-5asACA-hjhE8RRuQbypapcZrO5PVpwKZ1CSPsEmJ0QXfK8laKf__Mfwak-COcqpmOeU4Hd8UTJi0q21eN7z4k_xVz34gwvOYQZITwcMuBcF1HZRM5yXTMRYA7WKMKW0zKVQEBuz4v7a5XYIwD7RhbgRaSN4RmFUNQgqaNSLmQ4pXeNoxw4IvMHMnPCJl-Q"
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
RS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: RS512 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzMwODF9.CSR4yMVAcmWmn2rIoeqaM4cEZy9HgY3Y_nMARVNJFG0L2Erd45Mf26AWoo6jpg3-UOqeqVbbKAvFNrpxxJjVXHbvuH8VfS8USDm_enBsJ3WYBm2m-c98jLTVwF66Up7L5YlRL6WM6vAoeZM1PUeLcXu-5asACA-hjhE8RRuQbypapcZrO5PVpwKZ1CSPsEmJ0QXfK8laKf__Mfwak-COcqpmOeU4Hd8UTJi0q21eN7z4k_xVz34gwvOYQZITwcMuBcF1HZRM5yXTMRYA7WKMKW0zKVQEBuz4v7a5XYIwD7RhbgRaSN4RmFUNQgqaNSLmQ4pXeNoxw4IvMHMnPCJl-Q"
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
RS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: RS512 error, signature is invalid
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
