use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        jwt = require("resty.jwt-verification")
    }
_EOC_

master_on();
workers(1);

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: verify jwt
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local token = ngx.var.http_authorization
            if not token then
                ngx.log(ngx.STDERR, "Missing Authorization header")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end

            local space_pos = string.find(token, " ", 0, true)
            if space_pos == nil then
                ngx.log(ngx.STDERR, "Invalid auth header format")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
            token = string.sub(token, space_pos + 1)

            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----", nil)
            if not decoded_token then
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NzMwODF9.CSR4yMVAcmWmn2rIoeqaM4cEZy9HgY3Y_nMARVNJFG0L2Erd45Mf26AWoo6jpg3-UOqeqVbbKAvFNrpxxJjVXHbvuH8VfS8USDm_enBsJ3WYBm2m-c98jLTVwF66Up7L5YlRL6WM6vAoeZM1PUeLcXu-5asACA-hjhE8RRuQbypapcZrO5PVpwKZ1CSPsEmJ0QXfK8laKf__Mfwak-COcqpmOeU4Hd8UTJi0q21eN7z4k_xVz34gwvOYQZITwcMuBcF1HZRM5yXTMRYA7WKMKW0zKVQEBuz4v7a5XYIwD7RhbgRaSN4RmFUNQgqaNSLmQ4pXeNoxw4IvMHMnPCJl-Q
--- response_body
--- error_code: 200
--- no_error_log
[error]
