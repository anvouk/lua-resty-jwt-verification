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

            local decoded_token, err = jwt.verify(token, '{"kty":"RSA","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw","e":"AQAB","kid":"4d57bf466965e17c"}')
            if not decoded_token then
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJQUzI1NiIsImtpZCI6IjRkNTdiZjQ2Njk2NWUxN2MifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA4OTR9.Q2Ecg6tSieL3KGjp3SdR-891gFqa8AzEtEC5pYbZm1jqpFXOq-BbyB1fGDhb-dUH4B2Za6zvk3XQw01vPB47bhkcVwQ0qBQ02KjjNVsAm2ck0ZQRqNBe_4HOhc0eAEa9gV4cYIE4xqgneNhxX_BF7HcoGHrfyauQcJI6CuzE5rDDi_9i8v8X1hGkNI1mF68BJu9tk3wpJ5RDBNi77NLLRcLlf25AVfxS7ShQk07af4LVtZWpIAf-rii7XEROfcRB2Fwxl_u_JEX-b-Gz-F__O6sE4OZ7UekCQkM921MwZNPGPzcXZ_ZPvh44ioIfW0i34CHSzIl9P3XGb6dkA41FKw
--- response_body
--- error_code: 200
--- no_error_log
[error]
