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

            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"448yOd9bsM8y9o13v6pVazTpkfegk358sk1lMp-LXyQ","y":"DYppBkeKg8QRODhGnu4td6kmWZjok_dsj9uiDUyE9mI","crv":"secp256k1","kid":"4d77e9ed78d63bc5"}')
            if not decoded_token then
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJFUzI1NksiLCJraWQiOiI0ZDc3ZTllZDc4ZDYzYmM1In0.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA0MTV9.AcS-Ua4hjCqZOAvQdzLRM38uBR9pKTLy4KcuYEqc2PsBbZpynaHkXYjRW6jlemTDw5oGOEZs87L08CJBo0Dxsg
--- response_body
--- error_code: 200
--- no_error_log
[error]
