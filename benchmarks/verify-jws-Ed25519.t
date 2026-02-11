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

            local decoded_token, err = jwt.verify(token, '{"crv":"Ed25519","x":"-i7KjL2-4AdiQBtcBTpEseRzh5sFRfSCtuEAhpGrw5s","kty":"OKP","kid":"2f0199b8572edc12"}')
            if not decoded_token then
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiMmYwMTk5Yjg1NzJlZGMxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA1Mzd9.FGVv1EB8wWf7fT1m6VBkCfq5pxpWgm0fRU56rAJCnlw-B7xUbHtNNFn4Vl5uW15F8k5Hs9wjG4li6_LqvUsWBA
--- response_body
--- error_code: 200
--- no_error_log
[error]
