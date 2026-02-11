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

            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"5tLj4FVQLT0i2k2--Ekh-YhojZLz0cBsUH1T89qUbus","y":"BnkusUSnQHAwandtyLHcRRebZxrmzkT-GL0zau-lHpQ","crv":"P-256","kid":"b8f3c8a672544dfb"}')
            if not decoded_token then
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImI4ZjNjOGE2NzI1NDRkZmIifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA4NDh9.PjDoKi9o_GOAOFcqBrZl0p1dn1deu4Gzd-yhZiLITx2zaHCGr7JKSTsQTRetvU10CnE1klstwEyM_5r782pJ0Q
--- response_body
--- error_code: 200
--- no_error_log
[error]
