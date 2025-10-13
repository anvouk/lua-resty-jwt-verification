use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ECDH-ES + A256CBC-HS512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJ4IjoiWi13SmJZRzhuODU0elNkRzhuSThKblgxQkRvOGNYcG1QUVo1Y0JqUGRRUSIsImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCJ9fQ..RJ5mAMni8iHV41GXvpGsxg.Lm_twLxPloxIxG6QG9kjXw.r3Gwiml-ttol4ULuq707VUYKV6a0DSCIdvFm7HUdOao"
            local decoded_token, err = jwt.decrypt(token, "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIMCxXl/FEuh3pGo1Z++QRs2vudqkGd63mK0Js0f6y+55\n-----END PRIVATE KEY-----", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ECDH-ES|A256CBC-HS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ECDH-ES + A256CBC-HS512 error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJ4IjoiWi13SmJZRzhuODU0elNkRzhuSThKblgxQkRvOGNYcG1QUVo1Y0JqUGRRUSIsImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCJ9fQ..RJ5mAMni8iHV41GXvpGsxg.Lm_twLxPloxIxG6QG9kjXw.r3Gwiml-ttol4ULuq707VUYKV6a0DSCIdvFm7HUdOao"
            local decoded_token, err = jwt.decrypt(token, "-----BEGIN PRIVATE KEY-----\nAC4CAQAwBQYDK2VuBCIEIMCxXl/FEuh3pGo1Z++QRs2vudqkGd63mK0Js0f6y+55\n-----END PRIVATE KEY-----", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
        }
    }
--- request
    GET /t
--- response_body
nil
nil
--- error_code: 200
--- no_error_log
[error]
