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

=== TEST 1: A256KW + A128GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0.QLHAUFjbfcCi8E2oWGtqJa3zLzYes0UZ.76u0WRV84LhElJDf.-jGd1Holl1qO9Mkacw.R0LcWFil4PFW00kplKY4Sg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", nil)
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
A256KW|A128GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: A256KW + A128GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0.QLHAUFjbfcCi8E2oWGtqJa3zLzYes0UZ.76u0WRV84LhElJDf.-jGd1Holl1qO9Mkacw.R0LcWFil4PFW00kplKY4Sg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey99", nil)
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
nil
nil
invalid jwt: failed decrypting cek
--- error_code: 200
--- no_error_log
[error]
