use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: HS384 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4ODB9.B2l-OZwpiX3ftJbyYnki_NIUC4OUi_wfDMrNmOrze0SPngM0RBome3R_d14ZQnaN"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
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
HS384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: HS384 error, signature is invalid
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
