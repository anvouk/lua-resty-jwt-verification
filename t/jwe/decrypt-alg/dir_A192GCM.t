use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: dir + A192GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0..xw6LO08YC3fMwAMw.PNYAfmfzobVi98uylw.FdotyLpuKaJhDhFMtutMQQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSec", nil)
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
dir|A192GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: dir + A192GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0..xw6LO08YC3fMwAMw.PNYAfmfzobVi98uylw.FdotyLpuKaJhDhFMtutMQQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12super999", nil)
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
invalid jwt: failed decrypting jwt payload
--- error_code: 200
--- no_error_log
[error]
