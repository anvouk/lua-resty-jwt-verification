use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: dir + A256GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..I5yjU4ZVgvSqZn7A.sMRQl-c0gJKRYneCXw.qrQn-pAJo0ojQTFVucsL_A"
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
dir|A256GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: dir + A256GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..I5yjU4ZVgvSqZn7A.sMRQl-c0gJKRYneCXw.qrQn-pAJo0ojQTFVucsL_A"
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
invalid jwt: failed decrypting jwt payload
--- error_code: 200
--- no_error_log
[error]
