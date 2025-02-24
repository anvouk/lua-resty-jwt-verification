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

=== TEST 1: dir + A192CBC-HS384 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0..SSH3pnQzSjLuEmGXLfEaMA.Zgsi_oYKBalIP-D-2nnM_w.n8MmgKMidxumLT3_odHYhnazzP53_xwm"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12superSecretKey12", nil)
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
dir|A192CBC-HS384
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: dir + A192CBC-HS384 error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0..SSH3pnQzSjLuEmGXLfEaMA.Zgsi_oYKBalIP-D-2nnM_w.n8MmgKMidxumLT3_odHYhnazzP53_xwm"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12superSecretKey19", nil)
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

