use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: A256KW + A128CBC-HS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Yu1erKPIgp3sprKhRpF775JaPJHipHREFNADFGakFJ7Dz1yA5j4vBg.HOQmknGob8DY-2VilX-VCw.Z7f0Fi0Kqx2Muw_tnTgAlA.bA5-gOygH9lGOqnEQYHPmA"
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
A256KW|A128CBC-HS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: A256KW + A128CBC-HS256 error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Yu1erKPIgp3sprKhRpF775JaPJHipHREFNADFGakFJ7Dz1yA5j4vBg.HOQmknGob8DY-2VilX-VCw.Z7f0Fi0Kqx2Muw_tnTgAlA.bA5-gOygH9lGOqnEQYHPmA"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey19", nil)
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
