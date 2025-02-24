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

=== TEST 1: validation header claim typ, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Yxtxx_W3nuMC2VwMCYc1guZa7bmxQ8sHaLc_Qq5z-BWb_AfS1K00sw.ZpkqELJOyWcBrVCjihC-ZQ.RlmT2AGk-3W09aHitdVkIg.sB8D70n98i4j20yQYsVSFQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
false
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: validation header claim typ, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiTkFEQSJ9.cUsWMFSg4kwIOUl4ZDJsL3tjqm63ZOz6JrAAq5Ov_Ow1LhlMBVZ0zA.23HYtHyI3dj8Ajtsr7TDDQ.EAA2R0z2rRLQdoTqLeaHPQ.fw1ZqrFNVWvg7pY-qJ466w"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                typ = "NADA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
false
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: validation header claim typ, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiTkFEQSJ9.cUsWMFSg4kwIOUl4ZDJsL3tjqm63ZOz6JrAAq5Ov_Ow1LhlMBVZ0zA.23HYtHyI3dj8Ajtsr7TDDQ.EAA2R0z2rRLQdoTqLeaHPQ.fw1ZqrFNVWvg7pY-qJ466w"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                typ = "AAA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: header claim 'typ' mismatch: NADA
--- error_code: 200
--- no_error_log
[error]
