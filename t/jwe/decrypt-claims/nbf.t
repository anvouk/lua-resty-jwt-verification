use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: validation claim nbf, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.-_Q7ncs3xJw3kw6XTONbbS8HpUrWcp4jeSQOmUTDbKRVIEdlGh2h1w.lNizhzPUcEpicVpSDmrCww.jIghpIgxrtCKmYnUObuCNI9BGZsY7YSmPvY9G1WWqvQ.6tDkkOrJEajbrtzzwbR6Sw"
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

=== TEST 2: validation claim nbf, custom value, ignore
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.JNS7hn6fxnE7-EXmpaCUdZ97KNFQRHRyLbIWxe4ZoRBN3RKBG06QnQ.YeahAovdEGGBXOfLpy1QmA.jPY6JnJmkMY_0iOmzIkkzgSPU5LBPcv2WNO_Qo5Efh0.FQgM1cVJ1jgFgu8nC0twqQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                ignore_not_before = true
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

=== TEST 3: validation claim nbf, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.JNS7hn6fxnE7-EXmpaCUdZ97KNFQRHRyLbIWxe4ZoRBN3RKBG06QnQ.YeahAovdEGGBXOfLpy1QmA.jPY6JnJmkMY_0iOmzIkkzgSPU5LBPcv2WNO_Qo5Efh0.FQgM1cVJ1jgFgu8nC0twqQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: token is not yet valid (nbf claim)
--- error_code: 200
--- no_error_log
[error]
