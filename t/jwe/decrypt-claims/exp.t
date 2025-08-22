use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: validation claim exp, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.sWXQjKQToHi1tIaJo7JQwYIzCf694N72-adI5w_z5D8bSAM7vmuXXA.oU4oDw6G1eqInt1dEkCaHg.p-JjqYZ8LZ_RxF37en8UEbhUYLIgmRCsoh2zJBiiOn4.o_jl109B7QtehbzWnwMq_w"
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

=== TEST 2: validation claim exp, custom value, ignore
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Uo0IyQki5_EtxiWO8eZ_dYuDj-xYDuqB9IbQuIIMY0sfBHcMr7GNsg.gWnn0BSuyWADH4MJw23eAw.mRqx0w0TduPd8DubTJXVldLIpI1C859ecHSNjHuuHUo.NHdKbMo7oUiJ0UfqTgbI6g"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                ignore_expiration = true
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

=== TEST 3: validation claim exp, error, token has expired
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Uo0IyQki5_EtxiWO8eZ_dYuDj-xYDuqB9IbQuIIMY0sfBHcMr7GNsg.gWnn0BSuyWADH4MJw23eAw.mRqx0w0TduPd8DubTJXVldLIpI1C859ecHSNjHuuHUo.NHdKbMo7oUiJ0UfqTgbI6g"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: token has expired (exp claim)
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: validation claim exp, custom current_unix_timestamp, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.VXSa4tycysRmVUVsiuk_BjIyPjSJHBzlq3aoHMDv3bh8i76k1OPvPg.th8alfkWiZhF2v0UvN4Mlw.s-aS5C1u-VN9a2_W8tGOv8QEr2Ik9-aK5y7Gk4h4MZw.M65tcl94MKCKMkn_-fJckQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                current_unix_timestamp = 917823600,
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

=== TEST 5: validation claim exp, custom current_unix_timestamp and timestamp_skew_seconds, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.VXSa4tycysRmVUVsiuk_BjIyPjSJHBzlq3aoHMDv3bh8i76k1OPvPg.th8alfkWiZhF2v0UvN4Mlw.s-aS5C1u-VN9a2_W8tGOv8QEr2Ik9-aK5y7Gk4h4MZw.M65tcl94MKCKMkn_-fJckQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                current_unix_timestamp = 949359600,
                timestamp_skew_seconds = 36500,
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
