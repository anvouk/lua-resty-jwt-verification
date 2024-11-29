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

=== TEST 1: validation claim iss, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.5_VPlYEOwlBeqGqNogcZBu-MmbwRHLCCrn0M_zp5i1eSAgDTRJY7Jw.2EbSnHvxnkp9RQf0jR_WIQ.Bqw4ZpCDggfj-avXTeIYHK830598z1yFz0VQMJY10qY.zGWCzvLO0aP75QeG4djK_w"
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

=== TEST 2: validation claim iss, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.5_VPlYEOwlBeqGqNogcZBu-MmbwRHLCCrn0M_zp5i1eSAgDTRJY7Jw.2EbSnHvxnkp9RQf0jR_WIQ.Bqw4ZpCDggfj-avXTeIYHK830598z1yFz0VQMJY10qY.zGWCzvLO0aP75QeG4djK_w"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                issuer = "myissuer"
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

=== TEST 3: validation claim iss, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.5_VPlYEOwlBeqGqNogcZBu-MmbwRHLCCrn0M_zp5i1eSAgDTRJY7Jw.2EbSnHvxnkp9RQf0jR_WIQ.Bqw4ZpCDggfj-avXTeIYHK830598z1yFz0VQMJY10qY.zGWCzvLO0aP75QeG4djK_w"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                issuer = "AAA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: claim 'iss' mismatch: myissuer
--- error_code: 200
--- no_error_log
[error]
