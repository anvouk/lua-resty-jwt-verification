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

=== TEST 1: validation claim jti, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bk0Yt09-YyScnuLkNtiBV2Tz_PBKBMx-r8IJVtgBskfjYRu5LDcdNQ.lU9cIQ5c_g7nImr5WgTkIg.Ohld5lbQo3ZM1J345CTl_omSj4pvOakS-IvLhPajUrNq6X4DfCSdwm5qqz522u5D.vZH_yMueicp18o_9JegL1A"
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

=== TEST 2: validation claim jti, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bk0Yt09-YyScnuLkNtiBV2Tz_PBKBMx-r8IJVtgBskfjYRu5LDcdNQ.lU9cIQ5c_g7nImr5WgTkIg.Ohld5lbQo3ZM1J345CTl_omSj4pvOakS-IvLhPajUrNq6X4DfCSdwm5qqz522u5D.vZH_yMueicp18o_9JegL1A"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                jwtid = "0X34KG2x3e"
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

=== TEST 3: validation claim jti, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bk0Yt09-YyScnuLkNtiBV2Tz_PBKBMx-r8IJVtgBskfjYRu5LDcdNQ.lU9cIQ5c_g7nImr5WgTkIg.Ohld5lbQo3ZM1J345CTl_omSj4pvOakS-IvLhPajUrNq6X4DfCSdwm5qqz522u5D.vZH_yMueicp18o_9JegL1A"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                jwtid = "AAA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: claim 'jti' mismatch: 0X34KG2x3e
--- error_code: 200
--- no_error_log
[error]

