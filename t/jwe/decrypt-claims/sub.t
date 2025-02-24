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

=== TEST 1: validation claim sub, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.PXWlvIqUL8l3FyUu6j-ZjnxVjj1QdF_V_YCZ51-EsW6QxnzxKBDyjw.QJ6x0OPPGy_-wv0MVqAVhg.Ca-_PZdbLVSxNLgb4uZjA9oDDkkgiGeexZvt6TtUWkw.KPM1_UnaGnxdU-e4ZL2HFg"
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

=== TEST 2: validation claim sub, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.PXWlvIqUL8l3FyUu6j-ZjnxVjj1QdF_V_YCZ51-EsW6QxnzxKBDyjw.QJ6x0OPPGy_-wv0MVqAVhg.Ca-_PZdbLVSxNLgb4uZjA9oDDkkgiGeexZvt6TtUWkw.KPM1_UnaGnxdU-e4ZL2HFg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                subject = "waldo"
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

=== TEST 3: validation claim sub, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.PXWlvIqUL8l3FyUu6j-ZjnxVjj1QdF_V_YCZ51-EsW6QxnzxKBDyjw.QJ6x0OPPGy_-wv0MVqAVhg.Ca-_PZdbLVSxNLgb4uZjA9oDDkkgiGeexZvt6TtUWkw.KPM1_UnaGnxdU-e4ZL2HFg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                subject = "AAA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: claim 'sub' mismatch: waldo
--- error_code: 200
--- no_error_log
[error]
