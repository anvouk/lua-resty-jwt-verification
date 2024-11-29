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
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTEyODMsInN1YiI6IndhbGRvIn0.Y_u_Iqp_0X34KG2x3eM47KPOj7evPD7LCjgSDI9XdPA"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
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
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTEyODMsInN1YiI6IndhbGRvIn0.Y_u_Iqp_0X34KG2x3eM47KPOj7evPD7LCjgSDI9XdPA"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
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
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTEyODMsInN1YiI6IndhbGRvIn0.Y_u_Iqp_0X34KG2x3eM47KPOj7evPD7LCjgSDI9XdPA"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
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

