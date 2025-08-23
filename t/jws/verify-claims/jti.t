use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

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
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTE0NDgsImp0aSI6IjBYMzRLRzJ4M2UifQ.ptsajEUY1kIKOMgFNjbpdUFzojFwyR5OvnBvLbPJjzk"
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

=== TEST 2: validation claim jti, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTE0NDgsImp0aSI6IjBYMzRLRzJ4M2UifQ.ptsajEUY1kIKOMgFNjbpdUFzojFwyR5OvnBvLbPJjzk"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
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
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTE0NDgsImp0aSI6IjBYMzRLRzJ4M2UifQ.ptsajEUY1kIKOMgFNjbpdUFzojFwyR5OvnBvLbPJjzk"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
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
