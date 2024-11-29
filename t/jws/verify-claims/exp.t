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

=== TEST 1: validation claim exp, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTQzNjgsImV4cCI6NzI2MDc5MzIwMH0.pG0re869M2DSggRbI-LsrRgudUN5rxm-GLlVxTwy2lM"
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

=== TEST 2: validation claim exp, custom value, ignore
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTc3ODE4NjMsImV4cCI6MTcxNzc4MTg2NH0.2IY-a2VVqsVZNxRV9Kt-7VbzeJ3uZ4QWpcYVUUhG8EQ"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
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
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTQ0MjEsImV4cCI6OTQ5MzU5NjAwfQ.j_XXujm-nFEsHXh2XhaU45bbz5rfj8f3SvacmJ0pFX8"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
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
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcxMDAwNjEsImV4cCI6OTQ5MzU5NjAwfQ.xirAkb2Vqc1E5PCuUfH9hWpsrHAVmf2n5aaSsNMtSxc"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
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
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcxMDAwNjEsImV4cCI6OTQ5MzU5NjAwfQ.xirAkb2Vqc1E5PCuUfH9hWpsrHAVmf2n5aaSsNMtSxc"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
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
