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

=== TEST 1: validation claim aud, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMTMwODYsImF1ZCI6Im1lIn0.Ptzg00dgsTjV4NAuzIXgEmoICFii2YaAzmsMmFSCbjo"
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

=== TEST 2: validation claim aud, custom value, single jwt aud, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMTMwODYsImF1ZCI6Im1lIn0.Ptzg00dgsTjV4NAuzIXgEmoICFii2YaAzmsMmFSCbjo"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                audiences = { "not_me", "me" }
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

=== TEST 3: validation claim aud, custom value, single jwt aud, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMTMwODYsImF1ZCI6Im1lIn0.Ptzg00dgsTjV4NAuzIXgEmoICFii2YaAzmsMmFSCbjo"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                audiences = { "not_me", "not_me_again", "nope" }
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: claim 'aud' mismatch
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: validation claim aud, custom value, multiple jwt aud, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMTM1NTUsImF1ZCI6WyJhbmR5IiwibWFyaW8iLCJsdWlnaSIsIm1lIl19.NDVztL0aL88_P2JcijaD7EG9QcWzn7yP0mWh__V5B2A"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                audiences = { "not_me", "me" }
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

=== TEST 5: validation claim aud, custom value, multiple jwt aud, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMTM1NTUsImF1ZCI6WyJhbmR5IiwibWFyaW8iLCJsdWlnaSIsIm1lIl19.NDVztL0aL88_P2JcijaD7EG9QcWzn7yP0mWh__V5B2A"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                audiences = { "not_me", "not_me_again", "nope" }
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: claim 'aud' mismatch
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: validation claim aud, custom value, error, invalid configuration empty parameter audiences
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMTM1NTUsImF1ZCI6WyJhbmR5IiwibWFyaW8iLCJsdWlnaSIsIm1lIl19.NDVztL0aL88_P2JcijaD7EG9QcWzn7yP0mWh__V5B2A"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                audiences = {}
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid configuration: parameter options.audiences must contain at least a string
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: validation claim aud, custom value, error, invalid configuration is not an array
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMTM1NTUsImF1ZCI6WyJhbmR5IiwibWFyaW8iLCJsdWlnaSIsIm1lIl19.NDVztL0aL88_P2JcijaD7EG9QcWzn7yP0mWh__V5B2A"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                audiences = {"aa", ["bb"]="c"}
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid configuration: parameter options.audiences must be an array
--- error_code: 200
--- no_error_log
[error]
