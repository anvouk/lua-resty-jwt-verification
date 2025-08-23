use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: error, invalid configuration, token and secret are nil
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local decoded_token, err = jwt.verify(nil, nil, nil)
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
invalid configuration: both jwt token and a secret are required
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: error, invalid configuration, token is nil
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local decoded_token, err = jwt.verify(nil, "superSecretKey", nil)
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
invalid configuration: both jwt token and a secret are required
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: error, invalid configuration, secret is nil
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDY5MTh9.jyjJ_u2iNAlVuZO6BS8yB31vYb6grK1vgZ9eNxdqxUY"
            local decoded_token, err = jwt.verify(token, nil, nil)
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
invalid configuration: both jwt token and a secret are required
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: error, invalid jwt format
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "aaaa"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: found '1' sections instead of expected 3
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: error, invalid jwt format, invalid header
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "aaaaa.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDY5MTh9.jyjJ_u2iNAlVuZO6BS8yB31vYb6grK1vgZ9eNxdqxUY"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: failed decoding jwt header from base64
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: error, invalid jwt format, invalid payload
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaa.jyjJ_u2iNAlVuZO6BS8yB31vYb6grK1vgZ9eNxdqxUY"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: failed decoding jwt payload from base64
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: error, invalid jwt format, invalid signature
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDY5MTh9.aaaaa"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: failed decoding jwt signature from base64
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: validation valid_signing_algorithms, custom value, error, invalid configuration is not an array
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMTM1NTUsImF1ZCI6WyJhbmR5IiwibWFyaW8iLCJsdWlnaSIsIm1lIl19.NDVztL0aL88_P2JcijaD7EG9QcWzn7yP0mWh__V5B2A"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                valid_signing_algorithms = {"aa", "bb"}
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid configuration: parameter options.valid_signing_algorithms must be a dict
--- error_code: 200
--- no_error_log
[error]
