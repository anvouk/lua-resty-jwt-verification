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

=== TEST 1: error, invalid jwt format
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "aaaa"
            local decoded_token, err = jwt.verify(token, "superSecretKey")
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

=== TEST 2: error, invalid jwt format
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "aaaa.sss.bbbb.ff"
            local decoded_token, err = jwt.verify(token, "superSecretKey")
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: found '4' sections instead of expected 3
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: error, nbf claim is not yet valid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTMwODAsIm5iZiI6NDg0MDg1NTQ4MH0.f1jasQsm8ZGR83DBiITMybHW6y_8di0XSa-h7UaJdJ4"
            local decoded_token, err = jwt.verify(token, "superSecretKey")
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

=== TEST 4: error, exp claim is not valid, token has expired
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTM3NDksImV4cCI6MTcxNjY1Mzc1MH0.4XHWur1d8-ynwVoaF94GeHWayCUdr-Jdc_1R7dQWiRE"
            local decoded_token, err = jwt.verify(token, "superSecretKey")
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

=== TEST 5: ok, minimal token is valid HS256
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0"
            local decoded_token, err = jwt.verify(token, "superSecretKey")
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.iat)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
HS256
1716655015
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: ok, minimal token is valid HS384
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4ODB9.B2l-OZwpiX3ftJbyYnki_NIUC4OUi_wfDMrNmOrze0SPngM0RBome3R_d14ZQnaN"
            local decoded_token, err = jwt.verify(token, "superSecretKey")
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.iat)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
HS384
1716657880
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: ok, minimal token is valid HS512
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4OTJ9.6v1I0CHzem8vAMpJc77Dtu7P8J7UdUj99TrL1n_WeSfmpMhSArnxLEA-OLZBpzfw3L3u3IDGzlpziHhKuFDUgg"
            local decoded_token, err = jwt.verify(token, "superSecretKey")
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.iat)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
HS512
1716657892
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: error, signature does not match
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0"
            local decoded_token, err = jwt.verify(token, "invalidSecret")
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
invalid jwt: signature does not match
--- error_code: 200
--- no_error_log
[error]

=== TEST 9: ok, token with exp and nbf is valid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTk5OTYsIm5iZiI6MTcxNjY1OTk5NywiZXhwIjo0ODQwODYyMzk2fQ.1rjEuXyukmMZBvttQW2eZVvX9D3EwpG34x59xyVS7Go"
            local decoded_token, err = jwt.verify(token, "superSecretKey")
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.iat)
            ngx.say(decoded_token.payload.nbf)
            ngx.say(decoded_token.payload.exp)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
HS256
1716659996
1716659997
4840862396
bar
nil
--- error_code: 200
--- no_error_log
[error]
