use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NDkwNzJ9._MwFdsBPSyci9iARpoAaulReGcn1q7mKiPZjR2JDvdY"
            local header, err = jwt.decode_header_unsafe(token)
            ngx.say("alg: " .. header.alg)
        }
    }
--- request
    GET /t
--- response_body
alg: HS256
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: error, invalid jwt received
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "adasdasdasd"
            local header, err = jwt.decode_header_unsafe(token)
            ngx.say(header == nil)
            ngx.say(err ~= nil)
        }
    }
--- request
    GET /t
--- response_body
true
true
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: error, invalid json in base64 decoded header
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "anVuaw==.aa.bb"
            local header, err = jwt.decode_header_unsafe(token)
            ngx.say(header == nil)
            ngx.say(err ~= nil)
        }
    }
--- request
    GET /t
--- response_body
true
true
--- error_code: 200
--- no_error_log
[error]
