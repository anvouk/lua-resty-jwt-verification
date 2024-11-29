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

=== TEST 1: validation claim crit, claim is supported, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiYWxnIl19.eyJmb28iOiJiYXIiLCJpYXQiOjE3MzI5MjI0MTN9.hpQBv3oUXzqITlS7G32u1A3MkAAsOjQrvDZ_2JTK8hQ"
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

=== TEST 2: validation claim crit, claim is not supported, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiYWxnIiwiamt1Il0sImprdSI6IkFBQSJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MzI5MjI2MzN9.29XYUiU3vDhKMdKL46XKZr6TMwLyn-DVJI29WqL9vqM"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: jwt validation failed: crit claim not supported by this lib: jku
--- error_code: 200
--- no_error_log
[error]
