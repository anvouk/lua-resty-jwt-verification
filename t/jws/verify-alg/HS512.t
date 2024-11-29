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

=== TEST 1: HS512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4OTJ9.6v1I0CHzem8vAMpJc77Dtu7P8J7UdUj99TrL1n_WeSfmpMhSArnxLEA-OLZBpzfw3L3u3IDGzlpziHhKuFDUgg"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
HS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: HS512 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTc4OTJ9.6v1I0CHzem8vAMpJc77Dtu7P8J7UdUj99TrL1n_WeSfmpMhSArnxLEA-OLZBpzfw3L3u3IDGzlpziHhKuFDUgg"
            local decoded_token, err = jwt.verify(token, "invalidSecret", nil)
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
