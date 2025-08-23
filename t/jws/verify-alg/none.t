use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: none error, none alg is unsafe, useless and should always return invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTUyOTh9."
            local decoded_token, err = jwt.verify(token, "doesNotExists", {
                valid_signing_algorithms = { ["none"]="none" }
            })
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
unsafe jwt with none alg will never be verifiable
--- error_code: 200
--- no_error_log
[error]
