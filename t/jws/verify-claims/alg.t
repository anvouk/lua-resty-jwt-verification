use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: validation header claim alg, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDgyMzJ9.wGusDEnV4QySIvRz8FTsVrBoxmS_G2fTJYnbRYdH8rQ"
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

=== TEST 2: validation header claim alg, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6Ik5BREEifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDg0NDF9.aQYtD1Hg3n1L0w5fSWtqxujDqmEQPYwtkmExFjWdvB8"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                valid_signing_algorithms = {
                    ["HS256"]="HS256",
                },
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

=== TEST 3: validation header claim alg, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6Ik5BREEifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDg0NDF9.aQYtD1Hg3n1L0w5fSWtqxujDqmEQPYwtkmExFjWdvB8"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                valid_signing_algorithms = {
                    ["HS384"]="HS384", ["HS512"]="HS512",
                    ["RS256"]="RS256", ["RS384"]="RS384", ["RS512"]="RS512",
                    ["ES256"]="ES256", ["ES384"]="ES384", ["ES512"]="ES512",
                    ["PS256"]="PS256", ["PS384"]="PS384", ["PS512"]="PS512",
                },
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: signing algorithm is not enabled: HS256
--- error_code: 200
--- no_error_log
[error]
