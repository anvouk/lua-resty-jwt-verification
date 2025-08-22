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
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.zAIq7qVAEO-eCG6gOdd3ld8_IHzeq3UlaWLHF2IDn6nNUuHh5n_i4w.5CM864cgiBgFPwluW4ViRg.mUeX7zHDVNsXhys0XO5S4w.t3yAR_HU0GDTEyCbpRa6BQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
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
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.zAIq7qVAEO-eCG6gOdd3ld8_IHzeq3UlaWLHF2IDn6nNUuHh5n_i4w.5CM864cgiBgFPwluW4ViRg.mUeX7zHDVNsXhys0XO5S4w.t3yAR_HU0GDTEyCbpRa6BQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                valid_encryption_alg_algorithms = {
                    ["A128KW"]="A128KW",
                },
                valid_encryption_enc_algorithms = {
                    ["A128CBC-HS256"]="A128CBC-HS256",
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
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.zAIq7qVAEO-eCG6gOdd3ld8_IHzeq3UlaWLHF2IDn6nNUuHh5n_i4w.5CM864cgiBgFPwluW4ViRg.mUeX7zHDVNsXhys0XO5S4w.t3yAR_HU0GDTEyCbpRa6BQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                valid_encryption_alg_algorithms = {
                    ["A128KW"]="A128KW",
                },
                valid_encryption_enc_algorithms = {
                    ["A192CBC-HS384"]="A192CBC-HS384",
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
jwt validation failed: encryption algorithm 'enc' is not enabled: A128CBC-HS256
--- error_code: 200
--- no_error_log
[error]
