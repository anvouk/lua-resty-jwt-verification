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

=== TEST 8: validation header claim alg, ok
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

=== TEST 9: validation header claim alg, custom value, ok
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

=== TEST 10: validation header claim alg, custom value, error, value mismatch
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

=== TEST 11: validation header claim typ, ok
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

=== TEST 12: validation header claim typ, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6Ik5BREEifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDg0NDF9.aQYtD1Hg3n1L0w5fSWtqxujDqmEQPYwtkmExFjWdvB8"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                typ = "NADA"
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

=== TEST 13: validation header claim typ, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6Ik5BREEifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDg0NDF9.aQYtD1Hg3n1L0w5fSWtqxujDqmEQPYwtkmExFjWdvB8"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                typ = "AAA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: header claim 'typ' mismatch: NADA
--- error_code: 200
--- no_error_log
[error]

=== TEST 14: validation claim iss, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDk0NTksImlzcyI6Im15aXNzdWVyIn0.g2zSTqoLTtMWEQrcZzLxeJ753IdUB1rjeyjGUgHWE9A"
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

=== TEST 15: validation claim iss, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDk0NTksImlzcyI6Im15aXNzdWVyIn0.g2zSTqoLTtMWEQrcZzLxeJ753IdUB1rjeyjGUgHWE9A"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                issuer = "myissuer"
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

=== TEST 16: validation claim iss, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwMDk0NTksImlzcyI6Im15aXNzdWVyIn0.g2zSTqoLTtMWEQrcZzLxeJ753IdUB1rjeyjGUgHWE9A"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                issuer = "AAA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: claim 'iss' mismatch: myissuer
--- error_code: 200
--- no_error_log
[error]

=== TEST 15: validation claim aud, default value, ok
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

=== TEST 16: validation claim aud, custom value, single jwt aud, ok
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

=== TEST 17: validation claim aud, custom value, single jwt aud, error
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

=== TEST 18: validation claim aud, custom value, multiple jwt aud, ok
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

=== TEST 19: validation claim aud, custom value, multiple jwt aud, error
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

=== TEST 20: validation claim aud, custom value, error, invalid configuration empty parameter audiences
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

=== TEST 21: validation claim aud, custom value, error, invalid configuration is not an array
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

=== TEST 22: validation valid_signing_algorithms, custom value, error, invalid configuration is not an array
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

=== TEST 23: validation claim sub, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTEyODMsInN1YiI6IndhbGRvIn0.Y_u_Iqp_0X34KG2x3eM47KPOj7evPD7LCjgSDI9XdPA"
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

=== TEST 24: validation claim sub, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTEyODMsInN1YiI6IndhbGRvIn0.Y_u_Iqp_0X34KG2x3eM47KPOj7evPD7LCjgSDI9XdPA"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                subject = "waldo"
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

=== TEST 25: validation claim sub, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTEyODMsInN1YiI6IndhbGRvIn0.Y_u_Iqp_0X34KG2x3eM47KPOj7evPD7LCjgSDI9XdPA"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                subject = "AAA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: claim 'sub' mismatch: waldo
--- error_code: 200
--- no_error_log
[error]

=== TEST 26: validation claim jti, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTE0NDgsImp0aSI6IjBYMzRLRzJ4M2UifQ.ptsajEUY1kIKOMgFNjbpdUFzojFwyR5OvnBvLbPJjzk"
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

=== TEST 27: validation claim jti, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTE0NDgsImp0aSI6IjBYMzRLRzJ4M2UifQ.ptsajEUY1kIKOMgFNjbpdUFzojFwyR5OvnBvLbPJjzk"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                jwtid = "0X34KG2x3e"
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

=== TEST 28: validation claim jti, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTE0NDgsImp0aSI6IjBYMzRLRzJ4M2UifQ.ptsajEUY1kIKOMgFNjbpdUFzojFwyR5OvnBvLbPJjzk"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                jwtid = "AAA"
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
jwt validation failed: claim 'jti' mismatch: 0X34KG2x3e
--- error_code: 200
--- no_error_log
[error]

=== TEST 29: validation claim nbf, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTQyNjEsIm5iZiI6OTQ5MzU5NjAwfQ.NJkzt9jk35HLS-AtkwVMGeJjHk9ClsCPg74pV9NwKSE"
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

=== TEST 30: validation claim nbf, custom value, ignore
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTM0MTMsIm5iZiI6NDEwNTExOTYwMH0.UZQQO59BH_CWkmJ2tKqleVw8flMe8dQeazysySUmI18"
            local decoded_token, err = jwt.verify(token, "superSecretKey", {
                ignore_not_before = true
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

=== TEST 31: validation claim nbf, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTMwODAsIm5iZiI6NDg0MDg1NTQ4MH0.f1jasQsm8ZGR83DBiITMybHW6y_8di0XSa-h7UaJdJ4"
            local decoded_token, err = jwt.verify(token, "superSecretKey", nil)
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

=== TEST 32: validation claim exp, default value, ok
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

=== TEST 33: validation claim exp, custom value, ignore
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTcwOTQzNjgsImV4cCI6NzI2MDc5MzIwMH0.pG0re869M2DSggRbI-LsrRgudUN5rxm-GLlVxTwy2lM"
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

=== TEST 34: validation claim exp, error, token has expired
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

=== TEST 35: validation claim exp, custom current_unix_timestamp, ok
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

=== TEST 36: validation claim exp, custom current_unix_timestamp and timestamp_skew_seconds, ok
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
