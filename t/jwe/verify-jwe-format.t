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
            local decoded_token, err = jwt.decrypt(nil, nil, nil)
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
            local decoded_token, err = jwt.decrypt(nil, "superSecretKey12", nil)
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
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..iGMKbyfA8bvhlyjoGS-D4A.XuxiFXpwDoZCK23OMZ8G_w.7ooj8f7aUqYjhnosa8Yfew"
            local decoded_token, err = jwt.decrypt(token, nil, nil)
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
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: found '1' sections instead of expected 5
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: error, invalid jwt format, invalid header
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "aaaa..iGMKbyfA8bvhlyjoGS-D4A.XuxiFXpwDoZCK23OMZ8G_w.7ooj8f7aUqYjhnosa8Yfew"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
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
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..iGMKbyfA8bvhlyjoGS-D4A.saswdwdwdwd.7ooj8f7aUqYjhnosa8Yfew"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: failed decrypting jwt payload
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: error, invalid jwt format, invalid encrypted key
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.aaaa.5CM864cgiBgFPwluW4ViRg.mUeX7zHDVNsXhys0XO5S4w.t3yAR_HU0GDTEyCbpRa6BQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: failed decrypting cek
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: validation valid_encryption_alg_algorithms, custom value, error, invalid configuration is not an array
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.R4BuHZq2gq_QMBLIWwiGPYiTbP7EwJ58r-wQOMOcjXlPXvjv991N6Q.qBBJTB3322S-WkrYFUU2fA.e7Fz9WYRVJvxL5cZ1q6UrA.sNthlhj_3tRxbN_E_FdU8g"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                valid_encryption_alg_algorithms = {"aa", "bb"}
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid configuration: parameter options.valid_encryption_alg_algorithms must be a dict
--- error_code: 200
--- no_error_log
[error]

=== TEST 9: validation valid_encryption_enc_algorithms, custom value, error, invalid configuration is not an array
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.R4BuHZq2gq_QMBLIWwiGPYiTbP7EwJ58r-wQOMOcjXlPXvjv991N6Q.qBBJTB3322S-WkrYFUU2fA.e7Fz9WYRVJvxL5cZ1q6UrA.sNthlhj_3tRxbN_E_FdU8g"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
                valid_encryption_enc_algorithms = {"aa", "bb"}
            })
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid configuration: parameter options.valid_encryption_enc_algorithms must be a dict
--- error_code: 200
--- no_error_log
[error]
