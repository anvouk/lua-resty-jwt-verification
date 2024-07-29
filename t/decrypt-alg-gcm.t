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

=== TEST 1: dir + A128GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..snMFrN43B2CqoA00.6UKcM9nIkOCRD3YroA.macE5sYk3cjR0aFBPe_JpQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
dir|A128GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: dir + A128GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..snMFrN43B2CqoA00.6UKcM9nIkOCRD3YroA.macE5sYk3cjR0aFBPe_JpQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey99", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
nil
invalid jwt: failed decrypting jwt payload
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: dir + A192GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0..xw6LO08YC3fMwAMw.PNYAfmfzobVi98uylw.FdotyLpuKaJhDhFMtutMQQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSec", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
dir|A192GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: dir + A192GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0..xw6LO08YC3fMwAMw.PNYAfmfzobVi98uylw.FdotyLpuKaJhDhFMtutMQQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12super999", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
nil
invalid jwt: failed decrypting jwt payload
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: dir + A256GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..I5yjU4ZVgvSqZn7A.sMRQl-c0gJKRYneCXw.qrQn-pAJo0ojQTFVucsL_A"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
dir|A256GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: dir + A256GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..I5yjU4ZVgvSqZn7A.sMRQl-c0gJKRYneCXw.qrQn-pAJo0ojQTFVucsL_A"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey99", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
nil
invalid jwt: failed decrypting jwt payload
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: A128KW + A128GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.SWUbOGLzNO7fe0uFcQtSSPpVufMtCp3u.5x4F-xlGu8q-ibQm.ppkC9iq6C0L4yxTNFA.nPz3suVhHOef5UjAV1-Dmg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
A128KW|A128GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: A128KW + A128GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.SWUbOGLzNO7fe0uFcQtSSPpVufMtCp3u.5x4F-xlGu8q-ibQm.ppkC9iq6C0L4yxTNFA.nPz3suVhHOef5UjAV1-Dmg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey99", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
nil
invalid jwt: failed decrypting cek
--- error_code: 200
--- no_error_log
[error]

=== TEST 9: A192KW + A128GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0.8z3OTqbR-Bw1AxXgdQYDYfqBOZ7vYsI2.okGwlX48liHr_k8J.RcahnO80kDM1GnKtjg.R-hqfC41yA-NDa4FEFcW6A"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSec", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
A192KW|A128GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 10: A192KW + A128GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0.8z3OTqbR-Bw1AxXgdQYDYfqBOZ7vYsI2.okGwlX48liHr_k8J.RcahnO80kDM1GnKtjg.R-hqfC41yA-NDa4FEFcW6A"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12super999", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
nil
invalid jwt: failed decrypting cek
--- error_code: 200
--- no_error_log
[error]

=== TEST 11: A256KW + A128GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0.QLHAUFjbfcCi8E2oWGtqJa3zLzYes0UZ.76u0WRV84LhElJDf.-jGd1Holl1qO9Mkacw.R0LcWFil4PFW00kplKY4Sg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
A256KW|A128GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 12: A256KW + A128GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0.QLHAUFjbfcCi8E2oWGtqJa3zLzYes0UZ.76u0WRV84LhElJDf.-jGd1Holl1qO9Mkacw.R0LcWFil4PFW00kplKY4Sg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey99", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
nil
invalid jwt: failed decrypting cek
--- error_code: 200
--- no_error_log
[error]
