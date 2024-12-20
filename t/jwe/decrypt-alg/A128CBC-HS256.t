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

=== TEST 1: dir + A128CBC-HS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..iGMKbyfA8bvhlyjoGS-D4A.XuxiFXpwDoZCK23OMZ8G_w.7ooj8f7aUqYjhnosa8Yfew"
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
dir|A128CBC-HS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: dir + A128CBC-HS256 error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..iGMKbyfA8bvhlyjoGS-D4A.XuxiFXpwDoZCK23OMZ8G_w.7ooj8f7aUqYjhnosa8Yfew"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey19", nil)
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

=== TEST 3: A128KW + A128CBC-HS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.zAIq7qVAEO-eCG6gOdd3ld8_IHzeq3UlaWLHF2IDn6nNUuHh5n_i4w.5CM864cgiBgFPwluW4ViRg.mUeX7zHDVNsXhys0XO5S4w.t3yAR_HU0GDTEyCbpRa6BQ"
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
A128KW|A128CBC-HS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: A128KW + A128CBC-HS256 error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.zAIq7qVAEO-eCG6gOdd3ld8_IHzeq3UlaWLHF2IDn6nNUuHh5n_i4w.5CM864cgiBgFPwluW4ViRg.mUeX7zHDVNsXhys0XO5S4w.t3yAR_HU0GDTEyCbpRa6BQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey19", nil)
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

=== TEST 5: A192KW + A128CBC-HS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.vFug_UrLZ248kfJq3zkbKgmhOKlvdxsPWBDBfTwt47o6OSNVKAv4LQ.bnVlRQvVVUW2KfBjTXAGYQ.zc6Tr4NlE3iOoCcdiiENyg.eZ6VGWSOnyXwkbs3Xa15SQ"
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
A192KW|A128CBC-HS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: A192KW + A128CBC-HS256 error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.vFug_UrLZ248kfJq3zkbKgmhOKlvdxsPWBDBfTwt47o6OSNVKAv4LQ.bnVlRQvVVUW2KfBjTXAGYQ.zc6Tr4NlE3iOoCcdiiENyg.eZ6VGWSOnyXwkbs3Xa15SQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSe9", nil)
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

=== TEST 7: A256KW + A128CBC-HS256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Yu1erKPIgp3sprKhRpF775JaPJHipHREFNADFGakFJ7Dz1yA5j4vBg.HOQmknGob8DY-2VilX-VCw.Z7f0Fi0Kqx2Muw_tnTgAlA.bA5-gOygH9lGOqnEQYHPmA"
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
A256KW|A128CBC-HS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: A256KW + A128CBC-HS256 error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Yu1erKPIgp3sprKhRpF775JaPJHipHREFNADFGakFJ7Dz1yA5j4vBg.HOQmknGob8DY-2VilX-VCw.Z7f0Fi0Kqx2Muw_tnTgAlA.bA5-gOygH9lGOqnEQYHPmA"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey19", nil)
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
