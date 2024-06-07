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

=== TEST 8: validation header claim alg, ok
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

=== TEST 9: validation header claim alg, custom value, ok
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

=== TEST 10: validation header claim alg, custom value, error, value mismatch
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

=== TEST 11: validation header claim typ, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Yxtxx_W3nuMC2VwMCYc1guZa7bmxQ8sHaLc_Qq5z-BWb_AfS1K00sw.ZpkqELJOyWcBrVCjihC-ZQ.RlmT2AGk-3W09aHitdVkIg.sB8D70n98i4j20yQYsVSFQ"
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

=== TEST 12: validation header claim typ, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiTkFEQSJ9.cUsWMFSg4kwIOUl4ZDJsL3tjqm63ZOz6JrAAq5Ov_Ow1LhlMBVZ0zA.23HYtHyI3dj8Ajtsr7TDDQ.EAA2R0z2rRLQdoTqLeaHPQ.fw1ZqrFNVWvg7pY-qJ466w"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiTkFEQSJ9.cUsWMFSg4kwIOUl4ZDJsL3tjqm63ZOz6JrAAq5Ov_Ow1LhlMBVZ0zA.23HYtHyI3dj8Ajtsr7TDDQ.EAA2R0z2rRLQdoTqLeaHPQ.fw1ZqrFNVWvg7pY-qJ466w"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.5_VPlYEOwlBeqGqNogcZBu-MmbwRHLCCrn0M_zp5i1eSAgDTRJY7Jw.2EbSnHvxnkp9RQf0jR_WIQ.Bqw4ZpCDggfj-avXTeIYHK830598z1yFz0VQMJY10qY.zGWCzvLO0aP75QeG4djK_w"
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

=== TEST 15: validation claim iss, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.5_VPlYEOwlBeqGqNogcZBu-MmbwRHLCCrn0M_zp5i1eSAgDTRJY7Jw.2EbSnHvxnkp9RQf0jR_WIQ.Bqw4ZpCDggfj-avXTeIYHK830598z1yFz0VQMJY10qY.zGWCzvLO0aP75QeG4djK_w"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.5_VPlYEOwlBeqGqNogcZBu-MmbwRHLCCrn0M_zp5i1eSAgDTRJY7Jw.2EbSnHvxnkp9RQf0jR_WIQ.Bqw4ZpCDggfj-avXTeIYHK830598z1yFz0VQMJY10qY.zGWCzvLO0aP75QeG4djK_w"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 17: validation claim aud, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.vm3aFOsXjos5DwGt0OmG7xSQKJ18vyYaRYkE1v3jnHytsgoNTFknfw.c4-RqKNsUdR6BhRQJP0ojQ.z5HizO5jGXxbtmvJm-wcjesEMWe52f67DYK7f5gjYzM.mXMsY6FR4aJkGnSV9uGb0Q"
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

=== TEST 18: validation claim aud, custom value, single jwt aud, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.vm3aFOsXjos5DwGt0OmG7xSQKJ18vyYaRYkE1v3jnHytsgoNTFknfw.c4-RqKNsUdR6BhRQJP0ojQ.z5HizO5jGXxbtmvJm-wcjesEMWe52f67DYK7f5gjYzM.mXMsY6FR4aJkGnSV9uGb0Q"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 19: validation claim aud, custom value, single jwt aud, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.vm3aFOsXjos5DwGt0OmG7xSQKJ18vyYaRYkE1v3jnHytsgoNTFknfw.c4-RqKNsUdR6BhRQJP0ojQ.z5HizO5jGXxbtmvJm-wcjesEMWe52f67DYK7f5gjYzM.mXMsY6FR4aJkGnSV9uGb0Q"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 20: validation claim aud, custom value, multiple jwt aud, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a2YKuDbDfJOKCevxV2tyMYlQ3VSGASbeL12Ou24okWRdHzDJuHiz_Q.Jd5snhXkTHABiQSHWiPSBw.cix-_1ImwILSWNbawbMJJ1UaJjnpRrrCXZ60dsp40ba5ykjx95fdA4Xy-jdj2ywXuLIoHoz2eS2-s7YaF4YnkQ.XoLr_lX2rbzh9FQfD8nkAg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 21: validation claim aud, custom value, multiple jwt aud, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a2YKuDbDfJOKCevxV2tyMYlQ3VSGASbeL12Ou24okWRdHzDJuHiz_Q.Jd5snhXkTHABiQSHWiPSBw.cix-_1ImwILSWNbawbMJJ1UaJjnpRrrCXZ60dsp40ba5ykjx95fdA4Xy-jdj2ywXuLIoHoz2eS2-s7YaF4YnkQ.XoLr_lX2rbzh9FQfD8nkAg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 22: validation claim aud, custom value, error, invalid configuration empty parameter audiences
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a2YKuDbDfJOKCevxV2tyMYlQ3VSGASbeL12Ou24okWRdHzDJuHiz_Q.Jd5snhXkTHABiQSHWiPSBw.cix-_1ImwILSWNbawbMJJ1UaJjnpRrrCXZ60dsp40ba5ykjx95fdA4Xy-jdj2ywXuLIoHoz2eS2-s7YaF4YnkQ.XoLr_lX2rbzh9FQfD8nkAg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 23: validation claim aud, custom value, error, invalid configuration is not an array
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.a2YKuDbDfJOKCevxV2tyMYlQ3VSGASbeL12Ou24okWRdHzDJuHiz_Q.Jd5snhXkTHABiQSHWiPSBw.cix-_1ImwILSWNbawbMJJ1UaJjnpRrrCXZ60dsp40ba5ykjx95fdA4Xy-jdj2ywXuLIoHoz2eS2-s7YaF4YnkQ.XoLr_lX2rbzh9FQfD8nkAg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 24: validation valid_encryption_alg_algorithms, custom value, error, invalid configuration is not an array
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

=== TEST 25: validation valid_encryption_enc_algorithms, custom value, error, invalid configuration is not an array
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

=== TEST 26: validation claim sub, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.PXWlvIqUL8l3FyUu6j-ZjnxVjj1QdF_V_YCZ51-EsW6QxnzxKBDyjw.QJ6x0OPPGy_-wv0MVqAVhg.Ca-_PZdbLVSxNLgb4uZjA9oDDkkgiGeexZvt6TtUWkw.KPM1_UnaGnxdU-e4ZL2HFg"
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

=== TEST 27: validation claim sub, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.PXWlvIqUL8l3FyUu6j-ZjnxVjj1QdF_V_YCZ51-EsW6QxnzxKBDyjw.QJ6x0OPPGy_-wv0MVqAVhg.Ca-_PZdbLVSxNLgb4uZjA9oDDkkgiGeexZvt6TtUWkw.KPM1_UnaGnxdU-e4ZL2HFg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 28: validation claim sub, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.PXWlvIqUL8l3FyUu6j-ZjnxVjj1QdF_V_YCZ51-EsW6QxnzxKBDyjw.QJ6x0OPPGy_-wv0MVqAVhg.Ca-_PZdbLVSxNLgb4uZjA9oDDkkgiGeexZvt6TtUWkw.KPM1_UnaGnxdU-e4ZL2HFg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 29: validation claim jti, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bk0Yt09-YyScnuLkNtiBV2Tz_PBKBMx-r8IJVtgBskfjYRu5LDcdNQ.lU9cIQ5c_g7nImr5WgTkIg.Ohld5lbQo3ZM1J345CTl_omSj4pvOakS-IvLhPajUrNq6X4DfCSdwm5qqz522u5D.vZH_yMueicp18o_9JegL1A"
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

=== TEST 30: validation claim jti, custom value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bk0Yt09-YyScnuLkNtiBV2Tz_PBKBMx-r8IJVtgBskfjYRu5LDcdNQ.lU9cIQ5c_g7nImr5WgTkIg.Ohld5lbQo3ZM1J345CTl_omSj4pvOakS-IvLhPajUrNq6X4DfCSdwm5qqz522u5D.vZH_yMueicp18o_9JegL1A"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 31: validation claim jti, custom value, error, value mismatch
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bk0Yt09-YyScnuLkNtiBV2Tz_PBKBMx-r8IJVtgBskfjYRu5LDcdNQ.lU9cIQ5c_g7nImr5WgTkIg.Ohld5lbQo3ZM1J345CTl_omSj4pvOakS-IvLhPajUrNq6X4DfCSdwm5qqz522u5D.vZH_yMueicp18o_9JegL1A"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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












=== TEST 32: validation claim nbf, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.-_Q7ncs3xJw3kw6XTONbbS8HpUrWcp4jeSQOmUTDbKRVIEdlGh2h1w.lNizhzPUcEpicVpSDmrCww.jIghpIgxrtCKmYnUObuCNI9BGZsY7YSmPvY9G1WWqvQ.6tDkkOrJEajbrtzzwbR6Sw"
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

=== TEST 33: validation claim nbf, custom value, ignore
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.JNS7hn6fxnE7-EXmpaCUdZ97KNFQRHRyLbIWxe4ZoRBN3RKBG06QnQ.YeahAovdEGGBXOfLpy1QmA.jPY6JnJmkMY_0iOmzIkkzgSPU5LBPcv2WNO_Qo5Efh0.FQgM1cVJ1jgFgu8nC0twqQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 34: validation claim nbf, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.JNS7hn6fxnE7-EXmpaCUdZ97KNFQRHRyLbIWxe4ZoRBN3RKBG06QnQ.YeahAovdEGGBXOfLpy1QmA.jPY6JnJmkMY_0iOmzIkkzgSPU5LBPcv2WNO_Qo5Efh0.FQgM1cVJ1jgFgu8nC0twqQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
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

=== TEST 35: validation claim exp, default value, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.sWXQjKQToHi1tIaJo7JQwYIzCf694N72-adI5w_z5D8bSAM7vmuXXA.oU4oDw6G1eqInt1dEkCaHg.p-JjqYZ8LZ_RxF37en8UEbhUYLIgmRCsoh2zJBiiOn4.o_jl109B7QtehbzWnwMq_w"
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

=== TEST 36: validation claim exp, custom value, ignore
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Uo0IyQki5_EtxiWO8eZ_dYuDj-xYDuqB9IbQuIIMY0sfBHcMr7GNsg.gWnn0BSuyWADH4MJw23eAw.mRqx0w0TduPd8DubTJXVldLIpI1C859ecHSNjHuuHUo.NHdKbMo7oUiJ0UfqTgbI6g"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 37: validation claim exp, error, token has expired
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Uo0IyQki5_EtxiWO8eZ_dYuDj-xYDuqB9IbQuIIMY0sfBHcMr7GNsg.gWnn0BSuyWADH4MJw23eAw.mRqx0w0TduPd8DubTJXVldLIpI1C859ecHSNjHuuHUo.NHdKbMo7oUiJ0UfqTgbI6g"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", nil)
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

=== TEST 38: validation claim exp, custom current_unix_timestamp, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.VXSa4tycysRmVUVsiuk_BjIyPjSJHBzlq3aoHMDv3bh8i76k1OPvPg.th8alfkWiZhF2v0UvN4Mlw.s-aS5C1u-VN9a2_W8tGOv8QEr2Ik9-aK5y7Gk4h4MZw.M65tcl94MKCKMkn_-fJckQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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

=== TEST 39: validation claim exp, custom current_unix_timestamp and timestamp_skew_seconds, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.VXSa4tycysRmVUVsiuk_BjIyPjSJHBzlq3aoHMDv3bh8i76k1OPvPg.th8alfkWiZhF2v0UvN4Mlw.s-aS5C1u-VN9a2_W8tGOv8QEr2Ik9-aK5y7Gk4h4MZw.M65tcl94MKCKMkn_-fJckQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
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
