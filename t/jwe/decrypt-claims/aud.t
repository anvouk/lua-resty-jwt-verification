use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: validation claim aud, default value, ok
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

=== TEST 2: validation claim aud, custom value, single jwt aud, ok
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

=== TEST 3: validation claim aud, custom value, single jwt aud, error
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

=== TEST 4: validation claim aud, custom value, multiple jwt aud, ok
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

=== TEST 5: validation claim aud, custom value, multiple jwt aud, error
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

=== TEST 6: validation claim aud, custom value, error, invalid configuration empty parameter audiences
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
invalid configuration: parameter options.audiences must be an array containing at least a string
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: validation claim aud, custom value, error, invalid configuration is not an array
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
