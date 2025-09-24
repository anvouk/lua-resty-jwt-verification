use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: nested jwt outer decrypt, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0..wS4yA3FM2z7VXBT895q8pg.pFYLWmUK-3VcK1lMDjZee1TDiCzpanK9kWFJQfshyOLcwUjc9oWtJ-aYd6uteO__nJ4HYO3T5-Hy1i3keRiWrwQTqwNeJSiW-YZHtwKCs2aL0r4AJbS2aE0ju7bOW8VZ-EH3_PJIbbNy-TQB6l0iGw.fufBUI1Pd4OP4ab0BdPLJQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", {
                allow_nested_jwt = true
            })
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload)
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
eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJpbm5lciIsImlhdCI6MTc1ODc0MjMzN30.q2CBzcrKdqwXZG0XaApPP3MBtDRxBwaa-9JNoDyBm2c
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: nested jwt outer decrypt, error not enabled
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0..wS4yA3FM2z7VXBT895q8pg.pFYLWmUK-3VcK1lMDjZee1TDiCzpanK9kWFJQfshyOLcwUjc9oWtJ-aYd6uteO__nJ4HYO3T5-Hy1i3keRiWrwQTqwNeJSiW-YZHtwKCs2aL0r4AJbS2aE0ju7bOW8VZ-EH3_PJIbbNy-TQB6l0iGw.fufBUI1Pd4OP4ab0BdPLJQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload)
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
invalid jwt: nested jwt decryption is disabled
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: nested jwt outer decrypt, error token missing mandatory 'cty' key
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..qzZHZnOi0EoAZLSz8LNQgQ.RenZEqHW81g5tzbaRPruPlHxHy3be2P3RJPauHWU5KWA4G8X3NzwSxGZiqvwhroVKck0bBXr0fZMnttpFTyfaZc22finJo4XjNrPIUGghEK3FDOPmCftAxjwmRrk94E6GHZwcUvBnWAgx05kVCqVyA.h2FjyPLlnZNEJ2ZLxvPIVQ"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", {
                allow_nested_jwt = true
            })
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload)
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
invalid jwt: failed reading decrypted payload: Expected value but found invalid token at character 1
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: nested jwt outer decrypt, error token has invalid 'cty' key value
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiQUFBIn0..3OigOpcgWV8pUXNzuokuow.Equ3NMk9puGe_vsdzbujhiG7w-Zd34D26ZTKhmGMsXe_QMpqYmRMjoi_X8wWryhHixYeg8U9Yw8JXjLr_6XoJOXPbCe7gE2oE3aP4ghVcnM4ozTcxzQe1cRjg6u5H1-xooiVVTMwg6ge_7ZHAw4OgQ._IPHwoht-NUvzLDWh8QZFg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", {
                allow_nested_jwt = true
            })
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload)
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
invalid jwt: failed reading decrypted payload: Expected value but found invalid token at character 1
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: nested jwt outer decrypt, error token has invalid 'cty' key value
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiQUFBIn0..3OigOpcgWV8pUXNzuokuow.Equ3NMk9puGe_vsdzbujhiG7w-Zd34D26ZTKhmGMsXe_QMpqYmRMjoi_X8wWryhHixYeg8U9Yw8JXjLr_6XoJOXPbCe7gE2oE3aP4ghVcnM4ozTcxzQe1cRjg6u5H1-xooiVVTMwg6ge_7ZHAw4OgQ._IPHwoht-NUvzLDWh8QZFg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", {
                allow_nested_jwt = true
            })
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload)
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
invalid jwt: failed reading decrypted payload: Expected value but found invalid token at character 1
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: nested jwt outer decrypt and inner verify, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0..wS4yA3FM2z7VXBT895q8pg.pFYLWmUK-3VcK1lMDjZee1TDiCzpanK9kWFJQfshyOLcwUjc9oWtJ-aYd6uteO__nJ4HYO3T5-Hy1i3keRiWrwQTqwNeJSiW-YZHtwKCs2aL0r4AJbS2aE0ju7bOW8VZ-EH3_PJIbbNy-TQB6l0iGw.fufBUI1Pd4OP4ab0BdPLJQ"
            local decoded_token, err

            -- outer jwe
            decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", {
                allow_nested_jwt = true
            })
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
            ngx.say(err)

            -- inner jws
            decoded_token, err = jwt.verify(decoded_token.payload, "superSecretKey", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg)
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
eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJpbm5lciIsImlhdCI6MTc1ODc0MjMzN30.q2CBzcrKdqwXZG0XaApPP3MBtDRxBwaa-9JNoDyBm2c
nil
HS256
inner
nil
--- error_code: 200
--- no_error_log
[error]
