use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ECDH-ES+A256KW + A256GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsieCI6IkttZWdIWU9abTFXTkNXMVVycVowWG5EYlBzeDk1Q2UyNlV0VHdxRXY2WGsiLCJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AifX0.fkTmUeEFgVR-EjCmoB0KzSX-Jbq28qaaThEI5I5vVqgCQzb2i1ex_g.yKic2kIehLEe4z3i.JIHJKUd7NN8bJV4low.NooerGfeEqJlEI6d6xGd9g"
            local decoded_token, err = jwt.decrypt(token, "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIMCxXl/FEuh3pGo1Z++QRs2vudqkGd63mK0Js0f6y+55\n-----END PRIVATE KEY-----", nil)
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
ECDH-ES+A256KW|A256GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ECDH-ES+A256KW + A256GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsieCI6IkttZWdIWU9abTFXTkNXMVVycVowWG5EYlBzeDk1Q2UyNlV0VHdxRXY2WGsiLCJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AifX0.fkTmUeEFgVR-EjCmoB0KzSX-Jbq28qaaThEI5I5vVqgCQzb2i1ex_g.yKic2kIehLEe4z3i.JIHJKUd7NN8bJV4low.NooerGfeEqJlEI6d6xGd9g"
            local decoded_token, err = jwt.decrypt(token, "-----BEGIN PRIVATE KEY-----\nAC4CAQAwBQYDK2VuBCIEIMCxXl/FEuh3pGo1Z++QRs2vudqkGd63mK0Js0f6y+55\n-----END PRIVATE KEY-----", nil)
            if decoded_token ~= nil then
                ngx.say(decoded_token.header.alg .. "|" .. decoded_token.header.enc)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(decoded_token)
                ngx.say(decoded_token)
            end
        }
    }
--- request
    GET /t
--- response_body
nil
nil
--- error_code: 200
--- no_error_log
[error]
