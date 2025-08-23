use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ECDH-ES+A256KW + A256CBC-HS512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJlcGsiOnsieCI6IlNNbnZnWWlKazhkVDNQekxqRU9zeWVOUWo5RkxWQzIxZUZEa2RUbEtoR00iLCJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AifX0.AbOjfnBeBqRXpGji1g6OqrRUeAoJMSeKwtBSf0sPriKdeh6zaOw98_reRHx28HzgmLbTYL-khsvunGGQDCB7XHT_4FXj6uf8.5DzZlwSjRPrj0NFaIxgPqA.233id8zzCIhGv960nA_2xw.XelTAHo8IQcYxQRFkRnxDl0k7_CxeFiLz0CZeTIbbuY"
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
ECDH-ES+A256KW|A256CBC-HS512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ECDH-ES+A256KW + A256CBC-HS512 error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJlcGsiOnsieCI6IlNNbnZnWWlKazhkVDNQekxqRU9zeWVOUWo5RkxWQzIxZUZEa2RUbEtoR00iLCJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AifX0.AbOjfnBeBqRXpGji1g6OqrRUeAoJMSeKwtBSf0sPriKdeh6zaOw98_reRHx28HzgmLbTYL-khsvunGGQDCB7XHT_4FXj6uf8.5DzZlwSjRPrj0NFaIxgPqA.233id8zzCIhGv960nA_2xw.XelTAHo8IQcYxQRFkRnxDl0k7_CxeFiLz0CZeTIbbuY"
            local decoded_token, err = jwt.decrypt(token, "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnzYqsGtwcAEvibcN\n2z6hhSW4CXV5W9+QdhwIKI7wAyyhRANCAATm0uPgVVAtPSLaTb74SSH5iGiNkvPR\nwGxQfVPz2pRu6wZ5LrFEp0BwMGp3bcix3EUXm2ca5s5E/hi9M2rvpR6U\n-----END PRIVATE KEY-----", nil)
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
