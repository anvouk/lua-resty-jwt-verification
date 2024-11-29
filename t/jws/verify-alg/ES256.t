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

=== TEST 1: ES256 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDkwNzV9.JCCaBLnjxFzfigpLEocicSHbr13Dv6NS0FMVae0hhaHpIwqfvijUwHB5r51DQpnOpPEpE9Y3BOW2Gi_Hu0QAUA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5tLj4FVQLT0i2k2++Ekh+YhojZLz\n0cBsUH1T89qUbusGeS6xRKdAcDBqd23IsdxFF5tnGubORP4YvTNq76UelA==\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ES256 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDkwNzV9.JCCaBLnjxFzfigpLEocicSHbr13Dv6NS0FMVae0hhaHpIwqfvijUwHB5r51DQpnOpPEpE9Y3BOW2Gi_Hu0QAUA"
            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"5tLj4FVQLT0i2k2--Ekh-YhojZLz0cBsUH1T89qUbus","y":"BnkusUSnQHAwandtyLHcRRebZxrmzkT-GL0zau-lHpQ","crv":"P-256"}', nil)
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: ES256 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NDkwNzV9.JCCaBLnjxFzfigpLEocicSHbr13Dv6NS0FMVae0hhaHpIwqfvijUwHB5r51DQpnOpPEpE9Y3BOW2Gi_Hu0QAUA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERyD8tb/p+eCuCqwJKxwWrH/7aQnC\nn4e+pGcC5+p+MixMmUTb0pmvc5nkQdytKJj5vYrLh0YWvdZL2ZJhlMiZeg==\n-----END PUBLIC KEY-----", nil)
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
invalid jwt: signature does not match
--- error_code: 200
--- no_error_log
[error]
