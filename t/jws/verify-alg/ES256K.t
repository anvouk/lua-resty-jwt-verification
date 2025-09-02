use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ES256K ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NksifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNjUyMzh9.u_C-iC2Sv050E8MAQnIUMm5IJsky1SXniBlTlv6lWfK-DOMjQRyzQIjHe0NbHa4F5Xi2TJfLrkgvBMHzFYWr1g"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE448yOd9bsM8y9o13v6pVazTpkfegk358\nsk1lMp+LXyQNimkGR4qDxBE4OEae7i13qSZZmOiT92yP26INTIT2Yg==\n-----END PUBLIC KEY-----", nil)
            if not decoded_token then
                ngx.say(err)
                return
            end
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES256K
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ES256K ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NksifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNjUyMzh9.u_C-iC2Sv050E8MAQnIUMm5IJsky1SXniBlTlv6lWfK-DOMjQRyzQIjHe0NbHa4F5Xi2TJfLrkgvBMHzFYWr1g"
            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"448yOd9bsM8y9o13v6pVazTpkfegk358sk1lMp-LXyQ","y":"DYppBkeKg8QRODhGnu4td6kmWZjok_dsj9uiDUyE9mI","crv":"secp256k1"}', nil)
            if not decoded_token then
                ngx.say(err)
                return
            end
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
ES256K
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: ES256K error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzI1NksifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNjUyMzh9.u_C-iC2Sv050E8MAQnIUMm5IJsky1SXniBlTlv6lWfK-DOMjQRyzQIjHe0NbHa4F5Xi2TJfLrkgvBMHzFYWr1g"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAESxDrkoqkTFs/RKaTkhHlmJjGW9H7Thag\nCaRBhnlAJRzDXxWcddKNsLDNMwyXafCvwQz07auYcd897+MYOAOAhw==\n-----END PUBLIC KEY-----", nil)
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
