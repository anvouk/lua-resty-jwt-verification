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

=== TEST 1: Ed25519 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFZDI1NTE5In0.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNTc0MTB9.yfVBkTt8eVVZp7uzZx5-cHNNga9xESpeEAe8PW4YMlTnUvZrXB2cCdnNKqj78PUvb34K6dsKfIXkBlugn8ylBQ"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA+i7KjL2+4AdiQBtcBTpEseRzh5sFRfSCtuEAhpGrw5s=\n-----END PUBLIC KEY-----", nil)
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
Ed25519
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: Ed25519 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFZDI1NTE5In0.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNTc0MTB9.yfVBkTt8eVVZp7uzZx5-cHNNga9xESpeEAe8PW4YMlTnUvZrXB2cCdnNKqj78PUvb34K6dsKfIXkBlugn8ylBQ"
            local decoded_token, err = jwt.verify(token, '{"crv":"Ed25519","x":"-i7KjL2-4AdiQBtcBTpEseRzh5sFRfSCtuEAhpGrw5s","kty":"OKP"}', nil)
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
Ed25519
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: Ed25519 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFZDI1NTE5In0.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNTc0MTB9.yfVBkTt8eVVZp7uzZx5-cHNNga9xESpeEAe8PW4YMlTnUvZrXB2cCdnNKqj78PUvb34K6dsKfIXkBlugn8ylBQ"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtDH3k5x9yEIN4jM9fQQIQXort9sfoYYH+htmqO8DsEY=\n-----END PUBLIC KEY-----", nil)
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
