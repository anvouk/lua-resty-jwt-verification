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

=== TEST 1: ES512 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTAwMTh9.ATocuer0f8LHzW9BhHyvVqfBpMXyyiVNpvNLJdRwG465B8lFHRhWkAPg3SufQ12YBGhxtBZtbMCqtoI_1N6GDxQGAWvjg-M95GfAKLFHmN6WVVQAXolz7FaaV-e0cJkU_pg3ZY7IVb86X-EOAYRYZCAnWDcRUxXoDxtd_v1LDoLTsrPq"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA5JkQNYNYE4R+jwvyfS4lVFm5RFxy\n1agPFoQyQg6bF15hBtDxeifR6Y887Z0C22/MRoJMITp+zcnXlZ0ChfMnbdEB9LeF\np0cv7btxGr09x9wvOqqHPC9I20bIfeqOrvmeBkqCVJ+0Rib2tRpqbgoYA1b783CM\nCGSJpnynxvcNsmIE34k=\n-----END PUBLIC KEY-----", nil)
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
ES512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ES512 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTAwMTh9.ATocuer0f8LHzW9BhHyvVqfBpMXyyiVNpvNLJdRwG465B8lFHRhWkAPg3SufQ12YBGhxtBZtbMCqtoI_1N6GDxQGAWvjg-M95GfAKLFHmN6WVVQAXolz7FaaV-e0cJkU_pg3ZY7IVb86X-EOAYRYZCAnWDcRUxXoDxtd_v1LDoLTsrPq"
            local decoded_token, err = jwt.verify(token, '{"kty":"EC","x":"AOSZEDWDWBOEfo8L8n0uJVRZuURcctWoDxaEMkIOmxdeYQbQ8Xon0emPPO2dAttvzEaCTCE6fs3J15WdAoXzJ23R","y":"AfS3hadHL-27cRq9PcfcLzqqhzwvSNtGyH3qjq75ngZKglSftEYm9rUaam4KGANW-_NwjAhkiaZ8p8b3DbJiBN-J","crv":"P-521"}', nil)
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
ES512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: ES512 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY3NTAwMTh9.ATocuer0f8LHzW9BhHyvVqfBpMXyyiVNpvNLJdRwG465B8lFHRhWkAPg3SufQ12YBGhxtBZtbMCqtoI_1N6GDxQGAWvjg-M95GfAKLFHmN6WVVQAXolz7FaaV-e0cJkU_pg3ZY7IVb86X-EOAYRYZCAnWDcRUxXoDxtd_v1LDoLTsrPq"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBLDiw68N0/CzrYOgr5fBqu6z+Vgec\nXEf2unp4fha4R8gQOEXUPCVC/DnpStMgO1FS9zE2LHz18kt9v5KaTg4tE4oB42AB\ntXX7y6b/2SPZqWoRgTeIPr1JHpScqaIqY6T/+3R3/Fw2YWEFx5D0pdj6lUx6I2oO\nhgxXFjiFJce9EviLDq4=\n-----END PUBLIC KEY-----", nil)
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
