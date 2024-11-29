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

=== TEST 1: validation claim crit, claim is supported, ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3JpdCI6WyJhbGciXX0..BMWStwUKjcFT4m12LvYIyQ.nh-JJy7ZbC_qt1vy8THMODOszRg7gzQs5Jyt4w1HPTc.hWNItd9c44DcqmItVGXyHw"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", nil)
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

=== TEST 2: validation claim crit, claim is not supported, error
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3JpdCI6WyJhbGciLCJqa3UiXSwiamt1IjoiQUFBIn0..lfo8iPfhNbDV7Hb91Hi1EA.nZhNhjSGfVAVjH4WYxAY0_yXpFM4Dskh65RRzraL4dQ.7-zvT4ATMqfXrz6VAm80jg"
            local decoded_token, err = jwt.decrypt(token, "superSecretKey12superSecretKey12", nil)
            ngx.say(decoded_token == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
invalid jwt: jwt validation failed: crit claim not supported by this lib: jku
--- error_code: 200
--- no_error_log
[error]
