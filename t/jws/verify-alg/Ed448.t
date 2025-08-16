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

=== TEST 1: Ed448 ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFZDQ0OCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNjM3MTh9.GtEZvoKdOZiVAzLQ9nGFcT5orYifyZa0zgAz70numRaPFJoszBOZqWd7GSRFiERLmQaCiItNCgiAlzwwBAyCN1IAIerh70gS-cXPMdVLfWEcniJbK8zV3-WgI_g4wBXhiOstVZ3pYRM9pH6xcou7eysA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMEMwBQYDK2VxAzoAiku3DswbSsHFG73V1e/m9fFclJFSeyg/qTLthPFRzTaYvPpO\nE74qyo2grL3U8ySSU2L9o5Il1FiA\n-----END PUBLIC KEY-----", nil)
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
Ed448
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: Ed448 ok JWK
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFZDQ0OCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNjM3MTh9.GtEZvoKdOZiVAzLQ9nGFcT5orYifyZa0zgAz70numRaPFJoszBOZqWd7GSRFiERLmQaCiItNCgiAlzwwBAyCN1IAIerh70gS-cXPMdVLfWEcniJbK8zV3-WgI_g4wBXhiOstVZ3pYRM9pH6xcou7eysA"
            local decoded_token, err = jwt.verify(token, '{"crv":"Ed448","x":"iku3DswbSsHFG73V1e_m9fFclJFSeyg_qTLthPFRzTaYvPpOE74qyo2grL3U8ySSU2L9o5Il1FiA","kty":"OKP"}', nil)
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
Ed448
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: Ed448 error, signature is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJFZDQ0OCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNjM3MTh9.GtEZvoKdOZiVAzLQ9nGFcT5orYifyZa0zgAz70numRaPFJoszBOZqWd7GSRFiERLmQaCiItNCgiAlzwwBAyCN1IAIerh70gS-cXPMdVLfWEcniJbK8zV3-WgI_g4wBXhiOstVZ3pYRM9pH6xcou7eysA"
            local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMEMwBQYDK2VxAzoA0EDfIgND44pLoI2OgGjfsXPjKaf2va50ihm13QdgdVCATNme\np2XY2nudUTGSx/JCwfMtSb8C1/0A\n-----END PUBLIC KEY-----", nil)
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
