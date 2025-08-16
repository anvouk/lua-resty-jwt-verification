use Test::Nginx::Socket::Lua;

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    lua_shared_dict resty_jwt_verification_cache_jwks 10m;
_EOC_

repeat_each(1);
plan tests => repeat_each() * 3 * blocks();

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ok, jwt validated
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQwbkpPd2RIWmJZOUd4V3JDQlJiZ1NWViIsInR5cCI6IkpXVCJ9.eyJleHAiOjgwNDQzNDg4MjQsImZvbyI6ImJhciIsImlhdCI6MTczMzAwMTYyNCwibmJmIjoxNzMzMDAxNjI0fQ.RwwBSxsHBu6maA_WyqaI1ny3b1RZCQPHvIxVBlBQT5SfptQ3zVWdGg6bc6xJvXytNh_MvaF3Pm9ITbOOOCslycwKy67b-uUzQll_hjLHiiT7jr6LiqVbYHb6WjjGfMBCHJvAySYkR9omrFq5z6UuHGE4dqacDW-JnwIOZ0-p1N4_x31pGNT_tTbli2aW6wOZXKMr6UhIZaNgAMh9HieQ4A_tKda6MTO1vzSCob0hLS3u8qv3zJ76JaDplS8EukZlcXAFkqNXKzAJOD7Mdt_1yLMPdVLp-IMiwopbZZLdetbZBjVEHOBUrmpfj7EVJcFekqJjrroqabQW5t_iT652Vw",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token.header.alg)
            ngx.say(decoded_token.payload.foo)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
RS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: error, jwt does not have kid header
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed verifying jwt: token does not have kid header and this lib does not support this case
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: error, jwk endpoint returns 404
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 404;
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQwbkpPd2RIWmJZOUd4V3JDQlJiZ1NWViIsInR5cCI6IkpXVCJ9.eyJleHAiOjgwNDQzNDg4MjQsImZvbyI6ImJhciIsImlhdCI6MTczMzAwMTYyNCwibmJmIjoxNzMzMDAxNjI0fQ.RwwBSxsHBu6maA_WyqaI1ny3b1RZCQPHvIxVBlBQT5SfptQ3zVWdGg6bc6xJvXytNh_MvaF3Pm9ITbOOOCslycwKy67b-uUzQll_hjLHiiT7jr6LiqVbYHb6WjjGfMBCHJvAySYkR9omrFq5z6UuHGE4dqacDW-JnwIOZ0-p1N4_x31pGNT_tTbli2aW6wOZXKMr6UhIZaNgAMh9HieQ4A_tKda6MTO1vzSCob0hLS3u8qv3zJ76JaDplS8EukZlcXAFkqNXKzAJOD7Mdt_1yLMPdVLp-IMiwopbZZLdetbZBjVEHOBUrmpfj7EVJcFekqJjrroqabQW5t_iT652Vw",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed verifying jwt: failed fetching jwks, returned unexpected http status: 404
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: error, jwk endpoint returns ok but invalid payload
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQwbkpPd2RIWmJZOUd4V3JDQlJiZ1NWViIsInR5cCI6IkpXVCJ9.eyJleHAiOjgwNDQzNDg4MjQsImZvbyI6ImJhciIsImlhdCI6MTczMzAwMTYyNCwibmJmIjoxNzMzMDAxNjI0fQ.RwwBSxsHBu6maA_WyqaI1ny3b1RZCQPHvIxVBlBQT5SfptQ3zVWdGg6bc6xJvXytNh_MvaF3Pm9ITbOOOCslycwKy67b-uUzQll_hjLHiiT7jr6LiqVbYHb6WjjGfMBCHJvAySYkR9omrFq5z6UuHGE4dqacDW-JnwIOZ0-p1N4_x31pGNT_tTbli2aW6wOZXKMr6UhIZaNgAMh9HieQ4A_tKda6MTO1vzSCob0hLS3u8qv3zJ76JaDplS8EukZlcXAFkqNXKzAJOD7Mdt_1yLMPdVLp-IMiwopbZZLdetbZBjVEHOBUrmpfj7EVJcFekqJjrroqabQW5t_iT652Vw",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed verifying jwt: invalid json decoded: Expected value but found T_END at character 1
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: error, jwks structure is invalid
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keyzzz":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQwbkpPd2RIWmJZOUd4V3JDQlJiZ1NWViIsInR5cCI6IkpXVCJ9.eyJleHAiOjgwNDQzNDg4MjQsImZvbyI6ImJhciIsImlhdCI6MTczMzAwMTYyNCwibmJmIjoxNzMzMDAxNjI0fQ.RwwBSxsHBu6maA_WyqaI1ny3b1RZCQPHvIxVBlBQT5SfptQ3zVWdGg6bc6xJvXytNh_MvaF3Pm9ITbOOOCslycwKy67b-uUzQll_hjLHiiT7jr6LiqVbYHb6WjjGfMBCHJvAySYkR9omrFq5z6UuHGE4dqacDW-JnwIOZ0-p1N4_x31pGNT_tTbli2aW6wOZXKMr6UhIZaNgAMh9HieQ4A_tKda6MTO1vzSCob0hLS3u8qv3zJ76JaDplS8EukZlcXAFkqNXKzAJOD7Mdt_1yLMPdVLp-IMiwopbZZLdetbZBjVEHOBUrmpfj7EVJcFekqJjrroqabQW5t_iT652Vw",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed verifying jwt: jwks invalid format: missing or invalid field 'keys'
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: error, jwk key does not exist for passed jwt
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"AAnJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"AAC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQwbkpPd2RIWmJZOUd4V3JDQlJiZ1NWViIsInR5cCI6IkpXVCJ9.eyJleHAiOjgwNDQzNDg4MjQsImZvbyI6ImJhciIsImlhdCI6MTczMzAwMTYyNCwibmJmIjoxNzMzMDAxNjI0fQ.RwwBSxsHBu6maA_WyqaI1ny3b1RZCQPHvIxVBlBQT5SfptQ3zVWdGg6bc6xJvXytNh_MvaF3Pm9ITbOOOCslycwKy67b-uUzQll_hjLHiiT7jr6LiqVbYHb6WjjGfMBCHJvAySYkR9omrFq5z6UuHGE4dqacDW-JnwIOZ0-p1N4_x31pGNT_tTbli2aW6wOZXKMr6UhIZaNgAMh9HieQ4A_tKda6MTO1vzSCob0hLS3u8qv3zJ76JaDplS8EukZlcXAFkqNXKzAJOD7Mdt_1yLMPdVLp-IMiwopbZZLdetbZBjVEHOBUrmpfj7EVJcFekqJjrroqabQW5t_iT652Vw",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed verifying jwt: could not find jwk with kid: D0nJOwdHZbY9GxWrCBRbgSVV
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: ok, jwt validated with symmetric key
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"oct","k":"K5uTCaoTN1qmvogYKami3i0DGDF4A3kBuLHWYyKQXZU"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"oct","k":"gM5qVGDNZmt-8xr_Rzr-lQV8RawRI0zQ7v2XBxMNP0g"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJIUzI1NiIsImtpZCI6IjNrQzJ3Nm9qODFVYkQyWEtNcjdobUpjbCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNDM2MzJ9.hK5hT8I3fwy3tKpsHWUoINQ9WEvj6GHXEkwYsQaBXQM",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
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
true
nil
HS256
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: error, jwt validation with symmetric key fails because key is not correct
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"oct","k":"K5uTCaoTN1qmvogYKami3i0DGDF4A3kBuLHWYyKQXZU"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"oct","k":"phTiOJ96sdkOSgUBtU66KCfxLOcPYu-qpqh1qfGYzMQ"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJIUzI1NiIsImtpZCI6IjNrQzJ3Nm9qODFVYkQyWEtNcjdobUpjbCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNDM2MzJ9.hK5hT8I3fwy3tKpsHWUoINQ9WEvj6GHXEkwYsQaBXQM",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
invalid jwt: signature does not match
--- error_code: 200
--- no_error_log
[error]

=== TEST 9: error, jwks have missing required field kty
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","k":"K5uTCaoTN1qmvogYKami3i0DGDF4A3kBuLHWYyKQXZU"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","k":"gM5qVGDNZmt-8xr_Rzr-lQV8RawRI0zQ7v2XBxMNP0g"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJIUzI1NiIsImtpZCI6IjNrQzJ3Nm9qODFVYkQyWEtNcjdobUpjbCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNDM2MzJ9.hK5hT8I3fwy3tKpsHWUoINQ9WEvj6GHXEkwYsQaBXQM",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed verifying jwt: jwk kty field must be present
--- error_code: 200
--- no_error_log
[error]

=== TEST 10: error, jwks have unknown value in required field kty
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"AAA","k":"K5uTCaoTN1qmvogYKami3i0DGDF4A3kBuLHWYyKQXZU"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"AAA","k":"gM5qVGDNZmt-8xr_Rzr-lQV8RawRI0zQ7v2XBxMNP0g"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJIUzI1NiIsImtpZCI6IjNrQzJ3Nm9qODFVYkQyWEtNcjdobUpjbCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNDM2MzJ9.hK5hT8I3fwy3tKpsHWUoINQ9WEvj6GHXEkwYsQaBXQM",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed verifying jwt: unknown or unsupported kty: AAA
--- error_code: 200
--- no_error_log
[error]

=== TEST 11: error, jwks with symmetric keys have missing required field k
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"oct"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"oct"}]}';
    }

    location = /t {
        content_by_lua_block {
            local jwks = require "resty.jwt-verification-jwks"
            local jwks_cache_local = require "resty.jwt-verification-jwks-cache-local"
            local ok, err = jwks.init(jwks_cache_local)
            ngx.say(ok)
            ngx.say(err)
            if not ok then
                return
            end
            local decoded_token, err = jwks.verify_jwt_with_jwks(
                "eyJhbGciOiJIUzI1NiIsImtpZCI6IjNrQzJ3Nm9qODFVYkQyWEtNcjdobUpjbCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTUzNDM2MzJ9.hK5hT8I3fwy3tKpsHWUoINQ9WEvj6GHXEkwYsQaBXQM",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            ngx.say(decoded_token)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed verifying jwt: jwk k field must be present when kty is set to 'oct'
--- error_code: 200
--- no_error_log
[error]
