use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    lua_shared_dict resty_jwt_verification_cache_jwks 10m;
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ok, simple repeated retrieval
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
            ngx.say(ngx.shared.resty_jwt_verification_cache_jwks:get("openresty:jwt-verification:jwks:" .. "http://127.0.0.1:1984/.well-known/jwks.json"))
            local keys, err = jwks.fetch_jwks("http://127.0.0.1:1984/.well-known/jwks.json")
            ngx.say(keys)
            ngx.say(err)
            ngx.say(ngx.shared.resty_jwt_verification_cache_jwks:get("openresty:jwt-verification:jwks:" .. "http://127.0.0.1:1984/.well-known/jwks.json"))
            local keys, err = jwks.fetch_jwks("http://127.0.0.1:1984/.well-known/jwks.json")
            ngx.say(keys)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}
nil
{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}
{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ok, simple retrieval with http timeouts
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
            jwks.set_http_timeouts_ms(30 * 1000, 30 * 1000, 30 * 1000)
            local keys, err = jwks.fetch_jwks("http://127.0.0.1:1984/.well-known/jwks.json")
            ngx.say(keys)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: ok, simple retrieval with disable ssl verification
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
            jwks.set_http_ssl_verify(false)
            local keys, err = jwks.fetch_jwks("http://127.0.0.1:1984/.well-known/jwks.json")
            ngx.say(keys)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"pWVkzHTMLnvbZHWFd3mVc4wlQy_I-vjnlO7If-NTlIynkP4TQnqOd50Thoq5FLMspoIH4und47zeKAhbYEYL-M37L4d25vTZsYr80Zs1DomZvXPjUkffJV8PccYw6DaTTyCuYMW9qfuDDCu9OQZxHy70KtepmkX3TebSvYigTq-XS_HcROD7tED5zeJfEmF0wHwR5B7ggbbMZj5uwbggi3rTnpEsh4Twqp_tDxtvIXc2DU2MZIWz-K8iWa4xgZ30b8hb0xCCtqTaOVkzB-VL9-NPmc74koSI6qK24eJgT4YR-xOWsgvZPaLv47qlMWWCS1ZP47fYd0UJ3ERjGjpUVQ"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"RSA","alg":"RS256","e":"AQAB","n":"xZsmF55ztSgllN-B26Yt1tLn9ROXHV3x68iLjcdDdr4s0HT_qJ7GexM8FGqmiZCs4EbKXkkVA-0cvSklXWUJxIA-HWP2vXnv_fHp-YD9OCdhuzOprp5wKd3ukGBfwa7xAA_vLlGrMh0FdHMJxzuesg4-IxO8QiFrDnA8AMdvCptLcm9GQRDuEBJDmJ0PBc-vhv4cJ5UsBlY50MrMhHlbWR6koCFkjVFY9MGsujARi8uVXJBSkZBm3p5Msl5gdxd2659vjn-pUgkTN0gPzz0omYWcpJVBFF_JxknGu87UBn4LKci02ZEBCSpxXKnPn60iH8Qx6RpSA5UiTCb--reQuQ"}]}
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: error, url returned 500
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 500 '';
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
            local keys, err = jwks.fetch_jwks("http://127.0.0.1:1984/.well-known/jwks.json")
            ngx.say(keys)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed fetching jwks, returned unexpected http status: 500
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: error, url does not exist
--- http_config eval: $::HttpConfig
--- config
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
            local keys, err = jwks.fetch_jwks("http://127.0.0.1:1984/.well-known/jwks.json")
            ngx.say(keys)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
nil
failed fetching jwks, returned unexpected http status: 404
--- error_code: 200
--- error_log
[error]
