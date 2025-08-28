use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    lua_shared_dict resty_jwt_verification_cache_jwks 10m;
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: ok, jwt validated
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kty":"RSA","kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"enc","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw","e":"AQAB","d":"M4c9bCVWCA1k8NS1plXMpiaPAPhfse35FpzuDwNnZaZA-BSar9ZEFr7UwseMcTogqcKRyEQx0US0cuflWsi0MoKqRCvwlsrZpjG99urFHWf3PtCZg5klLsizMtH7Ey-i5ahtJxz-HKE9l-YFA-pfG9IHXYmr7cocoSJ3VjPmRREo727qCAPuA2SKKukAPtb4gwl8MaDnFSXW1NeQTNN_MQpxBz_CLvP54STCGIcVPmkUfGlx405eLIzxHAHPVDEdOhAqyeOiPpJ3lnpPSbSHCoMmtOsAVqLD99rkvgRxpQ6mJVH6_OcBpTGclcDMlG96UT2azF3uYS8VqvAitH6B4Q","p":"3NSJ-tTI6azZ_86RsMYYjIG20SDK6HKkPgFHF1UkUWCM7BSgRFnxghfdK5jwaHPNgibf2e5w5FNhPtVa_V76vrwpNSkIbC5STO-VGSnlBM1mX8WWoMTFHvs2g4-VM263YWZfuN2xon9H_qVUT3jmWpy6TqISs4BP5jnn_f-sCEk","q":"250mD4upjua7PK2x8dykI2EgS5YHy63FjtwDd-0T5_W9IxznBQovoUMi8678VUz7izBnVD03iSNW4pLSxdlp1YqgUO-aR7uIKGJ55ckUuuOyeqxQiLeQe3xulGYvNVc9yfYUsdAzfhtQAm4v3gfZzGG1RGqe2tmwiJjUp7VAOU8","dp":"gbRAWthyLXX-ERbmUZr4vkZN96U4KLF1MIoVlGnIzBdWji9LNvpRNKUJndrVkbQ6x7BHmLxJCILEwmAUcm8__ZmM5pF0Rf4rDs9FlqMZxelSsPvgDguk8B6DFWDXNH9aLFYx8OYduKDjy3iV_Zu4SQ53C0p8i3vY8hOe5HwwMik","dq":"zG421dW-WsWxmcRelrQ7Hqv08ieQzirOcjOgDuzj0NNR4vOuoWRf_g-O46QKRCVLKsA-D46EueXppTPjfETsXdmTboP767ZIAr_YlOxfnbEDnWn19a5akni8Puv4GgFCBVRK41LZ_BPUoM6NRHOubLCvmiZeBX8K87zAh_US-cU","qi":"KK8nyKjAl2ztkRZlYr4M6M78pr8FDKIvtAmgUiQKTiTRDXrL-q3aMRaJ2WtdqGwbjosjudy5_bdhQnr1v78tu8ogNCM4jL8oqrKhxBP35AMCEwWSqlzO7L5uHSA3V7flXq5IjpIg7btLSXl34xx-1qPmHqIQ5O7a6epcQxwWzDo"}]}';
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
            local decoded_token, err = jwks.decrypt_jwt_with_jwks(
                "eyJhbGciOiJSU0EtT0FFUC01MTIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiRDBuSk93ZEhaYlk5R3hXckNCUmJnU1ZWIn0.fZAJHfQFF07lwAXf0bgyCZZbbBUBN9c4rjE_JLhd4fG7xn8ZgaRFnUQ439qDDrrKnPlcBe05SOgm9Zn_Q9Mjj5s23TdNgDRi5z5nBmQmBUhF4kvG8__crgNg_cAvPW2G84RPB8qsQiAfBLh6-udgvq6_HlzWXi8Qj98rHXLE3rEA7PcUuuzU95ox0AeNFrdjB9lioZ8ruzqpVkbUu6F_yrsd7tq3dBWil6pALn0sCPbHkAzmZvO9JxtiotQ8OqjCitOv3bSLQFNMLgqoEl49sHFci6KQFO1ItVS4RjwJyoY0zPI5t_541KdD_4xzWzIo-MgZfelNZWT3amiJCfaK4g.lKy6G7eoeMXiuqONZR2MRw.u8qCjgYGLIieqe5LaV_1NyOZMlmGQPVF12h3yAbK81Q.QefyUw8hNU_39utrwSKKjBkd1pyXGBspah4U_VIOLcc",
                "http://127.0.0.1:1984/.well-known/jwks.json",
                nil
            )
            if decoded_token then
                ngx.say(decoded_token.header.alg)
                ngx.say(decoded_token.payload.foo)
            else
                ngx.say(nil)
                ngx.say(nil)
            end
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
nil
RSA-OAEP-512
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: ok, jwt validated with symmetric key
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"enc","kty":"oct","k":"c3VwZXJTZWNyZXRLZXkxMnN1cGVyU2VjcmV0S2V5MTI"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"oct","k":"gM5qVGDNZmt-8xr_Rzr-lQV8RawRI0zQ7v2XBxMNP0g"}]}';
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
            local decoded_token, err = jwks.decrypt_jwt_with_jwks(
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiRDBuSk93ZEhaYlk5R3hXckNCUmJnU1ZWIn0..P7Gz_F6ZWra9qujcds2CQQ.aNz1-cDWf7aJUfHxZBhEomPXBgTAq_45eeaB9vgCCRE.2mG75Eqb0NzcDVJXnqVzUA",
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
dir
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: error, jwt validation with symmetric key fails because key is not correct
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"enc","kty":"oct","k":"gM5qVGDNZmt-8xr_Rzr-lQV8RawRI0zQ7v2XBxMNP0g"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"oct","k":"gM5qVGDNZmt-8xr_Rzr-lQV8RawRI0zQ7v2XBxMNP0g"}]}';
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
            local decoded_token, err = jwks.decrypt_jwt_with_jwks(
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiRDBuSk93ZEhaYlk5R3hXckNCUmJnU1ZWIn0..P7Gz_F6ZWra9qujcds2CQQ.aNz1-cDWf7aJUfHxZBhEomPXBgTAq_45eeaB9vgCCRE.2mG75Eqb0NzcDVJXnqVzUA",
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
invalid jwt: failed decrypting jwt payload
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: error, jwks with symmetric keys have missing required field k
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"enc","kty":"oct"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"oct","k":"gM5qVGDNZmt-8xr_Rzr-lQV8RawRI0zQ7v2XBxMNP0g"}]}';
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
            local decoded_token, err = jwks.decrypt_jwt_with_jwks(
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiRDBuSk93ZEhaYlk5R3hXckNCUmJnU1ZWIn0..P7Gz_F6ZWra9qujcds2CQQ.aNz1-cDWf7aJUfHxZBhEomPXBgTAq_45eeaB9vgCCRE.2mG75Eqb0NzcDVJXnqVzUA",
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

=== TEST 5: error, jwk usage is for 'sig' only
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","kty":"oct","k":"c3VwZXJTZWNyZXRLZXkxMnN1cGVyU2VjcmV0S2V5MTI"},{"kid":"3kC2w6oj81UbD2XKMr7hmJcl","use":"sig","kty":"oct","k":"gM5qVGDNZmt-8xr_Rzr-lQV8RawRI0zQ7v2XBxMNP0g"}]}';
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
            local decoded_token, err = jwks.decrypt_jwt_with_jwks(
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiRDBuSk93ZEhaYlk5R3hXckNCUmJnU1ZWIn0..P7Gz_F6ZWra9qujcds2CQQ.aNz1-cDWf7aJUfHxZBhEomPXBgTAq_45eeaB9vgCCRE.2mG75Eqb0NzcDVJXnqVzUA",
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
failed verifying jwt: matching jwk with kid 'D0nJOwdHZbY9GxWrCBRbgSVV' cannot be used for decryption
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: error, jwt is a jws
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kty":"RSA","kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"enc","n":"vXFhNyhFWuWtFSJqfOAwp42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo-Zh7IciVijn-cVS2_aoBNg2HhfdYgfpQ_sb6jwbRqFMln2GmG-X2aJ2wXMJ_QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX-oBu-dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD88TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6_1MMnF48zlBbT_7_zORj84Z_yDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7Phw","e":"AQAB","d":"M4c9bCVWCA1k8NS1plXMpiaPAPhfse35FpzuDwNnZaZA-BSar9ZEFr7UwseMcTogqcKRyEQx0US0cuflWsi0MoKqRCvwlsrZpjG99urFHWf3PtCZg5klLsizMtH7Ey-i5ahtJxz-HKE9l-YFA-pfG9IHXYmr7cocoSJ3VjPmRREo727qCAPuA2SKKukAPtb4gwl8MaDnFSXW1NeQTNN_MQpxBz_CLvP54STCGIcVPmkUfGlx405eLIzxHAHPVDEdOhAqyeOiPpJ3lnpPSbSHCoMmtOsAVqLD99rkvgRxpQ6mJVH6_OcBpTGclcDMlG96UT2azF3uYS8VqvAitH6B4Q","p":"3NSJ-tTI6azZ_86RsMYYjIG20SDK6HKkPgFHF1UkUWCM7BSgRFnxghfdK5jwaHPNgibf2e5w5FNhPtVa_V76vrwpNSkIbC5STO-VGSnlBM1mX8WWoMTFHvs2g4-VM263YWZfuN2xon9H_qVUT3jmWpy6TqISs4BP5jnn_f-sCEk","q":"250mD4upjua7PK2x8dykI2EgS5YHy63FjtwDd-0T5_W9IxznBQovoUMi8678VUz7izBnVD03iSNW4pLSxdlp1YqgUO-aR7uIKGJ55ckUuuOyeqxQiLeQe3xulGYvNVc9yfYUsdAzfhtQAm4v3gfZzGG1RGqe2tmwiJjUp7VAOU8","dp":"gbRAWthyLXX-ERbmUZr4vkZN96U4KLF1MIoVlGnIzBdWji9LNvpRNKUJndrVkbQ6x7BHmLxJCILEwmAUcm8__ZmM5pF0Rf4rDs9FlqMZxelSsPvgDguk8B6DFWDXNH9aLFYx8OYduKDjy3iV_Zu4SQ53C0p8i3vY8hOe5HwwMik","dq":"zG421dW-WsWxmcRelrQ7Hqv08ieQzirOcjOgDuzj0NNR4vOuoWRf_g-O46QKRCVLKsA-D46EueXppTPjfETsXdmTboP767ZIAr_YlOxfnbEDnWn19a5akni8Puv4GgFCBVRK41LZ_BPUoM6NRHOubLCvmiZeBX8K87zAh_US-cU","qi":"KK8nyKjAl2ztkRZlYr4M6M78pr8FDKIvtAmgUiQKTiTRDXrL-q3aMRaJ2WtdqGwbjosjudy5_bdhQnr1v78tu8ogNCM4jL8oqrKhxBP35AMCEwWSqlzO7L5uHSA3V7flXq5IjpIg7btLSXl34xx-1qPmHqIQ5O7a6epcQxwWzDo"}]}';
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
            local decoded_token, err = jwks.decrypt_jwt_with_jwks(
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
failed verifying jwt: parsed token is a jws
--- error_code: 200
--- no_error_log
[error]
