use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: RSA-OAEP-256 + A192GCM ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyR0NNIn0.C_knzpA2ZquLB5dRZICMF9P_PapQ4E3_kKqu29ykriWB4NeDZ-rQd_oiSlz9AoQr3CvcT9nza5UWDRRGKcAgITLKr1dj8elD1SEpXvjF40ep2vALJ94vuXgqCxHeXK2nYAqFxKZ2DRWDbVsn8Gb9w7QHId8G2yQHibPvT9YMbGOp4vdgRo9CHUqkCgxpPIK0hhLd64Jh_PJGGnQTuRYMwojJ6b6rlf60P86fOZ0ReV7x-oIC078x6E8-lSgzVgJRdVz1S3D2ka3oyz3yim9zr72sHAa-_KkE5NdD5NlcF8XHQjoIG0ho4yOOM7oar4MxHY0701CFQ4F_r6VNPYwnig.7X48TXJ64d8xjKkg.mXsTy2_4Dk9VTUcLVNfUNik6zCUI1_gmVxZDO9O-.plopUvphKVo9TvTZyk_Arw"
            local decoded_token, err = jwt.decrypt(token, "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9cWE3KEVa5a0V\nImp84DCnjaUsif2QH2hpyKIqA0BhnxJjDm30Wj5mHshyJWKOf5xVLb9qgE2DYeF9\n1iB+lD+xvqPBtGoUyWfYaYb5fZonbBcwn9B/Gs8V070vfpsATCS5tRNhfCAxKbUq\npZE3zFf6gG751vLPDuJRuubDTJvNcpksm960K+a3St5TlO93ChzM5YUFIp5ifMGs\nLqEhIPzxNgMni2LDURZU66lAaqB6XQqMLuLB0hiLs9E6fr/UwycXjzOUFtP/v/M5\nGPzhn/IOebFm7UxDTuQepcNFi6ZJ8J6uDlfDm917tPPw7RNa1phXcclc1rRWk3k4\njcvjLs+HAgMBAAECggEAM4c9bCVWCA1k8NS1plXMpiaPAPhfse35FpzuDwNnZaZA\n+BSar9ZEFr7UwseMcTogqcKRyEQx0US0cuflWsi0MoKqRCvwlsrZpjG99urFHWf3\nPtCZg5klLsizMtH7Ey+i5ahtJxz+HKE9l+YFA+pfG9IHXYmr7cocoSJ3VjPmRREo\n727qCAPuA2SKKukAPtb4gwl8MaDnFSXW1NeQTNN/MQpxBz/CLvP54STCGIcVPmkU\nfGlx405eLIzxHAHPVDEdOhAqyeOiPpJ3lnpPSbSHCoMmtOsAVqLD99rkvgRxpQ6m\nJVH6/OcBpTGclcDMlG96UT2azF3uYS8VqvAitH6B4QKBgQDc1In61MjprNn/zpGw\nxhiMgbbRIMrocqQ+AUcXVSRRYIzsFKBEWfGCF90rmPBoc82CJt/Z7nDkU2E+1Vr9\nXvq+vCk1KQhsLlJM75UZKeUEzWZfxZagxMUe+zaDj5UzbrdhZl+43bGif0f+pVRP\neOZanLpOohKzgE/mOef9/6wISQKBgQDbnSYPi6mO5rs8rbHx3KQjYSBLlgfLrcWO\n3AN37RPn9b0jHOcFCi+hQyLzrvxVTPuLMGdUPTeJI1biktLF2WnViqBQ75pHu4go\nYnnlyRS647J6rFCIt5B7fG6UZi81Vz3J9hSx0DN+G1ACbi/eB9nMYbVEap7a2bCI\nmNSntUA5TwKBgQCBtEBa2HItdf4RFuZRmvi+Rk33pTgosXUwihWUacjMF1aOL0s2\n+lE0pQmd2tWRtDrHsEeYvEkIgsTCYBRybz/9mYzmkXRF/isOz0WWoxnF6VKw++AO\nC6TwHoMVYNc0f1osVjHw5h24oOPLeJX9m7hJDncLSnyLe9jyE57kfDAyKQKBgQDM\nbjbV1b5axbGZxF6WtDseq/TyJ5DOKs5yM6AO7OPQ01Hi866hZF/+D47jpApEJUsq\nwD4PjoS55emlM+N8ROxd2ZNug/vrtkgCv9iU7F+dsQOdafX1rlqSeLw+6/gaAUIF\nVErjUtn8E9Sgzo1Ec65ssK+aJl4FfwrzvMCH9RL5xQKBgCivJ8iowJds7ZEWZWK+\nDOjO/Ka/BQyiL7QJoFIkCk4k0Q16y/qt2jEWidlrXahsG46LI7ncuf23YUJ69b+/\nLbvKIDQjOIy/KKqyocQT9+QDAhMFkqpczuy+bh0gN1e35V6uSI6SIO27S0l5d+Mc\nftaj5h6iEOTu2unqXEMcFsw6\n-----END PRIVATE KEY-----", nil)
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
RSA-OAEP-256|A192GCM
bar
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: RSA-OAEP-256 + A192GCM error, wrong secret
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local jwt = require "resty.jwt-verification"
            local token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyR0NNIn0.C_knzpA2ZquLB5dRZICMF9P_PapQ4E3_kKqu29ykriWB4NeDZ-rQd_oiSlz9AoQr3CvcT9nza5UWDRRGKcAgITLKr1dj8elD1SEpXvjF40ep2vALJ94vuXgqCxHeXK2nYAqFxKZ2DRWDbVsn8Gb9w7QHId8G2yQHibPvT9YMbGOp4vdgRo9CHUqkCgxpPIK0hhLd64Jh_PJGGnQTuRYMwojJ6b6rlf60P86fOZ0ReV7x-oIC078x6E8-lSgzVgJRdVz1S3D2ka3oyz3yim9zr72sHAa-_KkE5NdD5NlcF8XHQjoIG0ho4yOOM7oar4MxHY0701CFQ4F_r6VNPYwnig.7X48TXJ64d8xjKkg.mXsTy2_4Dk9VTUcLVNfUNik6zCUI1_gmVxZDO9O-.plopUvphKVo9TvTZyk_Arw"
            local decoded_token, err = jwt.decrypt(token, "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsR5YNLBywkz2H\nQ72JYNjL3AkhyQPgOUBmuhar/7oZTb6Zk/wCHHfHJ8XmHC5oEm3Hz1/+TnShC2J+\nPuvOreZyTR4dIQMZvLchqeOXK2ZHccZZo/uA3tlDh6wJGaIG5Eh3ID47iFpFp24c\nshgNjfdpp+69BvkQ+KscGJ5628lPCmtQCRtJeLQr2jQlocJrF25sbwHIZDUoLTv6\nYvj3pr6Kn6bvxLjZYHGi47/hoqyXACqnhCyw+gmbfaOiAreV3HsUJPOevwk2SRzL\nhUUjTiUoYe4p2Tn6agQIWZa2kqwSSOMXGVOrKHmazgjom+vzrJ+gzS2GSOzUOXnw\nfbuilcjZAgMBAAECggEANTKhvg2KCmhdDoC3bU1vhHu8gic9QCbNoSsDRzdfMuMT\n4P6WSdyai+/XJzg6iD5wkcuSW8fEMdp/Hna1gAuo5lCz5NDF0VO5xPZd5dcr7RHP\n6uw9BE1MD5M8Z073/mLNkaNuNBnlri6GTOwdi0n0RTbq/InDrR7sT2+2uD9YCUSu\n1VNoBC+1yMj/4V8uxZE9h2+dFnt1R1JzSOszOV/JAjnCNSBbcI4wRyF0aNUL5H+l\n/FJ9crvMr179zZUVZpcPT7bNenrQXao+tW3k/Z+G+lJwKLhohTKkt/snUXk0YT70\nsKQ06bIf4djRYCJGnnLeXf0GmD6osBIPmB1JqynUJQKBgQDrZaXG7jikp2ed9+i1\nOMlN10owTPGaV0GdRpWUANQ1f55nx/DGRP7xTsdhWDZwnj7AFdCneC0/0qqCir5C\nHcMv2Uhr4L+X+5GwX0PN0qshybtNrM/FBHk3V0mwvMP97Z5hXPLClWkiIWklZCuq\nux13GFjxekzpHyiE5DK1ljD3ZwKBgQC7W7eZoi7LKaKizHfWpwcIUuS57TDAWgnI\nYTdjQwOJddZ/Hazm98o/BlQpeopeyl+ZgFoZiprg1+ueHf+q+HQY9hgVn0EfoVOL\n2Y69fb2O4Hx4f90G1X21xkCsXzqtDLPX5F2GPru3abL5l6VP+XRRMTbJIUI5LsNq\nlyrU9dhVvwKBgFHGYxvDgBv7J+zhxY7HJm+LPfOfl0MF0v5/GdFrpEzdg7sL42IN\nb/+GXY88pNTktGnoai7zecy1M5Tb/BJd4oPJ2PXZAtYah9cckSJ8cATx3sayJQ+N\naUrHYQsr2G5rUN0D/DWK0BYSQ0PBE8Zg8HCCHcvtr7BAqcPYvqEEhwg7AoGARdLg\nkbkHh1905QcegjitPkTmSQREbusfSjYw1iVbZBcuYSFGFq2yCdrp8qtgdgMlradP\n7MTjA3h0rvCvH6CIY+UTBLvdIVSWNkBWGfiKdHzk5mOAk9NsjhnccGDtFSDuxT6u\nPCGVA724nZwOV8e3uaqFqF9ktrreyRKdO9CDVzECgYEAx23rT1LstI+5dyP4GRR5\n3A3KB4m/+NIe1p1DCHsOZcYqlCH91+aWhgo92kYrLV1XCMK28Wlbvvp3MEqnSTV3\nTrAZiM3TyfD8+1GwyF1AwSb+zj+SN04Ezrj8GQGaDc32LqIK0B7NS09n56gP64az\nlPq/POqpDo0mt988ELW4w3Y=\n-----END PRIVATE KEY-----", nil)
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
nil
nil
invalid jwt: pkey:asymmetric_routine EVP_PKEY_decrypt: code: 0 error:30000E8:digital envelope routines:EVP_PKEY_decrypt:provider asym cipher failure:crypto/evp/asymcipher.c:314:
--- error_code: 200
--- no_error_log
[error]
