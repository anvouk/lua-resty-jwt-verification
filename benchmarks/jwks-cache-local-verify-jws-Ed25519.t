use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    lua_shared_dict resty_jwt_verification_cache_jwks 10m;
    init_by_lua_block {
        jwt = require("resty.jwt-verification")
        jwks = require("resty.jwt-verification-jwks")
        jwks_cache_local = require("resty.jwt-verification-jwks-cache-local")

        jwks_endpoint = "http://127.0.0.1:1984/.well-known/jwks.json"

        local ok, err = jwks.init(jwks_cache_local)
        if not ok then
            ngx.log(ngx.STDERR, "Failed JWKS client init")
            return
        end
    }
_EOC_

master_on();
workers(1);

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: verify jwt
--- http_config eval: $::HttpConfig
--- config
    location = /.well-known/jwks.json {
        return 200 '{"keys":[{"kid":"D0nJOwdHZbY9GxWrCBRbgSVV","use":"sig","crv":"Ed25519","x":"-i7KjL2-4AdiQBtcBTpEseRzh5sFRfSCtuEAhpGrw5s","kty":"OKP"}]}';
    }

    location = /t {
        content_by_lua_block {
            local token = ngx.var.http_authorization
            if not token then
                ngx.log(ngx.STDERR, "Missing Authorization header")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end

            local space_pos = string.find(token, " ", 0, true)
            if space_pos == nil then
                ngx.log(ngx.STDERR, "Invalid auth header format")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
            token = string.sub(token, space_pos + 1)

            local decoded_token, err = jwks.verify_jwt_with_jwks(
                token,
                jwks_endpoint,
                nil
            )
            if not decoded_token then
                ngx.log(ngx.STDERR, "Invalid jwt: " .. err)
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiRDBuSk93ZEhaYlk5R3hXckNCUmJnU1ZWIn0.eyJmb28iOiJiYXIiLCJpYXQiOjE3NTU5NjA5Njl9.0FzRe8y8GwbCvqLIPjvZWC1X-pcB_Hc6CKFvS97I1FOxNAvExdCRKAzvi2GCeXsxcywS50l9lRPFvEq23nHqAQ
--- response_body
--- error_code: 200
--- no_error_log
[error]
