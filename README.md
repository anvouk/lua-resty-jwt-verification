# JWT verification for openresty

JWT verification library for OpenResty.

## Table of Contents

- [Description](#description)
- [Status](#status)
- [Library non-goals](#library-non-goals)
- [Differences from lua-resty-jwt](#differences-from-lua-resty-jwt)
- [Supported features](#supported-features)
  - [JWS Verification](#jws-verification)
  - [JWE Decryption](#jwe-decryption)
  - [JWKS retrieval cache strategies](#jwks-retrieval-cache-strategies)
- [Planned missing features](#planned-missing-features)
- [Dependencies](#dependencies)
- [JWT verification usage](#jwt-verification-usage)
  - [jwt.decode_header_unsafe](#jwtdecode_header_unsafe)
  - [jwt.verify](#jwtverify)
  - [jwt.decrypt](#jwtdecrypt)
- [JWKS verification usage](#jwks-verification-usage)
  - [jwks.enable_cache_strategy_local](#jwksenable_cache_strategy_local)
  - [jwks.set_http_timeouts_ms](#jwksset_http_timeouts_ms)
  - [jwks.set_http_ssl_verify](#jwksset_http_ssl_verify)
  - [jwks.fetch_jwks](#jwksfetch_jwks)
  - [jwks.verify_jwt_with_jwks](#jwksverify_jwt_with_jwks)
- [RFCs used as reference](#rfcs-used-as-reference)
- [Run tests](#run-tests)
  - [Setup](#setup)
  - [Run](#run)

## Description

JWT verification library for OpenResty.

The project's goal is to be a modern and slimmer replacement for [lua-resty-jwt](https://github.com/cdbattags/lua-resty-jwt/)
with built-in support for JWKS.

This project does not provide JWT manipulation or creation features: you can only verify/decrypt tokens.

## Status

Ready for testing: looking for more people to take it for a spin and provide feedback.

The APIs should be stable; I'll provide a migration document in case breaking changes happen in future releases.

## Library non-goals

- JWT creation/modification
- Feature complete for the sake of RFCs completeness.
- Senseless and unsafe RFCs features (e.g. alg none) won't be implemented.

## Differences from lua-resty-jwt

Main differences are:
- No JWT manipulation of any kind (you can only decrypt/verify them)
- Simpler internal structure reliant on more recent [lua-resty-openssl](https://github.com/fffonion/lua-resty-openssl) and OpenSSL versions.
- Supports different JWE algorithms (see tables above).
- Automatic JWT verification given JWKS HTTP endpoint.

If any of the points above are a problem, or you need compatibility with older OpenResty versions, I
recommend sticking with [lua-resty-jwt](https://github.com/cdbattags/lua-resty-jwt/).

## Supported features

- JWS verification: with symmetric or asymmetric keys.
- JWE decryption: with symmetric or asymmetric keys.
- Asymmetric keys format supported:
  - PEM
  - DER
  - JWK
- JWT claims validation.
- Automatic JWKS fetching and JWT validation.
  - optional caching strategies.

### JWS Verification

|  Claims  |    Implemented     |
|:--------:|:------------------:|
|   alg    | :white_check_mark: |
|   jku    |        :x:         |
|   jwk    |        :x:         |
|   kid    | :white_check_mark: |
|   x5u    |        :x:         |
|   x5c    |        :x:         |
|   x5t    |        :x:         |
| x5t#S256 |        :x:         |
|   typ    | :white_check_mark: |
|   cty    |        :x:         |
|   crit   | :white_check_mark: |

|  Alg  |    Implemented     |
|:-----:|:------------------:|
| HS256 | :white_check_mark: |
| HS384 | :white_check_mark: |
| HS512 | :white_check_mark: |
| RS256 | :white_check_mark: |
| RS384 | :white_check_mark: |
| RS512 | :white_check_mark: |
| ES256 | :white_check_mark: |
| ES384 | :white_check_mark: |
| ES512 | :white_check_mark: |
| PS256 | :white_check_mark: |
| PS384 | :white_check_mark: |
| PS512 | :white_check_mark: |
| none  |        :x:         |

### JWE Decryption

|  Claims  |    Implemented     |
|:--------:|:------------------:|
|   alg    | :white_check_mark: |
|   enc    | :white_check_mark: |
|   zip    |        :x:         |
|   jku    |        :x:         |
|   jwk    |        :x:         |
|   kid    | :white_check_mark: |
|   x5u    |        :x:         |
|   x5c    |        :x:         |
|   x5t    |        :x:         |
| x5t#S256 |        :x:         |
|   typ    | :white_check_mark: |
|   cty    |        :x:         |
|   crit   | :white_check_mark: |

|        Alg         |     Implemented     | Requirements  |
|:------------------:|:-------------------:|:-------------:|
|       RSA1_5       |         :x:         |               |
|      RSA-OAEP      |         :x:         |               |
|    RSA-OAEP-256    |         :x:         |               |
|       A128KW       | :white_check_mark:  | *OpenSSL 3.0+ |
|       A192KW       | :white_check_mark:  | *OpenSSL 3.0+ |
|       A256KW       | :white_check_mark:  | *OpenSSL 3.0+ |
|        dir         | :white_check_mark:  |               |
|      ECDH-ES       |         :x:         |               |
|     A128GCMKW      |         :x:         |               |
|     A192GCMKW      |         :x:         |               |
|     A256GCMKW      |         :x:         |               |
| PBES2-HS256+A128KW |         :x:         |               |
| PBES2-HS384+A192KW |         :x:         |               |
| PBES2-HS512+A256KW |         :x:         |               |

> *The first official release of OpenResty including OpenSSL 3.0+ is [OpenResty 1.27.1.1](https://openresty.org/en/ann-1027001001.html)
> which shipped with OpenSSL 3.0.15 (Yes, the [godawful slow OpenSSL 3.0 series...](https://github.com/openssl/openssl/issues/17064)).
>
> So, please, go with [OpenResty 1.27.1.2](https://openresty.org/en/ann-1027001002.html) as a minimum, which shipped
> with OpenSSL 3.4.1.

|      Enc      |    Implemented     |
|:-------------:|:------------------:|
| A128CBC-HS256 | :white_check_mark: |
| A192CBC-HS384 | :white_check_mark: |
| A256CBC-HS512 | :white_check_mark: |
|    A128GCM    | :white_check_mark: |
|    A192GCM    | :white_check_mark: |
|    A256GCM    | :white_check_mark: |

## JWKS retrieval cache strategies

|   Cache Strategy    |    Implemented     |
|:-------------------:|:------------------:|
|      no cache       | :white_check_mark: |
| local (shared_dict) | :white_check_mark: |
|        redis        |        :x:         |

## Planned missing features

This is a list of missing features I'd like to implement when given enough time:
- Implement JWE validation with at least 1 asymmetric `alg`.
- Nested JWT (i.e. JWT in JWE).
- JWKS Redis cache strategy.
- Automatic JWKS validation for JWE.

## Dependencies

```bash
luarocks install lua-cjson
luarocks install lua-resty-openssl
luarocks install lua-resty-http
```

## JWT verification usage

### jwt.decode_header_unsafe

**syntax**: *header, err = jwt.decode_header_unsafe(token)*

Read a jwt header and convert it to a lua table.

> **Important**: this method does not validate JWT signature! Only use if you need to inspect the token's header
> without having to perform the full validation.

```lua
local jwt = require("resty.jwt-verification")

local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NDkwNzJ9._MwFdsBPSyci9iARpoAaulReGcn1q7mKiPZjR2JDvdY"
local header, err = jwt.decode_header_unsafe(token)
if not header then
    return nil, "malformed jwt: " .. err
end
print("alg: " .. header.alg) -- alg: HS256
```

### jwt.verify

**syntax**: *decoded_token, err = jwt.verify(token, secret, options?)*

Validate a JWS token and convert it to a lua table.

The optional parameter `options` can be passed to configure the token validator. Valid fields are:
- `valid_signing_algorithms` (dict<string, string> | nil): a dict containing allowed `alg` claims used to validate the JWT.
- `typ` (string | nil): if non-null, ensure JWT claim `typ` matches the passed value.
- `issuer` (string | nil): if non-null, ensure JWT claim `iss` matches the passed value.
- `audiences` (string | table | nil): if non-null, ensure JWT claim `aud` matches one of the supplied values.
- `subject` (string | nil): if non-null, ensure JWT claim `sub` matches the passed value.
- `jwtid` (string | nil): if non-null, ensure JWT claim `jti` matches the passed value.
- `ignore_not_before` (bool): If true, the JWT claim `nbf` will be ignored.
- `ignore_expiration` (bool): If true, the JWT claim `exp` will be ignored.
- `current_unix_timestamp` (datetime | nil): the JWT `nbf` and `exp` claims will be validated against this timestamp. If null,
will use the current datetime supplied by `ngx.time()`.
- `timestamp_skew_seconds` (int):

Default values for `options` fields:
```lua
local verify_default_options = {
    valid_signing_algorithms = {
        ["HS256"]="HS256", ["HS384"]="HS384", ["HS512"]="HS512",
        ["RS256"]="RS256", ["RS384"]="RS384", ["RS512"]="RS512",
        ["ES256"]="ES256", ["ES384"]="ES384", ["ES512"]="ES512",
        ["PS256"]="PS256", ["PS384"]="PS384", ["PS512"]="PS512",
    },
    typ = nil,
    issuer = nil,
    audiences = nil,
    subject = nil,
    jwtid = nil,
    ignore_not_before = false,
    ignore_expiration = false,
    current_unix_timestamp = nil,
    timestamp_skew_seconds = 1,
}
```

Minimal example with symmetric keys:
```lua
local jwt = require("resty.jwt-verification")

local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0"
local decoded_token, err = jwt.verify(token, "superSecretKey")
if not decoded_token then
    return nil, "invalid jwt: " .. err
end
print(decoded_token.header.alg) -- HS256
print(decoded_token.payload.foo) -- bar
```

Minimal example with asymmetric keys:
```lua
local jwt = require("resty.jwt-verification")

local token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2Njg2Mzd9.H6PE-zLizMMqefx8DG4X5glVjyxR9UNT225Tq2yufHhu4k9K0IGttpykjMCG8Ck_4Qt2ezEWIgoiWhSn1rv_zwxe7Pv-B09fDs7h1hbASi5MZ0YVAmK9ID1RCKM_NTBEnPLot_iopKZRj2_J5F7lvXwJDZSzEAFJZdrgjKeBS4saDZAv7SIL9Nk75rdhgY-RgRwsjmTYSksj7eioRJJLHifrMnlQDbdrBD5_Qk5tD6VPcssO-vIVBUAYrYYTa7M7A_v47UH84zDtzNYBbk9NrDbyq5-tYs0lZwNhIX8t-0VAxjuCyrrGZvv8_O01pdi90kQmntFIbaiDiD-1WlGcGA"
local decoded_token, err = jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXFhNyhFWuWtFSJqfOAw\np42lLIn9kB9oaciiKgNAYZ8SYw5t9Fo+Zh7IciVijn+cVS2/aoBNg2HhfdYgfpQ/\nsb6jwbRqFMln2GmG+X2aJ2wXMJ/QfxrPFdO9L36bAEwkubUTYXwgMSm1KqWRN8xX\n+oBu+dbyzw7iUbrmw0ybzXKZLJvetCvmt0reU5TvdwoczOWFBSKeYnzBrC6hISD8\n8TYDJ4tiw1EWVOupQGqgel0KjC7iwdIYi7PROn6/1MMnF48zlBbT/7/zORj84Z/y\nDnmxZu1MQ07kHqXDRYumSfCerg5Xw5vde7Tz8O0TWtaYV3HJXNa0VpN5OI3L4y7P\nhwIDAQAB\n-----END PUBLIC KEY-----")
if not decoded_token then
    return nil, "invalid jwt: " .. err
end
print(decoded_token.header.alg) -- RS256
print(decoded_token.payload.foo) -- bar
```

Examples with custom `options`:
```lua
local jwt = require("resty.jwt-verification")

local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0"
local decoded_token, err = jwt.verify(token, "superSecretKey", {
    valid_signing_algorithms = {["HS256"]="HS256", ["HS384"]="HS384", ["HS512"]="HS512"}, -- only allow HS family algs
    audiences = {"user", "admin"}, -- `aud` must be one of the following
    ignore_not_before = true -- ignore `nbf` claim (not recommended)
})
if not decoded_token then
    return nil, "invalid jwt: " .. err
end
print(decoded_token.header.alg) -- HS256
print(decoded_token.payload.foo) -- bar
```

### jwt.decrypt

**syntax**: *decoded_token, err = jwt.decrypt(token, secret, options?)*

Decrypt and validate a JWE token and convert it to a lua table.

The optional parameter `options` can be passed to configure the token validator. Valid fields are:
- `valid_encryption_alg_algorithms` (dict<string, string> | nil): a dict containing allowed `alg` claims used to decrypt the JWT.
- `valid_encryption_enc_algorithms` (dict<string, string> | nil): a dict containing allowed `enc` claims used to decrypt the JWT.
- `typ` (string | nil): if non-null, ensure JWT claim `typ` matches the passed value.
- `issuer` (string | nil): if non-null, ensure JWT claim `iss` matches the passed value.
- `audiences` (string | table | nil): if non-null, ensure JWT claim `aud` matches one of the supplied values.
- `subject` (string | nil): if non-null, ensure JWT claim `sub` matches the passed value.
- `jwtid` (string | nil): if non-null, ensure JWT claim `jti` matches the passed value.
- `ignore_not_before` (bool): If true, the JWT claim `nbf` will be ignored.
- `ignore_expiration` (bool): If true, the JWT claim `exp` will be ignored.
- `current_unix_timestamp` (datetime | nil): the JWT `nbf` and `exp` claims will be validated against this timestamp. If null,
  will use the current datetime supplied by `ngx.time()`.
- `timestamp_skew_seconds` (int):

Default values for `options` fields:
```lua
local decrypt_default_options = {
    valid_encryption_alg_algorithms = {
        ["A128KW"]="A128KW", ["A192KW"]="A192KW", ["A256KW"]="A256KW",
        ["dir"]="dir",
    },
    valid_encryption_enc_algorithms = {
        ["A128CBC-HS256"]="A128CBC-HS256",
        ["A192CBC-HS384"]="A192CBC-HS384",
        ["A256CBC-HS512"]="A256CBC-HS512",
        ["A128GCM"]="A128GCM",
        ["A192GCM"]="A192GCM",
        ["A256GCM"]="A256GCM",
    },
    typ = nil,
    issuer = nil,
    audiences = nil,
    subject = nil,
    jwtid = nil,
    ignore_not_before = false,
    ignore_expiration = false,
    current_unix_timestamp = nil,
    timestamp_skew_seconds = 1,
}
```

Minimal example with symmetric keys:
```lua
local jwt = require("resty.jwt-verification")

local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.zAIq7qVAEO-eCG6gOdd3ld8_IHzeq3UlaWLHF2IDn6nNUuHh5n_i4w.5CM864cgiBgFPwluW4ViRg.mUeX7zHDVNsXhys0XO5S4w.t3yAR_HU0GDTEyCbpRa6BQ"
local decoded_token, err = jwt.decrypt(token, "superSecretKey12")
if not decoded_token then
    return nil, "invalid jwt: " .. err
end
print(decoded_token.header.alg) -- A128KW
print(decoded_token.header.enc) -- A128CBC-HS256
print(decoded_token.payload.foo) -- bar
```

Minimal example with asymmetric keys:
`TODO: not implemented`

Examples with custom `options`:
```lua
local jwt = require("resty.jwt-verification")

local token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.zAIq7qVAEO-eCG6gOdd3ld8_IHzeq3UlaWLHF2IDn6nNUuHh5n_i4w.5CM864cgiBgFPwluW4ViRg.mUeX7zHDVNsXhys0XO5S4w.t3yAR_HU0GDTEyCbpRa6BQ"
local decoded_token, err = jwt.decrypt(token, "superSecretKey12", {
    valid_encryption_alg_algorithms = {["A128KW"]="A128KW"}, -- only allow A128KW family algs (requires OpenSSL 3.0+)
    valid_encryption_enc_algorithms = {["A128CBC-HS256"]="A128CBC-HS256"}, -- only allow A128CBC family encs
    audiences = {"user", "admin"}, -- `aud` must be one of the following
    ignore_not_before = true -- ignore `nbf` claim (not recommended)
})
if not decoded_token then
    return nil, "invalid jwt: " .. err
end
print(decoded_token.header.alg) -- A128KW
print(decoded_token.header.enc) -- A128CBC-HS256
print(decoded_token.payload.foo) -- bar
```

## JWKS verification usage

The `resty.jwt-verification-jwks` module implements automatic JWKS retrieval from an HTTP endpoint and subsequent JWT
validation with fetched keys.

The `resty.jwt-verification-jwks-cache-*` modules implement optional JWKS caching strategies. Only one caching strategy
can be enabled at a time; if none are enabled, the JWKS endpoint will be called once for every JWT to validate.

### jwks.enable_cache_strategy_local

**syntax**: *ok, err = jwks.enable_cache_strategy_local()*

Enables the JWKS cache strategy using the OpenResty built-in [shared memory dictionaries](https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/#ngxshareddict).

This works on a per OpenResty instance and does not perform any network call on cache hit.

```lua
local jwks = require("resty.jwt-verification-jwks")

local ok, err = jwks.enable_cache_strategy_local()
if not ok then
    ngx.say("Error enable cache strategy: ", err)
end
```

### jwks.set_http_timeouts_ms

**syntax**: *jwks.set_http_timeouts_ms(connect, send, read)*

Set HTTP client timeouts in milliseconds used for fetching JWKS.

```lua
local jwks = require("resty.jwt-verification-jwks")

jwks.enable_cache_strategy_local(5000, 5000, 5000)
```

### jwks.set_http_ssl_verify

**syntax**: *jwks.set_http_ssl_verify(enabled)*

Enable/disable TLS verification used by HTTP client for fetching JWKS.

By default, all TLS certificates are verified. If the JWKS endpoint is using self-signed certificates, either add
the respective root CA to the OS certs store or disable certificates verification with this endpoint (it's unsafe).

```lua
local jwks = require("resty.jwt-verification-jwks")

jwks.set_http_ssl_verify(false)
```

### jwks.fetch_jwks

**syntax**: *payload, err = jwks.fetch_jwks(endpoint)*

Manually fetch JWKS from HTTP endpoint; the returned payload, in case of success, is the HTTP response body as string:
No check is performed whatsoever whether the payload contains JWKS or something else.

If a caching strategy has been enabled, the endpoint will try to fetch it from the cache first. After a cache miss and
successful JWKS retrieval via HTTP, the cache will be updated with the result.

```lua
local jwks = require("resty.jwt-verification-jwks")

payload, err = jwks.fetch_jwks("https://www.googleapis.com/oauth2/v3/certs")
if payload == nil then
    print("failed fetching JWKS: ", err)
    return
end
print(payload) -- '{"keys":[{"alg":"RS256","e":"AQAB","kid":"882503a5fd56e9f734dfba5c50d7bf48db284ae9","kty":"RSA","n":"woRUr445_ODXrFeynz5L208aJkABOKQHEzbfGM_V1ijkYZWZKY0PXKPP_wRKcE4C6OyjDNd5gHh3dF5QsVhVDZCfR9QjTf94o4asngrHzdOcfQ0pZIvzu_vzaVG82VGLM-2rKQp8uz06A6TbUzbIv9wQ8wQpYDIdujNkLqL22Mkb2drPxm9Y9I05PmVdkkvAbu4Q_KRJWxykOigHp-hVBmpYS2P3xuX56gM7ZRcXXJKKUfrGel4nDhSIAAD1wBNcVVgKbb0TYfZmVpRSCji_b6JHjqYhYjUasdotYJzWl7quAFsN_X_4j-cHZ30OS81j--OiIxWpL11y1kcbE0u-Dw","use":"sig"},{"n":"m7GlcF1ExRB4braT7sDnZvlY3wpqX9krkVRqcVA-m43FWFYBtuSpd-lc0EV8R8TO180y0tSgJc7hviI1IBJQlNa7XkjVGhY0ZFUp5rTpC45QbA9Smo4CLa5HQIf-69rkkovjFNMuDQvNiYCgRPLyRjmQbN2uHl4fU3hhf5qFqKTKo7eLCZiEMjrOkTXziA7xJJigUGe-ab8U-AXNH1fnCbejzHEIxL0eUG_4r4xddImOxETDO5T65AQCeqs7vtYos2xq5SLFuaUsithRQ-IMm3OlcVhMjBYt6uvGS6IdMjKon4wThCxEqAEXg0nahiGjnQCW176SNF152__TOjQVwQ","alg":"RS256","kty":"RSA","use":"sig","kid":"8e8fc8e556f7a76d08d35829d6f90ae2e12cfd0d","e":"AQAB"}]}'
```

### jwks.verify_jwt_with_jwks

**syntax**: *jwt, err = jwks.verify_jwt_with_jwks(jwt_token, jwks_endpoint, jwt_options)*

Given a jwt_token as a string, verify its signature with JWKS provided by the HTTP service found at jwks_endpoint.

On success, the decrypted/verified JWT is returned as a lua table, otherwise nil and an error are returned.

The optional parameter `jwt_options` can be passed to configure the token validator when calling [jwt.verify](#jwtverify)
after having successfully fetched the JWKS. See [jwt.verify](#jwtverify) respective docs for more info about which options
can be passed.

> **Note**: As of this document, It's possible to verify any JWS using this method but no JWE: It's in the planned
> features to implement section.

```lua
local jwks = require("resty.jwt-verification-jwks")

jwt, err = jwks.verify_jwt_with_jwks("<MY_JWT>", "http://myservice:8888/.well-known/jwks.json", nil)
if jwt == nil then
    print("failed verifying jwt: ", err)
    return
end
print(jwt.header.alg)
print(tostring(jwt.payload))
```

## RFCs used as reference

- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) JSON Web Signature (JWS)
- [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) JSON Web Encryption (JWE)
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) JSON Web Key (JWK)
- [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) JSON Web Algorithms (JWA)
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) JSON Web Token (JWT)
- [RFC 7520](https://datatracker.ietf.org/doc/html/rfc7520) Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)

## Run tests

### Setup

Install test suit:
```bash
sudo cpan Test::Nginx
```

Install openresty: see https://openresty.org/en/linux-packages.html

### Run

```bash
export PATH=/usr/local/openresty/nginx/sbin:$PATH
prove -r t
```
