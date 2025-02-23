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
- [Missing features](#missing-features)
- [Dependencies](#dependencies)
- [JWT Verification Usage](#jwt-verification-usage)
  - [jwt.decode_header_unsafe](#jwtdecode_header_unsafe)
  - [jwt.verify](#jwtverify)
  - [jwt.decrypt](#jwtdecrypt)
- [RFCs used as reference](#rfcs-used-as-reference)
- [Run tests](#run-tests)
  - [Setup](#setup)
  - [Run](#run)

## Description

JWT verification library for OpenResty.

The project's goal is to be a modern and slimmer replacement for [lua-resty-jwt](https://github.com/cdbattags/lua-resty-jwt/).

This project does not provide JWT manipulation or creation features: you can only verify/decrypt tokens.

## Status

Ready for testing: looking for more people to take it for a spin and provide feedback.

## Library non-goals

- JWT creation/modification
- Feature complete for the sake of RFCs completeness.
- Senseless and unsafe RFCs features (e.g. alg none) won't be implemented.

## Differences from lua-resty-jwt

Main differences are:
- No JWT manipulation of any kind (you can only decrypt/verify them)
- Simpler internal structure reliant on more recent [lua-resty-openssl](https://github.com/fffonion/lua-resty-openssl) and OpenSSL versions.
- Supports different JWE algorithms (see tables above).

If any of the points above are a problem, or you need compatibility with older OpenResty version, I
recommend sticking with [lua-resty-jwt](https://github.com/cdbattags/lua-resty-jwt/).

## Supported features

- JWS verification: with symmetric or asymmetric keys.
- JWE decryption: with symmetric or asymmetric keys.
- Asymmetric keys format supported:
  - PEM
  - DER
  - JWK
- JWT claim validation.

### JWS Verification

|  Claims  |    Implemented     |
|:--------:|:------------------:|
|   alg    | :white_check_mark: |
|   jku    |        :x:         |
|   jwk    |        :x:         |
|   kid    |        :x:         |
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
|   kid    |        :x:         |
|   x5u    |        :x:         |
|   x5c    |        :x:         |
|   x5t    |        :x:         |
| x5t#S256 |        :x:         |
|   typ    | :white_check_mark: |
|   cty    |        :x:         |
|   crit   | :white_check_mark: |

|        Alg         |     Implemented     | Requirements |
|:------------------:|:-------------------:|:------------:|
|       RSA1_5       |         :x:         |              |
|      RSA-OAEP      |         :x:         |              |
|    RSA-OAEP-256    |         :x:         |              |
|       A128KW       | :white_check_mark:  | OpenSSL 3.0+ |
|       A192KW       | :white_check_mark:  | OpenSSL 3.0+ |
|       A256KW       | :white_check_mark:  | OpenSSL 3.0+ |
|        dir         | :white_check_mark:  |              |
|      ECDH-ES       |         :x:         |              |
|     A128GCMKW      |         :x:         |              |
|     A192GCMKW      |         :x:         |              |
|     A256GCMKW      |         :x:         |              |
| PBES2-HS256+A128KW |         :x:         |              |
| PBES2-HS384+A192KW |         :x:         |              |
| PBES2-HS512+A256KW |         :x:         |              |

|      Enc      |    Implemented     |
|:-------------:|:------------------:|
| A128CBC-HS256 | :white_check_mark: |
| A192CBC-HS384 | :white_check_mark: |
| A256CBC-HS512 | :white_check_mark: |
|    A128GCM    | :white_check_mark: |
|    A192GCM    | :white_check_mark: |
|    A256GCM    | :white_check_mark: |

## Missing features

- Implement JWE validation with at least 1 asymmetric `alg`.
- Nested JWT (i.e. JWT in JWE).
- JWKS workflow:
    - Key retrieval via HTTP with [lua-resty-http](https://github.com/ledgetech/lua-resty-http).
    - Automatic and configurable keys rotation.
    - Investigate keys caching (?).

## Dependencies

```bash
luarocks install lua-cjson
luarocks install lua-resty-openssl
luarocks install lua-resty-http
```

## JWT Verification Usage

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
