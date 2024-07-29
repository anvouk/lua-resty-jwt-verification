# JWT verification for openresty

JWT verification library for OpenResty.

The project's goal is to be a modern and slimmer replacement of the venerable [lua-resty-jwt](https://github.com/cdbattags/lua-resty-jwt/).

This project does not provide JWT manipulation or creation features: you can only verify/decrypt tokens.

## Status

Ready for testing: looking for more people to take it for a spin and provide feedback.

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
|   crit   |        :x:         |

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
|   crit   |        :x:         |

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

## Library non-goals

- JWT creation/modification
- Feature complete for the sake of RFCs completeness
- Senseless and unsafe RFCs features (e.g. alg none) won't be implemented.

## Dependencies

```bash
luarocks install lua-cjson
luarocks install lua-resty-openssl
luarocks install lua-resty-http
```

## Differences from lua-resty-jwt

Main differences are:
- No JWT manipulation of any kind (you can only decrypt/verify them)
- Simpler internal structure reliant on more recent [lua-resty-openssl](https://github.com/fffonion/lua-resty-openssl) and OpenSSL versions.
- Supports different JWE algorithms (see tables above).

If any of the points above are a problem, or you need compatibility with older OpenResty version, I
recommend sticking with [lua-resty-jwt](https://github.com/cdbattags/lua-resty-jwt/).

## Missing features

- Nested JWT (i.e. JWT in JWE).
- JWKS workflow:
    - Key retrieval via HTTP with [lua-resty-http](https://github.com/ledgetech/lua-resty-http).
    - Automatic and configurable keys rotation.
    - Investigate keys caching (?).

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
prove t
```
