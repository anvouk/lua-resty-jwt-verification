# JWT verification for openresty

## RFCs used as reference

- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) JSON Web Signature (JWS)
- [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) JSON Web Encryption (JWE)
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) JSON Web Key (JWK)
- [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) JSON Web Algorithms (JWA)
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) JSON Web Token (JWT)
- [RFC 7520](https://datatracker.ietf.org/doc/html/rfc7520) Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)

## Supported features

### JWS Verify

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

|      Enc      |     Implemented     |
|:-------------:|:-------------------:|
| A128CBC-HS256 | :white_check_mark:  |
| A192CBC-HS384 | :white_check_mark:  |
| A256CBC-HS512 | :white_check_mark:  |
|    A128GCM    |         :x:         |
|    A192GCM    |         :x:         |
|    A256GCM    |         :x:         |

## Library non-goals

- JWT creation/modification
- Feature complete for the sake of RFCs completeness

## Install dependencies

```bash
luarocks install lua-cjson
luarocks install lua-resty-openssl
luarocks install lua-resty-http
```

Dev deps:
```bash
luarocks install base64
```

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
