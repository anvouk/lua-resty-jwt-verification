# JWT verification for openresty

## Supported features

## RFCs used as reference

- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7520](https://datatracker.ietf.org/doc/html/rfc7520)

### JWS Verify

|  Alg  |    Implemented     |
|:-----:|:------------------:|
| HS256 | :white_check_mark: |
| HS384 | :white_check_mark: |
| HS512 | :white_check_mark: |
| RS256 | :white_check_mark: |
| RS384 | :white_check_mark: |
| RS512 | :white_check_mark: |
| ES256 |        :x:         |
| ES384 |        :x:         |
| ES512 |        :x:         |
| PS256 |        :x:         |
| PS384 |        :x:         |
| PS512 |        :x:         |
| none  |        :x:         |

### JWE Decryption

|        Alg         |     Implemented     |
|:------------------:|:-------------------:|
|       RSA1_5       |         :x:         |
|      RSA-OAEP      |         :x:         |
|    RSA-OAEP-256    |         :x:         |
|       A128KW       | :white_check_mark:  |
|       A192KW       | :white_check_mark:  |
|       A256KW       | :white_check_mark:  |
|        dir         |         :x:         |
|      ECDH-ES       |         :x:         |
|     A128GCMKW      |         :x:         |
|     A192GCMKW      |         :x:         |
|     A256GCMKW      |         :x:         |
| PBES2-HS256+A128KW |         :x:         |
| PBES2-HS384+A192KW |         :x:         |
| PBES2-HS512+A256KW |         :x:         |

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
