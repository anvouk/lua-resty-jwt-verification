# JWT verification for openresty

## v0.7.0 - 2025/10/25

### New features

### Improvements

- Security hardening.
- Added CI tests against multiple openresty versions.

### Fixes

## v0.6.0 - 2025/09/25

### New features

- Added support for nested jwts (jws-in-jwe).

### Improvements

- Minor security hardening for RSA-OAEP verification.
- Improved `audiences` option error message for validation.

### Fixes

## v0.5.0 - 2025/09/02

### New features

- Added support for `ES256K` jws alg
- Added support for `RSA-OAEP` jwe alg
- Added support for `RSA-OAEP-256` jwe alg
- Added support for `RSA-OAEP-384` jwe alg
- Added support for `RSA-OAEP-512` jwe alg
- Added new method `jwks.decrypt_jwt_with_jwks` for JWE decryption with JWKS

### Improvements

- Minor performance optimizations and cleanups
- Pinned `lua-resty-openssl>=1.6.2` since earlier versions do not support loading JWK keys for the `secp256k1` curve

### Fixes

- Fixed conversion to big-endian for large numbers.

## v0.4.0 - 2025/08/25

### New features

- Added support for `Ed25519` jws alg
- Added support for `Ed448` jws alg
- Added support for `ECDH-ES` jwe alg
- Added support for `ECDH-ES+A128KW` jwe alg
- Added support for `ECDH-ES+A192KW` jwe alg
- Added support for `ECDH-ES+A256KW` jwe alg
- Added support for loading jwk of `kty=OKP`

### Improvements

- Minor cleanups to internal project structure
- Minor performance optimizations
- Minor cleanups to internal tests structure
- Added internal benchmarking suite for future optimizations

### Fixes

- Fixed potential concurrency problem with `ngx.time()` being stored as global variable.

## v0.3.1 - 2025/08/16

### Fixes

- Added support for jwt verification with symmetric keys from jwks ([#3](https://github.com/anvouk/lua-resty-jwt-verification/pull/3))

## v0.3.0 - 2025/07/12

Initial stable release
