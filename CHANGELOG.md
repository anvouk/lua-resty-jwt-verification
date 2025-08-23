# JWT verification for openresty

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

- Fix potential concurrency problem with `ngx.time()` being stored as global variable.

## v0.3.1 - 2025/08/16

### Fixes

- Added support for jwt verification with symmetric keys from jwks ([#3](https://github.com/anvouk/lua-resty-jwt-verification/pull/3))

## v0.3.0 - 2025/07/12

Initial stable release
