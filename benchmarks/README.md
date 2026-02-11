# Benchmarks Results

## Table of Contents

- [Test environment](#test-environment)
- [OpenResty configuration](#openresty-configuration)
- [Benchmarks methodology](#benchmarks-methodology)
  - [Baseline](#baseline)
  - [HS256](#hs256)
  - [RS256](#rs256)
  - [PS256](#ps256)
  - [ES256](#es256)
  - [ES256K](#es256k)
  - [Ed25519](#ed25519)
  - [Ed448](#ed448)
- [Results](#results)

## Test environment

Personal Linux workstation setup:

```
Dell Precision Tower 5810
Linux 6.12.57+deb13-amd64
Debian GNU/Linux 13.2 (trixie)
CPU Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz
RAM 80GB DDR4 ECC @ 2100MHz
SSD 1 TB
```

## OpenResty configuration

```bash
$ openresty -V
nginx version: openresty/1.27.1.2
built by gcc 14.2.0 (Debian 14.2.0-19)
built with OpenSSL 3.5.1 1 Jul 2025 (running with OpenSSL 3.5.4 30 Sep 2025)
TLS SNI support enabled
configure arguments: --prefix=/opt/openresty-1.27.1.2/nginx --with-cc-opt=-O2 --add-module=../ngx_devel_kit-0.3.3 --add-module=../echo-nginx-module-0.63 --add-module=../xss-nginx-module-0.06 --add-module=../ngx_coolkit-0.2 --add-module=../set-misc-nginx-module-0.33 --add-module=../form-input-nginx-module-0.12 --add-module=../encrypted-session-nginx-module-0.09 --add-module=../srcache-nginx-module-0.33 --add-module=../ngx_lua-0.10.28 --add-module=../ngx_lua_upstream-0.07 --add-module=../headers-more-nginx-module-0.37 --add-module=../array-var-nginx-module-0.06 --add-module=../memc-nginx-module-0.20 --add-module=../redis2-nginx-module-0.15 --add-module=../redis-nginx-module-0.3.9 --add-module=../rds-json-nginx-module-0.17 --add-module=../rds-csv-nginx-module-0.09 --add-module=../ngx_stream_lua-0.0.16 --with-ld-opt=-Wl,-rpath,/opt/openresty-1.27.1.2/luajit/lib --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module --with-http_ssl_module
```

```bash
lua-resty-jwt-verification
   0.7.0-1 (installed)
lua-resty-openssl
   1.7.0-1 (installed)
lua-resty-http
   0.17.2-0 (installed)
```

## Benchmarks methodology

- Benchmarks files are executed individually and twice in a row: the results saved
are those from the second run only.
- All benchmarks are executed using the following flag `export TEST_NGINX_BENCHMARK='100000 40'`
- All benchmarks are executed against a single Nginx worker.
- Background programs and user interactions have been reduced to the minimum while the benchmarks
are running.

> **Important**: Despite my best efforts, the benchmarks are still running on my
> personal pc and as such some noise is expected. Also, I'm not flushing caches
> between each round, etc. To sum it up, take the results with a grain of salt.

### Baseline

No token verification

```bash
$ prove benchmarks/baseline-empty-200.t
benchmarks/baseline-empty-200.t .. benchmarks/baseline-empty-200.t TEST 1: baseline ok
weighttp -c40 -k -n100000 -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0' http://127.0.0.1:1984/t

weighttp 0.5 - lightweight and simple webserver benchmarking tool

spawning thread #1: 40 concurrent requests, 100000 total requests
starting benchmark...
progress:  10% done
progress:  20% done
progress:  30% done
progress:  40% done
progress:  50% done
progress:  60% done
progress:  70% done
progress:  80% done
progress:  90% done
progress: 100% done
{
  "reqs_per_sec": 102685,
  "kBps_per_sec": 16745,
  "secs_elapsed": 0.973851,
  "request_counts": {
    "started":    100000,
    "retired":    100000,
    "keep-alive": 99880
  },
  "response_counts": {
    "pass": 100000,
    "fail": 0,
    "errs": 0
  },
  "status_codes": {
    "2xx":  100000,
    "3xx":  0,
    "4xx":  0,
    "5xx":  0
  },
  "traffic": {
    "bytes_total":       16699600,
    "bytes_headers":     16399600,
    "bytes_body":          300000
  },
  "connect_times": {
     "num":       120,
     "avg":       365,
     "stddev":    305,
     "unit": "us",
      "0%":        26,
     "50%":       250,
     "66%":       452,
     "75%":       561,
     "80%":       645,
     "90%":       859,
     "95%":       967,
     "98%":      1016,
     "99%":      1032,
    "100%":      1110
  },
  "time_to_first_byte": {
     "num":    100000,
     "avg":       383,
     "stddev":     87,
     "unit": "us",
      "0%":       125,
     "50%":       342,
     "66%":       408,
     "75%":       463,
     "80%":       467,
     "90%":       486,
     "95%":       511,
     "98%":       568,
     "99%":       584,
    "100%":      4547
  },
  "response_times": {
     "num":    100000,
     "avg":       383,
     "stddev":     87,
     "unit": "us",
      "0%":       125,
     "50%":       342,
     "66%":       408,
     "75%":       463,
     "80%":       467,
     "90%":       486,
     "95%":       511,
     "98%":       568,
     "99%":       584,
    "100%":      4547
  },
  "total_times": {
     "num":    100000,
     "avg":       384,
     "stddev":     91,
     "unit": "us",
      "0%":       125,
     "50%":       342,
     "66%":       408,
     "75%":       463,
     "80%":       467,
     "90%":       486,
     "95%":       511,
     "98%":       569,
     "99%":       584,
    "100%":      4581
  }
}
benchmarks/baseline-empty-200.t .. ok
All tests successful.
Files=1, Tests=3,  1 wallclock secs ( 0.02 usr  0.00 sys +  0.30 cusr  0.90 csys =  1.22 CPU)
Result: PASS
```

### HS256

```bash
$ prove benchmarks/verify-jws-HS256.t
benchmarks/verify-jws-HS256.t .. benchmarks/verify-jws-HS256.t TEST 1: verify jwt
weighttp -c40 -k -n100000 -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0' http://127.0.0.1:1984/t

weighttp 0.5 - lightweight and simple webserver benchmarking tool

spawning thread #1: 40 concurrent requests, 100000 total requests
starting benchmark...
progress:  10% done
progress:  20% done
progress:  30% done
progress:  40% done
progress:  50% done
progress:  60% done
progress:  70% done
progress:  80% done
progress:  90% done
progress: 100% done
{
  "reqs_per_sec": 37100,
  "kBps_per_sec": 6050,
  "secs_elapsed": 2.695351,
  "request_counts": {
    "started":    100000,
    "retired":    100000,
    "keep-alive": 99880
  },
  "response_counts": {
    "pass": 100000,
    "fail": 0,
    "errs": 0
  },
  "status_codes": {
    "2xx":  100000,
    "3xx":  0,
    "4xx":  0,
    "5xx":  0
  },
  "traffic": {
    "bytes_total":       16699600,
    "bytes_headers":     16399600,
    "bytes_body":          300000
  },
  "connect_times": {
     "num":       120,
     "avg":       290,
     "stddev":    339,
     "unit": "us",
      "0%":        26,
     "50%":        93,
     "66%":       229,
     "75%":       534,
     "80%":       642,
     "90%":       872,
     "95%":       987,
     "98%":      1038,
     "99%":      1055,
    "100%":      1138
  },
  "time_to_first_byte": {
     "num":    100000,
     "avg":      1071,
     "stddev":    254,
     "unit": "us",
      "0%":       123,
     "50%":      1029,
     "66%":      1085,
     "75%":      1123,
     "80%":      1151,
     "90%":      1215,
     "95%":      1295,
     "98%":      1417,
     "99%":      1488,
    "100%":     21843
  },
  "response_times": {
     "num":    100000,
     "avg":      1071,
     "stddev":    254,
     "unit": "us",
      "0%":       123,
     "50%":      1029,
     "66%":      1085,
     "75%":      1123,
     "80%":      1151,
     "90%":      1215,
     "95%":      1295,
     "98%":      1417,
     "99%":      1488,
    "100%":     21843
  },
  "total_times": {
     "num":    100000,
     "avg":      1071,
     "stddev":    257,
     "unit": "us",
      "0%":       123,
     "50%":      1029,
     "66%":      1086,
     "75%":      1123,
     "80%":      1151,
     "90%":      1215,
     "95%":      1295,
     "98%":      1417,
     "99%":      1489,
    "100%":     21960
  }
}
benchmarks/verify-jws-HS256.t .. ok
All tests successful.
Files=1, Tests=3,  3 wallclock secs ( 0.02 usr  0.00 sys +  0.38 cusr  1.81 csys =  2.21 CPU)
Result: PASS
```

### RS256

```bash
$ prove benchmarks/verify-jws-RS256.t
benchmarks/verify-jws-RS256.t .. benchmarks/verify-jws-RS256.t TEST 1: verify jwt
weighttp -c40 -k -n100000 -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImUwNTAzOWIyNmI4OTg0MzYifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA3OTJ9.oGbafXuLqd5ZgNgY0is57qhKkEyQq0uXqnR73yBfI0qFFyK7UGBUFsYNN-MOp3wSDWKxTj579Fr0LUce-UiTV26LkRM4DFUzLJm2XzYh4aYqrOu7-tBj7DnKGAKYruLPFDAazp5up-kvBg31ZRyZIPvOlsDWq_Ob5K9Tg_EgTnrmFX0zcW-b4yTwjDYtJkXurEdJwZNcrKKQ7CW6ua8z1U0q7DIoVN56Dp4XO6K9Igviw6Ap4cB345kVz2cNzvLkgF8fcDfd9T3gSxLabH7yS5Xa1oqMiYOuz0TGvAvkfZEJPFbKVvNqmV2rGcoaLKv3q-_v5XQo07aFUcFN1jYd3Q' http://127.0.0.1:1984/t

weighttp 0.5 - lightweight and simple webserver benchmarking tool

spawning thread #1: 40 concurrent requests, 100000 total requests
starting benchmark...
progress:  10% done
progress:  20% done
progress:  30% done
progress:  40% done
progress:  50% done
progress:  60% done
progress:  70% done
progress:  80% done
progress:  90% done
progress: 100% done
{
  "reqs_per_sec": 9890,
  "kBps_per_sec": 1612,
  "secs_elapsed": 10.110552,
  "request_counts": {
    "started":    100000,
    "retired":    100000,
    "keep-alive": 99880
  },
  "response_counts": {
    "pass": 100000,
    "fail": 0,
    "errs": 0
  },
  "status_codes": {
    "2xx":  100000,
    "3xx":  0,
    "4xx":  0,
    "5xx":  0
  },
  "traffic": {
    "bytes_total":       16699600,
    "bytes_headers":     16399600,
    "bytes_body":          300000
  },
  "connect_times": {
     "num":       120,
     "avg":       336,
     "stddev":    441,
     "unit": "us",
      "0%":        52,
     "50%":        69,
     "66%":        90,
     "75%":       556,
     "80%":       670,
     "90%":      1103,
     "95%":      1330,
     "98%":      1440,
     "99%":      1477,
    "100%":      1626
  },
  "time_to_first_byte": {
     "num":    100000,
     "avg":      4030,
     "stddev":    866,
     "unit": "us",
      "0%":       484,
     "50%":      3859,
     "66%":      4033,
     "75%":      4212,
     "80%":      4312,
     "90%":      4504,
     "95%":      4619,
     "98%":      5587,
     "99%":      5963,
    "100%":     78088
  },
  "response_times": {
     "num":    100000,
     "avg":      4030,
     "stddev":    866,
     "unit": "us",
      "0%":       484,
     "50%":      3860,
     "66%":      4033,
     "75%":      4212,
     "80%":      4312,
     "90%":      4504,
     "95%":      4619,
     "98%":      5588,
     "99%":      5963,
    "100%":     78089
  },
  "total_times": {
     "num":    100000,
     "avg":      4030,
     "stddev":    869,
     "unit": "us",
      "0%":       484,
     "50%":      3860,
     "66%":      4033,
     "75%":      4212,
     "80%":      4312,
     "90%":      4504,
     "95%":      4619,
     "98%":      5588,
     "99%":      5966,
    "100%":     78163
  }
}
benchmarks/verify-jws-RS256.t .. ok
All tests successful.
Files=1, Tests=3, 10 wallclock secs ( 0.02 usr  0.00 sys +  0.53 cusr  3.98 csys =  4.53 CPU)
Result: PASS
```

### PS256

```bash
$ prove benchmarks/verify-jws-PS256.t
benchmarks/verify-jws-PS256.t .. benchmarks/verify-jws-PS256.t TEST 1: verify jwt
weighttp -c40 -k -n100000 -H 'Authorization: Bearer eyJhbGciOiJQUzI1NiIsImtpZCI6IjRkNTdiZjQ2Njk2NWUxN2MifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA4OTR9.Q2Ecg6tSieL3KGjp3SdR-891gFqa8AzEtEC5pYbZm1jqpFXOq-BbyB1fGDhb-dUH4B2Za6zvk3XQw01vPB47bhkcVwQ0qBQ02KjjNVsAm2ck0ZQRqNBe_4HOhc0eAEa9gV4cYIE4xqgneNhxX_BF7HcoGHrfyauQcJI6CuzE5rDDi_9i8v8X1hGkNI1mF68BJu9tk3wpJ5RDBNi77NLLRcLlf25AVfxS7ShQk07af4LVtZWpIAf-rii7XEROfcRB2Fwxl_u_JEX-b-Gz-F__O6sE4OZ7UekCQkM921MwZNPGPzcXZ_ZPvh44ioIfW0i34CHSzIl9P3XGb6dkA41FKw' http://127.0.0.1:1984/t

weighttp 0.5 - lightweight and simple webserver benchmarking tool

spawning thread #1: 40 concurrent requests, 100000 total requests
starting benchmark...
progress:  10% done
progress:  20% done
progress:  30% done
progress:  40% done
progress:  50% done
progress:  60% done
progress:  70% done
progress:  80% done
progress:  90% done
progress: 100% done
{
  "reqs_per_sec": 5279,
  "kBps_per_sec": 860,
  "secs_elapsed": 18.942017,
  "request_counts": {
    "started":    100000,
    "retired":    100000,
    "keep-alive": 99880
  },
  "response_counts": {
    "pass": 100000,
    "fail": 0,
    "errs": 0
  },
  "status_codes": {
    "2xx":  100000,
    "3xx":  0,
    "4xx":  0,
    "5xx":  0
  },
  "traffic": {
    "bytes_total":       16699600,
    "bytes_headers":     16399600,
    "bytes_body":          300000
  },
  "connect_times": {
     "num":       120,
     "avg":       338,
     "stddev":    445,
     "unit": "us",
      "0%":        56,
     "50%":        64,
     "66%":        79,
     "75%":       568,
     "80%":       681,
     "90%":      1088,
     "95%":      1348,
     "98%":      1461,
     "99%":      1500,
    "100%":      1652
  },
  "time_to_first_byte": {
     "num":    100000,
     "avg":      7561,
     "stddev":   1510,
     "unit": "us",
      "0%":       761,
     "50%":      7376,
     "66%":      7581,
     "75%":      7771,
     "80%":      7882,
     "90%":      8112,
     "95%":      8257,
     "98%":      8485,
     "99%":     11123,
    "100%":    144852
  },
  "response_times": {
     "num":    100000,
     "avg":      7561,
     "stddev":   1510,
     "unit": "us",
      "0%":       762,
     "50%":      7376,
     "66%":      7581,
     "75%":      7771,
     "80%":      7882,
     "90%":      8112,
     "95%":      8257,
     "98%":      8485,
     "99%":     11123,
    "100%":    144852
  },
  "total_times": {
     "num":    100000,
     "avg":      7562,
     "stddev":   1512,
     "unit": "us",
      "0%":       762,
     "50%":      7376,
     "66%":      7581,
     "75%":      7771,
     "80%":      7882,
     "90%":      8112,
     "95%":      8257,
     "98%":      8485,
     "99%":     11126,
    "100%":    144931
  }
}
benchmarks/verify-jws-PS256.t .. ok
All tests successful.
Files=1, Tests=3, 20 wallclock secs ( 0.02 usr  0.00 sys +  0.58 cusr  4.00 csys =  4.60 CPU)
Result: PASS
```

### ES256

```bash
$ prove benchmarks/verify-jws-ES256.t
benchmarks/verify-jws-ES256.t .. benchmarks/verify-jws-ES256.t TEST 1: verify jwt
weighttp -c40 -k -n100000 -H 'Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImI4ZjNjOGE2NzI1NDRkZmIifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA4NDh9.PjDoKi9o_GOAOFcqBrZl0p1dn1deu4Gzd-yhZiLITx2zaHCGr7JKSTsQTRetvU10CnE1klstwEyM_5r782pJ0Q' http://127.0.0.1:1984/t

weighttp 0.5 - lightweight and simple webserver benchmarking tool

spawning thread #1: 40 concurrent requests, 100000 total requests
starting benchmark...
progress:  10% done
progress:  20% done
progress:  30% done
progress:  40% done
progress:  50% done
progress:  60% done
progress:  70% done
progress:  80% done
progress:  90% done
progress: 100% done
{
  "reqs_per_sec": 3575,
  "kBps_per_sec": 583,
  "secs_elapsed": 27.967812,
  "request_counts": {
    "started":    100000,
    "retired":    100000,
    "keep-alive": 99880
  },
  "response_counts": {
    "pass": 100000,
    "fail": 0,
    "errs": 0
  },
  "status_codes": {
    "2xx":  100000,
    "3xx":  0,
    "4xx":  0,
    "5xx":  0
  },
  "traffic": {
    "bytes_total":       16699600,
    "bytes_headers":     16399600,
    "bytes_body":          300000
  },
  "connect_times": {
     "num":       120,
     "avg":       297,
     "stddev":    351,
     "unit": "us",
      "0%":        55,
     "50%":        73,
     "66%":        88,
     "75%":       552,
     "80%":       667,
     "90%":       904,
     "95%":      1020,
     "98%":      1072,
     "99%":      1090,
    "100%":      1175
  },
  "time_to_first_byte": {
     "num":    100000,
     "avg":     11170,
     "stddev":   2095,
     "unit": "us",
      "0%":       934,
     "50%":     10965,
     "66%":     11259,
     "75%":     11527,
     "80%":     11688,
     "90%":     11979,
     "95%":     12142,
     "98%":     12334,
     "99%":     12514,
    "100%":    211716
  },
  "response_times": {
     "num":    100000,
     "avg":     11170,
     "stddev":   2095,
     "unit": "us",
      "0%":       934,
     "50%":     10965,
     "66%":     11259,
     "75%":     11527,
     "80%":     11688,
     "90%":     11979,
     "95%":     12142,
     "98%":     12334,
     "99%":     12514,
    "100%":    211716
  },
  "total_times": {
     "num":    100000,
     "avg":     11171,
     "stddev":   2096,
     "unit": "us",
      "0%":       934,
     "50%":     10965,
     "66%":     11259,
     "75%":     11527,
     "80%":     11688,
     "90%":     11979,
     "95%":     12142,
     "98%":     12334,
     "99%":     12515,
    "100%":    211793
  }
}
benchmarks/verify-jws-ES256.t .. ok
All tests successful.
Files=1, Tests=3, 28 wallclock secs ( 0.02 usr  0.00 sys +  0.68 cusr  4.23 csys =  4.93 CPU)
Result: PASS
```

### ES256K

```bash
$ prove benchmarks/verify-jws-ES256K.t
benchmarks/verify-jws-ES256K.t .. benchmarks/verify-jws-ES256K.t TEST 1: verify jwt
weighttp -c40 -k -n100000 -H 'Authorization: Bearer eyJhbGciOiJFUzI1NksiLCJraWQiOiI0ZDc3ZTllZDc4ZDYzYmM1In0.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA0MTV9.AcS-Ua4hjCqZOAvQdzLRM38uBR9pKTLy4KcuYEqc2PsBbZpynaHkXYjRW6jlemTDw5oGOEZs87L08CJBo0Dxsg' http://127.0.0.1:1984/t

weighttp 0.5 - lightweight and simple webserver benchmarking tool

spawning thread #1: 40 concurrent requests, 100000 total requests
starting benchmark...
progress:  10% done
progress:  20% done
progress:  30% done
progress:  40% done
progress:  50% done
progress:  60% done
progress:  70% done
progress:  80% done
progress:  90% done
progress: 100% done
{
  "reqs_per_sec": 1399,
  "kBps_per_sec": 228,
  "secs_elapsed": 71.460361,
  "request_counts": {
    "started":    100000,
    "retired":    100000,
    "keep-alive": 99880
  },
  "response_counts": {
    "pass": 100000,
    "fail": 0,
    "errs": 0
  },
  "status_codes": {
    "2xx":  100000,
    "3xx":  0,
    "4xx":  0,
    "5xx":  0
  },
  "traffic": {
    "bytes_total":       16699600,
    "bytes_headers":     16399600,
    "bytes_body":          300000
  },
  "connect_times": {
     "num":       120,
     "avg":       363,
     "stddev":    425,
     "unit": "us",
      "0%":        61,
     "50%":        90,
     "66%":       126,
     "75%":       677,
     "80%":       820,
     "90%":      1090,
     "95%":      1228,
     "98%":      1298,
     "99%":      1320,
    "100%":      1426
  },
  "time_to_first_byte": {
     "num":    100000,
     "avg":     28545,
     "stddev":   5179,
     "unit": "us",
      "0%":      2276,
     "50%":     28354,
     "66%":     28628,
     "75%":     28847,
     "80%":     28981,
     "90%":     29271,
     "95%":     29485,
     "98%":     29776,
     "99%":     30404,
    "100%":    534218
  },
  "response_times": {
     "num":    100000,
     "avg":     28545,
     "stddev":   5179,
     "unit": "us",
      "0%":      2277,
     "50%":     28354,
     "66%":     28629,
     "75%":     28847,
     "80%":     28981,
     "90%":     29272,
     "95%":     29485,
     "98%":     29776,
     "99%":     30405,
    "100%":    534218
  },
  "total_times": {
     "num":    100000,
     "avg":     28545,
     "stddev":   5181,
     "unit": "us",
      "0%":      2277,
     "50%":     28354,
     "66%":     28629,
     "75%":     28847,
     "80%":     28981,
     "90%":     29272,
     "95%":     29485,
     "98%":     29776,
     "99%":     30406,
    "100%":    534322
  }
}
benchmarks/verify-jws-ES256K.t .. ok
All tests successful.
Files=1, Tests=3, 72 wallclock secs ( 0.02 usr  0.00 sys +  1.06 cusr  8.09 csys =  9.17 CPU)
Result: PASS
```

### Ed25519

```bash
$ prove benchmarks/verify-jws-Ed25519.t
benchmarks/verify-jws-Ed25519.t .. benchmarks/verify-jws-Ed25519.t TEST 1: verify jwt
weighttp -c40 -k -n100000 -H 'Authorization: Bearer eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiMmYwMTk5Yjg1NzJlZGMxMiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA1Mzd9.FGVv1EB8wWf7fT1m6VBkCfq5pxpWgm0fRU56rAJCnlw-B7xUbHtNNFn4Vl5uW15F8k5Hs9wjG4li6_LqvUsWBA' http://127.0.0.1:1984/t

weighttp 0.5 - lightweight and simple webserver benchmarking tool

spawning thread #1: 40 concurrent requests, 100000 total requests
starting benchmark...
progress:  10% done
progress:  20% done
progress:  30% done
progress:  40% done
progress:  50% done
progress:  60% done
progress:  70% done
progress:  80% done
progress:  90% done
progress: 100% done
{
  "reqs_per_sec": 3768,
  "kBps_per_sec": 614,
  "secs_elapsed": 26.532714,
  "request_counts": {
    "started":    100000,
    "retired":    100000,
    "keep-alive": 99880
  },
  "response_counts": {
    "pass": 100000,
    "fail": 0,
    "errs": 0
  },
  "status_codes": {
    "2xx":  100000,
    "3xx":  0,
    "4xx":  0,
    "5xx":  0
  },
  "traffic": {
    "bytes_total":       16699600,
    "bytes_headers":     16399600,
    "bytes_body":          300000
  },
  "connect_times": {
     "num":       120,
     "avg":       353,
     "stddev":    473,
     "unit": "us",
      "0%":        55,
     "50%":        66,
     "66%":        88,
     "75%":       542,
     "80%":       660,
     "90%":      1190,
     "95%":      1430,
     "98%":      1542,
     "99%":      1578,
    "100%":      1723
  },
  "time_to_first_byte": {
     "num":    100000,
     "avg":     10596,
     "stddev":   1973,
     "unit": "us",
      "0%":      1076,
     "50%":     10489,
     "66%":     10665,
     "75%":     10799,
     "80%":     10872,
     "90%":     11046,
     "95%":     11184,
     "98%":     11365,
     "99%":     11652,
    "100%":    200796
  },
  "response_times": {
     "num":    100000,
     "avg":     10597,
     "stddev":   1973,
     "unit": "us",
      "0%":      1076,
     "50%":     10489,
     "66%":     10665,
     "75%":     10799,
     "80%":     10872,
     "90%":     11046,
     "95%":     11185,
     "98%":     11365,
     "99%":     11652,
    "100%":    200796
  },
  "total_times": {
     "num":    100000,
     "avg":     10597,
     "stddev":   1975,
     "unit": "us",
      "0%":      1076,
     "50%":     10489,
     "66%":     10665,
     "75%":     10799,
     "80%":     10872,
     "90%":     11046,
     "95%":     11185,
     "98%":     11365,
     "99%":     11653,
    "100%":    200873
  }
}
benchmarks/verify-jws-Ed25519.t .. ok
All tests successful.
Files=1, Tests=3, 27 wallclock secs ( 0.02 usr  0.00 sys +  0.66 cusr  4.00 csys =  4.68 CPU)
Result: PASS
```

### Ed448

```bash
$ prove benchmarks/verify-jws-Ed448.t
benchmarks/verify-jws-Ed448.t .. benchmarks/verify-jws-Ed448.t TEST 1: verify jwt
weighttp -c40 -k -n100000 -H 'Authorization: Bearer eyJhbGciOiJFZDQ0OCIsImtpZCI6IjM5MjdjMDhlOWNjMTU0YzQifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA2MDB9.I80MRs0RdWjI1ovLLzrTpNndtmuhCN1tziapg_rJV9ugCRTqJCnz86xDcJbgn-DsO28VHPyhZIEAIk7o5Ck-xtMq5zP8T_OlfF4Ets46q8avxKMxEDMHsNtuh3osBj2Kq-nR5yrQ6matm4tJThx-iSkA' http://127.0.0.1:1984/t

weighttp 0.5 - lightweight and simple webserver benchmarking tool

spawning thread #1: 40 concurrent requests, 100000 total requests
starting benchmark...
progress:  10% done
progress:  20% done
progress:  30% done
progress:  40% done
progress:  50% done
progress:  60% done
progress:  70% done
progress:  80% done
progress:  90% done
progress: 100% done
{
  "reqs_per_sec": 2488,
  "kBps_per_sec": 405,
  "secs_elapsed": 40.192383,
  "request_counts": {
    "started":    100000,
    "retired":    100000,
    "keep-alive": 99880
  },
  "response_counts": {
    "pass": 100000,
    "fail": 0,
    "errs": 0
  },
  "status_codes": {
    "2xx":  100000,
    "3xx":  0,
    "4xx":  0,
    "5xx":  0
  },
  "traffic": {
    "bytes_total":       16699600,
    "bytes_headers":     16399600,
    "bytes_body":          300000
  },
  "connect_times": {
     "num":       120,
     "avg":       299,
     "stddev":    348,
     "unit": "us",
      "0%":        56,
     "50%":        87,
     "66%":        92,
     "75%":       544,
     "80%":       654,
     "90%":       878,
     "95%":       989,
     "98%":      1105,
     "99%":      1144,
    "100%":      1290
  },
  "time_to_first_byte": {
     "num":    100000,
     "avg":     16048,
     "stddev":   2946,
     "unit": "us",
      "0%":      1405,
     "50%":     15951,
     "66%":     16130,
     "75%":     16265,
     "80%":     16351,
     "90%":     16559,
     "95%":     16720,
     "98%":     16962,
     "99%":     17274,
    "100%":    304593
  },
  "response_times": {
     "num":    100000,
     "avg":     16048,
     "stddev":   2946,
     "unit": "us",
      "0%":      1405,
     "50%":     15951,
     "66%":     16130,
     "75%":     16266,
     "80%":     16351,
     "90%":     16559,
     "95%":     16720,
     "98%":     16962,
     "99%":     17274,
    "100%":    304593
  },
  "total_times": {
     "num":    100000,
     "avg":     16048,
     "stddev":   2947,
     "unit": "us",
      "0%":      1405,
     "50%":     15951,
     "66%":     16130,
     "75%":     16266,
     "80%":     16351,
     "90%":     16559,
     "95%":     16720,
     "98%":     16962,
     "99%":     17274,
    "100%":    304682
  }
}
benchmarks/verify-jws-Ed448.t .. ok
All tests successful.
Files=1, Tests=3, 40 wallclock secs ( 0.02 usr  0.01 sys +  0.90 cusr  6.50 csys =  7.43 CPU)
Result: PASS
```

## Results

|     Alg    | reqs_per_sec | total_times 50% (us) | total_times 99% (us) |                        System load                        |
|:----------:|:------------:|:--------------------:|:--------------------:|:---------------------------------------------------------:|
| (Baseline) |    102685    |          342         |          584         | ( 0.02 usr  0.00 sys +  0.30 cusr  0.90 csys =  1.22 CPU) |
|    HS256   |     37100    |         1029         |         1489         | ( 0.02 usr  0.00 sys +  0.38 cusr  1.81 csys =  2.21 CPU) |
|    RS256   |     9890     |         3860         |         5966         | ( 0.02 usr  0.00 sys +  0.53 cusr  3.98 csys =  4.53 CPU) |
|    PS256   |     5279     |         7376         |         11126        | ( 0.02 usr  0.00 sys +  0.58 cusr  4.00 csys =  4.60 CPU) |
|    ES256   |     3575     |         10965        |         12515        | ( 0.02 usr  0.00 sys +  0.68 cusr  4.23 csys =  4.93 CPU) |
|   ES256K   |     1399     |         28354        |         30406        | ( 0.02 usr  0.00 sys +  1.06 cusr  8.09 csys =  9.17 CPU) |
|   Ed25519  |     3768     |         10489        |         11653        | ( 0.02 usr  0.00 sys +  0.66 cusr  4.00 csys =  4.68 CPU) |
|    Ed448   |     2488     |         15951        |         17274        | ( 0.02 usr  0.01 sys +  0.90 cusr  6.50 csys =  7.43 CPU) |
