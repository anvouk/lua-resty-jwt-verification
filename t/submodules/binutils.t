use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: big-endian conversions ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local binutils = require("resty.jwt-verification.binutils")
            local value = 2
            ngx.say(ngx.encode_base64(binutils.uint64be(value)))
            ngx.say(ngx.encode_base64(binutils.uint32be(value)))
        }
    }
--- request
    GET /t
--- response_body
AAAAAAAAABA=
AAAAAg==
--- error_code: 200
--- no_error_log
[error]
