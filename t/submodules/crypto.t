use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: concat kdf ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local crypto = require("resty.jwt-verification.crypto")
            local secret = ngx.decode_base64("vLqJXZkHMg1rnYNWorjByhUHxnHIIeCKj9gNGAOj/1E=")
            local bits = 128
            local value = {0,0,0,7,65,49,50,56,71,67,77,0,0,0,0,0,0,0,0,0,0,0,128}
            for i, _ in ipairs(value) do
                value[i] = string.char(value[i])
            end
            local res, err = crypto.concat_kdf(secret, bits, table.concat(value))
            if not res then
                ngx.say(err)
                return
            end
            ngx.say(ngx.encode_base64(res))
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
IHV4VaZF8ghpVHLEJ5o0Dg==
nil
--- error_code: 200
--- no_error_log
[error]
