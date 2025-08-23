use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        jwt = require("resty.jwt-verification")
        jwt_secret = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIMCxXl/FEuh3pGo1Z++QRs2vudqkGd63mK0Js0f6y+55\n-----END PRIVATE KEY-----"
    }
_EOC_

master_on();
workers(1);

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: decrypt jwt
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local token = ngx.var.http_authorization
            if not token then
                ngx.say("Missing Authorization header")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end

            local space_pos = string.find(token, " ", 0, true)
            if space_pos == nil then
                ngx.say("Invalid auth header format")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
            token = string.sub(token, space_pos + 1)
            if not token then
                ngx.say("Invalid auth header format, token not found")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end

            local decoded_token, err = jwt.decrypt(token, jwt_secret, nil)
            if not decoded_token then
                ngx.say("Invalid token: " .. err)
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJlcGsiOnsieCI6IlZHUWlNX2FGOXNJVDZfQWRGRGt2TTZaT0N5bVpCakZUbjhnRTdDaVhYVUUiLCJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AifX0.4tSt45vbRsxEqP7ToAj6FOs4qM2P6opZYtGuQrgCWo64BDfM-zICDdFUWeGRVfHbBnxUtOMXheOIYbyY6lL5V148zKzZeEyR.z69Ey1WDI-MNoneiA7OrhQ._iMUn7Kc6rrGve7zlzKk5g.RhsRTj_yHJRvE2RjTHeiYh9NGLrlMYYjelXfrJwq8fs
--- response_body
--- error_code: 200
--- no_error_log
[error]
