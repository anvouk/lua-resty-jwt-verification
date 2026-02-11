use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        jwt = require("resty.jwt-verification")
    }
_EOC_

master_on();
workers(1);

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: verify jwt
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local token = ngx.var.http_authorization
            if not token then
                ngx.log(ngx.STDERR, "Missing Authorization header")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end

            local space_pos = string.find(token, " ", 0, true)
            if space_pos == nil then
                ngx.log(ngx.STDERR, "Invalid auth header format")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
            token = string.sub(token, space_pos + 1)

            local decoded_token, err = jwt.verify(token, '{"crv":"Ed448","x":"iku3DswbSsHFG73V1e_m9fFclJFSeyg_qTLthPFRzTaYvPpOE74qyo2grL3U8ySSU2L9o5Il1FiA","kty":"OKP","kid":"3927c08e9cc154c4"}')
            if not decoded_token then
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJFZDQ0OCIsImtpZCI6IjM5MjdjMDhlOWNjMTU0YzQifQ.eyJmb28iOiJiYXIiLCJpYXQiOjE3NzA4NDA2MDB9.I80MRs0RdWjI1ovLLzrTpNndtmuhCN1tziapg_rJV9ugCRTqJCnz86xDcJbgn-DsO28VHPyhZIEAIk7o5Ck-xtMq5zP8T_OlfF4Ets46q8avxKMxEDMHsNtuh3osBj2Kq-nR5yrQ6matm4tJThx-iSkA
--- response_body
--- error_code: 200
--- no_error_log
[error]
