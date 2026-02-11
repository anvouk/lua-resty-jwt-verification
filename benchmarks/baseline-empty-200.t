use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

master_on();
workers(1);

no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: baseline ok
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
        }
    }
--- request
    GET /t
--- more_headers
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE3MTY2NTUwMTV9.NuEhIzUuufJgPZ8CmCPnD4Vrw7EnTyWD8bGtYCwuDZ0
--- response_body
--- error_code: 200
--- no_error_log
[error]
