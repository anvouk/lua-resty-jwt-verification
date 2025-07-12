rockspec_format = "3.0"
package = "lua-resty-jwt-verification"
version = "0.3.0-1"
source = {
   url = "git+https://github.com/anvouk/lua-resty-jwt-verification",
   tag = "v0.3.0"
}
description = {
   summary = "JWT verification library for OpenResty.",
   detailed = [[
     Modern JWT verification library for OpenResty with JWKS support.
   ]],
   homepage = "https://github.com/anvouk/lua-resty-jwt-verification",
   license = "BSD-3-Clause license",
   issues_url = "https://github.com/anvouk/lua-resty-jwt-verification/issues",
   labels = {
     "openresty",
     "jwt",
     "jwks"
   }
}
dependencies = {
  'lua >= 5.1',
  'lua-resty-openssl >= 1.3.1',
  'lua-resty-http >= 0.17.2'
}
build = {
   type = "builtin",
   modules = {
      ["resty.jwt-verification"] = "lib/resty/jwt-verification.lua",
      ["resty.jwt-verification-jwks"] = "lib/resty/jwt-verification-jwks.lua",
      ["resty.jwt-verification-jwks-cache-local"] = "lib/resty/jwt-verification-jwks-cache-local.lua"
   }
}
