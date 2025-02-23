rockspec_format = "3.0"
package = "lua-resty-jwt-verification"
version = "0.1.0-2"
source = {
   url = "git+https://github.com/anvouk/lua-resty-jwt-verification",
   tag = "v0.1.0"
}
description = {
   summary = "JWT verification library for OpenResty.",
   detailed = [[
     Modern JWT verification library for OpenResty.
   ]],
   homepage = "https://github.com/anvouk/lua-resty-jwt-verification",
   license = "BSD-3-Clause license",
   issues_url = "https://github.com/anvouk/lua-resty-jwt-verification/issues",
   labels = {
     "openresty",
     "jwt"
   }
}
dependencies = {
  'lua >= 5.1',
  'lua-resty-openssl >= 1.3.1'
}
build = {
   type = "builtin",
   modules = {
      ["resty.jwt-verification"] = "lib/resty/jwt-verification.lua"
   }
}
