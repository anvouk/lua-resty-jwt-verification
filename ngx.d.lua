---openresty definitions stub
---@meta

---@enum ngx
ngx = {
   STDERR = "STDERR",
   EMERG = "EMERG",
   ALERT = "ALERT",
   CRIT = "CRIT",
   ERR = "ERR",
   WARN = "WARN",
   NOTICE = "NOTICE",
   INFO = "INFO",
   DEBUG = "DEBUG",

   shared = {
       resty_jwt_verification_cache_jwks = {
            ---@param self any
            ---@param key any
            get = function(self, key)
            end,

            ---@param self any
            ---@param key any
            ---@param value any
            ---@param expiry number
            ---@return boolean ok
            ---@return string error
            ---@return boolean forcible
            set = function(self, key, value, expiry)
            end
       }
   }
}

---Get current unix timestamp
---@nodiscard
---@return integer
function ngx.time()
end

---Openresty debug logs
---@param log_level ngx
function ngx.log(log_level, ...)
end

---@param str string
---@return string
function ngx.decode_base64(str)
end
