local cache_jwks = ngx.shared.resty_jwt_verification_cache_jwks

---This cache strategy uses openresty `ngx.shared` dict under the hood for immediate keys lookup from memory. To keep things
---simple here, a failed jwt validation, with a stale jwk found in cache, *WILL NOT* cascade into a cache refresh. Either
---reduce the default ttl by changing the config `default_exp_secs` or implement yourself the cache invalidation procedure: this
---could be done as an internal nginx endpoint which would clear the shared dict `resty_jwt_verification_cache_jwks` after
---being called by some other service post jwks rotation.
---A better approach, would be to use the Redis caching strategy instead (which has yet to be implemented, sorry >.<).
---This would also have the advantage of sharing the same cache amongst multiple openresty instances.
---Note: remember to define the shared dict `lua_shared_dict resty_jwt_verification_cache_jwks 10m;` at openresty startup.
---Items are shared among all the nginx instance workers.
local _M = { _VERSION = "0.6.0" }

---Get cached entry string for key.
---@nodiscard
---@param key string Cache key.
---@return string|nil value Return cached result as string if present, nil otherwise.
function _M.get(key)
    local val = cache_jwks:get(key)
    return val
end

---Cache data under key until expiry.
---@param key string Cache key.
---@param value string Cache value.
---@param expiry integer Cache entry expiry in seconds.
---@return boolean|nil ok true on success
---@return string|nil err nil on success, error message otherwise.
function _M.setex(key, value, expiry)
    local ok, err, forcible = cache_jwks:set(key, value, expiry)
    if not ok then
        return nil, "failed jwks local cache set: " .. err .. ", forcible: " .. forcible
    end

    return true
end

return _M
