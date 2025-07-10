local cache_jwks = ngx.shared.resty_jwt_verification_cache_jwks

local _M = { _VERSION = "0.2.0" }

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
---@param expiry number Cache entry expiry in seconds.
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
