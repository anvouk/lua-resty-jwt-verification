local cache_jwks = ngx.shared.resty_jwt_verification_cache_jwks

local _M = { _VERSION = "0.1.0" }

function _M.get(key)
    local val = cache_jwks:get(key)
    return val
end

function _M.setex(key, value, expiry)
    local ok, err, forcible = cache_jwks:set(key, value, expiry)
    if not ok then
        return nil, "failed jwks local cache set: " .. err .. ", forcible: " .. forcible
    end

    return true
end

return _M
