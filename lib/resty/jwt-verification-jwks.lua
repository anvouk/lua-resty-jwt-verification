local httpc = require("resty.http").new()
local cjson = require("cjson.safe")
local jwt = require("resty.jwt-verification")
local table_isarray = require("table.isarray")

local _M = { _VERSION = "0.2.0" }

local jwks_options = {
    cache = {
        prefix = "openresty:jwt-verification:jwks:",
        default_exp_secs = 12 * 3600,
        get = nil,
        setex = nil,
    },
    http_client = {
        ssl_verify = true
    }
}

---Get cached entry string for key.
---If no cache strategy is set, the cache mechanism will be disabled and this
---function will always return a cache miss.
---@param key string Cache key.
---@return string|nil #Cached result as string if present, nil otherwise.
local function cache_get(key)
    if jwks_options.cache.get == nil then
        -- cache is disabled, return nothing.
        return nil
    end
    return jwks_options.cache.get(jwks_options.cache.prefix .. key)
end

---Cache data under key until expiry.
---If no cache strategy is set, the cache mechanism will be disabled and this
---function will always return success and do nothing.
---@param key string Cache key.
---@param value string Cache value.
---@param expiry number Cache entry expiry in seconds.
---@return boolean|nil #true on success, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
local function cache_setex(key, value, expiry)
    if jwks_options.cache.setex == nil then
        -- cache is disabled, do nothing.
        return true
    end
    return jwks_options.cache.setex(jwks_options.cache.prefix .. key, value, expiry)
end

---Set jwks cache strategy to local.
---This cache strategy uses openresty `ngx.shared` dict under the hood for immediate keys lookup from memory. To keep things
---simple here, a failed jwt validation, with a stale jwk found in cache, *WILL NOT* cascade into a cache refresh. Either
---reduce the default ttl by changing the config `default_exp_secs` or implement yourself the cache invalidation procedure: this
---could be done as an internal nginx endpoint which would clear the shared dict `resty_jwt_verification_cache_jwks` after
---being called by some other service post jwks rotation.
---A better approach, would be to use the Redis caching strategy instead (which has yet to be implemented, sorry >.<).
---This would also have the advantage of sharing the same cache amongst multiple openresty instances.
---Note: remember to define the shared dict `lua_shared_dict resty_jwt_verification_cache_jwks 10m;` at openresty startup.
---Items are shared among all the nginx instance workers.
---@return boolean|nil #true on success, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
function _M.enable_cache_strategy_local()
    if jwks_options.cache.get ~= nil or jwks_options.cache.setex ~= nil then
        return nil, "jwks cache has already been initialized"
    end

    local jwks_cache_local = require("resty.jwt-verification-jwks-cache-local")
    jwks_options.cache.get = jwks_cache_local.get
    jwks_options.cache.setex = jwks_cache_local.setex
    return true
end

---Set jwks HTTP client timeouts.
---See resty.http docs for more info.
---@param connect number HTTP connection timeout in ms.
---@param send number HTTP send timeout in ms.
---@param read number HTTP read timeout in ms.
function _M.set_http_timeouts_ms(connect, send, read)
    httpc:set_timeouts(connect, send, read)
end

---Enable or disable TLS certs verification.
---Note: by default, all HTTPS certs are verified.
---@param enabled boolean Enable or disable functionality.
function _M.set_http_ssl_verify(enabled)
    jwks_options.http_client.ssl_verify = enabled
end

---Manually fetch the jwks from an endpoint. Cache strategy is applied if enabled.
---If you're simply looking to validate a jwt with the retrieved keys, consider using the `verify_jwt_with_jwks` method.
---Note: a cache failure will not trigger an error but will cause the HTTP request instead.
---@param endpoint string HTTP endpoint returning keys (generally ending with '/.well-known/jwks.json').
---@return string|nil #jwks as string when successfully fetched, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
function _M.fetch_jwks(endpoint)
    if endpoint == nil then
        return nil, "param endpoint cannot be nil"
    end

    local cached_value = cache_get(endpoint)
    if cached_value ~= nil then
        ngx.log(ngx.DEBUG, "jwks found in cache for endpoint: ", endpoint)
        return cached_value
    end

    local res, err = httpc:request_uri(endpoint, {
        method = "GET",
        ssl_verify = jwks_options.http_client.ssl_verify,
        keepalive = false
    })
    if not res then
        return nil, "failed fetching jwks: " .. err
    end
    if res.status ~= 200 then
        return nil, "failed fetching jwks, returned unexpected http status: " .. res.status
    end

    ngx.log(ngx.DEBUG, "jwks successfully fetched for endpoint: ", endpoint)

    local ok, err = cache_setex(endpoint, res.body, jwks_options.cache.default_exp_secs)
    if not ok then
        ngx.log(ngx.WARN, "failed saving fetched jwks entry in cache: ", err)
    end

    return res.body
end

---Verify an asymmetrically signed jwt using jwks from a remote HTTP endpoint.
---@param jwt_token string Raw jwt token.
---@param jwks_endpoint string HTTP endpoint from where to fetch jwks.
---@param jwt_options JwtVerifyOptions Configuration used to verify the jwt. See verify in resty.jwt-verification for more info.
---@return JwtResult|nil #Parsed jwt if valid, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
function _M.verify_jwt_with_jwks(jwt_token, jwks_endpoint, jwt_options)
    if jwt_token == nil or jwks_endpoint == nil then
        return nil, "params jwt_token and jwks_endpoint cannot be nil"
    end

    local unsafe_jwt_header, err = jwt.decode_header_unsafe(jwt_token)
    if not unsafe_jwt_header then
        return nil, "failed verifying jwt: " .. err
    end

    local kid = unsafe_jwt_header.kid
    if kid == nil then
        -- FIXME: is this actually something worth implementing or just an RFC completeness thing?
        return nil, "failed verifying jwt: token does not have kid header and this lib does not support this case"
    end

    local jwks, err = _M.fetch_jwks(jwks_endpoint)
    if jwks == nil then
        return nil, "failed verifying jwt: " .. err
    end
    ---@type table|nil, string|nil
    jwks, err = cjson.decode(jwks)
    if not jwks then
        return nil, "failed verifying jwt: invalid json decoded: " .. err
    end

    if jwks.keys == nil or not table_isarray(jwks.keys) then
        return nil, "failed verifying jwt: jwks invalid format: missing or invalid field 'keys'"
    end

    -- find public jwk used to sign our token
    local jwk_to_use
    for _, jwk in ipairs(jwks.keys) do
        if jwk.kid == kid then
            jwk_to_use = jwk
            break
        end
    end
    if jwk_to_use == nil then
        -- Note: we do not go down the rabbit hole of invalidating the cache and retrying with updated keys.
        -- If It's vital to ensure the cache is not stale, either fine-tune the cache ttl, change cache strategy or
        -- implement the cache invalidation procedure yourself upon jwks rotation.
        return nil, "failed verifying jwt: could not find jwk with kid: " .. kid
    end

    -- openssl can verify a signature from a jwk directly. We need, however, to pass it as a string.
    -- FIXME: can we safely avoid decoding and then re-encoding the jwk?
    jwk_to_use, err = cjson.encode(jwk_to_use)
    if not jwk_to_use then
        return nil, "failed verifying jwt: failed jsonify jwk: " .. err
    end

    return jwt.verify(jwt_token, jwk_to_use, jwt_options)
end

return _M
