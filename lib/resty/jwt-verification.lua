local cjson = require "cjson.safe"
local openssl_cipher = require "resty.openssl.cipher"
local hmac = require "resty.openssl.hmac"
local http = require "resty.http"

local _M = { _VERSION = "0.1.0" }

---decode_base64_segment_to_string Decode an encoded string in base64.
---@param base64_str string base64 encoded string.
---@return string, string Parsed string or error string.
local function decode_base64_segment_to_string(base64_str)
    base64_str = string.gsub(base64_str, "-", "+")
    base64_str = string.gsub(base64_str, "_", "/")
    local reminder = #base64_str % 4
    if reminder > 0 then
        base64_str = base64_str .. string.rep("=", 4 - reminder)
    end
    local decoded_header = ngx.decode_base64(base64_str)
    if not decoded_header then
        return nil, "failed decoding base64 string"
    end
    return decoded_header
end

---decode_base64_segment_to_table Decode a json encoded in base64 and return it as lua table.
---@param base64_str string base64 encoded json string.
---@return table, string Parsed content or error string.
local function decode_base64_segment_to_table(base64_str)
    local decoded_string, err = decode_base64_segment_to_string(base64_str)
    if not decoded_string then
        return nil, err
    end
    return cjson.decode(decoded_string)
end

---decode_header_unsafe Parse and decode a jwt header to a lua table. The header IS NOT validated in any way.
---@param jwt_token string Full jwt token as base64 encoded string.
---@return table, string Jwt header content as lua table or error string.
function _M.decode_header_unsafe(jwt_token)
    local dotpos = string.find(jwt_token, ".", 0, true)
    if not dotpos then
        return nil, "invalid jwt format: missing header"
    end
    return decode_base64_segment_to_table(string.sub(jwt_token, 1, dotpos - 1))
end

---split_jwt_sections Split a jwt string into its 3 subcomponents.
---@param jwt_token string Encoded jwt string.
---@return table Array containing jwt sections still base64 encoded.
local function split_jwt_sections(jwt_token)
    local t = {}
    for substr in string.gmatch(jwt_token, "([^.]+)") do
        table.insert(t, substr)
    end
    return t
end

---verify Verify jwt token and its claims.
---@param jwt_token string Raw jwt token.
---@param secret string Secret for symmetric signature validation.
---@return table, string Parsed jwt if valid or error string.
function _M.verify(jwt_token, secret)
    local jwt_sections = split_jwt_sections(jwt_token)
    if #jwt_sections ~= 3 then
        return nil, "invalid jwt: found '" .. #jwt_sections .. "' sections instead of expected 3"
    end

    local jwt_header, err = decode_base64_segment_to_table(jwt_sections[1])
    if not jwt_header then
        return nil, "invalid jwt: " .. err
    end
    if not jwt_header.alg or type(jwt_header.alg) ~= "string" then
        return nil, "invalid jwt: missing required string header claim 'alg'"
    end

    local jwt_payload, err = decode_base64_segment_to_table(jwt_sections[2])
    if not jwt_payload then
        return nil, "invalid jwt: " .. err
    end

    -- if nbf or exp are not valid, we skip the signature validation since the token will be invalid anyway.
    -- TODO: add clock skew support
    local now = ngx.time()
    if jwt_payload.nbf ~= nil then
        if type(jwt_payload.nbf) ~= "number" then
            return nil, "invalid jwt: nbf claim must be a number"
        end
        if jwt_payload.nbf > now then
            return nil, "jwt validation failed: token is not yet valid (nbf claim)"
        end
    end
    if jwt_payload.exp ~= nil then
        if type(jwt_payload.exp) ~= "number" then
            return nil, "invalid jwt: exp claim must be a number"
        end
        if now >= jwt_payload.exp then
            return nil, "jwt validation failed: token has expired (exp claim)"
        end
    end

    local jwt_signature = decode_base64_segment_to_string(jwt_sections[3])
    if not jwt_signature then
        return nil, "invalid jwt: failed decoding jwt signature from base64"
    end

    local hmac_instance
    if jwt_header.alg == "HS256" then
        hmac_instance = hmac.new(secret, "sha256")
    elseif jwt_header.alg == "HS384" then
        hmac_instance = hmac.new(secret, "sha384")
    elseif jwt_header.alg == "HS512" then
        hmac_instance = hmac.new(secret, "sha512")
    else
        return nil, "invalid jwt: invalid on unimplemented alg " .. jwt_header.alg
    end
    if not hmac_instance then
        return nil, "failed initializing hmac instance"
    end

    local signature = hmac_instance:final(string.format("%s.%s", jwt_sections[1], jwt_sections[2]))
    if not signature then
        return nil, "failed computing hmac signature for jwt"
    end

    if signature ~= jwt_signature then
        return nil, "invalid jwt: signature does not match"
    end

    return {
        header = jwt_header,
        payload = jwt_payload,
    }
end

return _M
