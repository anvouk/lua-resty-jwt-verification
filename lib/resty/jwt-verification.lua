local cjson = require "cjson.safe"
local pkey = require "resty.openssl.pkey"
local hmac = require "resty.openssl.hmac"

local _M = { _VERSION = "0.1.0" }

local md_alg_table = {
    ["HS256"] = "sha256",
    ["RS256"] = "sha256",
    ["ES256"] = "sha256",
    ["PS256"] = "sha256",
    ["HS384"] = "sha384",
    ["RS384"] = "sha384",
    ["ES384"] = "sha384",
    ["PS384"] = "sha384",
    ["HS512"] = "sha512",
    ["RS512"] = "sha512",
    ["ES512"] = "sha512",
    ["PS512"] = "sha512",
}

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
    if decoded_header == nil then
        return nil, "failed decoding base64 string"
    end
    return decoded_header
end

---decode_base64_segment_to_table Decode a json encoded in base64 and return it as lua table.
---@param base64_str string base64 encoded json string.
---@return table, string Parsed content or error string.
local function decode_base64_segment_to_table(base64_str)
    local decoded_string, err = decode_base64_segment_to_string(base64_str)
    if decoded_string == nil then
        return nil, err
    end
    return cjson.decode(decoded_string)
end

---decode_header_unsafe Parse and decode a jwt header to a lua table. The header IS NOT validated in any way.
---@param jwt_token string Full jwt token as base64 encoded string.
---@return table, string Jwt header content as lua table or error string.
function _M.decode_header_unsafe(jwt_token)
    local dotpos = string.find(jwt_token, ".", 0, true)
    if dotpos == nil then
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
    -- it's possible the signature part won't be there (e.g. none alg).
    if #t == 2 then
        table.insert(t, "")
    end
    return t
end

---hmac_sign Generate a signature with hmac for given message and secret.
---@param message string Message to sign.
---@param secret string Secret to use for signing message.
---@param md_alg string Either sha256, sha384 or sha512.
---@return string, string Signature or error string.
local function hmac_sign(message, secret, md_alg)
    local hmac_instance = hmac.new(secret, md_alg)
    if hmac_instance == nil then
        return nil, "failed initializing hmac instance"
    end

    return hmac_instance:final(message)
end

---rsa_verify Verify an existing signature for a message with RSA.
---@param message string Message which signature belongs to.
---@param signature string Message's signature.
---@param public_key_str string Public key used to verify the signature.
---@param md_alg string Either sha256, sha384 or sha512.
---@return boolean, string Whether the signature is valid or error string.
local function rsa_verify(message, signature, public_key_str, md_alg)
    local pk, err = pkey.new(public_key_str, {
        format = "*", -- choice of "PEM", "DER", "JWK" or "*" for auto detect
    })
    if pk == nil then
        return nil, "failed initializing openssl with public key: " .. err
    end

    return pk:verify(signature, message, md_alg)
end

---ecdsa_verify Verify an existing signature for a message with ECDSA.
---@param message string Message which signature belongs to.
---@param signature string Message's signature.
---@param public_key_str string Public key used to verify the signature.
---@param md_alg string Either sha256, sha384 or sha512.
---@return boolean, string Whether the signature is valid or error string.
local function ecdsa_verify(message, signature, public_key_str, md_alg)
    local pk, err = pkey.new(public_key_str, {
        format = "*", -- choice of "PEM", "DER", "JWK" or "*" for auto detect
    })
    if pk == nil then
        return nil, "failed initializing openssl with public key: " .. err
    end

    return pk:verify(signature, message, md_alg, nil, { ecdsa_use_raw = true })
end

---rsa_pss_verify Verify an existing signature for a message with RSA-PSS.
---@param message string Message which signature belongs to.
---@param signature string Message's signature.
---@param public_key_str string Public key used to verify the signature.
---@param alg string Jwt PS family alg.
---@return boolean, string Whether the signature is valid or error string.
local function rsa_pss_verify(message, signature, public_key_str, alg)
    local pk, err = pkey.new(public_key_str, {
        format = "*", -- choice of "PEM", "DER", "JWK" or "*" for auto detect
    })
    if pk == nil then
        return nil, "failed initializing openssl with public key: " .. err
    end

    return pk:verify(signature, message, alg, pkey.PADDINGS.RSA_PKCS1_PSS_PADDING)
end

---verify Verify jwt token and its claims.
---@param jwt_token string Raw jwt token.
---@param secret string Secret for symmetric signature or public key in either PEM, DER or JWK format.
---@return table, string Parsed jwt if valid or error string.
function _M.verify(jwt_token, secret)
    if jwt_token == nil or secret == nil then
        return nil, "invalid params: both jwt token and a secret are required"
    end

    local jwt_sections = split_jwt_sections(jwt_token)
    if #jwt_sections ~= 3 then
        return nil, "invalid jwt: found '" .. #jwt_sections .. "' sections instead of expected 3"
    end

    local jwt_header, err = decode_base64_segment_to_table(jwt_sections[1])
    if jwt_header == nil then
        return nil, "invalid jwt: " .. err
    end
    if jwt_header.alg == nil or type(jwt_header.alg) ~= "string" then
        return nil, "invalid jwt: missing required string header claim 'alg'"
    end

    local jwt_payload, err = decode_base64_segment_to_table(jwt_sections[2])
    if jwt_payload == nil then
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
    if jwt_signature == nil then
        return nil, "invalid jwt: failed decoding jwt signature from base64"
    end

    local jwt_portion_to_verify = string.format("%s.%s", jwt_sections[1], jwt_sections[2])

    if jwt_header.alg == "HS256" or jwt_header.alg == "HS384" or jwt_header.alg == "HS512" then
        local signature, err = hmac_sign(jwt_portion_to_verify, secret, md_alg_table[jwt_header.alg])
        if signature == nil then
            return nil, "failed signing jwt for validation: " .. err
        end

        -- FIXME: find a way to do this comparison in constant time
        if signature ~= jwt_signature then
            return nil, "invalid jwt: signature does not match"
        end
    elseif jwt_header.alg == "RS256" or jwt_header.alg == "RS384" or jwt_header.alg == "RS512" then
        local is_valid, err = rsa_verify(jwt_portion_to_verify, jwt_signature, secret, md_alg_table[jwt_header.alg])
        if is_valid == nil then
            return nil, "invalid jwt: " .. err
        elseif not is_valid then
            return nil, "invalid jwt: signature does not match"
        end
    elseif jwt_header.alg == "ES256" or jwt_header.alg == "ES384" or jwt_header.alg == "ES512" then
        local is_valid, err = ecdsa_verify(jwt_portion_to_verify, jwt_signature, secret, md_alg_table[jwt_header.alg])
        if is_valid == nil then
            return nil, "invalid jwt: " .. err
        elseif not is_valid then
            return nil, "invalid jwt: signature does not match"
        end
    elseif jwt_header.alg == "PS256" or jwt_header.alg == "PS384" or jwt_header.alg == "PS512" then
        local is_valid, err = rsa_pss_verify(jwt_portion_to_verify, jwt_signature, secret, md_alg_table[jwt_header.alg])
        if is_valid == nil then
            return nil, "invalid jwt: " .. err
        elseif not is_valid then
            return nil, "invalid jwt: signature does not match"
        end
    elseif jwt_header.alg == "none" then
        return nil, "unsafe jwt with none alg will never be verifiable"
    else
        return nil, "unknown jwt alg: " .. jwt_header.alg
    end

    return {
        header = jwt_header,
        payload = jwt_payload,
    }
end

return _M
