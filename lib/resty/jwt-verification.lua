local cjson = require "cjson.safe"
local pkey = require "resty.openssl.pkey"
local hmac = require "resty.openssl.hmac"
local isempty = require "table.isempty"
local isarray = require "table.isarray"

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

local verify_default_options = {
    valid_signing_algorithms = {
        ["HS256"]="HS256", ["HS384"]="HS384", ["HS512"]="HS512",
        ["RS256"]="RS256", ["RS384"]="RS384", ["RS512"]="RS512",
        ["ES256"]="ES256", ["ES384"]="ES384", ["ES512"]="ES512",
        ["PS256"]="PS256", ["PS384"]="PS384", ["PS512"]="PS512",
    },
    typ = nil,
    issuer = nil,
    audiences = nil,
    subject = nil,
    jwtid = nil,
    ignore_not_before = false,
    ignore_expiration = false,
    current_unix_timestamp = nil,
    timestamp_skew_seconds = 1,
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
        return nil, "failed decoding base64 string: " .. base64_str
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

---verify_jwt_audiences Verify jwt aud claims against a list of valid audiences.
---@param jwt_audiences table Jwt audiences array.
---@param options_audiences table Valid audiences array.
---@return boolean True if at least an audience matches one found in the aud jwt claim.
local function verify_jwt_audiences(jwt_audiences, options_audiences)
    for _, jwt_aud in ipairs(jwt_audiences) do
        for _, opt_aud in ipairs(options_audiences) do
            if jwt_aud == opt_aud then
                return true
            end
        end
    end
    return false
end

---verify Verify jwt token and its claims.
---@param jwt_token string Raw jwt token.
---@param secret string Secret for symmetric signature or public key in either PEM, DER or JWK format.
---@param options table Configuration used to verify the jwt.
---@return table, string Parsed jwt if valid or error string.
function _M.verify(jwt_token, secret, options)
    if jwt_token == nil or secret == nil then
        return nil, "invalid configuration: both jwt token and a secret are required"
    end

    if options == nil then
        options = verify_default_options
        options.current_unix_timestamp = ngx.time()
    elseif type(options) ~= "table" then
        return nil, "invalid configuration: parameter options is not a valid table"
    else
        if options.valid_signing_algorithms == nil then options.valid_signing_algorithms = verify_default_options.valid_signing_algorithms end
        if options.ignore_not_before == nil then options.ignore_not_before = verify_default_options.ignore_not_before end
        if options.ignore_expiration == nil then options.ignore_expiration = verify_default_options.ignore_expiration end
        if options.current_unix_timestamp == nil then options.current_unix_timestamp = ngx.time() end
        if options.timestamp_skew_seconds == nil then options.timestamp_skew_seconds = verify_default_options.timestamp_skew_seconds end

        -- ensure sensible configuration
        if options.audiences ~= nil then
            if isempty(options.audiences) then
                return nil, "invalid configuration: parameter options.audiences must contain at least a string"
            end
            if not isarray(options.audiences) then
                return nil, "invalid configuration: parameter options.audiences must be an array"
            end
        end
        if isarray(options.valid_signing_algorithms) then
            -- we require a dict because we don't want to iterate over every single field in the array to check
            -- the requested alg to be available...
            return nil, "invalid configuration: parameter options.valid_signing_algorithms must be a dict"
        end
    end

    --- jwt parsing ---

    local jwt_sections = split_jwt_sections(jwt_token)
    if #jwt_sections ~= 3 then
        return nil, "invalid jwt: found '" .. #jwt_sections .. "' sections instead of expected 3"
    end

    local jwt_header = decode_base64_segment_to_table(jwt_sections[1])
    if jwt_header == nil then
        return nil, "invalid jwt: failed decoding jwt header from base64"
    end
    if jwt_header.alg == nil or type(jwt_header.alg) ~= "string" then
        return nil, "invalid jwt: missing required string header claim 'alg'"
    end

    local jwt_payload = decode_base64_segment_to_table(jwt_sections[2])
    if jwt_payload == nil then
        return nil, "invalid jwt: failed decoding jwt payload from base64"
    end

    local jwt_signature = decode_base64_segment_to_string(jwt_sections[3])
    if jwt_signature == nil then
        return nil, "invalid jwt: failed decoding jwt signature from base64"
    end

    -- jwt verify signature --

    local jwt_portion_to_verify = string.format("%s.%s", jwt_sections[1], jwt_sections[2])

    if options.valid_signing_algorithms[jwt_header.alg] == nil then
        return nil, "jwt validation failed: signing algorithm is not enabled: " .. jwt_header.alg
    end

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

    -- jwt verify claims --

    if options.typ ~= nil then
        if jwt_header.typ ~= options.typ then
            return nil, "jwt validation failed: header claim 'typ' mismatch: " .. jwt_header.typ
        end
    end
    if options.issuer ~= nil then
        if jwt_payload.iss ~= options.issuer then
            return nil, "jwt validation failed: claim 'iss' mismatch: " .. jwt_payload.iss
        end
    end
    if options.audiences ~= nil then
        -- from jwt rfc 4.1.3:
        --   In the special case when the JWT has one audience, the "aud" value MAY be a
        --   single case-sensitive string containing a StringOrURI value.
        if type(jwt_payload.aud) == "string" then
            if not verify_jwt_audiences({ jwt_payload.aud }, options.audiences) then
                return nil, "jwt validation failed: claim 'aud' mismatch"
            end
        elseif type(jwt_payload.aud) == "table" then
            if not verify_jwt_audiences(jwt_payload.aud, options.audiences) then
                return nil, "jwt validation failed: claim 'aud' mismatch"
            end
        else
            return nil, "invalid jwt: claim 'aud' has invalid type"
        end
    end
    if options.subject ~= nil then
        if jwt_payload.sub ~= options.subject then
            return nil, "jwt validation failed: claim 'sub' mismatch: " .. jwt_payload.sub
        end
    end
    if options.jwtid ~= nil then
        if jwt_payload.jti ~= options.jwtid then
            return nil, "jwt validation failed: claim 'jti' mismatch: " .. jwt_payload.jti
        end
    end

    if jwt_payload.nbf ~= nil and options.ignore_not_before ~= true then
        if type(jwt_payload.nbf) ~= "number" then
            return nil, "invalid jwt: nbf claim must be a number"
        end
        if jwt_payload.nbf > options.current_unix_timestamp then
            return nil, "jwt validation failed: token is not yet valid (nbf claim)"
        end
    end
    if jwt_payload.exp ~= nil then
        if type(jwt_payload.exp) ~= "number" then
            return nil, "invalid jwt: exp claim must be a number"
        end
        if options.current_unix_timestamp >= jwt_payload.exp + options.timestamp_skew_seconds then
            return nil, "jwt validation failed: token has expired (exp claim)"
        end
    end

    --- jwt is valid ---

    return {
        header = jwt_header,
        payload = jwt_payload,
    }
end

return _M
