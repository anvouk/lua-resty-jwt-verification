local b64 = require("ngx.base64")
local cjson = require("cjson.safe")
local pkey = require("resty.openssl.pkey")
local hmac = require("resty.openssl.hmac")
local cipher = require("resty.openssl.cipher")
local table_isempty = require("table.isempty")
local table_isarray = require("table.isarray")

local _M = { _VERSION = "0.3.0" }

---@alias JwtHeader { alg: string, enc: string|nil, crit: string|table|nil, cty: string|nil }
---@alias JwtResult { header: JwtHeader, payload: table }

---@alias JwtShaMdAlg "sha256"|"sha384"|"sha512" supported sha types.
---@class (exact) JwtMdAlgTable
---@field [string] JwtShaMdAlg
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

---@alias JwtKeywrapAlgInfo { aes: string, enc_key_len: integer }
---@class (exact) JwtKeywrapAlgTable
---@field [string] JwtKeywrapAlgInfo
local keywrap_alg_table = {
    ["A128KW"] = {
        aes = "aes128-wrap",
        enc_key_len = 16,
    },
    ["A192KW"] = {
        aes = "aes192-wrap",
        enc_key_len = 24,
    },
    ["A256KW"] = {
        aes = "aes256-wrap",
        enc_key_len = 32,
    },
}

---@alias JwtDecryptAlgInfo { aes: boolean, hmac: JwtShaMdAlg|nil, mac_key_len: integer, enc_key_len: integer }
---@class (exact) JwtDecryptAlgTable
---@field [string] JwtDecryptAlgInfo
local decrypt_alg_table = {
    ["A128CBC-HS256"] = {
        aes = "aes-128-cbc",
        hmac = "sha256",
        mac_key_len = 16,
        enc_key_len = 16,
    },
    ["A192CBC-HS384"] = {
        aes = "aes-192-cbc",
        hmac = "sha384",
        mac_key_len = 24,
        enc_key_len = 24,
    },
    ["A256CBC-HS512"] = {
        aes = "aes-256-cbc",
        hmac = "sha512",
        mac_key_len = 32,
        enc_key_len = 32,
    },
    ["A128GCM"] = {
        aes = "aes-128-gcm",
        mac_key_len = 0,
        enc_key_len = 16,
    },
    ["A192GCM"] = {
        aes = "aes-192-gcm",
        mac_key_len = 0,
        enc_key_len = 24,
    },
    ["A256GCM"] = {
        aes = "aes-256-gcm",
        mac_key_len = 0,
        enc_key_len = 32,
    },
}

-- used to verify 'crit' claim
local crit_supported_claims_table = {
    ["crit"]="crit",
    ["alg"]="alg",
    ["enc"]="enc",
    ["typ"]="typ",
}

---@class (exact) JwtVerifyOptions Configure how a JWT will be verified.
---@field valid_signing_algorithms table<string, string> valid algs list. Verification will fail if JWT `alg` is
---not present in this list.
---@field typ string|nil JWT `typ` claim to verify. If nil, no check will be perfomed on this claim.
---@field issuer string|nil JWT `issuer` claim to verify. If nil, no check will be perfomed on this claim.
---@field audiences [string]|nil JWT `aud` claim to verify. If nil, no check will be perfomed on this claim.
---@field subject string|nil JWT `sub` claim to verify. If nil, no check will be perfomed on this claim.
---@field jwtid string|nil JWT `jti` claim to verify. If nil, no check will be perfomed on this claim.
---@field ignore_not_before boolean|nil If true, ignores the JWT claim `nbf` if present. This is a critical
---option, leave nil unless you know what you are doing.
---@field ignore_expiration boolean|nil If true, ignores the JWT claim `exp` if present. This is a critical
---option, leave nil unless you know what you are doing.
---@field current_unix_timestamp integer|nil Allows overriding the current date as a unix epoch timestamp if set. If
---nil, will default to calling `ngx.time()` on every JWT to verify.
---@field timestamp_skew_seconds integer Allows a margin in seconds in which the JWT can still be successfully
---verified after it already expired. Set to 0 to disable.
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

---@class (exact) JwtDecryptOptions Configure how a JWE will be decrypted.
---@field valid_encryption_alg_algorithms table<string, string> valid algs list. Decryption will fail if JWT `alg` claim
---is not present in this list.
---@field valid_encryption_enc_algorithms table<string, string> valid algs list. Decryption will fail if JWT `enc` claim
---is not present in this list.
---@field typ string|nil JWT `typ` claim to verify. If nil, no check will be perfomed on this claim.
---@field issuer string|nil JWT `issuer` claim to verify. If nil, no check will be perfomed on this claim.
---@field audiences [string]|nil JWT `aud` claim to verify. If nil, no check will be perfomed on this claim.
---@field subject string|nil JWT `sub` claim to verify. If nil, no check will be perfomed on this claim.
---@field jwtid string|nil JWT `jti` claim to verify. If nil, no check will be perfomed on this claim.
---@field ignore_not_before boolean|nil If true, ignores the JWT claim `nbf` if present. This is a critical
---option, leave nil unless you know what you are doing.
---@field ignore_expiration boolean|nil If true, ignores the JWT claim `exp` if present. This is a critical
---option, leave nil unless you know what you are doing.
---@field current_unix_timestamp integer|nil Allows overriding the current date as a unix epoch timestamp if set. If
---nil, will default to calling `ngx.time()` on every JWT to verify.
---@field timestamp_skew_seconds integer Allows a margin in seconds in which the JWT can still be successfully
---verified after it already expired. Set to 0 to disable.
local decrypt_default_options = {
    valid_encryption_alg_algorithms = {
        ["A128KW"]="A128KW", ["A192KW"]="A192KW", ["A256KW"]="A256KW",
        ["dir"]="dir",
    },
    valid_encryption_enc_algorithms = {
        ["A128CBC-HS256"]="A128CBC-HS256",
        ["A192CBC-HS384"]="A192CBC-HS384",
        ["A256CBC-HS512"]="A256CBC-HS512",
        ["A128GCM"]="A128GCM",
        ["A192GCM"]="A192GCM",
        ["A256GCM"]="A256GCM",
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

---Decode an encoded string in base64.
---@param base64_str string base64 encoded string.
---@return string|nil #Parsed string on success.
---@return string|nil err nil on success, error message otherwise.
local function decode_base64_segment_to_string(base64_str)
    local decoded_header = b64.decode_base64url(base64_str)
    if decoded_header == nil then
        return nil, "failed decoding base64 string: " .. base64_str
    end
    return decoded_header
end

---Decode a json encoded in base64 and return it as lua table.
---@param base64_str string base64 encoded json string.
---@return table|nil #Parsed content on success.
---@return string|nil err nil on success, error message otherwise.
local function decode_base64_segment_to_table(base64_str)
    local decoded_string, err = decode_base64_segment_to_string(base64_str)
    if decoded_string == nil then
        return nil, err
    end
    return cjson.decode(decoded_string)
end

---Parse and decode a jwt header to a lua table. The header IS NOT validated in any way.
---@param jwt_token string Full jwt token as base64 encoded string.
---@return table|nil #Jwt header content as lua table on success
---@return string|nil err nil on success, error message otherwise.
function _M.decode_header_unsafe(jwt_token)
    local dotpos = string.find(jwt_token, ".", 0, true)
    if dotpos == nil then
        return nil, "invalid jwt format: missing header"
    end
    return decode_base64_segment_to_table(string.sub(jwt_token, 1, dotpos - 1))
end

---Split a jwt string into its 3 subcomponents.
---@param jwt_token string Encoded jwt string.
---@return table #Array containing jwt sections still base64 encoded.
local function split_jwt_sections(jwt_token)
    local t = {}
    local begin_pos = 1
    local end_pos
    repeat
        end_pos = string.find(jwt_token, ".", begin_pos, true)
        if end_pos == nil then
            table.insert(t, string.sub(jwt_token, begin_pos))
            break
        end

        table.insert(t, string.sub(jwt_token, begin_pos, end_pos - 1))
        begin_pos = end_pos + 1
    until false
    return t
end

---Generate a signature with hmac for given message and secret.
---@param message string Message to sign.
---@param secret string Secret to use for signing message.
---@param md_alg JwtShaMdAlg Either sha256, sha384 or sha512.
---@return string|nil signature Hashed data on success.
---@return string|nil err nil on success, error message otherwise.
local function hmac_sign(message, secret, md_alg)
    local hmac_instance = hmac.new(secret, md_alg)
    if hmac_instance == nil then
        return nil, "failed initializing hmac instance"
    end

    return hmac_instance:final(message)
end

---Verify an existing signature for a message with RSA.
---@param message string Message which signature belongs to.
---@param signature string Message's signature.
---@param public_key_str string Public key used to verify the signature.
---@param md_alg JwtShaMdAlg Either sha256, sha384 or sha512.
---@return boolean|nil #Whether the signature is valid.
---@return string|nil err nil on success, error message otherwise.
local function rsa_verify(message, signature, public_key_str, md_alg)
    local pk, err = pkey.new(public_key_str, {
        format = "*", -- choice of "PEM", "DER", "JWK" or "*" for auto detect
    })
    if pk == nil then
        return nil, "failed initializing openssl with public key: " .. err
    end

    return pk:verify(signature, message, md_alg)
end

---Verify an existing signature for a message with ECDSA.
---@param message string Message which signature belongs to.
---@param signature string Message's signature.
---@param public_key_str string Public key used to verify the signature.
---@param md_alg JwtShaMdAlg Either sha256, sha384 or sha512.
---@return boolean|nil #Whether the signature is valid.
---@return string|nil err nil on success, error message otherwise.
local function ecdsa_verify(message, signature, public_key_str, md_alg)
    local pk, err = pkey.new(public_key_str, {
        format = "*", -- choice of "PEM", "DER", "JWK" or "*" for auto detect
    })
    if pk == nil then
        return nil, "failed initializing openssl with public key: " .. err
    end

    return pk:verify(signature, message, md_alg, nil, { ecdsa_use_raw = true })
end

---Verify an existing signature for a message with RSA-PSS.
---@param message string Message which signature belongs to.
---@param signature string Message's signature.
---@param public_key_str string Public key used to verify the signature.
---@param md_alg JwtShaMdAlg Either sha256, sha384 or sha512.
---@return boolean|nil #Whether the signature is valid.
---@return string|nil err nil on success, error message otherwise.
local function rsa_pss_verify(message, signature, public_key_str, md_alg)
    local pk, err = pkey.new(public_key_str, {
        format = "*", -- choice of "PEM", "DER", "JWK" or "*" for auto detect
    })
    if pk == nil then
        return nil, "failed initializing openssl with public key: " .. err
    end

    return pk:verify(signature, message, md_alg, pkey.PADDINGS.RSA_PKCS1_PSS_PADDING)
end

---Verify jwt aud claims against a list of valid audiences.
---@param jwt_audiences table Jwt audiences array.
---@param options_audiences table Valid audiences array.
---@return boolean #true if at least an audience matches one found in the aud jwt claim.
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

---Verifies crit calim as per jwt RFC.
---@param crit_claims table Jwt crit claim array.
---@return boolean|nil #true if jwt crit claim is successfully verified
---@return string|nil err nil on success, error message otherwise.
local function verify_claim_crit(crit_claims)
    if type(crit_claims) ~= "table" then
        return nil, "jwt validation failed: crit claim is not an array"
    end
    if not table_isarray(crit_claims) then
        return nil, "jwt validation failed: crit claim is not an array"
    end
    if table_isempty(crit_claims) then
        return nil, "jwt validation failed: crit claim cannot be an empty array"
    end

    for _, claim in ipairs(crit_claims) do
        if crit_supported_claims_table[claim] == nil then
            return nil, "jwt validation failed: crit claim not supported by this lib: " .. claim
        end
    end

    return true
end

---Check already verified or decrypted jwt against user validation options.
---@param jwt_header table Verified jwt header as table.
---@param jwt_payload table Verified or decrypted jwt payload as table (or string if jwe is not containing a jwt).
---@param options table User defined or default jwt validation options to check.
---@return boolean|nil #true if jwt claims verification succeeded
---@return string|nil err nil on success, error message otherwise.
local function verify_claims(jwt_header, jwt_payload, options)
    if options.typ ~= nil then
        if jwt_header.typ ~= options.typ then
            return nil, "jwt validation failed: header claim 'typ' mismatch: " .. (jwt_header.typ or "nil")
        end
    end
    if options.issuer ~= nil then
        if jwt_payload.iss ~= options.issuer then
            return nil, "jwt validation failed: claim 'iss' mismatch: " .. (jwt_payload.iss or "nil")
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
    if jwt_payload.exp ~= nil and options.ignore_expiration ~= true then
        if type(jwt_payload.exp) ~= "number" then
            return nil, "invalid jwt: exp claim must be a number"
        end
        if options.current_unix_timestamp >= jwt_payload.exp + options.timestamp_skew_seconds then
            return nil, "jwt validation failed: token has expired (exp claim)"
        end
    end

    return true
end

---Verify jwt token and its claims.
---@param jwt_token string Raw jwt token.
---@param secret string Secret for symmetric signature or public key in either PEM, DER or JWK format.
---@param options JwtVerifyOptions|nil Configuration used to verify the jwt (optional).
---@return JwtResult|nil #Parsed jwt if valid, nil and error string otherwise.
---@return string|nil err nil on success, error message otherwise.
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
            if table_isempty(options.audiences) then
                return nil, "invalid configuration: parameter options.audiences must contain at least a string"
            end
            if not table_isarray(options.audiences) then
                return nil, "invalid configuration: parameter options.audiences must be an array"
            end
        end
        if table_isarray(options.valid_signing_algorithms) then
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
    local jwt_payload = decode_base64_segment_to_table(jwt_sections[2])
    if jwt_payload == nil then
        return nil, "invalid jwt: failed decoding jwt payload from base64"
    end
    local jwt_signature = decode_base64_segment_to_string(jwt_sections[3])
    if jwt_signature == nil then
        return nil, "invalid jwt: failed decoding jwt signature from base64"
    end

    --- jwe sanity checks ---

    if jwt_header.alg == nil or type(jwt_header.alg) ~= "string" then
        return nil, "invalid jwt: missing or invalid required string header claim 'alg'"
    end
    if jwt_header.crit ~= nil then
        local crit_res, err = verify_claim_crit(jwt_header.crit)
        if not crit_res then
            return nil, "invalid jwt: " .. err
        end
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

    local verify_res, err = verify_claims(jwt_header, jwt_payload, options)
    if verify_res == nil then
        return nil, err
    end

    --- jwt is valid ---

    return {
        header = jwt_header,
        payload = jwt_payload,
    }
end

---Extract CEK for content decryption and mac key for authentication.
---@param enc_info JwtDecryptAlgInfo CEK encryption 'enc' parameters used for key extraction.
---@param secret string CEK decryption secret.
---@return string|nil cek CEK on success, nil otherwise.
---@return string|nil mac_key MAC key on success, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
local function derive_keys_alg_dir(enc_info, secret)
    if enc_info == nil then
        return nil, nil, "unsupported enc in cek calculation"
    end

    local secret_key_len = enc_info.mac_key_len + enc_info.enc_key_len
    if #secret ~= secret_key_len then
        return nil, nil, "secret key has not expected length of " .. secret_key_len
    end

    local cek = string.sub(secret, enc_info.mac_key_len + 1)
    local mac_key = string.sub(secret, 1, enc_info.mac_key_len)
    return cek, mac_key
end

---Extract Content Encryption Key (CEK) necessary for later payload decryption
---using AES KW family algs.
---@param enc_info JwtKeywrapAlgInfo CEK encryption 'alg' parameters used for key extraction.
---@param secret string CEK decryption secret.
---@param encrypted_key string Encrypted CEK embedded in the jwt but already base64 decoded.
---@return string|boolean|nil cek CEK on success, false on failed decryption, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
local function derive_cek_alg_aes_kw(enc_info, secret, encrypted_key)
    if enc_info == nil then
        return nil, "unsupported enc in cek calculation"
    end

    if #secret ~= enc_info.enc_key_len then
        return nil, "secret key has not expected length of " .. enc_info.enc_key_len
    end

    local c, err = cipher.new(enc_info.aes)
    if c == nil then
        return nil, "failed creating openssl cipher: " .. err
    end

    local decrypted_cek, _ = c:decrypt(secret, ngx.decode_base64("pqampqampqY="), encrypted_key)
    if decrypted_cek == nil then
        return false
    end
    return decrypted_cek
end

---64-bit big-endian representation of string length.
---See https://datatracker.ietf.org/doc/html/rfc7516#appendix-B.3
---Note: this function has been ported from lua-resty-jwt
---@param s string Data.
---@return string #Length of data as string.
local function binlen(s)
    local len = 8 * #s

    ---@diagnostic disable-next-line: param-type-not-match
    return string.char(len / 0x0100000000000000 % 0x100)
        .. string.char(len / 0x0001000000000000 % 0x100)
        .. string.char(len / 0x0000010000000000 % 0x100)
        .. string.char(len / 0x0000000100000000 % 0x100)
        .. string.char(len / 0x0000000001000000 % 0x100)
        .. string.char(len / 0x0000000000010000 % 0x100)
        .. string.char(len / 0x0000000000000100 % 0x100)
        .. string.char(len / 0x0000000000000001 % 0x100)
end

---Decrypt payload using AES-CBC family algs and verify given AEAD tag.
---@param enc_info table Decryption algorithm's specific settings.
---@param cek string CEK used for ciphertext decryption.
---@param mac_key string used for ciphertext authentication.
---@param ciphertext string Payload to decrypt.
---@param iv string Initialization Vector used during decryption.
---@param aead_aad string AEAD tag to verify.
---@param aead_tag string AEAD computed tag to verify against.
---@return string|boolean|nil #Decrypted payload on success, false on failed decryption, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
local function decrypt_content_cbc(enc_info, cek, mac_key, ciphertext, iv, aead_aad, aead_tag)
    local c, err = cipher.new(enc_info.aes)
    if c == nil then
        return nil, "failed creating openssl cipher: " .. err
    end

    local mac_data = table.concat({aead_aad, iv, ciphertext, binlen(aead_aad)})
    local computed_mac, err = hmac_sign(mac_data, mac_key, enc_info.hmac)
    if computed_mac == nil then
        return nil, "failed computing aead tag: " .. err
    end
    local computed_tag = string.sub(computed_mac, 1, enc_info.mac_key_len)

    -- FIXME: find a way to do this comparison in constant time
    if computed_tag ~= aead_tag then
        return false, "aead tag verification does not match"
        --return false, "aead tag verification does not match: '" .. computed_tag .. "' != '" .. aead_tag .. "' mac_key: " .. mac_key
    end

    -- cipher:decrypt(key, iv?, s, no_padding?, aead_aad?, aead_tag?)
    local decrypted_payload, _ = c:decrypt(cek, iv, ciphertext, false)
    if decrypted_payload == nil then
        return false
    end
    return decrypted_payload
end

---decrypt_content_gcm Decrypt payload using AES-GCM family algs and verify given AEAD tag.
---@param enc_info table Decryption algorithm's specific settings.
---@param cek string CEK used for ciphertext decryption.
---@param ciphertext string Payload to decrypt.
---@param iv string Initialization Vector used during decryption.
---@param aead_aad string AEAD tag to verify.
---@param aead_tag string AEAD computed tag to verify against.
---@return string|boolean|nil #Decrypted payload on success, false on failed decryption, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
local function decrypt_content_gcm(enc_info, cek, ciphertext, iv, aead_aad, aead_tag)
    local c, err = cipher.new(enc_info.aes)
    if c == nil then
        return nil, "failed creating openssl cipher: " .. err
    end

    -- cipher:decrypt(key, iv?, s, no_padding?, aead_aad?, aead_tag?)
    local decrypted_payload, _ = c:decrypt(cek, iv, ciphertext, false, aead_aad, aead_tag)
    if decrypted_payload == nil then
        return false
    end
    return decrypted_payload
end

---Decrypt a JWT token and verify its claims.
---@param jwt_token string Raw JWT token in JWE format.
---@param secret string Secret key for decryption, depending on the algorithm.
---@param options JwtDecryptOptions|nil Configuration options for decryption (optional).
---@return JwtResult|nil #Decrypted JWT with header and payload on valid JWT, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
function _M.decrypt(jwt_token, secret, options)
    if jwt_token == nil or secret == nil then
        return nil, "invalid configuration: both jwt token and a secret are required"
    end

    if options == nil then
        options = decrypt_default_options
        options.current_unix_timestamp = ngx.time()
    elseif type(options) ~= "table" then
        return nil, "invalid configuration: parameter options is not a valid table"
    else
        if options.valid_encryption_alg_algorithms == nil then options.valid_encryption_alg_algorithms = decrypt_default_options.valid_encryption_alg_algorithms end
        if options.valid_encryption_enc_algorithms == nil then options.valid_encryption_enc_algorithms = decrypt_default_options.valid_encryption_enc_algorithms end
        if options.ignore_not_before == nil then options.ignore_not_before = decrypt_default_options.ignore_not_before end
        if options.ignore_expiration == nil then options.ignore_expiration = decrypt_default_options.ignore_expiration end
        if options.current_unix_timestamp == nil then options.current_unix_timestamp = ngx.time() end
        if options.timestamp_skew_seconds == nil then options.timestamp_skew_seconds = decrypt_default_options.timestamp_skew_seconds end

        -- ensure sensible configuration
        if options.audiences ~= nil then
            if table_isempty(options.audiences) then
                return nil, "invalid configuration: parameter options.audiences must contain at least a string"
            end
            if not table_isarray(options.audiences) then
                return nil, "invalid configuration: parameter options.audiences must be an array"
            end
        end
        if table_isarray(options.valid_encryption_alg_algorithms) then
            -- we require a dict because we don't want to iterate over every single field in the array to check
            -- the requested alg to be available...
            return nil, "invalid configuration: parameter options.valid_encryption_alg_algorithms must be a dict"
        end
        if table_isarray(options.valid_encryption_enc_algorithms) then
            -- we require a dict because we don't want to iterate over every single field in the array to check
            -- the requested alg to be available...
            return nil, "invalid configuration: parameter options.valid_encryption_enc_algorithms must be a dict"
        end
    end

    --- jwe parsing ---

    local jwt_sections = split_jwt_sections(jwt_token)
    if #jwt_sections ~= 5 then
        -- note: we only support compact jwt with 5 sections instead of 6
        return nil, "invalid jwt: found '" .. #jwt_sections .. "' sections instead of expected 5"
    end

    local jwt_header = decode_base64_segment_to_table(jwt_sections[1])
    if jwt_header == nil then
        return nil, "invalid jwt: failed decoding jwt header from base64"
    end
    local jwt_encrypted_key = decode_base64_segment_to_string(jwt_sections[2])
    if jwt_encrypted_key == nil then
        return nil, "invalid jwt: failed decoding jwt encrypted key from base64"
    end
    local jwt_iv = decode_base64_segment_to_string(jwt_sections[3])
    if jwt_iv == nil then
        return nil, "invalid jwt: failed decoding jwt iv from base64"
    end
    local jwt_ciphertext = decode_base64_segment_to_string(jwt_sections[4])
    if jwt_ciphertext == nil then
        return nil, "invalid jwt: failed decoding jwt ciphertext from base64"
    end
    local jwt_auth_tag = decode_base64_segment_to_string(jwt_sections[5])
    if jwt_auth_tag == nil then
        return nil, "invalid jwt: failed decoding jwt authentication tag from base64"
    end

    --- jwe sanity checks ---

    if jwt_header.alg == nil or type(jwt_header.alg) ~= "string" then
        return nil, "invalid jwt: missing or invalid required string header claim 'alg'"
    end
    if jwt_header.enc == nil or type(jwt_header.enc) ~= "string" then
        return nil, "invalid jwt:  or invalid required string header claim 'enc'"
    end
    if jwt_header.zip ~= nil then
        return nil, "invalid jwt: claim 'zip' is not supported"
    end
    if jwt_header.crit ~= nil then
        local crit_res, err = verify_claim_crit(jwt_header.crit)
        if not crit_res then
            return nil, "invalid jwt: " .. err
        end
    end

    -- jwe decryption --

    if options.valid_encryption_alg_algorithms[jwt_header.alg] == nil then
        return nil, "jwt validation failed: encryption algorithm 'alg' is not enabled: " .. jwt_header.alg
    end
    if options.valid_encryption_enc_algorithms[jwt_header.enc] == nil then
        return nil, "jwt validation failed: encryption algorithm 'enc' is not enabled: " .. jwt_header.enc
    end

    local cek, mac_key, err
    if jwt_header.alg == "dir" then
        cek, mac_key, err = derive_keys_alg_dir(decrypt_alg_table[jwt_header.enc], secret)
    elseif jwt_header.alg == "A128KW" or jwt_header.alg == "A192KW" or jwt_header.alg == "A256KW" then
        cek, err = derive_cek_alg_aes_kw(keywrap_alg_table[jwt_header.alg], secret, jwt_encrypted_key)
        if cek == nil then
            return nil, "invalid jwt: " .. err
        elseif not cek then
            return nil, "invalid jwt: failed decrypting cek"
        end
        ---@cast cek string
        cek, mac_key, err = derive_keys_alg_dir(decrypt_alg_table[jwt_header.enc], cek)
    else
        return nil, "unknown or unsupported jwt alg: " .. jwt_header.alg
    end
    if cek == nil or mac_key == nil then
        return nil, "invalid jwt: " .. err
    end

    local aad = jwt_sections[1]

    local decrypted_payload
    if jwt_header.enc == "A128CBC-HS256" or jwt_header.enc == "A192CBC-HS384" or jwt_header.enc == "A256CBC-HS512" then
        decrypted_payload, err = decrypt_content_cbc(
            decrypt_alg_table[jwt_header.enc],
            cek,
            mac_key,
            jwt_ciphertext,
            jwt_iv,
            aad,
            jwt_auth_tag
        )
    elseif jwt_header.enc == "A128GCM" or jwt_header.enc == "A192GCM" or jwt_header.enc == "A256GCM" then
        decrypted_payload, err = decrypt_content_gcm(
            decrypt_alg_table[jwt_header.enc],
            cek,
            jwt_ciphertext,
            jwt_iv,
            aad,
            jwt_auth_tag
        )
    else
        return nil, "unknown or unsupported jwt enc: " .. jwt_header.enc
    end
    if decrypted_payload == nil then
        return nil, "invalid jwt: " .. err
    elseif not decrypted_payload then
        return nil, "invalid jwt: failed decrypting jwt payload"
        --return nil, "invalid jwt: failed decrypting jwt payload: " .. err .. "; cek: " ..  cek
    end

    -- jwt verify claims --

    ---@type table, string|nil
    decrypted_payload, err = cjson.decode(decrypted_payload);
    if decrypted_payload == nil then
        return nil, "invalid jwt: failed reading decrypted payload: " .. err
    end

    local verify_res, err = verify_claims(jwt_header, decrypted_payload, options)
    if verify_res == nil then
        return nil, err
    end

    --- jwt is valid ---

    return {
        header = jwt_header,
        payload = decrypted_payload,
    }
end

return _M
