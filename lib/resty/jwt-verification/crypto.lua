local bit = require("bit")
local buffer = require("string.buffer")
local digest = require("resty.openssl.digest")
local binutils = require("resty.jwt-verification.binutils")

local _M = {}

---Lua implementation of concat KDF as done in panva/jose lib.
---@param secret string
---@param bits integer
---@param value string
---@return string|nil secret on success, nil otherwise.
---@return string|nil err nil on success, error message otherwise.
function _M.concat_kdf(secret, bits, value)
    local iterations = math.ceil(bit.rshift(bits, 3) / 32)
    local res = buffer.new(iterations * 32)
    local buf = buffer.new(4 + #secret + #value)
    for iter = 1, iterations do
        buf:put(binutils.uint32be(iter), secret, value)
        --ngx.say(ngx.encode_base64(buf:tostring()))

        local d, err = digest.new("sha256")
        if not d then
            return nil, "failed creating openssl digest: " .. err
        end
        local digest_str, err = d:final(buf:get())
        if not digest_str then
            return nil, "failed calculating digest: " .. err
        end

        res:put(digest_str)
    end
    return res:get(bit.rshift(bits, 3))
end

return _M
