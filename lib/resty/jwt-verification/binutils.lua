local bit = require("bit")

local bit_band = bit.band
local bit_rshift = bit.rshift
local string_char = string.char

local _M = {}

---64-bit big-endian representation of number.
---@param value integer value to convert.
---@return string result unsigned 64-bit big-endian string representation of n.
function _M.uint64be(value)
    local hi = bit_rshift(value, 29)
    local lo = bit.lshift(value, 3)
    return string_char(
        bit_band(bit_rshift(hi, 24), 0xff),
        bit_band(bit_rshift(hi, 16), 0xff),
        bit_band(bit_rshift(hi, 8), 0xff),
        bit_band(hi, 0xff),
        bit_band(bit_rshift(lo, 24), 0xff),
        bit_band(bit_rshift(lo, 16), 0xff),
        bit_band(bit_rshift(lo, 8), 0xff),
        bit_band(lo, 0xff)
    )
end

---32-bit big-endian representation of number.
---@param value integer value to convert.
---@return string result unsigned 32-bit big-endian string representation of n.
function _M.uint32be(value)
    return string_char(
        bit_rshift(value, 24),
        bit_rshift(value, 16),
        bit_rshift(value, 8),
        bit_band(value, 0xff)
    )
end

---32-bit big-endian representation of number returned as table array.
---@param value integer value to convert.
---@return table result unsigned 32-bit big-endian string representation of n as table array.
function _M.uint32be_array(value)
    return {
        string_char(bit_rshift(value, 24)),
        string_char(bit_rshift(value, 16)),
        string_char(bit_rshift(value, 8)),
        string_char(bit_band(value, 0xff)),
    }
end

return _M
