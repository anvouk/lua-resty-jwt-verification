local bit = require("bit")

local _M = {}

---64-bit big-endian representation of number.
---@param value integer value to convert.
---@return string result unsigned 64-bit big-endian string representation of n.
function _M.uint64be(value)
    local hi = bit.rshift(value, 29)
    local lo = bit.lshift(value, 3)
    return string.char(
        bit.rshift(hi, 24),
        bit.rshift(hi, 16),
        bit.rshift(hi, 8),
        bit.band(hi, 0xff),
        bit.rshift(lo, 24),
        bit.rshift(lo, 16),
        bit.rshift(lo, 8),
        bit.band(lo, 0xff)
    )
end

---32-bit big-endian representation of number.
---@param value integer value to convert.
---@return string result unsigned 32-bit big-endian string representation of n.
function _M.uint32be(value)
    return string.char(
        bit.rshift(value, 24),
        bit.rshift(value, 16),
        bit.rshift(value, 8),
        bit.band(value, 0xff)
    )
end

---32-bit big-endian representation of number returned as table array.
---@param value integer value to convert.
---@return table result unsigned 32-bit big-endian string representation of n as table array.
function _M.uint32be_array(value)
    return {
        string.char(bit.rshift(value, 24)),
        string.char(bit.rshift(value, 16)),
        string.char(bit.rshift(value, 8)),
        string.char(bit.band(value, 0xff)),
    }
end

return _M
