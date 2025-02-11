--!strict
--!native

-- AES S–box
local sbox = buffer.fromstring(
	"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76" ..
	"\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0" ..
	"\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15" ..
	"\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75" ..
	"\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84" ..
	"\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf" ..
	"\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8" ..
	"\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2" ..
	"\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73" ..
	"\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb" ..
	"\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79" ..
	"\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08" ..
	"\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a" ..
	"\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e" ..
	"\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf" ..
	"\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16"
)

-- GF(2^8) multiplication helpers
local function mul2(x: number)
	local res = bit32.band(bit32.lshift(x, 1), 0xFF)
	if bit32.band(x, 0x80) ~= 0 then
		res = bit32.bxor(res, 0x1B)
	end
	return res
end

local function mul3(x: number)
	return bit32.bxor(mul2(x), x)
end

-- Precompute the T–tables.
local T0 = buffer.create(256 * 4)
local T1 = buffer.create(256 * 4)
local T2 = buffer.create(256 * 4)
local T3 = buffer.create(256 * 4)
for s = 0, 255 do
	local t = bit32.bor(bit32.lshift(mul2(s), 24),
		bit32.lshift(s, 16),
		bit32.lshift(s, 8),
		mul3(s))
	buffer.writeu32(T0, s * 4, t)
	buffer.writeu32(T1, s * 4, bit32.lrotate(t, 24))
	buffer.writeu32(T2, s * 4, bit32.lrotate(t, 16))
	buffer.writeu32(T3, s * 4, bit32.lrotate(t, 8))
end

local function aesenc(out: buffer, out_offset: number, block: buffer, block_offset: number, round_key: buffer)
	local a0 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 0))
	local a1 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 5))
	local a2 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 10))
	local a3 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 15))

	local b0 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 4))
	local b1 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 9))
	local b2 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 14))
	local b3 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 3))

	local c0 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 8))
	local c1 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 13))
	local c2 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 2))
	local c3 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 7))

	local d0 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 12))
	local d1 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 1))
	local d2 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 6))
	local d3 = buffer.readu8(sbox, buffer.readu8(block, block_offset + 11))

	local a_word = bit32.bxor(
		buffer.readu32(T0, a0 * 4),
		buffer.readu32(T1, a1 * 4),
		buffer.readu32(T2, a2 * 4),
		buffer.readu32(T3, a3 * 4)
	)
	local b_word = bit32.bxor(
		buffer.readu32(T0, b0 * 4),
		buffer.readu32(T1, b1 * 4),
		buffer.readu32(T2, b2 * 4),
		buffer.readu32(T3, b3 * 4)
	)
	local c_word = bit32.bxor(
		buffer.readu32(T0, c0 * 4),
		buffer.readu32(T1, c1 * 4),
		buffer.readu32(T2, c2 * 4),
		buffer.readu32(T3, c3 * 4)
	)
	local d_word = bit32.bxor(
		buffer.readu32(T0, d0 * 4),
		buffer.readu32(T1, d1 * 4),
		buffer.readu32(T2, d2 * 4),
		buffer.readu32(T3, d3 * 4)
	)

	local a_rkWord = bit32.byteswap(buffer.readu32(round_key, 0))
	local b_rkWord = bit32.byteswap(buffer.readu32(round_key, 4))
	local c_rkWord = bit32.byteswap(buffer.readu32(round_key, 8))
	local d_rkWord = bit32.byteswap(buffer.readu32(round_key, 12))
	buffer.writeu32(out, out_offset, bit32.byteswap(bit32.bxor(a_word, a_rkWord)))
	buffer.writeu32(out, out_offset + 4, bit32.byteswap(bit32.bxor(b_word, b_rkWord)))
	buffer.writeu32(out, out_offset + 8, bit32.byteswap(bit32.bxor(c_word, c_rkWord)))
	buffer.writeu32(out, out_offset + 12, bit32.byteswap(bit32.bxor(d_word, d_rkWord)))
end

return aesenc
