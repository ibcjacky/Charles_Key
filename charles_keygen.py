# -*- coding: utf-8 -*-
import struct
import random
from ctypes import c_int32, c_uint32

# ----- 核心算法部分 -----
rounds = 12
roundKeys = 2 * (rounds + 1)


def rotate_left(x, y):
    y &= 0x1F
    return c_int32((x << y) | (c_uint32(x).value >> (32 - y))).value


def rotate_right(x, y):
    y &= 0x1F
    return c_int32((c_uint32(x).value >> y) | (x << (32 - y))).value


def pk_long(a, b):
    return (a & 0xFFFFFFFF) | (b << 32)


class CkCipher:
    def __init__(self, ck_key):
        self.rk = [0] * roundKeys

        ld = [
            c_int32(ck_key & 0xFFFFFFFF).value,
            c_int32((ck_key >> 32) & 0xFFFFFFFF).value
        ]

        self.rk[0] = -1209970333
        for i in range(1, roundKeys):
            self.rk[i] = c_int32(self.rk[i - 1] + -1640531527).value

        a, b = 0, 0
        i, j = 0, 0

        for _ in range(3 * roundKeys):
            self.rk[i] = rotate_left(c_int32(self.rk[i] + (a + b)).value, 3)
            a = self.rk[i]
            ld[j] = rotate_left(c_int32(ld[j] + (a + b)).value, a + b)
            b = ld[j]
            i = (i + 1) % roundKeys
            j = (j + 1) % 2

    def encrypt(self, in_val):
        a = c_int32((in_val & 0xFFFFFFFF) + self.rk[0]).value
        b = c_int32(((in_val >> 32) & 0xFFFFFFFF) + self.rk[1]).value

        for r in range(1, rounds + 1):
            a = rotate_left(a ^ b, b) + self.rk[2 * r]
            a = c_int32(a).value
            b = rotate_left(b ^ a, a) + self.rk[2 * r + 1]
            b = c_int32(b).value

        return pk_long(a, b)

    def decrypt(self, in_val):
        a = c_int32(in_val & 0xFFFFFFFF).value
        b = c_int32((in_val >> 32) & 0xFFFFFFFF).value

        for i in range(rounds, 0, -1):
            b = rotate_right(b - self.rk[2 * i + 1], a) ^ a
            b = c_int32(b).value
            a = rotate_right(a - self.rk[2 * i], b) ^ b
            a = c_int32(a).value

        b = c_int32(b - self.rk[1]).value
        a = c_int32(a - self.rk[0]).value
        return pk_long(a, b)


def crack(text):
    name = text.encode('utf-8')
    length = len(name) + 4
    padded = ((-length) & (8 - 1)) + length

    if padded < 8:
        padded = 8

    buff = struct.pack('>I', len(name)) + name
    buff = buff.ljust(padded, b'\x00')

    ck_name = 0x7a21c951691cd470
    ck_key = -5408575981733630035
    ck = CkCipher(ck_name)
    out_buff = bytearray()

    for i in range(0, padded, 8):
        chunk = buff[i:i + 8]
        now_var = struct.unpack('>Q', chunk.ljust(8, b'\x00'))[0]
        dd = ck.encrypt(now_var)
        dd_unsigned = dd & 0xFFFFFFFFFFFFFFFF
        out_buff.extend(struct.pack('>Q', dd_unsigned))

    n = 0
    for b in out_buff:
        signed_byte = struct.unpack('b', bytes([b]))[0] if b > 127 else b
        n = rotate_left(n ^ signed_byte, 0x3)

    prefix = c_int32(n ^ 0x54882f8a).value
    suffix = c_int32(random.randint(0, 0x7FFFFFFF)).value

    in_val = (prefix << 32) & 0xFFFFFFFF00000000
    s = suffix

    if (s >> 16) in [0x0401, 0x0402, 0x0403]:
        in_val |= c_uint32(s).value
    else:
        in_val |= 0x01000000 | (c_uint32(s).value & 0xFFFFFF)

    out = CkCipher(ck_key).decrypt(in_val)

    n2 = 0
    for i in range(56, -8, -8):
        n2 ^= (in_val >> i) & 0xFF

    vv = c_int32(n2 & 0xFF).value
    if vv < 0:
        vv = -vv

    return f"{vv:02x}{out & 0xFFFFFFFFFFFFFFFF:016x}"


if __name__ == '__main__':
    print(crack("123456789"))
