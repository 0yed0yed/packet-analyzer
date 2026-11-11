"""AES-128 (فك التشفير فقط) + CBC بدون أي مكتبات خارجية.

بيتستخدم كـ fallback لو pycryptodome مش متثبّت (مثلاً على أندرويد، عشان نتجنّب بناء مكتبة C).
أبطأ من pycryptodome، بس كافي لتحليل باكتات.
"""
from __future__ import annotations

from typing import List


def _build_sboxes() -> tuple[List[int], List[int]]:
    """توليد الـ S-box من تعريفها الرياضي (GF(2^8)) بدل جدول مكتوب بالإيد."""
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF   # p *= 3
        q ^= (q << 1) & 0xFF                                              # q /= 3
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        rot = lambda x, n: ((x << n) | (x >> (8 - n))) & 0xFF  # noqa: E731
        sbox[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _build_sboxes()


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


MUL9 = [_mul(i, 9) for i in range(256)]
MUL11 = [_mul(i, 11) for i in range(256)]
MUL13 = [_mul(i, 13) for i in range(256)]
MUL14 = [_mul(i, 14) for i in range(256)]

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def expand_key(key: bytes) -> List[List[int]]:
    """11 round keys (كل واحد 16 بايت) لمفتاح AES-128."""
    if len(key) != 16:
        raise ValueError("only AES-128 (16-byte key) is supported")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]                 # RotWord
            temp = [SBOX[b] for b in temp]             # SubWord
            temp[0] ^= _RCON[i // 4 - 1]
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(11)]


def decrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    """فك بلوك واحد (16 بايت). الـ state مرتّب column-major زي معيار FIPS-197."""
    state = [b ^ k for b, k in zip(block, round_keys[10])]
    for rnd in range(9, -1, -1):
        # InvShiftRows: الصف r بيتزاح يمين r خانات
        shifted = [0] * 16
        for r in range(4):
            for c in range(4):
                shifted[r + 4 * ((c + r) % 4)] = state[r + 4 * c]
        # InvSubBytes + AddRoundKey
        rk = round_keys[rnd]
        state = [INV_SBOX[b] ^ k for b, k in zip(shifted, rk)]
        if rnd:  # InvMixColumns (كل الراوندات ما عدا الأخيرة)
            out = [0] * 16
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = state[c:c + 4]
                out[c] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3]
                out[c + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3]
                out[c + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3]
                out[c + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3]
            state = out
    return bytes(state)


def cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC decrypt. ``data`` لازم يكون مضاعف 16. من غير إزالة padding."""
    if len(data) % 16 or len(iv) != 16:
        raise ValueError("data must be a multiple of 16 bytes and iv 16 bytes")
    round_keys = expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        plain = decrypt_block(block, round_keys)
        out += bytes(a ^ b for a, b in zip(plain, prev))
        prev = block
    return bytes(out)
