"""
AES-128 manual (tanpa library kriptografi) + mode CBC + padding PKCS#7.

Struktur state: list 16 byte, urutan column-major (sama seperti FIPS-197):
    state[r + 4*c]  = baris r, kolom c
"""
import os

# ---------------------------------------------------------------- GF(2^8)
def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B          # polinomial irreducible x^8+x^4+x^3+x+1
    return a & 0xFF


def gmul(a, b):
    """Perkalian di GF(2^8)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r


def _build_sbox():
    # 1) invers perkalian di GF(2^8)  2) transformasi affine  3) XOR 0x63
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if gmul(x, y) == 1:
                inv[x] = y
                break
    sbox = [0] * 256
    for x in range(256):
        b = inv[x]
        s = b
        for i in range(1, 5):
            s ^= ((b << i) | (b >> (8 - i))) & 0xFF   # rotasi kiri i bit
        sbox[x] = s ^ 0x63
    inv_sbox = [0] * 256
    for x in range(256):
        inv_sbox[sbox[x]] = x
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ---------------------------------------------------------- key expansion
def expand_key(key):
    """key: 16 byte -> 11 round key (masing-masing 16 byte)."""
    assert len(key) == 16
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [SBOX[b] for b in t]               # SubWord
            t[0] ^= RCON[i // 4 - 1]               # Rcon
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


# ------------------------------------------------------------ transformasi
def add_round_key(s, rk):
    return [s[i] ^ rk[i] for i in range(16)]


def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    # baris r digeser r byte ke kiri
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def _mix_col(col, m):
    return [
        gmul(col[0], m[(0 - i) % 4]) ^ gmul(col[1], m[(1 - i) % 4]) ^
        gmul(col[2], m[(2 - i) % 4]) ^ gmul(col[3], m[(3 - i) % 4])
        for i in range(4)
    ]


def mix_columns(s):
    out = []
    for c in range(4):
        out += _mix_col(s[4 * c:4 * c + 4], (2, 3, 1, 1))
    return out


def inv_mix_columns(s):
    out = []
    for c in range(4):
        out += _mix_col(s[4 * c:4 * c + 4], (0x0E, 0x0B, 0x0D, 0x09))
    return out


# ------------------------------------------------------------- blok tunggal
def encrypt_block(block, round_keys):
    s = add_round_key(list(block), round_keys[0])
    for r in range(1, 10):
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        s = add_round_key(s, round_keys[r])
    s = sub_bytes(s)
    s = shift_rows(s)
    s = add_round_key(s, round_keys[10])
    return bytes(s)


def decrypt_block(block, round_keys):
    s = add_round_key(list(block), round_keys[10])
    for r in range(9, 0, -1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, round_keys[r])
        s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s, round_keys[0])
    return bytes(s)


# ------------------------------------------------------- CBC + PKCS#7 padding
def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def unpad(data):
    if not data or len(data) % 16:
        raise ValueError("panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("padding tidak valid (key salah / data rusak)")
    return data[:-n]


def encrypt(plaintext, key, iv=None):
    """plaintext, key: bytes (key 16 byte). Return IV(16) + ciphertext."""
    rk = expand_key(key)
    iv = iv if iv is not None else os.urandom(16)
    data = pad(plaintext)
    out, prev = [iv], iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = encrypt_block(blk, rk)
        out.append(prev)
    return b"".join(out)


def decrypt(data, key):
    """data = IV(16) + ciphertext. Return plaintext bytes."""
    if len(data) < 32 or len(data) % 16:
        raise ValueError("ciphertext tidak valid")
    rk = expand_key(key)
    prev, out = data[:16], []
    for i in range(16, len(data), 16):
        c = data[i:i + 16]
        out.append(bytes(a ^ b for a, b in zip(decrypt_block(c, rk), prev)))
        prev = c
    return unpad(b"".join(out))


# ------------------------------------------------------------------ self-test
if __name__ == "__main__":
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = encrypt_block(pt, expand_key(key))
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
    assert decrypt_block(ct, expand_key(key)) == pt
    assert SBOX[0x00] == 0x63 and SBOX[0x53] == 0xED
    msg = b"Halo Bob, ini pesan rahasia dari Alice!"
    assert decrypt(encrypt(msg, b"KunciRahasia1234"), b"KunciRahasia1234") == msg
    print("AES OK (cocok dengan vektor uji FIPS-197)")
