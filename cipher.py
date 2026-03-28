"""
=============================================================================
  Mini Block Cipher — Project #22 (FINAL VERSION)
=============================================================================
  + SPN (64-bit, 8 rounds)
  + CBC mode (entropy improvement)
  + Key derivation (SHA-256 → 64-bit)
  + PKCS7 padding
=============================================================================
"""

import math
import random
import time
import hashlib


# =============================================================================
# CONSTANTS
# =============================================================================

MASK64 = 0xFFFFFFFFFFFFFFFF
MASK8  = 0xFF

ROUND_CONSTANTS = [
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
]

SHIFT_AMOUNTS = [3, 7, 11, 13, 17, 19, 23, 29]


# =============================================================================
# S-BOX
# =============================================================================

SBOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7,
]

INV_SBOX = [0] * 16
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i


# =============================================================================
# P-BOX
# =============================================================================

PBOX = [
     4,20,36,52, 5,21,37,53,
     6,22,38,54, 7,23,39,55,
     0,16,32,48, 1,17,33,49,
     2,18,34,50, 3,19,35,51,
    12,28,44,60,13,29,45,61,
    14,30,46,62,15,31,47,63,
     8,24,40,56, 9,25,41,57,
    10,26,42,58,11,27,43,59,
]

INV_PBOX = [0]*64
for i,v in enumerate(PBOX):
    INV_PBOX[v] = i


# =============================================================================
# HELPERS
# =============================================================================

def rot_left_64(val, n):
    n %= 64
    return ((val << n) | (val >> (64 - n))) & MASK64


def apply_sbox(block, sbox):
    result = 0
    for i in range(16):
        nibble = (block >> (i*4)) & 0xF
        result |= sbox[nibble] << (i*4)
    return result


def apply_pbox(block, pbox):
    result = 0
    for i in range(64):
        bit = (block >> i) & 1
        result |= bit << pbox[i]
    return result


def mix_add_mod(block):
    b = [(block >> (i*8)) & MASK8 for i in range(8)]
    m = [(b[i] + b[i+1]) & MASK8 for i in range(7)] + [b[7]]
    result = 0
    for i,v in enumerate(m):
        result |= v << (i*8)
    return result


def inv_mix_add_mod(block):
    m = [(block >> (i*8)) & MASK8 for i in range(8)]
    b = [0]*8
    b[7] = m[7]
    for i in range(6,-1,-1):
        b[i] = (m[i] - b[i+1]) & MASK8
    result = 0
    for i,v in enumerate(b):
        result |= v << (i*8)
    return result


# =============================================================================
# KEY DERIVATION (NEW)
# =============================================================================

def derive_key(password: str) -> bytes:
    digest = hashlib.sha256(password.encode()).digest()
    return digest[:8]


# =============================================================================
# KEY SCHEDULE
# =============================================================================

def key_schedule(key):
    subkeys = []
    k = key & MASK64
    for i in range(8):
        k = rot_left_64(k,7)
        k ^= ROUND_CONSTANTS[i]
        subkeys.append(k)
    return subkeys


# =============================================================================
# BLOCK ENCRYPT / DECRYPT
# =============================================================================

def encrypt_block(pt, key):
    subkeys = key_schedule(key)
    state = pt ^ key

    for r in range(8):
        state = apply_sbox(state, SBOX)
        state = apply_pbox(state, PBOX)
        state = mix_add_mod(state)

        sk = subkeys[r]
        state = (state + sk) & MASK64
        state ^= rot_left_64(sk,13)
        state = rot_left_64(state, SHIFT_AMOUNTS[r])

    return state


def decrypt_block(ct, key):
    subkeys = key_schedule(key)
    state = ct

    for r in reversed(range(8)):
        state = rot_left_64(state, 64-SHIFT_AMOUNTS[r])
        sk = subkeys[r]
        state ^= rot_left_64(sk,13)
        state = (state - sk) & MASK64
        state = inv_mix_add_mod(state)
        state = apply_pbox(state, INV_PBOX)
        state = apply_sbox(state, INV_SBOX)

    return state ^ key


# =============================================================================
# CBC MODE (NEW)
# =============================================================================

def encrypt_cbc(plaintext, key_bytes, iv=None):
    if iv is None:
        iv = random.randbytes(8)

    pad_len = 8 - (len(plaintext)%8)
    plaintext += bytes([pad_len]*pad_len)

    key = int.from_bytes(key_bytes,'big')
    prev = int.from_bytes(iv,'big')

    ciphertext = iv

    for i in range(0,len(plaintext),8):
        block = int.from_bytes(plaintext[i:i+8],'big')
        block ^= prev
        ct = encrypt_block(block,key)
        ciphertext += ct.to_bytes(8,'big')
        prev = ct

    return ciphertext


def decrypt_cbc(ciphertext, key_bytes):
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]

    key = int.from_bytes(key_bytes,'big')
    prev = int.from_bytes(iv,'big')

    plaintext = b''

    for i in range(0,len(ciphertext),8):
        block = int.from_bytes(ciphertext[i:i+8],'big')
        pt = decrypt_block(block,key)
        pt ^= prev
        plaintext += pt.to_bytes(8,'big')
        prev = block

    pad_len = plaintext[-1]
    return plaintext[:-pad_len]


# =============================================================================
# DEMO
# =============================================================================

def demo():
    print("\n=== DEMO CBC + KEY DERIVATION ===")

    password = "SecurePassword123"
    key = derive_key(password)

    message = b"Hello Hello Hello Hello Hello Hello"

    ct = encrypt_cbc(message, key)
    rec = decrypt_cbc(ct, key)

    print("Password :", password)
    print("Key      :", key.hex())
    print("Plaintext:", message)
    print("Cipher   :", ct.hex())
    print("Recovered:", rec)
    print("Match    :", rec == message)


if __name__ == "__main__":
    demo()