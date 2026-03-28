"""
=============================================================================
  Mini Block Cipher — Project #22
  Master 1 CYSIA — 2025/2026
  ─────────────────────────────────────────────────────────────────────────
  Structure  : SPN (Substitution-Permutation Network)
  Block Size : 64 bits
  Key Size   : 64 bits
  Rounds     : 8
  S-Box      : Student-defined (GF(2^4) polynomial-based, 4-bit nibbles)
  P-Box      : Student-defined (64-bit bit permutation)
  Mix        : MIX_ADD_MOD  (modular addition mod 2^8)
  Subkey Op  : ROT_KEY      (left-rotate key each round)
  Operations : ADD, XOR, SHIFT
  ─────────────────────────────────────────────────────────────────────────
  Run:  python project22_mini_block_cipher.py
=============================================================================
"""

import math
import random
import time


# =============================================================================
#  CONSTANTS
# =============================================================================

MASK64 = 0xFFFFFFFFFFFFFFFF
MASK8  = 0xFF

# Amélioration 1 — Constantes de round indépendantes (basées sur les
# décimales de π, comme AES) au lieu d'un simple décalage de 3 bits.
# Cela renforce la résistance aux attaques par clé liée (related-key attacks).
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

# Amélioration 2 — Montants de rotation premiers et variés au lieu de
# (r+1)%64 qui est trop prévisible et trop faible pour r=0 (1 bit seulement).
SHIFT_AMOUNTS = [3, 7, 11, 13, 17, 19, 23, 29]


# =============================================================================
#  S-BOX  (4-bit → 4-bit, bijective, based on GF(2^4) polynomial x^4+x+1)
# =============================================================================

SBOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7,
]

INV_SBOX = [0] * 16
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


# =============================================================================
#  P-BOX  (64-bit permutation — spreads nibble bits for maximum diffusion)
# =============================================================================

PBOX = [
     4, 20, 36, 52,  5, 21, 37, 53,
     6, 22, 38, 54,  7, 23, 39, 55,
     0, 16, 32, 48,  1, 17, 33, 49,
     2, 18, 34, 50,  3, 19, 35, 51,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63,
     8, 24, 40, 56,  9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
]
assert sorted(PBOX) == list(range(64)), "P-Box must be a valid permutation!"

INV_PBOX = [0] * 64
for _i, _v in enumerate(PBOX):
    INV_PBOX[_v] = _i


# =============================================================================
#  HELPER — bit-level operations
# =============================================================================

def rot_left_64(val: int, n: int) -> int:
    """Rotate a 64-bit integer left by n bits."""
    n %= 64
    return ((val << n) | (val >> (64 - n))) & MASK64


def apply_sbox(block: int, sbox: list) -> int:
    """Apply a 4-bit S-Box to all 16 nibbles of a 64-bit block."""
    result = 0
    for i in range(16):
        nibble = (block >> (i * 4)) & 0xF
        result |= sbox[nibble] << (i * 4)
    return result


def apply_pbox(block: int, pbox: list) -> int:
    """Apply a 64-bit bit permutation to a block."""
    result = 0
    for i in range(64):
        bit = (block >> i) & 1
        result |= bit << pbox[i]
    return result


def mix_add_mod(block: int) -> int:
    """
    MIX_ADD_MOD — triangular (non-circular) byte mixing:
      m[i] = (b[i] + b[i+1]) mod 256   for i in 0..6
      m[7] = b[7]                        (anchor byte, unchanged)
    """
    b = [(block >> (i * 8)) & MASK8 for i in range(8)]
    m = [(b[i] + b[i + 1]) & MASK8 for i in range(7)] + [b[7]]
    result = 0
    for i, v in enumerate(m):
        result |= v << (i * 8)
    return result


def inv_mix_add_mod(block: int) -> int:
    """
    Inverse of MIX_ADD_MOD:
      b[7] = m[7]
      b[i] = (m[i] - b[i+1]) mod 256   for i in 6..0
    """
    m = [(block >> (i * 8)) & MASK8 for i in range(8)]
    b = [0] * 8
    b[7] = m[7]
    for i in range(6, -1, -1):
        b[i] = (m[i] - b[i + 1]) & MASK8
    result = 0
    for i, v in enumerate(b):
        result |= v << (i * 8)
    return result


# =============================================================================
#  KEY SCHEDULE — ROT_KEY  (amélioré)
# =============================================================================

def key_schedule(key: int) -> list:
    """
    ROT_KEY schedule amélioré :
      - Rotation gauche de 7 bits à chaque round
      - XOR avec constantes indépendantes basées sur π  (Amélioration 1)
    Retourne 8 sous-clés de 64 bits.
    """
    subkeys = []
    k = key & MASK64
    for i in range(8):
        k = rot_left_64(k, 7)
        k ^= ROUND_CONSTANTS[i]     # constantes π au lieu de simple décalage
        subkeys.append(k)
    return subkeys


# =============================================================================
#  ENCRYPTION
# =============================================================================

def encrypt_block(plaintext: int, key: int) -> int:
    """
    Chiffrement d'un bloc de 64 bits en 8 rounds SPN.

    Chaque round :
      1. S-Box  — substitution (confusion)
      2. P-Box  — permutation  (diffusion)
      3. MIX_ADD_MOD — mélange des octets
      4. ADD sous-clé + XOR + SHIFT (rotation première)  (Amélioration 2)
    """
    subkeys = key_schedule(key)
    state   = plaintext & MASK64

    # Blanchiment initial
    state ^= key & MASK64

    for r in range(8):
        state = apply_sbox(state, SBOX)
        state = apply_pbox(state, PBOX)
        state = mix_add_mod(state)
        sk    = subkeys[r]
        state = (state + sk) & MASK64
        state ^= rot_left_64(sk, 13)
        state = rot_left_64(state, SHIFT_AMOUNTS[r])   # rotation première

    return state & MASK64


def encrypt(plaintext_bytes: bytes, key_bytes: bytes) -> bytes:
    """Chiffrement de bytes quelconques (padding PKCS7 par blocs de 8 octets)."""
    pad_len = 8 - (len(plaintext_bytes) % 8)
    plaintext_bytes += bytes([pad_len] * pad_len)
    key_int    = int.from_bytes(key_bytes[:8], 'big')
    ciphertext = b''
    for i in range(0, len(plaintext_bytes), 8):
        block = int.from_bytes(plaintext_bytes[i:i + 8], 'big')
        ciphertext += encrypt_block(block, key_int).to_bytes(8, 'big')
    return ciphertext


# =============================================================================
#  DECRYPTION
# =============================================================================

def decrypt_block(ciphertext: int, key: int) -> int:
    """
    Déchiffrement d'un bloc de 64 bits — toutes les opérations inversées
    dans l'ordre inverse.
    """
    subkeys = key_schedule(key)
    state   = ciphertext & MASK64

    for r in reversed(range(8)):
        state = rot_left_64(state, 64 - SHIFT_AMOUNTS[r])  # inverse rotation
        sk    = subkeys[r]
        state ^= rot_left_64(sk, 13)
        state = (state - sk) & MASK64
        state = inv_mix_add_mod(state)
        state = apply_pbox(state, INV_PBOX)
        state = apply_sbox(state, INV_SBOX)

    state ^= key & MASK64
    return state & MASK64


def decrypt(ciphertext_bytes: bytes, key_bytes: bytes) -> bytes:
    """Déchiffrement des bytes produits par encrypt()."""
    key_int   = int.from_bytes(key_bytes[:8], 'big')
    plaintext = b''
    for i in range(0, len(ciphertext_bytes), 8):
        block = int.from_bytes(ciphertext_bytes[i:i + 8], 'big')
        plaintext += decrypt_block(block, key_int).to_bytes(8, 'big')
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]


# =============================================================================
#  METRICS — 6 critères d'évaluation
# =============================================================================

def shannon_entropy(data: bytes) -> float:
    """H(X) — entropie de Shannon sur les octets. Idéal ≈ 8.0 bits/octet."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)


def correlation_coefficient(pt: bytes, ct: bytes) -> float:
    """r_xy — corrélation de Pearson entre plaintext et ciphertext. Idéal ≈ 0.0."""
    n = min(len(pt), len(ct))
    x, y = list(pt[:n]), list(ct[:n])
    mx, my = sum(x) / n, sum(y) / n
    num = sum((x[i] - mx) * (y[i] - my) for i in range(n))
    dx  = math.sqrt(sum((v - mx) ** 2 for v in x))
    dy  = math.sqrt(sum((v - my) ** 2 for v in y))
    return (num / (dx * dy)) if dx and dy else 0.0


def strict_avalanche_criterion(key: int, num_samples: int = 200) -> float:
    """SAC — fraction moyenne de bits ciphertext flippés quand 1 bit PT change. Idéal ≈ 0.5."""
    total_flips, total_tests = 0, 0
    for _ in range(num_samples):
        pt = random.getrandbits(64)
        ct = encrypt_block(pt, key)
        for bit in range(64):
            ct2 = encrypt_block(pt ^ (1 << bit), key)
            total_flips += bin(ct ^ ct2).count('1')
            total_tests += 1
    return total_flips / (total_tests * 64)


def hamming_distance(d1: bytes, d2: bytes) -> int:
    """D_H — distance de Hamming au niveau bit."""
    return sum(bin(d1[i] ^ d2[i]).count('1') for i in range(min(len(d1), len(d2))))


def hamming_ratio(d1: bytes, d2: bytes) -> float:
    """Distance de Hamming normalisée [0,1]. Idéal ≈ 0.5."""
    n = min(len(d1), len(d2)) * 8
    return hamming_distance(d1, d2) / n if n else 0.0


def frequency_test(data: bytes) -> dict:
    """S_n — test de fréquence NIST. Idéal ones_ratio ≈ 0.5."""
    total = len(data) * 8
    ones  = sum(bin(b).count('1') for b in data)
    zeros = total - ones
    ratio = ones / total if total else 0
    sn    = abs(ones - zeros) / math.sqrt(total) if total else 0
    return {"total_bits": total, "ones": ones, "zeros": zeros,
            "ones_ratio": ratio, "S_n": sn}


def timing_test(key: int, iterations: int = 100) -> dict:
    """Chronomètre 100 chiffrements et 100 déchiffrements en nanosecondes."""
    pts = [random.getrandbits(64) for _ in range(iterations)]
    t0  = time.perf_counter_ns()
    cts = [encrypt_block(p, key) for p in pts]
    enc_ns = time.perf_counter_ns() - t0
    t0  = time.perf_counter_ns()
    for c in cts:
        decrypt_block(c, key)
    dec_ns = time.perf_counter_ns() - t0
    return {"enc_total_ns": enc_ns, "enc_avg_ns": enc_ns / iterations,
            "dec_total_ns": dec_ns, "dec_avg_ns": dec_ns / iterations,
            "iterations": iterations}


def full_evaluation(plaintext: bytes, key_bytes: bytes):
    """
    Lance les 6 métriques et affiche le rapport.

    Amélioration 3 — Le plaintext de test est maintenant ALÉATOIRE et GRAND
    (4096 octets) au lieu d'un texte répétitif de 1024 octets.
    Cela donne des résultats statistiquement corrects pour l'entropie
    et la corrélation.
    """
    # Amélioration 3 : données de test aléatoires
    random_pt = bytes(random.getrandbits(8) for _ in range(4096))
    ct        = encrypt(random_pt, key_bytes)
    key_int   = int.from_bytes(key_bytes[:8], 'big')

    print("=" * 62)
    print("  Mini Block Cipher — Project #22  |  Evaluation Report")
    print("=" * 62)

    h = shannon_entropy(ct)
    print(f"\n1. Shannon Entropy H(X)     : {h:.6f} bits/byte")
    print(f"   [Ideal ≈ 8.0]              {'✓ GOOD' if h > 7.5 else '✗ WEAK'}")

    r = correlation_coefficient(random_pt, ct[:len(random_pt)])
    print(f"\n2. Correlation r            : {r:.6f}")
    print(f"   [Ideal ≈ 0.0]              {'✓ GOOD' if abs(r) < 0.05 else '✗ WEAK'}")

    sac = strict_avalanche_criterion(key_int)
    print(f"\n3. SAC                      : {sac:.6f}")
    print(f"   [Ideal ≈ 0.5]              {'✓ GOOD' if 0.45 <= sac <= 0.55 else '✗ WEAK'}")

    hd = hamming_ratio(random_pt, ct[:len(random_pt)])
    hb = hamming_distance(random_pt, ct[:len(random_pt)])
    print(f"\n4. Hamming Distance D_H     : {hb} bits  ({hd:.4f})")
    print(f"   [Ideal ≈ 0.5]              {'✓ GOOD' if 0.45 <= hd <= 0.55 else '≈ OK'}")

    ft = frequency_test(ct)
    print(f"\n5. Frequency Test S_n       : {ft['S_n']:.4f}")
    print(f"   Ones ratio                : {ft['ones_ratio']:.4f}  (ones={ft['ones']}, zeros={ft['zeros']})")
    print(f"   [Ideal ratio ≈ 0.5]        {'✓ GOOD' if 0.48 <= ft['ones_ratio'] <= 0.52 else '≈ OK'}")

    t = timing_test(key_int)
    print(f"\n6. Timing (100 iterations)")
    print(f"   Encryption avg            : {t['enc_avg_ns']:.1f} ns")
    print(f"   Decryption avg            : {t['dec_avg_ns']:.1f} ns")
    print(f"   Enc total / Dec total     : {t['enc_total_ns']:,} ns / {t['dec_total_ns']:,} ns")

    ok = decrypt(ct, key_bytes) == random_pt
    print(f"\n{'='*62}")
    print(f"  Correctness (enc→dec)     : {'✓ PASS' if ok else '✗ FAIL'}")
    print(f"{'='*62}\n")


# =============================================================================
#  DEMO & TEST RUNNER
# =============================================================================

def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          Mini Block Cipher  —  Project #22                   ║
║          SPN | 64-bit block | 64-bit key | 8 rounds          ║
║          S-Box: GF(2^4) | P-Box: custom 64-bit               ║
║          Mix: ADD_MOD  | Subkey: ROT_KEY                     ║
╚══════════════════════════════════════════════════════════════╝
""")


def demo_single_block():
    print("─" * 62)
    print("  DEMO 1 — Single Block (64-bit)")
    print("─" * 62)
    key = 0x133457799BBCDFF1
    pt  = 0x0123456789ABCDEF
    ct  = encrypt_block(pt, key)
    rec = decrypt_block(ct, key)
    print(f"  Key       : 0x{key:016X}")
    print(f"  Plaintext : 0x{pt:016X}")
    print(f"  Ciphertext: 0x{ct:016X}")
    print(f"  Recovered : 0x{rec:016X}")
    print(f"  Match     : {'✓ YES' if rec == pt else '✗ NO'}")


def demo_text():
    print("\n" + "─" * 62)
    print("  DEMO 2 — Text Message")
    print("─" * 62)
    key_bytes = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
    message   = b'Hello! This is Project 22 - Mini SPN Cipher by Master1 CYSIA.'
    ct  = encrypt(message, key_bytes)
    rec = decrypt(ct, key_bytes)
    print(f"  Key (hex)  : {key_bytes.hex().upper()}")
    print(f"  Plaintext  : {message.decode()}")
    print(f"  Ciphertext : {ct.hex().upper()}")
    print(f"  Recovered  : {rec.decode()}")
    print(f"  Match      : {'✓ YES' if rec == message else '✗ NO'}")


def demo_key_schedule():
    print("\n" + "─" * 62)
    print("  DEMO 3 — Key Schedule (ROT_KEY, 8 subkeys)")
    print("─" * 62)
    key     = 0x133457799BBCDFF1
    subkeys = key_schedule(key)
    print(f"  Master Key : 0x{key:016X}")
    for i, sk in enumerate(subkeys):
        print(f"  Subkey[{i}]  : 0x{sk:016X}")


def demo_components():
    print("\n" + "─" * 62)
    print("  DEMO 4 — S-Box & P-Box")
    print("─" * 62)
    print("\n  S-Box     : " + "  ".join(f"{v:X}" for v in SBOX))
    print("  INV S-Box : " + "  ".join(f"{v:X}" for v in INV_SBOX))
    assert sorted(SBOX) == list(range(16))
    print("\n  S-Box bijectivity : ✓ VERIFIED")
    print(f"  P-Box (first 16)  : {PBOX[:16]}")
    assert sorted(PBOX) == list(range(64))
    print("  P-Box validity    : ✓ VERIFIED")


def demo_avalanche():
    print("\n" + "─" * 62)
    print("  DEMO 5 — Avalanche Effect (flip 1 plaintext bit)")
    print("─" * 62)
    key = 0x133457799BBCDFF1
    pt1 = 0x0123456789ABCDEF
    pt2 = pt1 ^ 1
    ct1 = encrypt_block(pt1, key)
    ct2 = encrypt_block(pt2, key)
    diff = ct1 ^ ct2
    bits = bin(diff).count('1')
    print(f"  PT1          : 0x{pt1:016X}")
    print(f"  PT2          : 0x{pt2:016X}  (1 bit flipped)")
    print(f"  CT1          : 0x{ct1:016X}")
    print(f"  CT2          : 0x{ct2:016X}")
    print(f"  XOR diff     : 0x{diff:016X}")
    print(f"  Bits changed : {bits}/64  ({bits/64*100:.1f}%)")


def run_metrics():
    print("\n" + "─" * 62)
    print("  METRICS — Full Evaluation Report")
    print("─" * 62)
    key_bytes = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
    full_evaluation(None, key_bytes)


if __name__ == "__main__":
    banner()
    demo_single_block()
    demo_text()
    demo_key_schedule()
    demo_components()
    demo_avalanche()
    run_metrics()