"""
=============================================================================
  Mini Block Cipher — Project #22 (FINAL OPTIMIZED + PRO VERSION)
  Master 1 CYSIA — 2025/2026
  ─────────────────────────────────────────────────────────────────────────
  Structure  : SPN (Substitution-Permutation Network)
  Block Size : 64 bits
  Key Size   : 64 bits
  Rounds     : 8
  S-Box      : Student-defined (dynamically generated from GF(2^4) + improved affine)
  P-Box      : Student-defined (64-bit bit permutation)
  Mix        : MIX_ADD_MOD  (modular addition mod 2^8)
  Subkey Op  : NL_KEY       (ROT + SBOX + ADD_MOD + XOR — non-lineaire)
  Operations : ADD, XOR, SHIFT
  Modes      : CTR
  ─────────────────────────────────────────────────────────────────────────
  Run:  python project22_mini_block_cipher.py
=============================================================================
"""

import math
import os
import random
import time
import secrets
import hashlib
import hmac


# =============================================================================
#  CUSTOM EXCEPTIONS (NEW)
# =============================================================================

class PaddingError(Exception):
    pass

class MACError(Exception):
    pass


# =============================================================================
#  CONSTANTS
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
#  S-BOX
# =============================================================================

# =============================================================================
#  S-BOX 8x8 haute non-linéarité
# =============================================================================
def generate_sbox_gf256():
    poly = 0x11B  # x^8 + x^4 + x^3 + x + 1 (AES standard)

    def gf_mult(a, b):
        res = 0
        while b:
            if b & 1:
                res ^= a
            a <<= 1
            if a & 0x100:
                a ^= poly
            b >>= 1
        return res & 0xFF

    def gf_inv(a):
        if a == 0:
            return 0
        for x in range(1, 256):
            if gf_mult(a, x) == 1:
                return x
        return 0

    def affine(x):
        # transformation affine simple
        x = x & 0xFF
        return x ^ ((x << 1 | x >> 7) & 0xFF) ^ ((x << 2 | x >> 6) & 0xFF) ^ 0x63

    sbox = [affine(gf_inv(i)) for i in range(256)]
    return sbox

SBOX = generate_sbox_gf256()
INV_SBOX = [0]*256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# =============================================================================
#  Diffusion XOR après S-Box
# =============================================================================
def xor_diffusion(state: int) -> int:
    b = [(state >> (8*i)) & 0xFF for i in range(8)]
    for i in range(8):
        b[i] ^= b[(i+1)%8]
    result = 0
    for i, v in enumerate(b):
        result |= (v & 0xFF) << (i*8)
    return result

def inv_xor_diffusion(state: int) -> int:
    b = [(state >> (8*i)) & 0xFF for i in range(8)]
    for i in reversed(range(8)):
        b[i] ^= b[(i+1)%8]
    result = 0
    for i, v in enumerate(b):
        result |= (v & 0xFF) << (i*8)
    return result

# =============================================================================
#  P-BOX
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
#  HELPER
# =============================================================================

def rot_left_64(val: int, n: int) -> int:
    n %= 64
    return ((val << n) | (val >> (64 - n))) & MASK64


def apply_sbox(block: int, sbox: list) -> int:
    result = 0
    for i in range(8):
        byte = (block >> (i * 8)) & 0xFF
        result |= sbox[byte] << (i * 8)
    return result


def apply_pbox(block: int, pbox: list) -> int:
    result = 0
    for i in range(64):
        bit = (block >> i) & 1
        result |= bit << pbox[i]
    return result


def mix_add_mod(block: int) -> int:
    b = [(block >> (i * 8)) & MASK8 for i in range(8)]
    m = [(b[i] + b[i + 1]) & MASK8 for i in range(7)] + [b[7]]
    result = 0
    for i, v in enumerate(m):
        result |= v << (i * 8)
    return result


def inv_mix_add_mod(block: int) -> int:
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
#  KEY SCHEDULE
# =============================================================================

def key_schedule(key: int) -> list:
    """
    Key schedule non-lineaire (Option 2 — Robuste).

    Chaque round applique :
      1. ROT gauche de 7 bits         (diffusion lineaire)
      2. S-Box sur les 8 octets       (non-linearite GF(2^8))
      3. Addition mod 2^64 avec RC[i] (casse la structure GF(2))
      4. XOR avec RC[i] decale        (confusion supplementaire)

    Resultat : k_i = f_non-lineaire(k_{i-1})
    => impossible de retrouver k_{i-1} depuis k_i sans inverser la S-Box.
    => resistance aux attaques related-key et slide attacks.
    """
    subkeys = []
    k = key & MASK64
    for i in range(8):
        k = rot_left_64(k, 7)                            # diffusion
        k = apply_sbox(k, SBOX)                          # non-linearite
        k = (k + ROUND_CONSTANTS[i]) & MASK64            # addition mod 2^64
        k ^= rot_left_64(ROUND_CONSTANTS[i], 17)         # XOR decale
        subkeys.append(k)
    return subkeys


# =============================================================================
#  ENCRYPTION / DECRYPTION (block level)
# =============================================================================

def encrypt_block(plaintext: int, key: int) -> int:
    subkeys = key_schedule(key)
    state   = plaintext & MASK64
    state ^= key & MASK64
    for r in range(8):
        # Rond avec diffusion XOR
        state = apply_sbox(state, SBOX)       # Substitution
        state = xor_diffusion(state)          # <--- Nouvelle diffusion
        state = apply_pbox(state, PBOX)       # Permutation
        state = mix_add_mod(state)            # Diffusion simple
        sk = subkeys[r]
        state = (state + sk) & MASK64
        state ^= rot_left_64(sk, 13)
        state = rot_left_64(state, SHIFT_AMOUNTS[r])
    return state & MASK64


def decrypt_block(ciphertext: int, key: int) -> int:
    subkeys = key_schedule(key)
    state   = ciphertext & MASK64
    for r in reversed(range(8)):
        state = rot_left_64(state, 64 - SHIFT_AMOUNTS[r])
        sk = subkeys[r]
        state ^= rot_left_64(sk, 13)
        state = (state - sk) & MASK64
        state = inv_mix_add_mod(state)
        state = apply_pbox(state, INV_PBOX)
        state = inv_xor_diffusion(state)   # <--- inverser le XOR
        state = apply_sbox(state, INV_SBOX)
    state ^= key & MASK64
    return state & MASK64


# =============================================================================
#  CTR MODE
# =============================================================================

def _ctr_keystream_block(key: int, nonce: int, counter: int) -> int:
    """
    Génère un bloc de flux en chiffrant (nonce XOR counter).
    Le nonce occupe les 32 bits hauts, le compteur les 32 bits bas.
    """
    counter_block = ((nonce & 0xFFFFFFFF) << 32) | (counter & 0xFFFFFFFF)
    return encrypt_block(counter_block, key)


def encrypt_ctr(plaintext: bytes, key_bytes: bytes, nonce: bytes = None) -> bytes:
    """
    Mode CTR (Counter Mode) — SANS padding, parallélisable, auto-inverse.

    Format de sortie : nonce (4 octets) || ciphertext (même longueur que plaintext)

    Avantages :
      - Pas de padding nécessaire (longueur ciphertext = longueur plaintext)
      - Chiffrement et déchiffrement identiques (XOR avec keystream)
      - Parallélisable (chaque bloc est indépendant)
      - Accès aléatoire possible

    Structure du bloc compteur (64 bits) :
      [nonce 32 bits | counter 32 bits]
    """
    if nonce is None:
        nonce = secrets.token_bytes(4)          # 4 octets = 32 bits
    nonce_int = int.from_bytes(nonce, 'big')
    key_int   = int.from_bytes(key_bytes[:8], 'big')

    ciphertext = bytearray()
    for i in range(0, len(plaintext), 8):
        block     = plaintext[i:i + 8]
        counter   = i // 8                      # numéro du bloc courant
        keystream = _ctr_keystream_block(key_int, nonce_int, counter)
        ks_bytes  = keystream.to_bytes(8, 'big')
        # XOR byte à byte (gère les blocs partiels en fin de message)
        for j, b in enumerate(block):
            ciphertext.append(b ^ ks_bytes[j])

    return nonce + bytes(ciphertext)            # préfixe le nonce pour le déchiffrement


def decrypt_ctr(ciphertext: bytes, key_bytes: bytes) -> bytes:
    nonce_int = int.from_bytes(ciphertext[:4], "big")
    payload   = ciphertext[4:]
    key_int   = int.from_bytes(key_bytes[:8], "big")
    plaintext = bytearray()
    for i in range(0, len(payload), 8):
        block    = payload[i:i + 8]
        ks       = _ctr_keystream_block(key_int, nonce_int, i // 8).to_bytes(8, "big")
        for j, b in enumerate(block):
            plaintext.append(b ^ ks[j])
    return bytes(plaintext)


# =============================================================================
#  KEY DERIVATION + MAC
# =============================================================================

def derive_key_pbkdf2(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return key[:8], salt


def encrypt_with_mac(plaintext: bytes, key_bytes: bytes) -> bytes:
    ciphertext = encrypt_ctr(plaintext, key_bytes)
    mac = hmac.new(key_bytes, ciphertext, hashlib.sha256).digest()[:8]
    return ciphertext + mac


def decrypt_with_mac(data: bytes, key_bytes: bytes) -> bytes:
    ciphertext, received_mac = data[:-8], data[-8:]
    expected_mac = hmac.new(key_bytes, ciphertext, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(received_mac, expected_mac):
        raise MACError("MAC invalide → intégrité compromise (message modifié ou mauvaise clé)" )
    return decrypt_ctr(ciphertext, key_bytes)


# =============================================================================
#  METRICS
# =============================================================================

def differential_uniformity(sbox: list) -> int:
    n = len(sbox)
    max_count = 0
    for delta_in in range(1, n):
        counts = [0] * n
        for x in range(n):
            delta_out = sbox[x] ^ sbox[x ^ delta_in]
            counts[delta_out] += 1
        max_count = max(max_count, max(counts))
    return max_count

# =============================================================================
#  S-BOX ADVANCED ANALYSIS (NEW)
# =============================================================================

def linear_approximation_table(sbox: list):
    """
    Calcule la LAT via Walsh-Hadamard Transform (WHT) — O(n^2 * log n).
    Beaucoup plus rapide que la version naive O(n^3) pour n=256.
    """
    size = len(sbox)
    lat  = [[0] * size for _ in range(size)]
    for b in range(size):
        f = [bin(b & sbox[x]).count('1') % 2 for x in range(size)]
        w = [1 - 2 * v for v in f]
        step = 1
        while step < size:
            for i in range(0, size, step * 2):
                for j in range(i, i + step):
                    u, v2 = w[j], w[j + step]
                    w[j]        = u + v2
                    w[j + step] = u - v2
            step <<= 1
        for a in range(size):
            lat[a][b] = w[a] // 2
    return lat


def max_linear_bias(lat):
    """Retourne le biais lineaire maximum (hors a=0 ou b=0)."""
    return max(
        abs(lat[a][b])
        for a in range(1, len(lat))
        for b in range(1, len(lat[0]))
    )


def sbox_nonlinearity(sbox):
    """
    Non-linearite = 2^(n-1) - max_bias
    Pour GF(2^8) : idealement proche de 112 (AES atteint 112).
    """
    n        = int(math.log2(len(sbox)))
    lat      = linear_approximation_table(sbox)
    max_bias = max_linear_bias(lat)
    return 2**(n - 1) - max_bias


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)


def correlation_coefficient(pt: bytes, ct: bytes) -> float:
    n = min(len(pt), len(ct))
    x, y = list(pt[:n]), list(ct[:n])
    mx, my = sum(x) / n, sum(y) / n
    num = sum((x[i] - mx) * (y[i] - my) for i in range(n))
    dx  = math.sqrt(sum((v - mx) ** 2 for v in x))
    dy  = math.sqrt(sum((v - my) ** 2 for v in y))
    return (num / (dx * dy)) if dx and dy else 0.0


def strict_avalanche_criterion(key: int, num_samples: int = 200) -> float:
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
    return sum(bin(d1[i] ^ d2[i]).count('1') for i in range(min(len(d1), len(d2))))


def hamming_ratio(d1: bytes, d2: bytes) -> float:
    n = min(len(d1), len(d2)) * 8
    return hamming_distance(d1, d2) / n if n else 0.0


def frequency_test(data: bytes) -> dict:
    total = len(data) * 8
    ones  = sum(bin(b).count('1') for b in data)
    zeros = total - ones
    ratio = ones / total if total else 0
    sn    = abs(ones - zeros) / math.sqrt(total) if total else 0
    return {"total_bits": total, "ones": ones, "zeros": zeros,
            "ones_ratio": ratio, "S_n": sn}


def timing_test(key: int, iterations: int = 100) -> dict:
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


def collect_metrics(key_bytes: bytes) -> dict:
    """Collecte toutes les métriques et retourne un dictionnaire (pour le plot)."""
    random_pt = bytes(random.getrandbits(8) for _ in range(4096))
    ct_raw    = encrypt_ctr(random_pt, key_bytes)
    ct        = ct_raw[4:]   # retirer le nonce pour les métriques
    key_int   = int.from_bytes(key_bytes[:8], 'big')

    h   = shannon_entropy(ct)
    r   = correlation_coefficient(random_pt, ct[:len(random_pt)])
    sac = strict_avalanche_criterion(key_int)
    hd  = hamming_ratio(random_pt, ct[:len(random_pt)])
    ft  = frequency_test(ct)
    t   = timing_test(key_int)

    print("  [*] Calcul LAT (Walsh-Hadamard)...")
    lat      = linear_approximation_table(SBOX)
    lin_bias = max_linear_bias(lat)
    nonlin   = len(SBOX) // 2 - lin_bias   # 2^(n-1) - max_bias, n=8

    return {
        "entropy":       h,
        "correlation":   abs(r),
        "sac":           sac,
        "hamming":       hd,
        "ones_ratio":    ft["ones_ratio"],
        "enc_avg_ns":    t["enc_avg_ns"],
        "dec_avg_ns":    t["dec_avg_ns"],
        "diff_unif":     differential_uniformity(SBOX),
        "lin_bias":      lin_bias,
        "nonlinearity":  nonlin,
    }


def full_evaluation(plaintext: bytes, key_bytes: bytes):
    random_pt = bytes(random.getrandbits(8) for _ in range(4096))
    ct_raw    = encrypt_ctr(random_pt, key_bytes)
    ct        = ct_raw[4:]   # retirer le nonce pour les métriques
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

    rec_raw = decrypt_ctr(ct_raw, key_bytes)
    ok = rec_raw == random_pt
    print(f"\n{'='*62}")
    print(f"  Correctness (enc→dec)     : {'✓ PASS' if ok else '✗ FAIL'}")
    print(f"{'='*62}\n")

    print("  [*] Calcul LAT (Walsh-Hadamard)...")
    lat      = linear_approximation_table(SBOX)
    lin_bias = max_linear_bias(lat)
    nonlin   = len(SBOX) // 2 - lin_bias   # 2^(n-1) - max_bias

    print(f"\n7. Linear Bias             : {lin_bias}")
    print(f"   [Ideal ≤ 32 for 8-bit]   {'✓ GOOD' if lin_bias <= 32 else '✗ WEAK'}")

    print(f"\n8. Nonlinearity            : {nonlin}")
    print(f"   [Ideal ≥ 96 for 8-bit]   {'✓ GOOD' if nonlin >= 96 else '≈ OK' if nonlin >= 80 else '✗ WEAK'}")


# =============================================================================
#  PLOT — Metrics Dashboard (matplotlib)
# =============================================================================

def plot_metrics(key_bytes: bytes):
    """
    Génère un dashboard matplotlib avec 6 sous-graphes pour visualiser
    toutes les métriques de sécurité du cipher.
    Sauvegarde le fichier 'metrics_dashboard.png'.
    """
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        import numpy as np
    except ImportError:
        print("  [!] matplotlib non installé. Exécutez : pip install matplotlib")
        return

    print("\n  [*] Collecte des métriques pour le plot (patientez ~30s)...")
    m = collect_metrics(key_bytes)
    key_int = int.from_bytes(key_bytes[:8], 'big')

    # ── Palette ──────────────────────────────────────────────────────────────
    BG      = "#0D1117"
    PANEL   = "#161B22"
    ACCENT  = "#58A6FF"
    GREEN   = "#3FB950"
    ORANGE  = "#F78166"
    YELLOW  = "#E3B341"
    GRID    = "#21262D"
    TEXT    = "#C9D1D9"
    SUBTEXT = "#8B949E"

    fig = plt.figure(figsize=(16, 10), facecolor=BG)
    fig.suptitle("Mini Block Cipher — Project #22  |  Metrics Dashboard",
                 fontsize=16, fontweight='bold', color=TEXT, y=0.97)

    gs = fig.add_gridspec(2, 3, hspace=0.48, wspace=0.38,
                          left=0.07, right=0.97, top=0.90, bottom=0.08)

    def styled_ax(ax, title):
        ax.set_facecolor(PANEL)
        for spine in ax.spines.values():
            spine.set_color(GRID)
        ax.tick_params(colors=SUBTEXT, labelsize=9)
        ax.set_title(title, color=TEXT, fontsize=10, fontweight='bold', pad=8)
        ax.yaxis.label.set_color(SUBTEXT)
        ax.xaxis.label.set_color(SUBTEXT)
        ax.grid(color=GRID, linewidth=0.6, zorder=0)

    # ── 1. Shannon Entropy ────────────────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, 0])
    styled_ax(ax1, "1 · Shannon Entropy H(X)")
    val = m["entropy"]
    color = GREEN if val > 7.5 else ORANGE
    bar = ax1.bar(["Ciphertext"], [val], color=color, width=0.4, zorder=3)
    ax1.bar(["Ciphertext"], [8.0], color=GRID, width=0.4, zorder=2)
    ax1.set_ylim(0, 8.4)
    ax1.axhline(8.0, color=YELLOW, linestyle='--', linewidth=1.2, label='Ideal = 8.0', zorder=4)
    ax1.legend(fontsize=8, labelcolor=SUBTEXT, facecolor=PANEL, edgecolor=GRID)
    ax1.set_ylabel("bits / byte")
    ax1.text(0, val + 0.05, f"{val:.4f}", ha='center', va='bottom', color=color, fontsize=10, fontweight='bold')

    # ── 2. Correlation ────────────────────────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 1])
    styled_ax(ax2, "2 · Pearson Correlation |r|")
    val = m["correlation"]
    color = GREEN if val < 0.05 else ORANGE
    ax2.bar(["PT vs CT"], [val], color=color, width=0.4, zorder=3)
    ax2.axhline(0.05, color=YELLOW, linestyle='--', linewidth=1.2, label='Threshold = 0.05', zorder=4)
    ax2.set_ylim(0, max(0.15, val * 1.5))
    ax2.legend(fontsize=8, labelcolor=SUBTEXT, facecolor=PANEL, edgecolor=GRID)
    ax2.set_ylabel("|r|")
    ax2.text(0, val + 0.001, f"{val:.5f}", ha='center', va='bottom', color=color, fontsize=10, fontweight='bold')

    # ── 3. SAC gauge ──────────────────────────────────────────────────────────
    ax3 = fig.add_subplot(gs[0, 2])
    styled_ax(ax3, "3 · Strict Avalanche Criterion")
    val = m["sac"]
    color = GREEN if 0.45 <= val <= 0.55 else ORANGE
    categories = ['SAC']
    ax3.barh(categories, [val], color=color, height=0.4, zorder=3)
    ax3.axvline(0.5, color=YELLOW, linestyle='--', linewidth=1.5, label='Ideal = 0.5', zorder=4)
    ax3.axvspan(0.45, 0.55, color=GREEN, alpha=0.12, label='Good range [0.45-0.55]', zorder=2)
    ax3.set_xlim(0, 1)
    ax3.legend(fontsize=8, labelcolor=SUBTEXT, facecolor=PANEL, edgecolor=GRID)
    ax3.set_xlabel("Fraction of bits flipped")
    ax3.text(val + 0.01, 0, f"{val:.4f}", va='center', color=color, fontsize=10, fontweight='bold')

    # ── 4. Hamming Distance ───────────────────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 0])
    styled_ax(ax4, "4 · Hamming Distance (normalized)")
    val = m["hamming"]
    color = GREEN if 0.45 <= val <= 0.55 else YELLOW
    ax4.barh(['HD ratio'], [val], color=color, height=0.4, zorder=3)
    ax4.axvline(0.5, color=YELLOW, linestyle='--', linewidth=1.5, label='Ideal = 0.5', zorder=4)
    ax4.axvspan(0.45, 0.55, color=GREEN, alpha=0.12, zorder=2)
    ax4.set_xlim(0, 1)
    ax4.legend(fontsize=8, labelcolor=SUBTEXT, facecolor=PANEL, edgecolor=GRID)
    ax4.set_xlabel("Ratio [0, 1]")
    ax4.text(val + 0.01, 0, f"{val:.4f}", va='center', color=color, fontsize=10, fontweight='bold')

    # ── 5. Frequency Test (ones ratio) ────────────────────────────────────────
    ax5 = fig.add_subplot(gs[1, 1])
    styled_ax(ax5, "5 · Frequency Test — Bit Balance")
    ones  = m["ones_ratio"]
    zeros = 1 - ones
    color_o = GREEN if 0.48 <= ones <= 0.52 else YELLOW
    bars = ax5.bar(['Ones', 'Zeros'], [ones, zeros], color=[color_o, ACCENT], width=0.5, zorder=3)
    ax5.axhline(0.5, color=YELLOW, linestyle='--', linewidth=1.2, label='Ideal = 0.5', zorder=4)
    ax5.set_ylim(0, 0.6)
    ax5.legend(fontsize=8, labelcolor=SUBTEXT, facecolor=PANEL, edgecolor=GRID)
    ax5.set_ylabel("Ratio")
    for bar, v in zip(bars, [ones, zeros]):
        ax5.text(bar.get_x() + bar.get_width() / 2, v + 0.005,
                 f"{v:.4f}", ha='center', color=TEXT, fontsize=9, fontweight='bold')

    # ── 6. Timing ─────────────────────────────────────────────────────────────
    ax6 = fig.add_subplot(gs[1, 2])
    styled_ax(ax6, "6 · Timing (avg per block, ns)")
    enc_ns = m["enc_avg_ns"]
    dec_ns = m["dec_avg_ns"]
    b = ax6.bar(['Encrypt', 'Decrypt'], [enc_ns, dec_ns], color=[ACCENT, ORANGE], width=0.5, zorder=3)
    ax6.set_ylabel("Nanoseconds")
    for bar, v in zip(b, [enc_ns, dec_ns]):
        ax6.text(bar.get_x() + bar.get_width() / 2, v * 1.02,
                 f"{v:,.0f} ns", ha='center', color=TEXT, fontsize=9, fontweight='bold')
    ax6.set_ylim(0, max(enc_ns, dec_ns) * 1.25)

    # ── Footer ────────────────────────────────────────────────────────────────
    fig.text(0.5, 0.01,
             f"S-Box Differential Uniformity: {m['diff_unif']} (ideal ≤ 4)  |  "
             f"8 rounds SPN  |  GF(2⁴) S-Box  |  64-bit block",
             ha='center', color=SUBTEXT, fontsize=9)

    out = "metrics_dashboard.png"
    plt.savefig(out, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close()
    print(f"  [✓] Plot sauvegardé : {out}")
    return out


# =============================================================================
#  DIFFERENTIAL ATTACK SIMULATION
# =============================================================================

def bit_flip(data: bytes, bit_index: int) -> bytes:
    byte_index = bit_index // 8
    bit_pos = bit_index % 8
    flipped = bytearray(data)
    flipped[byte_index] ^= (1 << bit_pos)
    return bytes(flipped)


def differential_attack_test(key: bytes, trials=100):
    print("\n[ DIFFERENTIAL ATTACK TEST ]")

    total_diff = 0
    block_size = 8  # 64 bits
    key_int = int.from_bytes(key, 'big')

    for _ in range(trials):
        pt = os.urandom(block_size)
        pt_flipped = bit_flip(pt, random.randint(0, 63))

        pt_int        = int.from_bytes(pt, 'big')
        pt_flipped_int = int.from_bytes(pt_flipped, 'big')

        ct1 = encrypt_block(pt_int, key_int)
        ct2 = encrypt_block(pt_flipped_int, key_int)

        diff = ct1 ^ ct2
        diff_bits = bin(diff).count('1')

        total_diff += diff_bits

    avg_diff = total_diff / trials
    ratio = avg_diff / 64

    print(f"Average bit difference : {avg_diff:.2f} / 64")
    print(f"Avalanche ratio        : {ratio:.4f}")

    if 0.45 <= ratio <= 0.55:
        print("✓ Strong resistance to differential attack")
    else:
        print("✗ Weak diffusion → vulnerable")

    return ratio

# =============================================================================
#  BRUTE FORCE ATTACK SIMULATION
# =============================================================================

def brute_force_attack(ciphertext: bytes, plaintext: bytes, key_bits=16):
    print("\n[ BRUTE FORCE ATTACK TEST ]")

    max_key = 2 ** key_bits
    start = time.time()
    ct_int = int.from_bytes(ciphertext, 'big')
    pt_int = int.from_bytes(plaintext,  'big')

    for k in range(max_key):
        key_int = k

        try:
            recovered = decrypt_block(ct_int, key_int)
            if recovered == pt_int:
                end = time.time()
                print(f"✓ Key found: {k}")
                print(f"Time: {end - start:.2f} sec")
                return k
        except:
            pass

    print("✗ Key not found")
    return None


# =============================================================================
#  ATTAQUE A3 — Fixed Point Test (S-Box)
# =============================================================================
def fixed_point_test(sbox: list):
    """
    Un point fixe est x tel que S(x) = x (la S-Box ne change pas la valeur).
    Un point fixe complementaire est x tel que S(x) = x XOR 0xFF.
    Moins il y en a, meilleure est la S-Box. AES : 0 points fixes.
    """
    print("\n[ FIXED POINT TEST — S-Box ]")
    fixed = [x for x in range(len(sbox)) if sbox[x] == x]
    comp  = [x for x in range(len(sbox)) if sbox[x] == (x ^ 0xFF)]
    print(f"  Points fixes           : {len(fixed)}  {fixed[:8]}")
    print(f"  Points complementaires : {len(comp)}  {comp[:8]}")
    if len(fixed) == 0:
        print("  ✓ Aucun point fixe — S-Box optimale")
    else:
        print(f"  ✗ {len(fixed)} points fixes detectes — risque faible")
    return len(fixed), len(comp)


# =============================================================================
#  ATTAQUE A4 — Bit Independence Criterion (S-Box)
# =============================================================================
def bit_independence_criterion(sbox: list):
    """
    Pour chaque paire de bits de sortie (i, j), mesure leur correlation.
    Si bit_i et bit_j de S(x) sont independants → correlation ≈ 0.
    Valeur BIC : moyenne des correlations absolues (ideal = 0).
    """
    print("\n[ BIT INDEPENDENCE CRITERION — S-Box ]")
    size   = len(sbox)
    n_bits = 8
    correlations = []
    for i in range(n_bits):
        for j in range(i + 1, n_bits):
            bi = [(sbox[x] >> i) & 1 for x in range(size)]
            bj = [(sbox[x] >> j) & 1 for x in range(size)]
            mi = sum(bi) / size
            mj = sum(bj) / size
            num = sum((bi[x] - mi) * (bj[x] - mj) for x in range(size))
            di  = math.sqrt(sum((v - mi) ** 2 for v in bi))
            dj  = math.sqrt(sum((v - mj) ** 2 for v in bj))
            corr = (num / (di * dj)) if di and dj else 0
            correlations.append(abs(corr))
    avg_corr = sum(correlations) / len(correlations)
    max_corr = max(correlations)
    print(f"  Paires de bits testees : {len(correlations)}")
    print(f"  Correlation moyenne    : {avg_corr:.6f}  (ideal = 0.0)")
    print(f"  Correlation max        : {max_corr:.6f}")
    if avg_corr < 0.1:
        print("  ✓ Bits de sortie independants — S-Box solide")
    else:
        print("  ✗ Correlation detectee entre bits de sortie")
    return avg_corr, max_corr


# =============================================================================
#  ATTAQUE B2 — Linear Attack Simulation (Cipher)
# =============================================================================
def linear_attack_simulation(key: int, num_samples: int = 1000):
    """
    Simule une attaque lineaire sur le cipher complet.
    Teste des masques aleatoires et mesure le biais observe sur PT et CT.
    Un cipher securise → tous les biais ≈ 0 (pas de correlation PT/CT).
    """
    print("\n[ LINEAR ATTACK SIMULATION — Cipher ]")
    print(f"  Echantillons : {num_samples}")
    best_bias  = 0
    best_masks = (0, 0)
    tested     = 100
    for _ in range(tested):
        mask_pt = random.getrandbits(64)
        mask_ct = random.getrandbits(64)
        count   = 0
        for _ in range(num_samples):
            pt  = random.getrandbits(64)
            ct  = encrypt_block(pt, key)
            lhs = bin(pt & mask_pt).count('1') % 2
            rhs = bin(ct & mask_ct).count('1') % 2
            if lhs == rhs:
                count += 1
        bias = abs(count / num_samples - 0.5)
        if bias > best_bias:
            best_bias  = bias
            best_masks = (mask_pt, mask_ct)
    print(f"  Meilleur biais trouve  : {best_bias:.6f}")
    print(f"  Masque PT              : 0x{best_masks[0]:016X}")
    print(f"  Masque CT              : 0x{best_masks[1]:016X}")
    print(f"  Seuil statistique (2s) : {2.0/num_samples**0.5:.4f}")
    threshold = 2.0 / num_samples**0.5   # seuil statistique = 2 sigma
    if best_bias < threshold:
        print("  ✓ Aucune approximation lineaire exploitable — cipher resistant")
    else:
        print("  ✗ Biais significatif — vulnerabilite potentielle")
    return best_bias


# =============================================================================
#  ATTAQUE B3 — Related-Key Attack (Key Schedule)
# =============================================================================
def related_key_attack(num_trials: int = 500):
    """
    Teste si deux cles proches (differant d'1 bit) produisent des
    ciphertexts tres differents pour le meme plaintext.
    Key schedule fort (NL) → ratio ≈ 0.5 (50% des bits changent).
    """
    print("\n[ RELATED-KEY ATTACK TEST — Key Schedule ]")
    total_bits = 0
    for _ in range(num_trials):
        key1 = random.getrandbits(64)
        bit  = random.randint(0, 63)
        key2 = key1 ^ (1 << bit)
        pt   = random.getrandbits(64)
        ct1  = encrypt_block(pt, key1)
        ct2  = encrypt_block(pt, key2)
        total_bits += bin(ct1 ^ ct2).count('1')
    avg   = total_bits / num_trials
    ratio = avg / 64
    print(f"  Trials                 : {num_trials}")
    print(f"  Diff moyenne CT        : {avg:.2f} / 64 bits")
    print(f"  Ratio                  : {ratio:.4f}  (ideal ≈ 0.5)")
    if 0.45 <= ratio <= 0.55:
        print("  ✓ Key schedule fort — 1 bit de cle → 50% CT different")
    else:
        print("  ✗ Key schedule faible — relation entre cles proches")
    return ratio

# =============================================================================
#  DEMO & TEST RUNNER
# =============================================================================

def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          Mini Block Cipher  —  Project #22                   ║
║          SPN | 64-bit block | 64-bit key | 8 rounds          ║
║          S-Box: GF(2^4) dynamique | P-Box: custom 64-bit     ║
║          Mix: ADD_MOD  | Subkey: NL_KEY (non-lineaire)       ║
║          Mode: CTR                                           ║
║          + PBKDF2 + Encrypt-then-MAC (HMAC-SHA256)           ║
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


def demo_ctr():
    """DEMO CTR — Mode Compteur."""
    print("\n" + "─" * 62)
    print("  DEMO 2 — Text Message (CTR Mode)")
    print("─" * 62)
    key_bytes = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
    message   = b'Hello! This is Project 22 - Mini SPN Cipher (CTR Mode - no padding!).'

    ct         = encrypt_ctr(message, key_bytes)
    nonce_used = ct[:4]
    payload    = ct[4:]
    rec        = decrypt_ctr(ct, key_bytes)

    print(f"  Key (hex)         : {key_bytes.hex().upper()}")
    print(f"  Nonce (auto)      : {nonce_used.hex().upper()}")
    print(f"  Plaintext         : {message.decode()}")
    print(f"  Plaintext len     : {len(message)} bytes")
    print(f"  Ciphertext len    : {len(payload)} bytes  (= plaintext len, NO padding)")
    print(f"  Ciphertext (hex)  : {payload.hex().upper()}")
    print(f"  Recovered         : {rec.decode()}")
    print(f"  Match             : {'✓ YES' if rec == message else '✗ NO'}")

    # Test avec nonce fixe
    print(f"\n  ── Deterministic test (fixed nonce) ──")
    fixed_nonce = b'\xAB\xCD\xEF\x01'
    ct1 = encrypt_ctr(message, key_bytes, fixed_nonce)
    ct2 = encrypt_ctr(message, key_bytes, fixed_nonce)
    print(f"  CT1 == CT2 (same nonce) : {'✓ YES' if ct1 == ct2 else '✗ NO'}")

    # Test accès aléatoire (seek) — avantage CTR
    print(f"\n  ── Random access (CTR advantage) ──")
    key_int   = int.from_bytes(key_bytes, 'big')
    nonce_int = int.from_bytes(fixed_nonce, 'big')
    # Déchiffrement direct du bloc 2 (octets 16-23) sans traiter les blocs précédents
    block_idx = 2
    ks = _ctr_keystream_block(key_int, nonce_int, block_idx)
    ks_bytes = ks.to_bytes(8, 'big')
    ct_payload = ct1[4:]   # enlever nonce
    ct_block2  = ct_payload[block_idx*8 : block_idx*8 + 8]
    recovered_block2 = bytes(a ^ b for a, b in zip(ct_block2, ks_bytes))
    expected_block2  = message[block_idx*8 : block_idx*8 + 8]
    print(f"  Direct decrypt block {block_idx} : {recovered_block2}")
    print(f"  Expected block {block_idx}       : {expected_block2}")
    print(f"  Seek match            : {'✓ YES' if recovered_block2 == expected_block2 else '✗ NO'}")


def demo_secure_mac():
    print("\n" + "─" * 62)
    print("  DEMO 3 — Secure Mode (PBKDF2 + CTR + Encrypt-then-MAC)")
    print("─" * 62)
    password = "Master1CYSIA2026_SecurePassword"
    key, salt = derive_key_pbkdf2(password)
    message   = b'Hello! This is Project 22 - Secure version with MAC.'
    ct  = encrypt_with_mac(message, key)
    try:
        rec = decrypt_with_mac(ct, key)
        print(f"  Password   : {password}")
        print(f"  Salt       : {salt.hex()}")
        print(f"  Derived Key: {key.hex()}")
        print(f"  Plaintext  : {message.decode()}")
        print(f"  Ciphertext : {ct.hex().upper()}")
        print(f"  Recovered  : {rec.decode()}")
        print(f"  Match      : {'✓ YES' if rec == message else '✗ NO'}")
        print(f"  MAC Status : ✓ VALID")
    except (PaddingError, MACError) as e:
        print(f"  Error: {e}")


def demo_key_schedule():
    print("\n" + "─" * 62)
    print("  DEMO 4 — Key Schedule (NL_KEY non-lineaire, 8 subkeys)")
    print("─" * 62)
    key     = 0x133457799BBCDFF1
    subkeys = key_schedule(key)
    print(f"  Master Key : 0x{key:016X}")
    for i, sk in enumerate(subkeys):
        print(f"  Subkey[{i}]  : 0x{sk:016X}")


def demo_components():
    print("\n" + "─" * 62)
    print("  DEMO 5 — S-Box & P-Box")
    print("─" * 62)
    print("\n  S-Box (first 16) : " + "  ".join(f"{v:02X}" for v in SBOX[:16]))
    print("  INV S-Box (first 16) : " + "  ".join(f"{v:02X}" for v in INV_SBOX[:16]))
    assert sorted(SBOX) == list(range(256))
    print("\n  S-Box bijectivity : ✓ VERIFIED")
    print(f"  P-Box (first 16)  : {PBOX[:16]}")
    assert sorted(PBOX) == list(range(64))
    print("  P-Box validity    : ✓ VERIFIED")
    du = differential_uniformity(SBOX)
    print(f"  Differential uniformity : {du} (Ideal ≤4)")


def demo_avalanche():
    print("\n" + "─" * 62)
    print("  DEMO 6 — Avalanche Effect")
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

  #_________________________production______________________________________________
"""
# AES-GCM pour chiffrement authentifié (nouvellement ajouté)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b""):
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce + ct

def aes_gcm_decrypt(key: bytes, data: bytes, aad: bytes = b""):
    nonce = data[:12]
    ct    = data[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, aad)

#hkdf pour dériver une clé à partir d'une clé maître (ex: mot de passe)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_key_hkdf(master_key: bytes, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'project22-aes-key',
    )

    return hkdf.derive(master_key), salt


def secure_encrypt_pro(password: str, plaintext: bytes):
    master = hashlib.sha256(password.encode()).digest()

    key, salt = derive_key_hkdf(master)
    ct = aes_gcm_encrypt(key, plaintext)

    return salt + ct


def secure_decrypt_pro(password: str, data: bytes):
    salt = data[:16]
    ct   = data[16:]

    master = hashlib.sha256(password.encode()).digest()
    key, _ = derive_key_hkdf(master, salt)

    return aes_gcm_decrypt(key, ct)

#attack demo: chosen plaintext attack 
def chosen_plaintext_attack_demo():
    print("\n[ CHOSEN PLAINTEXT ATTACK — ECB WEAKNESS ]")

    key = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'

    pt1 = b'A' * 16
    pt2 = b'A' * 16

    ct1 = encrypt(pt1, key)
    ct2 = encrypt(pt2, key)

    print("CT1:", ct1.hex())
    print("CT2:", ct2.hex())

    if ct1 == ct2:
        print("✗ ECB is deterministic → vulnerable")
    else:
        print("✓ Unexpected behavior")


#test nist 
def nist_like_random_test():
    data = os.urandom(10000)
    freq = frequency_test(data)

    print("\n[ NIST-LIKE TEST ]")
    print("Ones ratio:", freq["ones_ratio"])

    if 0.49 <= freq["ones_ratio"] <= 0.51:
        print("✓ PASS")
    else:
        print("✗ FAIL")            
"""

if __name__ == "__main__":
    banner()
    demo_single_block()
    demo_ctr()
    demo_secure_mac()
    demo_key_schedule()
    demo_components()
    demo_avalanche()
    run_metrics()

    # Plot des métriques
    key_bytes = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
    plot_metrics(key_bytes)

    # Differential test
    differential_attack_test(key_bytes)

    # Brute-force test (sur version faible)
    test_key_int = 12345
    pt_bytes = b"ABCDEFGH"
    pt_int = int.from_bytes(pt_bytes, 'big')
    ct_int = encrypt_block(pt_int, test_key_int)
    ct_bytes = ct_int.to_bytes(8, 'big')

    brute_force_attack(ct_bytes, pt_bytes, key_bits=16)

    # ── Nouvelles attaques ──
    key_int = int.from_bytes(key_bytes, 'big')
    fixed_point_test(SBOX)
    bit_independence_criterion(SBOX)
    linear_attack_simulation(key_int)
    related_key_attack()

"""
    print("\n===== AES-GCM =====")

    password = "strongpassword123"
    message = b"Hello Master Crypto"

    # --- Encryption ---
    encrypted = secure_encrypt_pro(password, message)
    print("Encrypted:", encrypted.hex())

    # --- Decryption ---
    decrypted = secure_decrypt_pro(password, encrypted)
    print("Decrypted:", decrypted)

    # --- Attack demo ---
    chosen_plaintext_attack_demo()

    # --- NIST test ---
    nist_like_random_test() ca mon code complet je besoin de suprimier le mode cbc et ecb dons le code sons modification le code  
"""