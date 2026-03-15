import math
import random
import time

# =========================================================
# SBOX MATHEMATIQUE DYNAMIQUE
# =========================================================
def generate_sbox(key):
    sbox = list(range(256))
    random.seed(key ^ 0xA5A5A5A5A5A5A5A5)
    random.shuffle(sbox)
    inv = [0]*256
    for i,v in enumerate(sbox):
        inv[v] = i
    return sbox, inv

# =========================================================
# PBOX MATHEMATIQUE DYNAMIQUE (64 bits)
# =========================================================
def generate_pbox(key):
    pbox = list(range(64))
    random.seed(key ^ 0x123456789ABCDEF)
    random.shuffle(pbox)
    inv_pbox = [0]*64
    for i,p in enumerate(pbox):
        inv_pbox[p] = i
    return pbox, inv_pbox

# =========================================================
# ROTATION
# =========================================================
def rotl(x,r):
    return ((x<<r)|(x>>(64-r))) & 0xFFFFFFFFFFFFFFFF

# =========================================================
# SUBSTITUTION
# =========================================================
def substitute(state,sbox):
    res = 0
    for i in range(8):
        b = (state>>(8*i)) & 0xFF
        res |= sbox[b]<<(8*i)
    return res

# =========================================================
# PERMUTATION
# =========================================================
def permute(state,pbox):
    res = 0
    for i,p in enumerate(pbox):
        if (state>>i)&1:
            res |= 1<<p
    return res

# =========================================================
# MIX ADD MOD (100% inversible)
# =========================================================
def mix_bytes(state):
    b = [(state>>(8*i)) & 0xFF for i in range(8)]
    for i in range(7):
        b[i] = (b[i] + b[i+1]) % 256
    res = 0
    for i in range(8):
        res |= b[i]<<(8*i)
    return res

def inv_mix_bytes(state):
    b = [(state>>(8*i)) & 0xFF for i in range(8)]
    for i in reversed(range(7)):
        b[i] = (b[i] - b[i+1]) % 256
    res = 0
    for i in range(8):
        res |= b[i]<<(8*i)
    return res

# =========================================================
# KEY SCHEDULE RENFORCEE
# =========================================================
def generate_round_keys(key, rounds, sbox):
    keys = []
    k = key
    for r in range(rounds+1):
        k = rotl(k, 7)
        byte = (k>>56) & 0xFF
        k ^= sbox[byte]<<48
        k ^= r<<56
        # diffusion supplémentaire
        k ^= (k & 0x0F0F0F0F0F0F0F0F) << 4
        k &= 0xFFFFFFFFFFFFFFFF
        keys.append(k)
    return keys

# =========================================================
# CIPHER AVANCE
# =========================================================
class MiniCipher:
    def __init__(self,key):
        self.rounds = 14
        self.sbox, self.inv_sbox = generate_sbox(key)
        self.pbox, self.inv_pbox = generate_pbox(key)
        self.round_keys = generate_round_keys(key, self.rounds, self.sbox)

    # ---------------- ENCRYPTION ----------------
    def encrypt(self, pt):
        state = pt
        for r in range(self.rounds-1):
            state ^= self.round_keys[r]
            state = substitute(state, self.sbox)
            state = permute(state, self.pbox)
            state = mix_bytes(state)
        state ^= self.round_keys[self.rounds-1]
        state = substitute(state, self.sbox)
        state ^= self.round_keys[self.rounds]
        return state

    # ---------------- DECRYPTION ----------------
    def decrypt(self, ct):
        state = ct
        state ^= self.round_keys[self.rounds]
        state = substitute(state, self.inv_sbox)
        state ^= self.round_keys[self.rounds-1]
        for r in reversed(range(self.rounds-1)):
            state = inv_mix_bytes(state)
            state = permute(state, self.inv_pbox)
            state = substitute(state, self.inv_sbox)
            state ^= self.round_keys[r]
        return state

# =========================================================
# METRICS
# =========================================================
def hamming_distance(a,b):
    return bin(a^b).count("1")

def avalanche_test(cipher, pt):
    pt2 = pt ^ 1
    c1 = cipher.encrypt(pt)
    c2 = cipher.encrypt(pt2)
    return hamming_distance(c1,c2)

def entropy(cipher):
    bits=[]
    for _ in range(200):
        pt=random.getrandbits(64)
        ct=cipher.encrypt(pt)
        for i in range(64):
            bits.append((ct>>i)&1)
    p=sum(bits)/len(bits)
    if p==0 or p==1:
        return 0
    return -p*math.log2(p)-(1-p)*math.log2(1-p)

def frequency_test(cipher):
    zeros=0
    ones=0
    for _ in range(200):
        pt=random.getrandbits(64)
        ct=cipher.encrypt(pt)
        for i in range(64):
            if (ct>>i)&1:
                ones+=1
            else:
                zeros+=1
    return zeros, ones

def correlation_test(cipher):
    pts=[]
    cts=[]
    for _ in range(200):
        pt=random.getrandbits(64)
        ct=cipher.encrypt(pt)
        pts.append(pt)
        cts.append(ct)
    mean_p=sum(pts)/len(pts)
    mean_c=sum(cts)/len(cts)
    num=0
    den1=0
    den2=0
    for i in range(len(pts)):
        num+=(pts[i]-mean_p)*(cts[i]-mean_c)
        den1+=(pts[i]-mean_p)**2
        den2+=(cts[i]-mean_c)**2
    return num/math.sqrt(den1*den2)

def time_test(cipher):
    pts=[random.getrandbits(64) for _ in range(100)]
    start=time.time_ns()
    for pt in pts:
        ct=cipher.encrypt(pt)
        cipher.decrypt(ct)
    end=time.time_ns()
    return end-start

# =========================================================
# FONCTION DE NETTOYAGE HEX
# =========================================================
def clean_hex_input(s):
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    elif s.startswith("x"):
        s = s[1:]
    # Vérifie que le reste est bien hex
    if any(c not in "0123456789abcdef" for c in s):
        raise ValueError("Invalid hexadecimal input!")
    return s

# =========================================================
# PROGRAMME INTERACTIF
# =========================================================
print("\n===== MINI BLOCK CIPHER AVANCE (FINAL) =====\n")

while True:
    try:
        key_input = input("Enter KEY (hex): ")
        pt_input  = input("Enter PLAINTEXT (hex): ")
        key = int(clean_hex_input(key_input), 16)
        pt  = int(clean_hex_input(pt_input), 16)
    except ValueError as e:
        print("Erreur de saisie hexadécimale:", e)
        continue

    cipher = MiniCipher(key)
    ct = cipher.encrypt(pt)
    dec = cipher.decrypt(ct)

    print("\nRESULTS")
    print("KEY:", hex(key))
    print("PT :", hex(pt))
    print("CT :", hex(ct))
    print("DEC:", hex(dec))
    print("OK :", pt==dec)

    print("\n===== SECURITY METRICS =====")
    print("Avalanche effect:", avalanche_test(cipher, pt), "bits")
    print("Entropy:", entropy(cipher))
    zeros, ones = frequency_test(cipher)
    print("Frequency test -> zeros:", zeros, "ones:", ones)
    print("Correlation coefficient:", correlation_test(cipher))
    print("Hamming distance PT-CT:", hamming_distance(pt, ct))
    print("Time for 100 enc/dec:", time_test(cipher), "ns")

    cont=input("\nTest another message? (y/n): ")
    if cont.lower()!="y":
        break