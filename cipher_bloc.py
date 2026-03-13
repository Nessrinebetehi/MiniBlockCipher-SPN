import math
import random
import time

# =========================================================
# SBOX MATHEMATIQUE
# =========================================================

def generate_sbox():

    sbox = []

    for x in range(256):
        y = (pow(x,3,257) ^ 0xA5) % 256
        sbox.append(y)

    inv = [0]*256
    for i,v in enumerate(sbox):
        inv[v] = i

    return sbox,inv


SBOX,INV_SBOX = generate_sbox()


# =========================================================
# PBOX MATHEMATIQUE
# =========================================================

PBOX = [(13*i)%64 for i in range(64)]

INV_PBOX = [0]*64
for i,p in enumerate(PBOX):
    INV_PBOX[p] = i


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
# MIX ADD MOD (inversible)
# =========================================================

def mix_add_mod(state):

    b = [(state>>(8*i)) & 0xFF for i in range(8)]

    for i in range(7):
        b[i] = (b[i] + b[i+1]) % 256

    res = 0
    for i in range(8):
        res |= b[i]<<(8*i)

    return res


def inv_mix_add_mod(state):

    b = [(state>>(8*i)) & 0xFF for i in range(8)]

    for i in reversed(range(7)):
        b[i] = (b[i] - b[i+1]) % 256

    res = 0
    for i in range(8):
        res |= b[i]<<(8*i)

    return res


# =========================================================
# KEY SCHEDULE
# =========================================================

def generate_round_keys(key,rounds):

    keys=[]
    k=key

    for r in range(rounds+1):

        k = rotl(k,7)

        byte = (k>>56)&0xFF

        k ^= SBOX[byte]<<48

        k ^= r<<56

        k &= 0xFFFFFFFFFFFFFFFF

        keys.append(k)

    return keys


# =========================================================
# CIPHER
# =========================================================

class MiniCipher:

    def __init__(self,key):

        self.rounds = 8
        self.round_keys = generate_round_keys(key,self.rounds)

    # ---------------- ENCRYPTION ----------------

    def encrypt(self,pt):

        state = pt

        for r in range(self.rounds-1):

            state ^= self.round_keys[r]
            state = substitute(state,SBOX)
            state = permute(state,PBOX)
            state = mix_add_mod(state)

        state ^= self.round_keys[self.rounds-1]
        state = substitute(state,SBOX)
        state ^= self.round_keys[self.rounds]

        return state


    # ---------------- DECRYPTION ----------------

    def decrypt(self,ct):

        state = ct

        state ^= self.round_keys[self.rounds]
        state = substitute(state,INV_SBOX)
        state ^= self.round_keys[self.rounds-1]

        for r in reversed(range(self.rounds-1)):

            state = inv_mix_add_mod(state)
            state = permute(state,INV_PBOX)
            state = substitute(state,INV_SBOX)
            state ^= self.round_keys[r]

        return state


# =========================================================
# METRICS
# =========================================================

# Hamming Distance
def hamming_distance(a,b):
    return bin(a ^ b).count("1")


# Strict Avalanche Criterion
def avalanche_test(cipher,pt):

    pt2 = pt ^ 1

    c1 = cipher.encrypt(pt)
    c2 = cipher.encrypt(pt2)

    return hamming_distance(c1,c2)


# Shannon Entropy
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


# Frequency Test
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

    return zeros,ones


# Correlation Coefficient
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


# Time Test
def time_test(cipher):

    pts=[random.getrandbits(64) for _ in range(100)]

    start=time.time_ns()

    for pt in pts:
        ct=cipher.encrypt(pt)
        cipher.decrypt(ct)

    end=time.time_ns()

    return end-start


# =========================================================
# PROGRAMME INTERACTIF
# =========================================================

print("\n===== MINI BLOCK CIPHER TEST =====\n")

while True:

    key_input=input("Enter KEY (hex): ")
    pt_input=input("Enter PLAINTEXT (hex): ")

    key=int(key_input,16)
    pt=int(pt_input,16)

    cipher=MiniCipher(key)

    ct=cipher.encrypt(pt)
    dec=cipher.decrypt(ct)

    print("\nRESULTS")
    print("KEY:",hex(key))
    print("PT :",hex(pt))
    print("CT :",hex(ct))
    print("DEC:",hex(dec))
    print("OK :",pt==dec)

    # metrics
    print("\n===== SECURITY METRICS =====")

    avalanche=avalanche_test(cipher,pt)
    print("Avalanche effect:",avalanche,"bits")

    ent=entropy(cipher)
    print("Entropy:",ent)

    zeros,ones=frequency_test(cipher)
    print("Frequency test -> zeros:",zeros,"ones:",ones)

    corr=correlation_test(cipher)
    print("Correlation coefficient:",corr)

    hd=hamming_distance(pt,ct)
    print("Hamming distance PT-CT:",hd)

    t=time_test(cipher)
    print("Time for 100 enc/dec:",t,"ns")

    cont=input("\nTest another message? (y/n): ")

    if cont.lower()!="y":
        break