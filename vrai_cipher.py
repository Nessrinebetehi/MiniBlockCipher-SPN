import os
import math
import random
import time
from hashlib import sha256

# ================== SBOX/PBOX DYNAMIQUE ==================
def generate_sbox(key):
    sbox = list(range(256))
    random.seed(key ^ 0xA5A5A5A5A5A5A5A5)
    random.shuffle(sbox)
    inv = [0]*256
    for i,v in enumerate(sbox):
        inv[v] = i
    return sbox, inv

def generate_pbox(key):
    pbox = list(range(128))
    random.seed(key ^ 0x123456789ABCDEF)
    random.shuffle(pbox)
    inv_pbox = [0]*128
    for i,p in enumerate(pbox):
        inv_pbox[p] = i
    return pbox, inv_pbox

# ================== UTILITAIRES ==================
def rotl(x,r,bits=128):
    return ((x<<r)|(x>>(bits-r))) & ((1<<bits)-1)

def substitute(state,sbox):
    res = 0
    for i in range(16):
        b = (state>>(8*i)) & 0xFF
        res |= sbox[b]<<(8*i)
    return res

def permute(state,pbox):
    res = 0
    for i,p in enumerate(pbox):
        if (state>>i)&1:
            res |= 1<<p
    return res

def mix_bytes(state):
    b = [(state>>(8*i)) & 0xFF for i in range(16)]
    new_b = [0]*16
    for i in range(16):
        new_b[i] = (b[i] + b[(i+1)%16] + b[(i+3)%16]) % 256
    res = 0
    for i in range(16):
        res |= new_b[i]<<(8*i)
    return res

def inv_mix_bytes(state):
    b = [(state>>(8*i)) & 0xFF for i in range(16)]
    new_b = [0]*16
    for i in range(16):
        new_b[i] = (b[i] - b[(i+1)%16] - b[(i+3)%16]) % 256
    res = 0
    for i in range(16):
        res |= new_b[i]<<(8*i)
    return res

def generate_round_keys(key, rounds, sbox):
    keys = []
    k = key
    for r in range(rounds+1):
        k = rotl(k,7,bits=128)
        byte = (k>>120) & 0xFF
        k ^= sbox[byte]<<112
        k ^= r<<120
        k ^= (k & 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F)<<4
        k &= (1<<128)-1
        keys.append(k)
    return keys

# ================== CIPHER ==================
class StrongCipher:
    def __init__(self,key, rounds=16):
        self.rounds = rounds
        self.sbox, self.inv_sbox = generate_sbox(key)
        self.pbox, self.inv_pbox = generate_pbox(key)
        self.round_keys = generate_round_keys(key, self.rounds, self.sbox)

    def encrypt_block(self, pt):
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

    def decrypt_block(self, ct):
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

# ================== HMAC ==================
def compute_hmac(key, data):
    return sha256(key.to_bytes(16,'big') + data).digest()

# ================== PADDING ==================
def pad_block(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]*pad_len)

def unpad_block(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data  # sécurité
    return data[:-pad_len]

# ================== FONCTIONS FICHIERS ==================
def encrypt_file(filename, key):
    cipher = StrongCipher(key)
    iv = random.getrandbits(128)
    outname = filename + ".enc"
    with open(filename,"rb") as f, open(outname,"wb") as out:
        out.write(iv.to_bytes(16,'big'))
        prev = iv
        while True:
            block = f.read(16)
            if not block:
                break
            if len(block)<16:
                block = pad_block(block)
            pt = int.from_bytes(block,'big') ^ prev
            ct = cipher.encrypt_block(pt)
            out.write(ct.to_bytes(16,'big'))
            prev = ct

    # HMAC sur IV + données chiffrées
    with open(outname,"rb") as f:
        data = f.read()
    hmac = compute_hmac(key, data)
    with open(outname,"ab") as out:
        out.write(hmac)
    print(f"[+] File encrypted: {outname}")

def decrypt_file(filename, key):
    cipher = StrongCipher(key)
    with open(filename,"rb") as f:
        content = f.read()

    if len(content) < 16 + 32:
        print("[-] Fichier trop court pour contenir IV + HMAC")
        return

    iv = int.from_bytes(content[:16],'big')
    data = content[16:-32]
    hmac_stored = content[-32:]

    # Vérification HMAC sur IV + données chiffrées
    if compute_hmac(key, content[:-32]) != hmac_stored:
        print("[-] HMAC verification failed! File may be tampered.")
        return

    outname = filename.replace(".enc",".dec")
    prev = iv
    with open(outname,"wb") as out:
        for i in range(0,len(data),16):
            ct = int.from_bytes(data[i:i+16],'big')
            pt = cipher.decrypt_block(ct) ^ prev
            out.write(pt.to_bytes(16,'big'))
            prev = ct

    # retirer padding
    with open(outname,"rb") as f:
        content = f.read()
    with open(outname,"wb") as f:
        f.write(unpad_block(content))

    print(f"[+] File decrypted: {outname}")

# ================== PROGRAMME ==================
if __name__=="__main__":
    print("=== STRONG BLOCK CIPHER FILE ENCRYPTION ===")
    key_input = input("Enter key (hex, 128-bit min): ")
    key = int(key_input,16)
    choice = input("Encrypt or Decrypt file? (e/d): ").lower()
    filename = input("Enter full path or filename: ")
    if choice=='e':
        encrypt_file(filename,key)
    else:
        decrypt_file(filename,key)