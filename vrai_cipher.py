import os
import random
import hashlib
import hmac

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

    inv = [0]*128

    for i,p in enumerate(pbox):
        inv[p] = i

    return pbox, inv


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

    new = [0]*16

    for i in range(16):

        new[i] = (b[i] + b[(i+1)%16] + b[(i+3)%16]) % 256

    res = 0

    for i in range(16):

        res |= new[i]<<(8*i)

    return res


def inv_mix_bytes(state):

    b = [(state>>(8*i)) & 0xFF for i in range(16)]

    new = [0]*16

    for i in range(16):

        new[i] = (b[i] - b[(i+1)%16] - b[(i+3)%16]) % 256

    res = 0

    for i in range(16):

        res |= new[i]<<(8*i)

    return res


# ================== KEY SCHEDULE ==================

def generate_round_keys(key, rounds, sbox):

    keys = []

    k = key

    for r in range(rounds+1):

        k = rotl(k,7,128)

        byte = (k>>120) & 0xFF

        k ^= sbox[byte]<<112

        k ^= r<<120

        k ^= (k & 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F)<<4

        k &= (1<<128)-1

        keys.append(k)

    return keys


# ================== CIPHER ==================

class StrongCipher:

    def __init__(self,key,rounds=16):

        self.rounds = rounds

        self.sbox,self.inv_sbox = generate_sbox(key)

        self.pbox,self.inv_pbox = generate_pbox(key)

        self.round_keys = generate_round_keys(key,rounds,self.sbox)


    def encrypt_block(self,pt):

        state = pt

        for r in range(self.rounds-1):

            state ^= self.round_keys[r]

            state = substitute(state,self.sbox)

            state = permute(state,self.pbox)

            state = mix_bytes(state)

        state ^= self.round_keys[self.rounds-1]

        state = substitute(state,self.sbox)

        state ^= self.round_keys[self.rounds]

        return state


    def decrypt_block(self,ct):

        state = ct

        state ^= self.round_keys[self.rounds]

        state = substitute(state,self.inv_sbox)

        state ^= self.round_keys[self.rounds-1]

        for r in reversed(range(self.rounds-1)):

            state = inv_mix_bytes(state)

            state = permute(state,self.inv_pbox)

            state = substitute(state,self.inv_sbox)

            state ^= self.round_keys[r]

        return state


# ================== HMAC SECURISE ==================

def compute_hmac(key,data):

    return hmac.new(key.to_bytes(16,'big'),data,hashlib.sha256).digest()


# ================== PADDING ==================

def pad(data):

    pad_len = 16 - (len(data)%16)

    return data + bytes([pad_len]*pad_len)


def unpad(data):

    pad_len = data[-1]

    if pad_len<1 or pad_len>16:

        return data

    return data[:-pad_len]


# ================== ENCRYPT FILE ==================

def encrypt_file(filename,key):

    cipher = StrongCipher(key)

    iv = int.from_bytes(os.urandom(16),'big')

    outname = filename + ".enc"

    with open(filename,"rb") as f:

        data = f.read()

    data = pad(data)

    prev = iv

    encrypted = b''

    for i in range(0,len(data),16):

        block = int.from_bytes(data[i:i+16],'big')

        block ^= prev

        ct = cipher.encrypt_block(block)

        encrypted += ct.to_bytes(16,'big')

        prev = ct

    final_data = iv.to_bytes(16,'big') + encrypted

    tag = compute_hmac(key,final_data)

    with open(outname,"wb") as f:

        f.write(final_data + tag)

    print("[+] File encrypted ->",outname)


# ================== DECRYPT FILE ==================

def decrypt_file(filename,key):

    cipher = StrongCipher(key)

    with open(filename,"rb") as f:

        content = f.read()

    if len(content) < 48:

        print("[-] File too small")

        return

    iv = int.from_bytes(content[:16],'big')

    ciphertext = content[16:-32]

    tag = content[-32:]

    if compute_hmac(key,content[:-32]) != tag:

        print("[-] HMAC verification failed!")

        return

    prev = iv

    decrypted = b''

    for i in range(0,len(ciphertext),16):

        ct = int.from_bytes(ciphertext[i:i+16],'big')

        pt = cipher.decrypt_block(ct)

        pt ^= prev

        decrypted += pt.to_bytes(16,'big')

        prev = ct

    decrypted = unpad(decrypted)

    outname = filename.replace(".enc",".dec")

    with open(outname,"wb") as f:

        f.write(decrypted)

    print("[+] File decrypted ->",outname)


# ================== PROGRAMME ==================

if __name__ == "__main__":

    print("=== STRONG BLOCK CIPHER FILE ENCRYPTION ===")

    key_hex = input("Enter key (128-bit hex): ")

    key = int(key_hex,16)

    mode = input("Encrypt or Decrypt? (e/d): ").lower()

    filename = input("Enter filename: ")

    if mode == "e":

        encrypt_file(filename,key)

    else:

        decrypt_file(filename,key)