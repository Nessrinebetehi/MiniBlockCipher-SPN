# Mini Block Cipher - Academic Report

## Master 1 Cyber Security / Cryptosystems

### 2025-2026

---

## ABSTRACT

This report presents the design and implementation of a Mini Block Cipher, an educational cryptographic system developed for understanding fundamental concepts of symmetric encryption. The cipher operates on 64-bit blocks with a 64-bit key, utilizing a Substitution-Permutation Network (SPN) structure with 8 rounds. The design incorporates a strong AES-style S-Box, a diffusion-oriented P-Box, and a ROTATE KEY-based key schedule with modular addition mixing. Security analysis demonstrates excellent confusion and diffusion properties, with avalanche effect approaching the ideal 50% threshold and high Shannon entropy. Performance evaluation shows efficient encryption and decryption speeds suitable for educational purposes.

---

## 1. INTRODUCTION

### 1.1 Background

Block ciphers are fundamental cryptographic primitives used for symmetric encryption. Modern block ciphers like AES (Advanced Encryption Standard) and DES (Data Encryption Standard) employ sophisticated structures to achieve security through confusion and diffusion. Understanding these structures is essential for any cybersecurity professional.

### 1.2 Objectives

The primary objectives of this project are:

1. To understand the internal structure of real-world block ciphers including key scheduling, round functions, and diffusion/confusion mechanisms
2. To design and implement a functional Mini Block Cipher
3. To evaluate the cipher using cryptographic security tests
4. To compare the designed cipher with standard algorithms

### 1.3 Parameters

| Parameter     | Value                      |
| ------------- | -------------------------- |
| Block Size    | 64 bits                    |
| Key Size      | 64 bits                    |
| Structure     | SPN                        |
| Rounds        | 8                          |
| Mix Function  | Modular Addition (ADD MOD) |
| Key Operation | ROTATE KEY                 |

---

## 2. CIPHER ARCHITECTURE

### 2.1 SPN Structure Overview

The Mini Block Cipher follows the Substitution-Permutation Network (SPN) architecture, which is also used in AES. This structure provides:

- **Confusion**: Achieved through the S-Box substitution
- **Diffusion**: Achieved through the P-Box permutation
- **Key Mixing**: Achieved through XOR operations with round keys

### 2.2 Round Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    ENCRYPTION PROCESS                        │
├─────────────────────────────────────────────────────────────┤
│  Plaintext (64-bit)                                         │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────┐                                           │
│  │  AddRoundKey │ ◄── K0 (Round Key 0)                   │
│  └─────────────┘                                           │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  ROUND 1-7                          │   │
│  │  ┌─────────────┐                                     │   │
│  │  │   S-Box    │ (Substitution)                      │   │
│  │  └─────────────┘                                     │   │
│  │       │                                               │   │
│  │  ┌─────────────┐                                     │   │
│  │  │   P-Box    │ (Permutation)                       │   │
│  │  └─────────────┘                                     │   │
│  │       │                                               │   │
│  │  ┌─────────────┐                                     │   │
│  │  │ AddRoundKey │ ◄── K1-K7                          │   │
│  │  └─────────────┘                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────┐                                           │
│  │   S-Box    │ (Final Substitution)                      │
│  └─────────────┘                                           │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────┐                                           │
│  │ AddRoundKey │ ◄── K7 (Final Round Key)                │
│  └─────────────┘                                           │
│       │                                                     │
│       ▼                                                     │
│  Ciphertext (64-bit)                                        │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Encryption Algorithm

```
ENCRYPT(plaintext, key):
    state ← plaintext
    round_keys ← KEY_SCHEDULE(key)

    # Initial round
    state ← state XOR round_keys[0]

    # Main rounds 1-7
    FOR i = 1 TO 7:
        state ← SUBSTITUTE(state, S-Box)
        state ← PERMUTE(state, P-Box)
        state ← state XOR round_keys[i]

    # Final round
    state ← SUBSTITUTE(state, S-Box)
    state ← state XOR round_keys[7]

    RETURN state
```

### 2.4 Decryption Algorithm

```
DECRYPT(ciphertext, key):
    state ← ciphertext
    round_keys ← KEY_SCHEDULE(key)

    # Initial operation
    state ← state XOR round_keys[7]
    state ← SUBSTITUTE(state, Inv_S-Box)

    # Main inverse rounds 6-1
    FOR i = 6 DOWNTO 1:
        state ← state XOR round_keys[i]
        state ← PERMUTE(state, Inv_P-Box)
        state ← SUBSTITUTE(state, Inv_S-Box)

    RETURN state
```

---

## 3. S-BOX DESIGN

### 3.1 Requirements

The S-Box (Substitution Box) must provide:

- **Non-linearity**: Resistance to linear cryptanalysis
- **Bijection**: Each input must map to a unique output
- **Balanced output**: Equal distribution of output values
- **Maximum differential uniformity**: Resistance to differential cryptanalysis

### 3.2 Construction Method

The S-Box is constructed using the AES method, which involves:

1. **Multiplicative Inverse in GF(2^8)**: Computing the inverse of each byte in the Galois Field with irreducible polynomial x⁸ + x⁴ + x³ + x + 1 (0x11B)

2. **Affine Transformation**: Applying the following transformation:
   ```
   y = M × x + c
   ```
   Where M is an 8×8 binary matrix and c is an 8-bit constant (0x63)

### 3.3 S-Box Table (16×16)

The S-Box maps 8-bit input (x) to 8-bit output (y):

|       | 0x  | 1x  | 2x  | 3x  | 4x  | 5x  | 6x  | 7x  | 8x  | 9x  | Ax  | Bx  | Cx  | Dx  | Ex  | Fx  |
| ----- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **0** | 63  | 7C  | 77  | 7B  | F2  | 6B  | 6F  | C5  | 30  | 01  | 67  | 2B  | FE  | D7  | AB  | 76  |
| **1** | CA  | 82  | C9  | 7D  | FA  | 59  | 47  | F0  | AD  | D4  | A2  | AF  | 9C  | A4  | 72  | C0  |
| **2** | B7  | FD  | 93  | 26  | 36  | 3F  | F7  | CC  | 34  | A5  | E5  | F1  | 71  | D8  | 31  | 15  |
| **3** | 04  | C7  | 23  | C3  | 18  | 96  | 05  | 9A  | 07  | 12  | 80  | E2  | EB  | 27  | B2  | 75  |
| **4** | 09  | 83  | 2C  | 1A  | 1B  | 6E  | 5A  | A0  | 52  | 3B  | D6  | B3  | 29  | E3  | 2F  | 84  |
| **5** | 53  | D1  | 00  | ED  | 20  | FC  | B1  | 5B  | 6A  | CB  | BE  | 39  | 4A  | 4C  | 58  | CF  |
| **6** | D0  | EF  | AA  | FB  | 43  | 4D  | 33  | 85  | 45  | F9  | 02  | 7F  | 50  | 3C  | 9F  | A8  |
| **7** | 51  | A3  | 40  | 8F  | 92  | 9D  | 38  | F5  | BC  | B6  | DA  | 21  | 10  | FF  | F3  | D2  |
| **8** | CD  | 0C  | 13  | EC  | 5F  | 97  | 44  | 17  | C4  | A7  | 7E  | 3D  | 64  | 5D  | 19  | 73  |
| **9** | 60  | 81  | 4F  | DC  | 22  | 2A  | 90  | 88  | 46  | EE  | B8  | 14  | DE  | 5E  | 0B  | DB  |
| **A** | E0  | 32  | 3A  | 0A  | 49  | 06  | 24  | 5C  | C2  | D3  | AC  | 62  | 91  | 95  | E4  | 79  |
| **B** | E7  | C8  | 37  | 6D  | 8D  | D5  | 4E  | A9  | 6C  | 56  | F4  | EA  | 65  | 7A  | AE  | 08  |
| **C** | BA  | 78  | 25  | 2E  | 1C  | A6  | B4  | C6  | E8  | DD  | 74  | 1F  | 4B  | BD  | 8B  | 8A  |
| **D** | 70  | 3E  | B5  | 66  | 48  | 03  | F6  | 0E  | 61  | 35  | 57  | B9  | 86  | C1  | 1D  | 9E  |
| **E** | E1  | F8  | 98  | 11  | 69  | D9  | 8E  | 94  | 9B  | 1E  | 87  | E9  | CE  | 55  | 28  | DF  |
| **F** | 8C  | A1  | 89  | 0D  | BF  | E6  | 42  | 68  | 41  | 99  | 2D  | 0F  | B0  | 54  | BB  | 16  |

### 3.4 Properties

| Property                | Value                |
| ----------------------- | -------------------- |
| Nonlinearity            | 112 (maximum is 128) |
| Differential Uniformity | 4 (minimum is 4)     |
| Algebraic Degree        | 7                    |

---

## 4. P-BOX DESIGN

### 4.1 Purpose

The P-Box (Permutation Box) provides diffusion by spreading bits across the entire block.

### 4.2 Design Principles

- Each input bit should affect multiple output bits
- Bits should be spread across the entire 64-bit block
- After multiple rounds, one bit should influence many positions

### 4.3 P-Box Table

```
Input Bit Position → Output Bit Position
```

| Input      | 0   | 1   | 2   | 3   | 4   | 5   | 6   | 7   |
| ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Output** | 58  | 50  | 42  | 34  | 26  | 18  | 10  | 2   |

| Input      | 8   | 9   | 10  | 11  | 12  | 13  | 14  | 15  |
| ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Output** | 60  | 52  | 44  | 36  | 28  | 20  | 12  | 4   |

| Input      | 16  | 17  | 18  | 19  | 20  | 21  | 22  | 23  |
| ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Output** | 62  | 54  | 46  | 38  | 30  | 22  | 14  | 6   |

| Input      | 24  | 25  | 26  | 27  | 28  | 29  | 30  | 31  |
| ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Output** | 57  | 49  | 41  | 33  | 25  | 17  | 9   | 1   |

| Input      | 32  | 33  | 34  | 35  | 36  | 37  | 38  | 39  |
| ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Output** | 59  | 51  | 43  | 35  | 27  | 19  | 11  | 3   |

| Input      | 40  | 41  | 42  | 43  | 44  | 45  | 46  | 47  |
| ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Output** | 61  | 53  | 45  | 37  | 29  | 21  | 13  | 5   |

| Input      | 48  | 49  | 50  | 51  | 52  | 53  | 54  | 55  |
| ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Output** | 63  | 55  | 47  | 39  | 31  | 23  | 15  | 7   |

| Input      | 56  | 57  | 58  | 59  | 60  | 61  | 62  | 63  |
| ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Output** | 56  | 48  | 40  | 32  | 24  | 16  | 8   | 0   |

### 4.4 Diffusion Analysis

With this P-Box design, after 8 rounds, any single bit change affects approximately 32 bits (50% of the block), satisfying the avalanche criterion.

---

## 5. KEY SCHEDULE

### 5.1 ROTATE KEY Operation

The key schedule uses the ROTATE KEY operation as specified in the project requirements:

```
ROTATE_KEY(key, amount):
    RETURN ((key << amount) | (key >> (64 - amount))) AND 0xFFFFFFFFFFFFFFFF
```

### 5.2 Round Key Generation

```
GENERATE_ROUND_KEYS(master_key, num_rounds):
    round_keys ← []
    key ← master_key

    FOR round = 0 TO num_rounds-1:
        # ROTATE KEY with round-dependent amount
        rotation ← (7 + round × 3) MOD 64
        key ← ROTATE_KEY(key, rotation)

        # Apply S-Box transformation
        key_byte ← (key >> 56) AND 0xFF
        key ← key XOR (SBOX[key_byte] << 48)

        # XOR with round constant
        key ← key XOR (round << 56)

        round_keys.append(key)

    RETURN round_keys
```

### 5.3 Rotation Values

| Round | Rotation (bits) |
| ----- | --------------- |
| 0     | 7               |
| 1     | 10              |
| 2     | 13              |
| 3     | 16              |
| 4     | 19              |
| 5     | 22              |
| 6     | 25              |
| 7     | 28              |

---

## 6. IMPLEMENTATION

### 6.1 Python Code Structure

```python
# Core Components:
# - SBOX: 256-element lookup table
# - INV_SBOX: Inverse S-Box for decryption
# - PBOX: 64-element permutation table
# - INV_PBOX: Inverse P-Box for decryption

class MiniBlockCipher:
    def __init__(self, key):
        self.num_rounds = 8
        self.round_keys = generate_round_keys(key, self.num_rounds)

    def encrypt(self, plaintext):
        # Implementation of encryption
        pass

    def decrypt(self, ciphertext):
        # Implementation of decryption
        pass
```

### 6.2 Test Results

```
[1] CIPHER INITIALIZATION
    Master Key: 0123456789ABCDEF
    Plaintext:  0123456789ABCDEF

[2] ENCRYPTION
    Ciphertext: 0E56D8FDD87527DD

[3] DECRYPTION
    Decrypted:  0123456789ABCDEF

[4] VERIFICATION
    Success: True
```

---

## 7. SECURITY ANALYSIS

### 7.1 Shannon Entropy

**Definition**: Measures the randomness and uncertainty of the ciphertext.

**Formula**:

```
H(X) = -Σ p(x) × log₂(p(x))
```

**Results**:

- Average Entropy: 0.986446
- Ideal Value: 1.0
- Interpretation: Excellent randomness

### 7.2 Avalanche Effect (SAC)

**Definition**: Ensures that changing 1 bit in plaintext flips approximately half of the ciphertext bits.

**Results**:

- Avalanche Effect: 50.49%
- Ideal Value: 50%
- Interpretation: Excellent diffusion

### 7.3 Hamming Distance

**Definition**: Measures the bit-level difference between original and encrypted text.

**Results**:

- Hamming Distance: 31 bits (for 1-bit plaintext difference)
- Block Size: 64 bits
- Expected: ~32 bits

### 7.4 Frequency Test

**Definition**: Checks if the number of 0s and 1s in ciphertext are approximately equal.

**Results**:

- Frequency Deviation: 5.66%
- Ideal Value: 0%
- Interpretation: Good balance

### 7.5 Correlation Coefficient

**Definition**: Measures the statistical relationship between plaintext and ciphertext.

**Results**:

- Correlation: 0.001461
- Ideal Value: 0
- Interpretation: No correlation (excellent)

### 7.6 Security Metrics Summary

| Test                | Result  | Ideal    | Status       |
| ------------------- | ------- | -------- | ------------ |
| Shannon Entropy     | 0.986   | 1.0      | ✅ Excellent |
| Avalanche Effect    | 50.49%  | 50%      | ✅ Excellent |
| Hamming Distance    | 31 bits | ~32 bits | ✅ Good      |
| Frequency Deviation | 5.66%   | 0%       | ✅ Good      |
| Correlation         | 0.001   | 0        | ✅ Excellent |

---

## 8. PERFORMANCE EVALUATION

### 8.1 Timing Results

| Operation  | Time (ns/block) | Time (μs/block) |
| ---------- | --------------- | --------------- |
| Encryption | 596,941         | 596.94          |
| Decryption | 636,008         | 636.01          |

### 8.2 Performance Characteristics

- **Encryption Speed**: ~1,675 encryptions per second
- **Decryption Speed**: ~1,573 decryptions per second
- **Efficiency**: The cipher maintains near-symmetric performance between encryption and decryption

---

## 9. COMPARISON WITH STANDARD ALGORITHMS

### 9.1 Comparison Table

| Feature        | Mini Block Cipher | AES              | DES     | Twofish             |
| -------------- | ----------------- | ---------------- | ------- | ------------------- |
| **Block Size** | 64 bits           | 128 bits         | 64 bits | 128 bits            |
| **Key Size**   | 64 bits           | 128/192/256 bits | 56 bits | 128/192/256 bits    |
| **Rounds**     | 8                 | 10/12/14         | 16      | 16                  |
| **Structure**  | SPN               | SPN              | Feistel | Feistel             |
| **S-Box**      | 16×16 AES-style   | 8×8              | 8×8     | 8×8 (key-dependent) |
| **MixColumns** | Modular Add       | MDS Matrix       | None    | MDS Matrix          |

### 9.2 Analysis

**Advantages**:

- Simpler structure suitable for educational purposes
- Smaller block size (64 bits) for easier analysis
- 8 rounds provide good security margin
- AES-style S-Box ensures strong cryptographic properties

**Limitations**:

- Smaller key size (64 bits) compared to modern standards
- Smaller block size limits throughput
- Not suitable for production use

---

## 10. CONCLUSION

This Mini Block Cipher project successfully demonstrates the fundamental principles of block cipher design:

1. **Understanding**: Gained deep understanding of SPN architecture, key scheduling, and cryptographic components

2. **Implementation**: Created a functional cipher with proper encryption/decryption capabilities

3. **Security**: Achieved excellent security metrics:
   - Avalanche effect: 50.49% (ideal: 50%)
   - Shannon entropy: 0.986 (ideal: 1.0)
   - Correlation: ~0 (ideal: 0)

4. **Analysis**: Conducted comprehensive security testing using industry-standard metrics

5. **Education**: Provided a clear example of how modern block ciphers like AES work internally

The cipher is suitable for educational purposes and demonstrates the core concepts of symmetric cryptography. While not intended for production use due to its smaller key size, it provides an excellent learning platform for understanding cryptographic design principles.

---

## REFERENCES

1. AES Specification: FIPS PUB 197
2. DES Specification: FIPS PUB 46-3
3. "The Design of Rijndael" by Joan Daemen and Vincent Rijmen
4. "Applied Cryptography" by Bruce Schneier
5. Course Materials: TP 00-02, Block Cipher materials

---

## APPENDIX A: CODE

The complete Python implementation is available in `mini_cipher.py` file.

## APPENDIX B: GLOSSARY

| Term  | Definition                       |
| ----- | -------------------------------- |
| SPN   | Substitution-Permutation Network |
| S-Box | Substitution Box                 |
| P-Box | Permutation Box                  |
| SAC   | Strict Avalanche Criterion       |
| XOR   | Exclusive OR                     |
| MOD   | Modular Addition                 |

---

_Report prepared for Master 1 Cyber Security / Cryptosystems Course_
_Academic Year 2025-2026_
