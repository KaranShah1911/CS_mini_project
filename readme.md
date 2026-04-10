# AES-RSA Hybrid Security Framework

This mini-project demonstrates a complete, production-ready implementation of a hybrid cryptographic system utilizing **AES-128 (Symmetric Encryption)** and **RSA (Asymmetric Encryption)**. 

The framework provides three crucial security pillars:
1. **Data Secrecy (Confidentiality):** Achieved via AES-128 encryption.
2. **File Authentication (Non-Repudiation):** Achieved via RSA Digital Signatures.
3. **Data Integrity:** Achieved by signing a SHA-256 hash of the ciphertext.

This repository features 5 Python scripts that represent a real-world secure communication pipeline between a Sender and a Receiver.

---

## The 5-Step Pipeline Explained

### 1. Key Generation (`Key Generation of RSA.py`)
This script acts on behalf of the **Receiver**. It generates mathematically secure primes to construct an RSA Public/Private key pair. 

**Code Snippet: Automated File I/O**
```python
public_key = {
    "n": str(n),
    "e": str(e)
}
with open("public_key.json", "w") as f:
    json.dump(public_key, f, indent=2)
```
**Explanation:** Once the keys are generated, they are immediately formatted into a JSON dictionary and saved. The `public_key.json` is distributed to anyone who wants to send a secure file, while the `private_key.json` remains securely with the receiver. This replaces manual copy-pasting of 600-digit numbers!

---

### 2. File Encryption & Signature (`AES Encryption.py`)
This script acts on behalf of the **Sender**. The sender has a secret message and wants to lock it. Instead of locking the massive file with slow RSA algorithms, it uses fast AES.

**Code Snippet: SHA-256 Key Derivation Function (KDF)**
```python
aes_key_bytes = hashlib.sha256(str_password.encode()).digest()[:16]
```
**Explanation:** Humans are terrible at remembering 16-character randomized keys (like `x7F!9aQ...`). This KDF allows the sender to type a human-readable password (like `SecurePassword123`). We hash it using SHA-256, and truncate it to exactly 16 bytes (128-bits) to strictly satisfy the requirements of AES-128.

**Code Snippet: PKCS#7 Padding**
```python
plaintext_bytes = str_plaintext.encode('utf-8')
pad_len = 16 - (len(plaintext_bytes) % 16)
padded_bytes = plaintext_bytes + bytes([pad_len] * pad_len)
```
**Explanation:** Block ciphers like AES require the input data to be an exact multiple of the block size (16 bytes). PKCS#7 padding calculates how many bytes are missing, and fills that exact space with bytes representing that number (e.g., if 4 bytes are missing, it pads `0x04 0x04 0x04 0x04`). This allows the system to encrypt messages of *any* arbitrary length!

**Code Snippet: Digital Signatures**
```python
hash_hex = hashlib.sha256(ct_bytes).hexdigest()
signature = pow(int(hash_hex, 16), d, n)
```
**Explanation:** Before sending the AES ciphertext, the sender creates a SHA-256 "fingerprint" of it. They then encrypt that fingerprint using their own RSA *private* key `d`. Because only the sender possesses `d`, anyone decrypting it with the sender's public key `e` is absolutely sure the sender was the one who signed it (Authentication), and that the file hasn't been altered (Integrity).

---

### 3. Secure Transport of AES Key (`Hybrid RSA Encryption.py`)
The sender encrypted the data with AES, but how do they give the receiver the password? They don't! Instead, they use Hybrid Cryptography.

**Code Snippet: Int Encoding & RSA Encryption**
```python
# Convert exactly 16-bytes of AES key into a single massive integer
plaintext_int = int.from_bytes(aes_key_bytes, byteorder='big')
# Encrypt utilizing the Receiver's Public Key (e, n)
ciphertext_int = fast_exp(plaintext_int, e, n)
```
**Explanation:** The raw 16-byte AES key generated in Step 2 is converted into a large mathematical integer. It is then encrypted using the **Receiver's Public RSA Key**. This acts as a digital lockbox that realistically *only* the receiver can open. The sender then transmits the encrypted AES key, the AES ciphertext, and the Digital Signature across the internet.

---

### 4. AES Key Recovery (`Hybrid RSA Decryption.py`)
The **Receiver** gets the files. First, they must recover the AES key to unlock the data. 

**Code Snippet: CRT RSA Decryption & Byte Decoding**
```python
plaintext_int = (x2 + h * q) % (p * q)
aes_key_bytes = plaintext_int.to_bytes(16, byteorder='big')
```
**Explanation:** The script automatically loads the receiver's `private_key.json`. Because RSA decryption is mathematically heavy, it uses the **Chinese Remainder Theorem (CRT)** to speed up the `d` modulus calculations significantly using the prime factors `p` and `q`. The resulting integer is safely converted back into exactly 16 bytes representing the original AES key.

---

### 5. Decryption & Verification (`AES Decryption.py`)
The **Receiver** finally uses the recovered AES key to decrypt the ciphertext, but first, they verify the sender's signature. Notice that **this script never asks the user for a password**!

**Code Snippet: Signature Verification**
```python
actual_hash_hex = hashlib.sha256(ct_bytes).hexdigest()
hash_from_sig = pow(signature, e_pub, n_pub)

if hash_from_sig == int(actual_hash_hex, 16):
    print("Signature is VALID")
```
**Explanation:** The receiver takes the ciphertext block, recalculates the SHA-256 hash using the same algorithm as the sender. They then "unlock" the signature using the sender's public key `e_pub`. If the unlocked hash perfectly matches their newly calculated hash, it proves mathematically that the file is authentic and hasn't suffered a man-in-the-middle attack!

**Code Snippet: PKCS#7 Unpadding**
```python
pad_value = all_plaintext_bytes[-1]
unpadded_bytes = all_plaintext_bytes[:-pad_value]
```
**Explanation:** Once the AES AES-128 block-decryption loop completes, the script looks at the very last byte of the message. Due to PKCS#7 standards, if the byte is `0x04`, it mathematically guarantees that the last 4 bytes are padding. The script slices them off (`[:-pad_value]`), revealing the beautifully recovered original message of any length.

---

## How to Run the Pipeline

Execute the following commands in order in your terminal:

```bash
# 1. Receiver generates their RSA keys
python "Key Generation of RSA.py"

# 2. Sender encrypts the secret message with a password
python "AES Encryption.py"

# 3. Sender securely wraps the AES key for transport
python "Hybrid RSA Encryption.py"

# 4. Receiver unwraps the AES key using their private key
python "Hybrid RSA Decryption.py"

# 5. Receiver decrypts the message and verifies the signature
python "AES Decryption.py"
```
