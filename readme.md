# Hybrid Security Frameworks

This repository contains a collection of three production-ready hybrid cryptographic systems. Each system leverages **AES (Advanced Encryption Standard)** for fast, bulk data encryption, paired with a different asymmetric cryptography method for secure key transport and digital signatures. 

These implementations provide three crucial security pillars:
1. **Data Secrecy (Confidentiality):** Bulk encryption via AES.
2. **File Authentication (Non-Repudiation):** Achieved via Digital Signatures (RSA, ECDSA, or DSA).
3. **Data Integrity:** Achieved by signing a SHA-256 hash of the ciphertext.

---

## 1. AES-RSA Hybrid Framework
**Folder:** `AES-RSA/Scripts`

This framework was built from scratch and relies on the mathematical difficulty of factoring large prime numbers. It features a completely manual, pure Python implementation of AES-128 and RSA.

### Pipeline
1. **Key Generation:** Generates 1024-bit RSA key pairs.
2. **AES Encryption:** Derives a 16-byte key from a user password via SHA-256, applies PKCS#7 padding, and block-encrypts the message. It then creates an RSA Digital Signature.
3. **Hybrid Encryption:** Encrypts the 16-byte AES key using the Receiver's RSA Public Key for secure transport.
4. **Hybrid Decryption:** The Receiver uses the Chinese Remainder Theorem (CRT) alongside their RSA Private Key to recover the AES key.
5. **AES Decryption:** Verifies the RSA digital signature, decrypts the message, and removes the padding.

### How to Run
Navigate to the `AES-RSA/Scripts` folder and run the following commands sequentially:

```bash
# 1. Receiver generates their RSA keys
python "Key Generation of RSA.py"
```
* **What it does:** Generates large primes `p` and `q`, calculates the modulus `n`, and derives public/private keys `e` and `d`. Saves them to `public_key.json` and `private_key.json`.

```bash
# 2. Sender encrypts the secret message with a password
python "AES Encryption.py"
```
* **What it does:** Asks for a password and a message. Derives an AES key via SHA-256, encrypts the message block-by-block, and signs the ciphertext with the Sender's RSA private key. Saves `aes_ciphertext.json` and `signature.json`.

```bash
# 3. Sender securely wraps the AES key for transport
python "Hybrid RSA Encryption.py"
```
* **What it does:** Re-derives the AES key from the password, converts it to an integer, and encrypts it using the Receiver's RSA public key. Saves to `rsa_encrypted_key.json`.

```bash
# 4. Receiver unwraps the AES key using their private key
python "Hybrid RSA Decryption.py"
```
* **What it does:** The receiver uses their private key to mathematically unlock the AES key. The recovered key is saved to `aes_key_recovered.json`.

```bash
# 5. Receiver decrypts the message and verifies the signature
python "AES Decryption.py"
```
* **What it does:** Uses the recovered AES key to decrypt the message, verifies the digital signature to ensure authenticity, and prints the original message.

---

## 2. AES-ECC Hybrid Framework
**Folder:** `AES-ECC/Scripts`

This framework utilizes the `cryptography` Python library and relies on Elliptic Curve Cryptography (ECC), specifically the `SECP256R1` curve. ECC provides the same level of security as RSA but with significantly smaller key sizes.

### Pipeline
1. **Key Generation:** Generates long-term ECC identity keys for both Sender and Receiver.
2. **Hybrid Encrypt:** Uses Elliptic Curve Diffie-Hellman (ECDH) with an ephemeral key to create a shared secret. It then uses HKDF to derive a Key Encryption Key (KEK) which encrypts a random AES key via AES-GCM. The message is encrypted, and an ECDSA signature is generated.
3. **Hybrid Decrypt:** The Receiver uses their private key and the ephemeral public key to reconstruct the shared secret, derive the KEK, recover the AES key, verify the ECDSA signature, and decrypt the message.

### How to Run
Navigate to the `AES-ECC/Scripts` folder and run the following commands sequentially:

```bash
# 1. Generate identity keys for both parties
python "Step1_ECC_Key_Gen.py"
```
* **What it does:** Uses the `SECP256R1` curve to generate ECC key pairs for both the Sender and the Receiver. Saves them as PEM files.

```bash
# 2. Sender encrypts the message, wraps the AES key, and signs the payload
python "Step2_Hybrid_Encrypt.py"
```
* **What it does:** Generates an ephemeral ECC key, computes an ECDH shared secret with the Receiver's public key, and derives a KEK via HKDF. Encrypts a random AES key with the KEK, encrypts the message with the AES key (both using AES-GCM), and signs the entire package with ECDSA. Outputs `encrypted_package.json`.

```bash
# 3. Receiver verifies the signature, unwraps the AES key, and decrypts the message
python "Step3_Hybrid_Decrypt.py"
```
* **What it does:** Loads the JSON package, reconstructs the ECDH shared secret using the Receiver's private key, re-derives the KEK, recovers the AES key, verifies the ECDSA signature, and finally decrypts the message.

---

## 3. AES-El Gamal Hybrid Framework
**Folder:** `AES-El Gamal/Scripts`

This framework pairs modern AES-GCM encryption with a from-scratch mathematical implementation of El Gamal cryptography, which relies on the difficulty of computing discrete logarithms.

### Pipeline
1. **Key Generation:** Generates El Gamal keys (from scratch using a 2048-bit safe prime) and DSA keys (via library) for digital signatures.
2. **Hybrid Encrypt:** Generates a random AES key, encrypts the message via AES-GCM, and mathematically encrypts the AES key using El Gamal equations (`c1 = g^k mod p`, `c2 = m * y^k mod p`). The payload is then signed using DSA.
3. **Hybrid Decrypt:** Verifies the DSA signature. If valid, uses the Receiver's El Gamal private key to mathematically recover the AES key (`m = c2 * inverse(c1^x mod p)`). Finally, the message is decrypted.

### How to Run
Navigate to the `AES-El Gamal/Scripts` folder and run the following commands sequentially:

```bash
# 1. Generate El Gamal and DSA keys
python "Step1_Key_Generation.py"
```
* **What it does:** Generates the Receiver's El Gamal keys (prime `p`, generator `g`, private `x`, public `y`) using pure Python math and saves them to a JSON file. Generates the Sender's DSA keys using the `cryptography` library and saves them as PEM files.

```bash
# 2. Sender encrypts the message, wraps the AES key via El Gamal, and signs with DSA
python "Step2_Hybrid_Encrypt.py"
```
* **What it does:** Generates a random 256-bit AES key and encrypts the message using AES-GCM. Converts the AES key into a large integer and encrypts it using El Gamal math from scratch, yielding ciphertexts `c1` and `c2`. Signs the payload with the Sender's DSA private key and saves it all to `encrypted_package.json`.

```bash
# 3. Receiver verifies the signature, unwraps the AES key via El Gamal, and decrypts
python "Step3_Hybrid_Decrypt.py"
```
* **What it does:** Loads the package and verifies the DSA signature mathematically. Recovers the AES key integer using from-scratch El Gamal decryption math (`c2 * modular_inverse(c1^x) mod p`) and converts it back to bytes. Decrypts the message using the recovered AES key via AES-GCM.
