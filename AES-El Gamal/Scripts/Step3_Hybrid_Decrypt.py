# =====================================================================
# Step 3: Hybrid Decryption
#   DSA Verify + El Gamal Recover AES Key + AES-GCM Decrypt
# =====================================================================
# Pipeline:
#   1. Load encrypted_package.json + Receiver's El Gamal keys + Sender's DSA pub
#   2. Verify DSA signature (halt if invalid!)
#   3. El Gamal recover AES key from (c1, c2)  [from scratch]
#   4. AES-GCM decrypt the message
# =====================================================================

import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# =====================================================================
#              El Gamal Decryption (From Scratch)
# =====================================================================
def mod_inverse(a, m):
    """
    Compute modular inverse of a mod m using Fermat's Little Theorem.
    Since m is prime: a^(-1) = a^(m-2) mod m
    """
    return pow(a, m - 2, m)


def elgamal_decrypt(c1, c2, x, p):
    """
    El Gamal decryption from scratch.
    
    Given:
        c1, c2: ciphertext pair from encryption
        x: receiver's private key
        p: prime modulus
    
    Math:
        s = c1^x mod p          (reconstruct the shared secret)
        s_inv = s^(p-2) mod p   (modular inverse via Fermat's Little Theorem)
        plaintext = c2 * s_inv mod p
    
    Returns:
        plaintext as integer
    """
    # Compute shared secret: s = c1^x mod p
    s = pow(c1, x, p)

    # Compute modular inverse of s
    s_inv = mod_inverse(s, p)

    # Recover plaintext: m = c2 * s^(-1) mod p
    plaintext_int = (c2 * s_inv) % p

    return plaintext_int


# =====================================================================
#                           MAIN EXECUTION
# =====================================================================
print("*" * 60)
print("       STEP 3: Hybrid Decryption + Signature Verification")
print("       DSA Verify + El Gamal + AES-GCM")
print("*" * 60)

# --- 1. Load Keys & Package ---
print("\n--- Loading Keys ---")

# Load Receiver's El Gamal keys (private key x needed for decryption)
elgamal_path = os.path.join(SCRIPT_DIR, "receiver_elgamal_keys.json")
with open(elgamal_path, "r") as f:
    eg_keys = json.load(f)
p = int(eg_keys["p"])
g = int(eg_keys["g"])
x = int(eg_keys["x"])
y = int(eg_keys["y"])
print(f"  Receiver El Gamal private key loaded")
print(f"    p: {str(p)[:50]}... ({len(str(p))} digits)")
print(f"    x: {str(x)[:50]}... ({len(str(x))} digits)")

# Load Sender's DSA public key
dsa_pub_path = os.path.join(SCRIPT_DIR, "sender_dsa_public.pem")
with open(dsa_pub_path, "rb") as f:
    sender_dsa_public = serialization.load_pem_public_key(f.read())
print(f"  Sender DSA public key loaded (for verification)")

# Load encrypted package
print("\n--- Loading Encrypted Package ---")
pkg_path = os.path.join(SCRIPT_DIR, "encrypted_package.json")
with open(pkg_path, "r") as f:
    package = json.load(f)

ciphertext = base64.b64decode(package["ciphertext"])
nonce = base64.b64decode(package["nonce"])
c1 = int(package["c1"])
c2 = int(package["c2"])
signature = base64.b64decode(package["signature"])

print(f"  Ciphertext: {len(ciphertext)} bytes")
print(f"  c1: {str(c1)[:50]}... ({len(str(c1))} digits)")
print(f"  c2: {str(c2)[:50]}... ({len(str(c2))} digits)")
print(f"  Signature: {len(signature)} bytes (DER-encoded)")

# --- 2. Verify DSA Signature ---
print("\n--- DSA Digital Signature Verification ---")

# Reconstruct the same payload that was signed
c1_bytes = c1.to_bytes((c1.bit_length() + 7) // 8, byteorder='big')
c2_bytes = c2.to_bytes((c2.bit_length() + 7) // 8, byteorder='big')
payload_to_verify = ciphertext + c1_bytes + c2_bytes + nonce

try:
    sender_dsa_public.verify(
        signature,
        payload_to_verify,
        hashes.SHA256()
    )
    print("  [VALID] DSA Signature is VALID -- File is authentic and untampered!")
except InvalidSignature:
    print("  [FAILED] DSA Signature verification FAILED!")
    print("  WARNING: The data may have been tampered with. Aborting.")
    exit(1)

# --- 3. El Gamal Recover AES Key (from scratch) ---
print("\n--- El Gamal Decryption of AES Key (from scratch) ---")

aes_key_int = elgamal_decrypt(c1, c2, x, p)
print(f"  Recovered AES key integer: {aes_key_int}")
print(f"  Recovered integer bit-length: {aes_key_int.bit_length()} bits")

# Convert integer back to 32 bytes
aes_key = aes_key_int.to_bytes(32, byteorder='big')
print(f"  Recovered AES key (hex): {aes_key.hex()}")
print(f"  AES key length: {len(aes_key)} bytes ({len(aes_key)*8}-bit)")

# --- 4. AES-GCM Decrypt Message ---
print("\n--- AES-GCM Message Decryption ---")
cipher = AESGCM(aes_key)
plaintext_bytes = cipher.decrypt(nonce, ciphertext, None)
plaintext = plaintext_bytes.decode("utf-8")
print(f"  Decrypted length: {len(plaintext_bytes)} bytes")

print("\n" + "*" * 60)
print(f"  Original Message = {plaintext}")
print("*" * 60)
