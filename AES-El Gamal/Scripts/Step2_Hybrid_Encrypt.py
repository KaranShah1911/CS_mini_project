# =====================================================================
# Step 2: Hybrid Encryption
#   AES-GCM (message) + El Gamal (AES key) + DSA (signature)
# =====================================================================
# Pipeline:
#   1. Generate random 256-bit AES key
#   2. AES-GCM encrypt the user's plaintext message
#   3. El Gamal encrypt the AES key -> (c1, c2)  [from scratch]
#   4. DSA sign (ciphertext + c1 + c2 + nonce)
#   5. Save encrypted_package.json
# =====================================================================

import os
import json
import base64
import secrets
from cryptography.hazmat.primitives.asymmetric import dsa, utils as dsa_utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# =====================================================================
#              El Gamal Encryption (From Scratch)
# =====================================================================
def elgamal_encrypt(plaintext_int, p, g, y):
    """
    El Gamal encryption from scratch.
    
    Given:
        plaintext_int: the message as a large integer (must be < p)
        p: prime modulus
        g: generator
        y: receiver's public key (y = g^x mod p)
    
    Returns:
        (c1, c2) ciphertext pair where:
            c1 = g^k mod p
            c2 = plaintext_int * y^k mod p
        k is a random ephemeral key
    """
    # Generate random ephemeral key k in [2, p-2]
    k = secrets.randbelow(p - 3) + 2

    # c1 = g^k mod p
    c1 = pow(g, k, p)

    # c2 = m * y^k mod p
    s = pow(y, k, p)  # shared secret
    c2 = (plaintext_int * s) % p

    return c1, c2, k


# =====================================================================
#                           MAIN EXECUTION
# =====================================================================
print("*" * 60)
print("       STEP 2: Hybrid Encryption")
print("       AES-GCM + El Gamal + DSA Signature")
print("*" * 60)

# --- 1. Load Keys ---
print("\n--- Loading Keys ---")

# Load Receiver's El Gamal public key
elgamal_path = os.path.join(SCRIPT_DIR, "receiver_elgamal_keys.json")
with open(elgamal_path, "r") as f:
    eg_keys = json.load(f)
p = int(eg_keys["p"])
g = int(eg_keys["g"])
y = int(eg_keys["y"])
print(f"  Receiver El Gamal public key loaded")
print(f"    p: {str(p)[:50]}... ({len(str(p))} digits)")
print(f"    g: {g}")
print(f"    y: {str(y)[:50]}... ({len(str(y))} digits)")

# Load Sender's DSA private key
dsa_priv_path = os.path.join(SCRIPT_DIR, "sender_dsa_private.pem")
with open(dsa_priv_path, "rb") as f:
    sender_dsa_private = serialization.load_pem_private_key(f.read(), password=None)
print(f"  Sender DSA private key loaded (for signing)")

# --- 2. Generate Random AES Key ---
print("\n--- Generating Random AES Key ---")
aes_key = os.urandom(32)  # 256-bit key
print(f"  AES key (hex): {aes_key.hex()}")
print(f"  AES key length: {len(aes_key)} bytes ({len(aes_key)*8}-bit)")

# --- 3. AES-GCM Encrypt Message ---
print("\n--- AES-GCM Message Encryption ---")
plaintext = input("Enter the message you want to encrypt: ")
plaintext_bytes = plaintext.encode("utf-8")
print(f"  Plaintext length: {len(plaintext_bytes)} bytes")

cipher = AESGCM(aes_key)
nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
ciphertext = cipher.encrypt(nonce, plaintext_bytes, None)
print(f"  Ciphertext length: {len(ciphertext)} bytes (includes 16-byte GCM auth tag)")

# --- 4. El Gamal Encrypt AES Key (from scratch) ---
print("\n--- El Gamal Encryption of AES Key (from scratch) ---")

# Convert 32-byte AES key to a large integer
aes_key_int = int.from_bytes(aes_key, byteorder='big')
print(f"  AES key as integer: {aes_key_int}")
print(f"  AES key integer bit-length: {aes_key_int.bit_length()} bits")
print(f"  Prime p bit-length: {p.bit_length()} bits  (key < p: {aes_key_int < p})")

c1, c2, k = elgamal_encrypt(aes_key_int, p, g, y)
print(f"\n  Ephemeral k: {str(k)[:50]}...")
print(f"  c1 = g^k mod p: {str(c1)[:50]}... ({len(str(c1))} digits)")
print(f"  c2 = m*y^k mod p: {str(c2)[:50]}... ({len(str(c2))} digits)")

# --- 5. DSA Sign the payload ---
print("\n--- DSA Digital Signature ---")

# Build the payload to sign: ciphertext + c1_bytes + c2_bytes + nonce
# Convert c1, c2 to fixed-length byte representations
c1_bytes = c1.to_bytes((c1.bit_length() + 7) // 8, byteorder='big')
c2_bytes = c2.to_bytes((c2.bit_length() + 7) // 8, byteorder='big')
payload_to_sign = ciphertext + c1_bytes + c2_bytes + nonce

signature = sender_dsa_private.sign(
    payload_to_sign,
    hashes.SHA256()
)
print(f"  Payload signed: {len(payload_to_sign)} bytes")
print(f"  DSA Signature length: {len(signature)} bytes (DER-encoded)")

# Decode signature components for display
r, s = dsa_utils.decode_dss_signature(signature)
print(f"  Signature (r): {r}")
print(f"  Signature (s): {s}")

# --- 6. Save Encrypted Package ---
package = {
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "nonce": base64.b64encode(nonce).decode(),
    "c1": str(c1),
    "c2": str(c2),
    "signature": base64.b64encode(signature).decode()
}

pkg_path = os.path.join(SCRIPT_DIR, "encrypted_package.json")
with open(pkg_path, "w") as f:
    json.dump(package, f, indent=2)

print("\n" + "*" * 60)
print(f"  Encrypted package saved to: {pkg_path}")
print("  Contents: ciphertext, nonce, c1, c2, DSA signature")
print("*" * 60)
