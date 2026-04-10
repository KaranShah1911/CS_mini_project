import hashlib
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

print("*********************************************************")
print("       STEP 3: Hybrid RSA Encryption of AES Key")
print("*********************************************************")
print()

# =====================================================================
# UPGRADE 2: Base64 Encoding — Replace broken base-53 with proper
#             integer encoding of the raw AES key bytes
# UPGRADE 3: Automated File I/O — Load public key from JSON
# UPGRADE 4: Key Derivation — SHA-256 hash of user password
# =====================================================================

# --- Load RSA public key automatically ---
pub_path = os.path.join(SCRIPT_DIR, "public_key.json")
if not os.path.exists(pub_path):
    print("ERROR: public_key.json not found!")
    print("Please run 'Key Generation of RSA.py' first (Step 1).")
    exit(1)

with open(pub_path, "r") as f:
    pub_key = json.load(f)

n = int(pub_key["n"])
e = int(pub_key["e"])
print("Public key (n, e) loaded from public_key.json")
print(f"  n = {str(n)[:60]}...  ({len(str(n))} digits)")
print(f"  e = {str(e)[:60]}...  ({len(str(e))} digits)")
print()

# --- Get password from user and derive AES key via SHA-256 KDF ---
password = input("Please enter the password (same one used in AES Encryption): ")

aes_key_bytes = hashlib.sha256(password.encode()).digest()[:16]
print()
print("AES key derived via SHA-256 KDF (16 bytes for AES-128):")
print(f"  Key bytes (hex): {aes_key_bytes.hex()}")
print()

# --- Convert AES key bytes to a large integer for RSA encryption ---
# This replaces the broken base-53 dictionary encoding.
# int.from_bytes is lossless and production-grade.
plaintext_int = int.from_bytes(aes_key_bytes, byteorder='big')
print(f"AES key as integer: {plaintext_int}")
print()


# fast modular exponentiation (preserved from original code)
def fast_exp(base, exponent, modulo):
    r = 1
    if 1 & exponent:
        r = base
    while exponent:
        exponent >>= 1
        base = (base * base) % modulo
        if exponent & 1:
            r = (r * base) % modulo
    return r


# --- RSA Encrypt the AES key integer ---
ciphertext_int = fast_exp(plaintext_int, e, n)
print(f"RSA-encrypted AES key (ciphertext integer):")
print(f"  {str(ciphertext_int)[:80]}...")
print(f"  ({len(str(ciphertext_int))} digits)")
print()

# --- Save the RSA-encrypted key to file ---
out_path = os.path.join(SCRIPT_DIR, "rsa_encrypted_key.json")
with open(out_path, "w") as f:
    json.dump({"ciphertext_int": str(ciphertext_int)}, f, indent=2)

print("*********************************************************")
print(f"  RSA-encrypted AES key saved to: {out_path}")
print("*********************************************************")