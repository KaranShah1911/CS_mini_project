import math
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

print("*********************************************************")
print("       STEP 4: Hybrid RSA Decryption of AES Key")
print("*********************************************************")
print()

# =====================================================================
# UPGRADE 2: Base64 Encoding — Decode integer back to bytes (replaces
#             broken base-53 dictionary loop)
# UPGRADE 3: Automated File I/O — Load private key and encrypted key
#             from JSON files; write recovered key to JSON
# =====================================================================


# --- Helper functions (preserved from original code) ---

def modInverse(a, m):
    m0 = m
    y1 = 0
    x_1 = 1
    if m == 1:
        return 0
    while a > 1:
        # q is quotient
        q_1 = a // m

        t = m

        # m is remainder now, process
        # same as Euclid's algorithm
        m = a % m
        a = t
        t = y1

        # Update x and y
        y1 = x_1 - q_1 * y1
        x_1 = t
    # Make x positive
    if x_1 < 0:
        x_1 = x_1 + m0
    return x_1


# Calculates the greatest common divisor of two integers
# Extended Euclidean Algorithm
def gcd(a, b):
    while a != 0 and b != 0:
        rem = a % b
        a = b
        b = rem
    return a


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


# --- Load private key automatically ---
priv_path = os.path.join(SCRIPT_DIR, "private_key.json")
if not os.path.exists(priv_path):
    print("ERROR: private_key.json not found!")
    print("Please run 'Key Generation of RSA.py' first (Step 1).")
    exit(1)

with open(priv_path, "r") as f:
    priv_key = json.load(f)

d = int(priv_key["d"])
p = int(priv_key["p"])
q = int(priv_key["q"])
n = int(priv_key["n"])

print("Private key (d, p, q) loaded from private_key.json")
print(f"  p = {str(p)[:50]}...  ({len(str(p))} digits)")
print(f"  q = {str(q)[:50]}...  ({len(str(q))} digits)")
print()

# --- Load the RSA-encrypted AES key ---
enc_path = os.path.join(SCRIPT_DIR, "rsa_encrypted_key.json")
if not os.path.exists(enc_path):
    print("ERROR: rsa_encrypted_key.json not found!")
    print("Please run 'Hybrid RSA Encryption.py' first (Step 3).")
    exit(1)

with open(enc_path, "r") as f:
    enc_data = json.load(f)

ciphertext_int = int(enc_data["ciphertext_int"])
print(f"RSA ciphertext integer loaded ({len(str(ciphertext_int))} digits)")
print()

# --- CRT-based RSA Decryption (preserved from original code) ---
# For speeding up calculation of q', I divide it here.
dp = d % (p - 1)
dq = d % (q - 1)
q_inverse = modInverse(q, p)
q_inverse = q_inverse % p

# If q' is negative, I should make it positive.
if q_inverse < 0:
    q_inverse += p

x1 = fast_exp(ciphertext_int, dp, p)
x2 = fast_exp(ciphertext_int, dq, q)

if x1 > x2:
    h = q_inverse * (x1 - x2) % p
else:
    h = (q_inverse * ((x1 + math.ceil(q / p) * p) - x2)) % p

plaintext_int = (x2 + h * q) % (p * q)

print(f"RSA-decrypted AES key integer: {plaintext_int}")
print()

# --- Convert integer back to 16 bytes (the AES key) ---
# This replaces the broken base-53 dictionary decoding.
aes_key_bytes = plaintext_int.to_bytes(16, byteorder='big')
print(f"Recovered AES key bytes (hex): {aes_key_bytes.hex()}")
print()

# --- Save the recovered AES key to file ---
# The AES Decryption script will load this file instead of asking for a password.
# This is the core of the hybrid key transport: the receiver never knows the password.
key_hex_list = [hex(b) for b in aes_key_bytes]

out_path = os.path.join(SCRIPT_DIR, "aes_key_recovered.json")
with open(out_path, "w") as f:
    json.dump({"aes_key_hex": key_hex_list}, f, indent=2)

print("*********************************************************")
print(f"  Recovered AES key saved to: {out_path}")
print("  (AES Decryption will use this key -- no password needed)")
print("*********************************************************")
