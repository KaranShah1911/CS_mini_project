# =====================================================================
# Step 1: Key Generation (El Gamal from scratch + DSA from library)
# =====================================================================
# Generates:
#   - Receiver: El Gamal keys (p, g, x, y) using pure Python math
#   - Sender:   DSA keys using the cryptography library
# =====================================================================

import os
import json
import secrets
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# =====================================================================
#                 El Gamal Math (From Scratch)
# =====================================================================

# --- 2048-bit Safe Prime from RFC 3526 (MODP Group 14) ---
# Using a standardized prime is universally accepted practice.
# The "from scratch" aspect is the El Gamal encryption/decryption math.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

# Generator for MODP Group 14
G = 2


def generate_elgamal_keys():
    """
    Generate El Gamal key pair from scratch.
    
    Private key: x = random integer in [2, p-2]
    Public key:  y = g^x mod p
    """
    # Private key: random integer in range [2, p-2]
    x = secrets.randbelow(P - 3) + 2

    # Public key: y = g^x mod p (using Python's built-in modular exponentiation)
    y = pow(G, x, P)

    return x, y


# =====================================================================
#                           MAIN EXECUTION
# =====================================================================
print("*" * 60)
print("       STEP 1: Key Generation")
print("           El Gamal (Receiver) + DSA (Sender)")
print("*" * 60)

# --- Receiver: El Gamal Keys (from scratch) ---
print("\n--- Generating Receiver El Gamal Key Pair (from scratch) ---")
print(f"  Prime p: {str(P)[:60]}...  ({len(str(P))} digits)")
print(f"  Generator g: {G}")

x_priv, y_pub = generate_elgamal_keys()
print(f"  Private key x: {str(x_priv)[:60]}...  ({len(str(x_priv))} digits)")
print(f"  Public key  y: {str(y_pub)[:60]}...  ({len(str(y_pub))} digits)")

elgamal_keys = {
    "p": str(P),
    "g": str(G),
    "x": str(x_priv),
    "y": str(y_pub)
}
elgamal_path = os.path.join(SCRIPT_DIR, "receiver_elgamal_keys.json")
with open(elgamal_path, "w") as f:
    json.dump(elgamal_keys, f, indent=2)
print(f"\n  El Gamal keys saved to: {elgamal_path}")

# --- Sender: DSA Keys (from library) ---
print("\n--- Generating Sender DSA Key Pair (cryptography library) ---")
dsa_private_key = dsa.generate_private_key(key_size=2048)
dsa_public_key = dsa_private_key.public_key()

# Save DSA private key
dsa_priv_path = os.path.join(SCRIPT_DIR, "sender_dsa_private.pem")
with open(dsa_priv_path, "wb") as f:
    f.write(dsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save DSA public key
dsa_pub_path = os.path.join(SCRIPT_DIR, "sender_dsa_public.pem")
with open(dsa_pub_path, "wb") as f:
    f.write(dsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

dsa_params = dsa_public_key.public_numbers()
print(f"  DSA Key Size: 2048-bit")
print(f"  DSA Public y: {str(dsa_params.y)[:60]}...")
print(f"  Private key saved to: {dsa_priv_path}")
print(f"  Public key saved to:  {dsa_pub_path}")

print("\n" + "*" * 60)
print("  Key generation complete!")
print("  Receiver: El Gamal keys (receiver_elgamal_keys.json)")
print("  Sender:   DSA keys (sender_dsa_private.pem, sender_dsa_public.pem)")
print("*" * 60)
