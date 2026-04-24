# =====================================================================
# Step 1: ECC Key Generation (Sender + Receiver)
# =====================================================================
# Generates SECP256R1 (NIST P-256) key pairs for both the Sender and
# the Receiver. Keys are saved as PEM files for use in Steps 2 and 3.
# =====================================================================

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_keypair(name):
    """Generate an ECC private/public key pair and save as PEM files."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Serialize and save the private key (no password protection for lab use)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    priv_path = os.path.join(SCRIPT_DIR, f"{name}_private.pem")
    with open(priv_path, "wb") as f:
        f.write(priv_pem)

    # Serialize and save the public key
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_path = os.path.join(SCRIPT_DIR, f"{name}_public.pem")
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    # Display the public key point for educational visibility
    pub_numbers = public_key.public_numbers()
    return priv_path, pub_path, pub_numbers


# =====================================================================
#                           MAIN EXECUTION
# =====================================================================
print("*" * 60)
print("       STEP 1: ECC Key Pair Generation (SECP256R1)")
print("*" * 60)

# --- Sender Keys ---
print("\n--- Generating Sender Key Pair ---")
s_priv, s_pub, s_nums = generate_keypair("sender")
print(f"  Curve: SECP256R1 (NIST P-256)")
print(f"  Public Key X: {s_nums.x}")
print(f"  Public Key Y: {s_nums.y}")
print(f"  Private key saved to: {s_priv}")
print(f"  Public key saved to:  {s_pub}")

# --- Receiver Keys ---
print("\n--- Generating Receiver Key Pair ---")
r_priv, r_pub, r_nums = generate_keypair("receiver")
print(f"  Curve: SECP256R1 (NIST P-256)")
print(f"  Public Key X: {r_nums.x}")
print(f"  Public Key Y: {r_nums.y}")
print(f"  Private key saved to: {r_priv}")
print(f"  Public key saved to:  {r_pub}")

print("\n" + "*" * 60)
print("  4 PEM key files generated successfully!")
print("  Sender's public key is shared with Receiver (and vice versa)")
print("*" * 60)
