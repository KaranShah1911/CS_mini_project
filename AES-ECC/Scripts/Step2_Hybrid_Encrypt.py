# =====================================================================
# Step 2: Hybrid Encryption (ECDH + HKDF + AES-GCM + ECDSA)
# =====================================================================
# Pipeline:
#   1. Load Sender's Private Key + Receiver's Public Key
#   2. Generate ephemeral ECC key pair for ECDH
#   3. ECDH -> Shared Secret
#   4. HKDF -> KEK (Key Encryption Key)
#   5. Generate random AES key, encrypt it with KEK via AES-GCM
#   6. Encrypt user's message with AES key via AES-GCM
#   7. ECDSA sign the entire payload
#   8. Save encrypted_package.json
# =====================================================================

import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def load_private_key(filename):
    """Load an ECC private key from a PEM file."""
    path = os.path.join(SCRIPT_DIR, filename)
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(filename):
    """Load an ECC public key from a PEM file."""
    path = os.path.join(SCRIPT_DIR, filename)
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def pub_key_to_pem_bytes(public_key):
    """Serialize a public key to PEM bytes for storage."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# =====================================================================
#                           MAIN EXECUTION
# =====================================================================
print("*" * 60)
print("       STEP 2: Hybrid ECC Encryption")
print("*" * 60)

# --- 1. Load Keys ---
print("\n--- Loading Keys ---")
sender_private = load_private_key("sender_private.pem")
receiver_public = load_public_key("receiver_public.pem")
print("  Sender's private key loaded (for ECDSA signing)")
print("  Receiver's public key loaded (for ECDH)")

# --- 2. Generate Ephemeral ECC Key Pair ---
print("\n--- Generating Ephemeral Key Pair ---")
ephemeral_private = ec.generate_private_key(ec.SECP256R1())
ephemeral_public = ephemeral_private.public_key()
eph_nums = ephemeral_public.public_numbers()
print(f"  Ephemeral Public X: {eph_nums.x}")
print(f"  Ephemeral Public Y: {eph_nums.y}")
print("  (This ephemeral key is single-use and will be sent to Receiver)")

# --- 3. ECDH -> Shared Secret ---
print("\n--- ECDH Key Agreement ---")
shared_secret = ephemeral_private.exchange(ec.ECDH(), receiver_public)
print(f"  Shared Secret (hex): {shared_secret.hex()}")
print(f"  Shared Secret length: {len(shared_secret)} bytes")

# --- 4. HKDF -> KEK (Key Encryption Key) ---
print("\n--- HKDF Key Derivation ---")
kek = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"aes-ecc-hybrid-kek"
).derive(shared_secret)
print(f"  KEK derived (hex): {kek.hex()}")
print(f"  KEK length: {len(kek)} bytes (256-bit for AES-256-GCM)")

# --- 5. Generate Random AES Key & Encrypt It with KEK ---
print("\n--- Encrypting AES Key with KEK (AES-GCM) ---")
aes_key = os.urandom(32)  # 256-bit random AES key for message encryption
print(f"  Random AES key (hex): {aes_key.hex()}")

kek_cipher = AESGCM(kek)
nonce_key = os.urandom(12)  # 96-bit nonce for AES-GCM
encrypted_aes_key = kek_cipher.encrypt(nonce_key, aes_key, None)
print(f"  AES key encrypted with KEK ({len(encrypted_aes_key)} bytes including GCM tag)")

# --- 6. Get User Message & Encrypt with AES Key (AES-GCM) ---
print("\n--- AES-GCM Message Encryption ---")
plaintext = input("Enter the message you want to encrypt: ")
plaintext_bytes = plaintext.encode("utf-8")
print(f"  Plaintext length: {len(plaintext_bytes)} bytes")

msg_cipher = AESGCM(aes_key)
nonce_msg = os.urandom(12)  # separate nonce for message encryption
ciphertext = msg_cipher.encrypt(nonce_msg, plaintext_bytes, None)
print(f"  Ciphertext length: {len(ciphertext)} bytes (includes 16-byte GCM auth tag)")

# --- 7. ECDSA Signature ---
print("\n--- ECDSA Digital Signature ---")
# Build the payload bytes that we will sign (ciphertext + encrypted_key + ephemeral_pub)
ephemeral_pub_pem = pub_key_to_pem_bytes(ephemeral_public)
payload_to_sign = ciphertext + encrypted_aes_key + ephemeral_pub_pem

signature = sender_private.sign(
    payload_to_sign,
    ec.ECDSA(hashes.SHA256())
)
# Decode the DER-encoded signature for display
r, s = utils.decode_dss_signature(signature)
print(f"  Signature (r): {r}")
print(f"  Signature (s): {s}")
print(f"  Signature length: {len(signature)} bytes (DER-encoded)")

# --- 8. Save Encrypted Package ---
package = {
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "nonce_msg": base64.b64encode(nonce_msg).decode(),
    "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
    "nonce_key": base64.b64encode(nonce_key).decode(),
    "ephemeral_public_key": ephemeral_pub_pem.decode(),
    "signature": base64.b64encode(signature).decode()
}

pkg_path = os.path.join(SCRIPT_DIR, "encrypted_package.json")
with open(pkg_path, "w") as f:
    json.dump(package, f, indent=2)

print("\n" + "*" * 60)
print(f"  Encrypted package saved to: {pkg_path}")
print("  Contents: ciphertext, nonces, encrypted_key,")
print("            ephemeral_pubkey, ECDSA signature")
print("*" * 60)
