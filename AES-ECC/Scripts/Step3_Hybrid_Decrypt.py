# =====================================================================
# Step 3: Hybrid Decryption (ECDH + HKDF + ECDSA Verify + AES-GCM)
# =====================================================================
# Pipeline:
#   1. Load Receiver's Private Key + Sender's Public Key
#   2. Load encrypted_package.json
#   3. ECDH -> Shared Secret (using Receiver Private + Ephemeral Public)
#   4. HKDF -> KEK
#   5. Decrypt AES Key using KEK
#   6. Verify ECDSA Signature (halt if invalid!)
#   7. Decrypt the message using the recovered AES key
# =====================================================================

import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

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


# =====================================================================
#                           MAIN EXECUTION
# =====================================================================
print("*" * 60)
print("       STEP 3: Hybrid ECC Decryption + Signature Verification")
print("*" * 60)

# --- 1. Load Keys ---
print("\n--- Loading Keys ---")
receiver_private = load_private_key("receiver_private.pem")
sender_public = load_public_key("sender_public.pem")
print("  Receiver's private key loaded (for ECDH)")
print("  Sender's public key loaded (for ECDSA verification)")

# --- 2. Load Encrypted Package ---
print("\n--- Loading Encrypted Package ---")
pkg_path = os.path.join(SCRIPT_DIR, "encrypted_package.json")
with open(pkg_path, "r") as f:
    package = json.load(f)

ciphertext = base64.b64decode(package["ciphertext"])
nonce_msg = base64.b64decode(package["nonce_msg"])
encrypted_aes_key = base64.b64decode(package["encrypted_aes_key"])
nonce_key = base64.b64decode(package["nonce_key"])
ephemeral_pub_pem = package["ephemeral_public_key"].encode()
signature = base64.b64decode(package["signature"])

print(f"  Ciphertext: {len(ciphertext)} bytes")
print(f"  Encrypted AES key: {len(encrypted_aes_key)} bytes")
print(f"  Signature: {len(signature)} bytes (DER-encoded)")

# Deserialize the ephemeral public key from PEM
ephemeral_public = serialization.load_pem_public_key(ephemeral_pub_pem)
eph_nums = ephemeral_public.public_numbers()
print(f"  Ephemeral Public X: {eph_nums.x}")
print(f"  Ephemeral Public Y: {eph_nums.y}")

# --- 3. ECDH -> Shared Secret ---
print("\n--- ECDH Key Agreement ---")
shared_secret = receiver_private.exchange(ec.ECDH(), ephemeral_public)
print(f"  Shared Secret (hex): {shared_secret.hex()}")
print(f"  Shared Secret length: {len(shared_secret)} bytes")
print("  (Must match the sender's shared secret -- ECDH guarantees this!)")

# --- 4. HKDF -> KEK ---
print("\n--- HKDF Key Derivation ---")
kek = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"aes-ecc-hybrid-kek"
).derive(shared_secret)
print(f"  KEK derived (hex): {kek.hex()}")

# --- 5. Decrypt AES Key ---
print("\n--- Decrypting AES Key with KEK (AES-GCM) ---")
kek_cipher = AESGCM(kek)
aes_key = kek_cipher.decrypt(nonce_key, encrypted_aes_key, None)
print(f"  Recovered AES key (hex): {aes_key.hex()}")
print(f"  AES key length: {len(aes_key)} bytes ({len(aes_key)*8}-bit)")

# --- 6. Verify ECDSA Signature ---
print("\n--- ECDSA Digital Signature Verification ---")
payload_to_verify = ciphertext + encrypted_aes_key + ephemeral_pub_pem

try:
    sender_public.verify(
        signature,
        payload_to_verify,
        ec.ECDSA(hashes.SHA256())
    )
    r, s = utils.decode_dss_signature(signature)
    print(f"  Signature (r): {r}")
    print(f"  Signature (s): {s}")
    print("  [VALID] Signature is VALID -- File is authentic and untampered!")
except InvalidSignature:
    print("  [FAILED] Signature verification FAILED!")
    print("  WARNING: The data may have been tampered with. Aborting.")
    exit(1)

# --- 7. Decrypt Message ---
print("\n--- AES-GCM Message Decryption ---")
msg_cipher = AESGCM(aes_key)
plaintext_bytes = msg_cipher.decrypt(nonce_msg, ciphertext, None)
plaintext = plaintext_bytes.decode("utf-8")
print(f"  Decrypted length: {len(plaintext_bytes)} bytes")

print("\n" + "*" * 60)
print(f"  Original Message = {plaintext}")
print("*" * 60)
