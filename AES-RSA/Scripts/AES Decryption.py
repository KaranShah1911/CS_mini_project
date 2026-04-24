import hashlib
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

print("*********************************************************")
print("       STEP 5: AES-128 Decryption + Signature Verification")
print("*********************************************************")
print()

# =====================================================================
# UPGRADE 1: Digital Signatures — Verify RSA signature of ciphertext
# UPGRADE 3: Automated File I/O — Load key from aes_key_recovered.json
#             (NO password prompt — true hybrid key transport)
# UPGRADE (User Request): PKCS#7 Unpadding for variable-length messages
# =====================================================================

# --- AES S-Box (standard Rijndael S-Box) ---
s_box = {"0x0": "0x63", "0x1": "0x7c", "0x2": "0x77", "0x3": "0x7b", "0x4": "0xf2", "0x5": "0x6b", "0x6": "0x6f",
         "0x7": "0xc5", "0x8": "0x30", "0x9": "0x1", "0xa": "0x67", "0xb": "0x2b", "0xc": "0xfe", "0xd": "0xd7",
         "0xe": "0xab", "0xf": "0x76", "0x10": "0xca", "0x11": "0x82", "0x12": "0xc9", "0x13": "0x7d", "0x14": "0xfa",
         "0x15": "0x59", "0x16": "0x47", "0x17": "0xf0", "0x18": "0xad", "0x19": "0xd4", "0x1a": "0xa2", "0x1b": "0xaf",
         "0x1c": "0x9c", "0x1d": "0xa4", "0x1e": "0x72", "0x1f": "0xc0", "0x20": "0xb7", "0x21": "0xfd", "0x22": "0x93",
         "0x23": "0x26", "0x24": "0x36", "0x25": "0x3f", "0x26": "0xf7", "0x27": "0xcc", "0x28": "0x34", "0x29": "0xa5",
         "0x2a": "0xe5", "0x2b": "0xf1", "0x2c": "0x71", "0x2d": "0xd8", "0x2e": "0x31", "0x2f": "0x15", "0x30": "0x4",
         "0x31": "0xc7", "0x32": "0x23", "0x33": "0xc3", "0x34": "0x18", "0x35": "0x96", "0x36": "0x5", "0x37": "0x9a",
         "0x38": "0x7", "0x39": "0x12", "0x3a": "0x80", "0x3b": "0xe2", "0x3c": "0xeb", "0x3d": "0x27", "0x3e": "0xb2",
         "0x3f": "0x75", "0x40": "0x9", "0x41": "0x83", "0x42": "0x2c", "0x43": "0x1a", "0x44": "0x1b", "0x45": "0x6e",
         "0x46": "0x5a", "0x47": "0xa0", "0x48": "0x52", "0x49": "0x3b", "0x4a": "0xd6", "0x4b": "0xb3", "0x4c": "0x29",
         "0x4d": "0xe3", "0x4e": "0x2f", "0x4f": "0x84", "0x50": "0x53", "0x51": "0xd1", "0x52": "0x0", "0x53": "0xed",
         "0x54": "0x20", "0x55": "0xfc", "0x56": "0xb1", "0x57": "0x5b", "0x58": "0x6a", "0x59": "0xcb", "0x5a": "0xbe",
         "0x5b": "0x39", "0x5c": "0x4a", "0x5d": "0x4c", "0x5e": "0x58", "0x5f": "0xcf", "0x60": "0xd0", "0x61": "0xef",
         "0x62": "0xaa", "0x63": "0xfb", "0x64": "0x43", "0x65": "0x4d", "0x66": "0x33", "0x67": "0x85", "0x68": "0x45",
         "0x69": "0xf9", "0x6a": "0x2", "0x6b": "0x7f", "0x6c": "0x50", "0x6d": "0x3c", "0x6e": "0x9f", "0x6f": "0xa8",
         "0x70": "0x51", "0x71": "0xa3", "0x72": "0x40", "0x73": "0x8f", "0x74": "0x92", "0x75": "0x9d", "0x76": "0x38",
         "0x77": "0xf5", "0x78": "0xbc", "0x79": "0xb6", "0x7a": "0xda", "0x7b": "0x21", "0x7c": "0x10", "0x7d": "0xff",
         "0x7e": "0xf3", "0x7f": "0xd2", "0x80": "0xcd", "0x81": "0xc", "0x82": "0x13", "0x83": "0xec", "0x84": "0x5f",
         "0x85": "0x97", "0x86": "0x44", "0x87": "0x17", "0x88": "0xc4", "0x89": "0xa7", "0x8a": "0x7e", "0x8b": "0x3d",
         "0x8c": "0x64", "0x8d": "0x5d", "0x8e": "0x19", "0x8f": "0x73", "0x90": "0x60", "0x91": "0x81", "0x92": "0x4f",
         "0x93": "0xdc", "0x94": "0x22", "0x95": "0x2a", "0x96": "0x90", "0x97": "0x88", "0x98": "0x46", "0x99": "0xee",
         "0x9a": "0xb8", "0x9b": "0x14", "0x9c": "0xde", "0x9d": "0x5e", "0x9e": "0xb", "0x9f": "0xdb", "0xa0": "0xe0",
         "0xa1": "0x32", "0xa2": "0x3a", "0xa3": "0xa", "0xa4": "0x49", "0xa5": "0x6", "0xa6": "0x24", "0xa7": "0x5c",
         "0xa8": "0xc2", "0xa9": "0xd3", "0xaa": "0xac", "0xab": "0x62", "0xac": "0x91", "0xad": "0x95", "0xae": "0xe4",
         "0xaf": "0x79", "0xb0": "0xe7", "0xb1": "0xc8", "0xb2": "0x37", "0xb3": "0x6d", "0xb4": "0x8d", "0xb5": "0xd5",
         "0xb6": "0x4e", "0xb7": "0xa9", "0xb8": "0x6c", "0xb9": "0x56", "0xba": "0xf4", "0xbb": "0xea", "0xbc": "0x65",
         "0xbd": "0x7a", "0xbe": "0xae", "0xbf": "0x8", "0xc0": "0xba", "0xc1": "0x78", "0xc2": "0x25", "0xc3": "0x2e",
         "0xc4": "0x1c", "0xc5": "0xa6", "0xc6": "0xb4", "0xc7": "0xc6", "0xc8": "0xe8", "0xc9": "0xdd", "0xca": "0x74",
         "0xcb": "0x1f", "0xcc": "0x4b", "0xcd": "0xbd", "0xce": "0x8b", "0xcf": "0x8a", "0xd0": "0x70", "0xd1": "0x3e",
         "0xd2": "0xb5", "0xd3": "0x66", "0xd4": "0x48", "0xd5": "0x3", "0xd6": "0xf6", "0xd7": "0xe", "0xd8": "0x61",
         "0xd9": "0x35", "0xda": "0x57", "0xdb": "0xb9", "0xdc": "0x86", "0xdd": "0xc1", "0xde": "0x1d", "0xdf": "0x9e",
         "0xe0": "0xe1", "0xe1": "0xf8", "0xe2": "0x98", "0xe3": "0x11", "0xe4": "0x69", "0xe5": "0xd9", "0xe6": "0x8e",
         "0xe7": "0x94", "0xe8": "0x9b", "0xe9": "0x1e", "0xea": "0x87", "0xeb": "0xe9", "0xec": "0xce", "0xed": "0x55",
         "0xee": "0x28", "0xef": "0xdf", "0xf0": "0x8c", "0xf1": "0xa1", "0xf2": "0x89", "0xf3": "0xd", "0xf4": "0xbf",
         "0xf5": "0xe6", "0xf6": "0x42", "0xf7": "0x68", "0xf8": "0x41", "0xf9": "0x99", "0xfa": "0x2d", "0xfb": "0xf",
         "0xfc": "0xb0", "0xfd": "0x54", "0xfe": "0xbb", "0xff": "0x16"}

inv_s_box = {v: k for k, v in s_box.items()}

# --- AES Round Constants ---
round_constant_array = [["0x01", "0x00", "0x00", "0x00"], ["0x02", "0x00", "0x00", "0x00"],
                        ["0x04", "0x00", "0x00", "0x00"], ["0x08", "0x00", "0x00", "0x00"],
                        ["0x10", "0x00", "0x00", "0x00"], ["0x20", "0x00", "0x00", "0x00"],
                        ["0x40", "0x00", "0x00", "0x00"], ["0x80", "0x00", "0x00", "0x00"],
                        ["0x1b", "0x00", "0x00", "0x00"], ["0x36", "0x00", "0x00", "0x00"]]


# ==============================================================
#  AES Core Functions (same algorithm as original, refactored)
# ==============================================================

def xor_words(a, b):
    """XOR two 4-element hex-string lists."""
    return [hex(int(a[i], 16) ^ int(b[i], 16)) for i in range(4)]


def key_expansion(key_hex):
    """
    AES-128 Key Expansion.
    Takes a 16-element hex list (the key), returns a list of 11 round key
    arrays (each 16 hex strings): [round_key_0, round_key_1, ..., round_key_10].
    """
    round_keys = [key_hex[:]]
    prev_key = key_hex[:]

    for r in range(10):
        w0 = prev_key[0:4]
        w1 = prev_key[4:8]
        w2 = prev_key[8:12]
        w3 = prev_key[12:16]
        original_w3 = w3[:]

        # g function: circular left shift → S-Box → add round constant
        shifted = [w3[1], w3[2], w3[3], w3[0]]
        substituted = [s_box[s] for s in shifted]
        g_result = []
        for j in range(4):
            g_result.append(hex(int(substituted[j], 16) ^ int(round_constant_array[r][j], 16)))

        new_w0 = xor_words(w0, g_result)
        new_w1 = xor_words(w1, new_w0)
        new_w2 = xor_words(w2, new_w1)
        new_w3 = xor_words(original_w3, new_w2)

        new_key = new_w0 + new_w1 + new_w2 + new_w3
        round_keys.append(new_key)
        prev_key = new_key

        print(f"  Round Key {r + 1}: {new_key}")

    return round_keys


def arr_to_state(flat_hex):
    """Convert 16-element flat hex list to 4x4 state matrix (column-major, AES spec)."""
    state = [[None] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = flat_hex[col * 4 + row]
    return state


def state_to_flat(state):
    """Convert 4x4 state matrix back to 16-element flat hex list (column-major)."""
    flat = []
    for col in range(4):
        for row in range(4):
            flat.append(state[row][col])
    return flat


def xor_state(state, key_matrix):
    """XOR two 4x4 state matrices element-wise."""
    result = [[None] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = hex(int(state[i][j], 16) ^ int(key_matrix[i][j], 16))
    return result


def inv_sub_bytes(state):
    """Apply inverse S-Box substitution to every byte of the state matrix."""
    result = [[None] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = inv_s_box[state[i][j]]
    return result


def inv_shift_rows(state):
    """AES InvShiftRows: right-rotate row i by i positions."""
    result = [row[:] for row in state]  # deep copy
    # Row 0: no shift
    # Row 1: shift right by 1  (= left by 3)
    result[1] = [state[1][3], state[1][0], state[1][1], state[1][2]]
    # Row 2: shift right by 2  (= left by 2)
    result[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
    # Row 3: shift right by 3  (= left by 1)
    result[3] = [state[3][1], state[3][2], state[3][3], state[3][0]]
    return result


def gf_mul(a, b):
    """Multiply two numbers in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p


def inv_mix_columns(state):
    """AES InvMixColumns: multiply each column by the inverse polynomial matrix in GF(2^8)."""
    result = [[None] * 4 for _ in range(4)]
    for c in range(4):
        s0 = int(state[0][c], 16)
        s1 = int(state[1][c], 16)
        s2 = int(state[2][c], 16)
        s3 = int(state[3][c], 16)
        # Inverse MixColumns matrix: [0x0e, 0x0b, 0x0d, 0x09] (circulant)
        result[0][c] = hex(gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3))
        result[1][c] = hex(gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3))
        result[2][c] = hex(gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3))
        result[3][c] = hex(gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3))
    return result


def aes_decrypt_block(ciphertext_hex, round_keys):
    """
    Decrypts a single 16-byte block using AES-128.
    ciphertext_hex: list of 16 hex strings
    round_keys:     list of 11 round key arrays [rk0, rk1, ..., rk10]
    Returns:        list of 16 hex strings (the decrypted plaintext block)
    """
    # Build state matrix
    state = arr_to_state(ciphertext_hex)

    # Initial AddRoundKey with round key 10
    rk10 = arr_to_state(round_keys[10])
    state = xor_state(state, rk10)

    # Rounds 9 down to 1: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
    for r in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        rk = arr_to_state(round_keys[r])
        state = xor_state(state, rk)
        state = inv_mix_columns(state)

    # Final round (round 0): InvShiftRows → InvSubBytes → AddRoundKey (no InvMixColumns)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    rk0 = arr_to_state(round_keys[0])
    state = xor_state(state, rk0)

    return state_to_flat(state)


# ==============================================================
#  Load all input files (NO password prompt — hybrid key transport)
# ==============================================================

# --- Load recovered AES key (from Hybrid RSA Decryption, Step 4) ---
key_path = os.path.join(SCRIPT_DIR, "aes_key_recovered.json")
if not os.path.exists(key_path):
    print("ERROR: aes_key_recovered.json not found!")
    print("Please run 'Hybrid RSA Decryption.py' first (Step 4).")
    exit(1)

with open(key_path, "r") as f:
    key_data = json.load(f)

key = key_data["aes_key_hex"]
print(f"AES key loaded from aes_key_recovered.json")
print(f"  Key: {key}")
print(f"  (Recovered via RSA key transport -- no password needed!)")
print()

# --- Load AES ciphertext ---
ct_path = os.path.join(SCRIPT_DIR, "aes_ciphertext.json")
if not os.path.exists(ct_path):
    print("ERROR: aes_ciphertext.json not found!")
    print("Please run 'AES Encryption.py' first (Step 2).")
    exit(1)

with open(ct_path, "r") as f:
    ct_data = json.load(f)

all_ciphertext = ct_data["ciphertext"]
num_blocks = ct_data["num_blocks"]
print(f"Ciphertext loaded: {len(all_ciphertext)} bytes ({num_blocks} block(s))")
print()

# ==============================================================
#  UPGRADE 1: Digital Signature Verification
# ==============================================================

sig_path = os.path.join(SCRIPT_DIR, "signature.json")
pub_path = os.path.join(SCRIPT_DIR, "public_key.json")

if os.path.exists(sig_path) and os.path.exists(pub_path):
    with open(sig_path, "r") as f:
        sig_data = json.load(f)
    with open(pub_path, "r") as f:
        pub_key = json.load(f)

    signature = int(sig_data["signature"])
    n_pub = int(pub_key["n"])
    e_pub = int(pub_key["e"])

    # Recompute SHA-256 hash of the ciphertext
    ct_byte_values = [int(x, 16) for x in all_ciphertext]
    ct_bytes = bytes(ct_byte_values)
    actual_hash_hex = hashlib.sha256(ct_bytes).hexdigest()
    actual_hash_int = int(actual_hash_hex, 16)

    # Verify: hash_from_signature = signature^e mod n
    hash_from_sig = pow(signature, e_pub, n_pub)

    print("--- Digital Signature Verification ---")
    print(f"  Computed SHA-256:    {actual_hash_hex}")
    if hash_from_sig == actual_hash_int:
        print(f"  [VALID] Signature is VALID -- File is authentic and untampered!")
    else:
        print(f"  [FAILED] Signature is INVALID -- File may have been tampered with!")
    print()
else:
    print("WARNING: signature.json or public_key.json not found. Skipping signature verification.")
    print()

# ==============================================================
#  Key Expansion (runs once for all blocks)
# ==============================================================

print("--- AES Key Expansion ---")
round_keys = key_expansion(key)
print()

# ==============================================================
#  Decrypt each 16-byte block
# ==============================================================

all_plaintext_bytes = []

for block_idx in range(num_blocks):
    ct_block = all_ciphertext[block_idx * 16 : (block_idx + 1) * 16]

    print(f"--- Decrypting Block {block_idx + 1}/{num_blocks} ---")
    print(f"  Ciphertext block: {ct_block}")

    pt_block = aes_decrypt_block(ct_block, round_keys)
    print(f"  Plaintext block:  {pt_block}")

    # Convert hex strings to byte values
    for h in pt_block:
        all_plaintext_bytes.append(int(h, 16))

    print()

# ==============================================================
#  PKCS#7 Unpadding
# ==============================================================

# The last byte tells us how many padding bytes were added
pad_value = all_plaintext_bytes[-1]

if 1 <= pad_value <= 16:
    # Verify all padding bytes are correct
    padding_valid = all(b == pad_value for b in all_plaintext_bytes[-pad_value:])
    if padding_valid:
        unpadded_bytes = all_plaintext_bytes[:-pad_value]
        print(f"PKCS#7 padding removed: {pad_value} byte(s)")
    else:
        print("WARNING: PKCS#7 padding is invalid. Showing raw output.")
        unpadded_bytes = all_plaintext_bytes
else:
    print("WARNING: No valid PKCS#7 padding detected. Showing raw output.")
    unpadded_bytes = all_plaintext_bytes

# Convert bytes to string
original_message = bytes(unpadded_bytes).decode('utf-8', errors='replace')

print()
print("*********************************************************")
print(f"  Original Message = {original_message}")
print("*********************************************************")