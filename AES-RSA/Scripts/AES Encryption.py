import hashlib
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

print("*********************************************************")
print("       STEP 2: AES-128 Encryption")
print("*********************************************************")
print()

# =====================================================================
# UPGRADE 1: Digital Signatures — Sign ciphertext with RSA private key
# UPGRADE 4: Key Derivation — SHA-256 hash of user password → 16-byte key
# UPGRADE (User Request): PKCS#7 Padding for variable-length messages
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
    round_key_0 is the original key itself.
    """
    round_keys = [key_hex[:]]
    prev_key = key_hex[:]

    for r in range(10):
        # Split previous round key into four 4-byte words
        w0 = prev_key[0:4]
        w1 = prev_key[4:8]
        w2 = prev_key[8:12]
        w3 = prev_key[12:16]
        original_w3 = w3[:]

        # --- g function on w3 ---
        # 1. Circular byte left shift
        shifted = [w3[1], w3[2], w3[3], w3[0]]
        # 2. S-Box byte substitution
        substituted = [s_box[s] for s in shifted]
        # 3. Add round constant
        g_result = []
        for j in range(4):
            g_result.append(hex(int(substituted[j], 16) ^ int(round_constant_array[r][j], 16)))

        # --- Generate 4 new words ---
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


def sub_bytes(state):
    """Apply S-Box substitution to every byte of the state matrix."""
    result = [[None] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = s_box[state[i][j]]
    return result


def shift_rows(state):
    """AES ShiftRows: left-rotate row i by i positions."""
    result = [row[:] for row in state]  # deep copy
    # Row 0: no shift
    # Row 1: shift left by 1
    result[1] = [state[1][1], state[1][2], state[1][3], state[1][0]]
    # Row 2: shift left by 2
    result[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
    # Row 3: shift left by 3
    result[3] = [state[3][3], state[3][0], state[3][1], state[3][2]]
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


def mix_columns(state):
    """AES MixColumns: multiply each column by the fixed polynomial matrix in GF(2^8)."""
    result = [[None] * 4 for _ in range(4)]
    for c in range(4):
        s0 = int(state[0][c], 16)
        s1 = int(state[1][c], 16)
        s2 = int(state[2][c], 16)
        s3 = int(state[3][c], 16)
        result[0][c] = hex(gf_mul(2, s0) ^ gf_mul(3, s1) ^ s2 ^ s3)
        result[1][c] = hex(s0 ^ gf_mul(2, s1) ^ gf_mul(3, s2) ^ s3)
        result[2][c] = hex(s0 ^ s1 ^ gf_mul(2, s2) ^ gf_mul(3, s3))
        result[3][c] = hex(gf_mul(3, s0) ^ s1 ^ s2 ^ gf_mul(2, s3))
    return result


def aes_encrypt_block(plaintext_hex, round_keys):
    """
    Encrypts a single 16-byte block using AES-128.
    plaintext_hex: list of 16 hex strings (e.g., ['0x41', '0x42', ...])
    round_keys:    list of 11 round key arrays (each 16 hex strings)
    Returns:       list of 16 hex strings (the ciphertext block)
    """
    # Build state matrix (column-major)
    state = arr_to_state(plaintext_hex)
    key_matrix = arr_to_state(round_keys[0])

    # Round 0: AddRoundKey only
    state = xor_state(state, key_matrix)

    # Rounds 1–9: SubBytes → ShiftRows → MixColumns → AddRoundKey
    for r in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        rk = arr_to_state(round_keys[r])
        state = xor_state(state, rk)

    # Round 10: SubBytes → ShiftRows → AddRoundKey (NO MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    rk10 = arr_to_state(round_keys[10])
    state = xor_state(state, rk10)

    # Convert back to flat list
    return state_to_flat(state)


# ==============================================================
#  Input: Password (KDF) + Plaintext message
# ==============================================================

str_password = input("Enter password: ")
str_plaintext = input("Enter the message you want to encrypt: ")

# UPGRADE 4: Key Derivation Function — SHA-256 of password, first 16 bytes
aes_key_bytes = hashlib.sha256(str_password.encode()).digest()[:16]
key = [hex(b) for b in aes_key_bytes]

print()
print(f"Password:    '{str_password}'")
print(f"Derived Key: {key}")
print(f"  (SHA-256 of password, truncated to 128 bits for AES-128)")
print()

# PKCS#7 Padding: pad plaintext to a multiple of 16 bytes
plaintext_bytes = str_plaintext.encode('utf-8')
pad_len = 16 - (len(plaintext_bytes) % 16)
# If already a multiple of 16, add a full 16-byte padding block
if pad_len == 0:
    pad_len = 16
padded_bytes = plaintext_bytes + bytes([pad_len] * pad_len)

num_blocks = len(padded_bytes) // 16
print(f"Original message length: {len(plaintext_bytes)} bytes")
print(f"PKCS#7 padding added:    {pad_len} bytes (0x{pad_len:02x})")
print(f"Total padded length:     {len(padded_bytes)} bytes ({num_blocks} block(s))")
print()

# ==============================================================
#  Key Expansion (runs once for all blocks)
# ==============================================================

print("--- AES Key Expansion ---")
round_keys = key_expansion(key)
print()

# ==============================================================
#  Encrypt each 16-byte block
# ==============================================================

all_ciphertext = []

for block_idx in range(num_blocks):
    block_bytes = padded_bytes[block_idx * 16 : (block_idx + 1) * 16]
    block_hex = [hex(b) for b in block_bytes]

    print(f"--- Encrypting Block {block_idx + 1}/{num_blocks} ---")
    print(f"  Plaintext block: {block_hex}")

    ct_block = aes_encrypt_block(block_hex, round_keys)
    all_ciphertext.extend(ct_block)

    print(f"  Ciphertext block: {ct_block}")
    print()

print("Full Ciphertext = ", all_ciphertext)
print()

# ==============================================================
#  UPGRADE 1: Digital Signature (SHA-256 hash signed with RSA)
# ==============================================================

# Convert ciphertext to raw bytes for hashing
ct_byte_values = [int(x, 16) for x in all_ciphertext]
ct_bytes = bytes(ct_byte_values)
hash_hex = hashlib.sha256(ct_bytes).hexdigest()
hash_int = int(hash_hex, 16)

print(f"SHA-256 hash of ciphertext: {hash_hex}")
print()

# Load private key for signing
priv_path = os.path.join(SCRIPT_DIR, "private_key.json")
if not os.path.exists(priv_path):
    print("WARNING: private_key.json not found! Cannot create digital signature.")
    print("Run 'Key Generation of RSA.py' first. Ciphertext saved without signature.")
    signature = None
else:
    with open(priv_path, "r") as f:
        priv_key = json.load(f)
    d = int(priv_key["d"])
    n = int(priv_key["n"])

    # Sign: signature = hash^d mod n
    signature = pow(hash_int, d, n)
    print(f"Digital Signature created (RSA-signed SHA-256 hash)")
    print(f"  Signature: {str(signature)[:80]}...")
    print()

# ==============================================================
#  Save output files
# ==============================================================

ct_path = os.path.join(SCRIPT_DIR, "aes_ciphertext.json")
with open(ct_path, "w") as f:
    json.dump({"ciphertext": all_ciphertext, "num_blocks": num_blocks}, f, indent=2)

if signature is not None:
    sig_path = os.path.join(SCRIPT_DIR, "signature.json")
    with open(sig_path, "w") as f:
        json.dump({"signature": str(signature), "hash": hash_hex}, f, indent=2)

print("*********************************************************")
print(f"  Ciphertext saved to:  {ct_path}")
if signature is not None:
    print(f"  Signature saved to:   {sig_path}")
print("*********************************************************")
