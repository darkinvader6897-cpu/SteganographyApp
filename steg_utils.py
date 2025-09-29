# steg_utils.py
from PIL import Image
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib
from reedsolo import RSCodec, ReedSolomonError

MAGIC = b"STEG"

# ----------- Encryption helpers -----------

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt + cipher.nonce + tag + ciphertext

def decrypt_data(enc_data: bytes, password: str) -> bytes:
    salt, nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:48], enc_data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ----------- ECC helpers -----------

def add_ecc(data: bytes, parity_symbols: int) -> bytes:
    if parity_symbols <= 0:
        return data
    rsc = RSCodec(parity_symbols)
    return rsc.encode(data)

def remove_ecc(data_with_parity: bytes, parity_symbols: int) -> (bytes, int):
    if parity_symbols <= 0:
        return data_with_parity, 0
    rsc = RSCodec(parity_symbols)
    try:
        decoded, corrected_errors = rsc.decode(data_with_parity, only_erasures=False)
        if isinstance(decoded, (list, tuple)):
            return bytes(decoded[0]), corrected_errors
        return bytes(decoded), corrected_errors
    except ReedSolomonError:
        raise

# ----------- Bit helpers -----------

def bytes_to_bits(b: bytes):
    return "".join(f"{byte:08b}" for byte in b)

def bits_to_bytes(bitstr: str) -> bytes:
    n = len(bitstr)
    if n % 8 != 0:
        bitstr = bitstr + "0" * (8 - (n % 8))
    return bytes(int(bitstr[i:i+8], 2) for i in range(0, len(bitstr), 8))

def capacity_bits(img: Image.Image):
    w, h = img.size
    return w * h * 3

# ----------- Payload packing -----------

def pack_payload(filename: str, payload_bytes: bytes, encrypted: bool, ecc_parity: int) -> bytes:
    filename_bytes = filename.encode("utf-8")
    sha256_hash = hashlib.sha256(payload_bytes).digest()
    header = (
        MAGIC
        + struct.pack(">I", len(payload_bytes))
        + struct.pack(">H", len(filename_bytes))
        + (b"\x01" if encrypted else b"\x00")
        + struct.pack(">H", ecc_parity)
        + sha256_hash
    )
    return header + filename_bytes + payload_bytes

def unpack_payload(data: bytes):
    if len(data) < 45:
        raise ValueError("Data too short")
    if data[:4] != MAGIC:
        raise ValueError("No STEG payload found")
    payload_len = struct.unpack(">I", data[4:8])[0]
    filename_len = struct.unpack(">H", data[8:10])[0]
    encrypted_flag = data[10] == 1
    ecc_parity = struct.unpack(">H", data[11:13])[0]
    stored_hash = data[13:45]

    expected_total = 45 + filename_len + payload_len
    if len(data) < expected_total:
        raise ValueError("Incomplete payload")

    filename = data[45:45+filename_len].decode("utf-8", errors="replace")
    payload = data[45+filename_len:45+filename_len+payload_len]

    # Tamper detection
    computed_hash = hashlib.sha256(payload).digest()
    tampered = computed_hash != stored_hash

    # Estimate tamper fraction if ECC
    if ecc_parity > 0:
        try:
            _, corrected_errors = remove_ecc(payload, ecc_parity)
            tamper_fraction = min(corrected_errors / ecc_parity, 1.0)
        except:
            tamper_fraction = 1.0
    else:
        tamper_fraction = 1.0 if tampered else 0.0

    return filename, payload, encrypted_flag, tampered, tamper_fraction

# ----------- Embed / Extract -----------

def embed_bytes_into_image(img: Image.Image, data_bytes: bytes, progress_callback=None) -> Image.Image:
    img_rgb = img.convert("RGB")
    w, h = img_rgb.size
    total_capacity = capacity_bits(img_rgb)
    total_bits_needed = len(data_bytes) * 8
    if total_bits_needed > total_capacity:
        raise ValueError(f"Payload too large ({total_bits_needed} bits) for image capacity ({total_capacity} bits)")

    bits = bytes_to_bits(data_bytes)
    pixels = list(img_rgb.getdata())
    new_pixels = []
    bit_idx = 0
    total_bits = len(bits)

    for i, (r, g, b) in enumerate(pixels):
        r_new, g_new, b_new = r, g, b
        for ch in range(3):
            if bit_idx < total_bits:
                bit = int(bits[bit_idx])
                if ch == 0: r_new = (r & ~1) | bit
                elif ch == 1: g_new = (g & ~1) | bit
                else: b_new = (b & ~1) | bit
                bit_idx += 1
        new_pixels.append((r_new, g_new, b_new))
        if progress_callback and i % 5000 == 0:
            progress_callback(min(bit_idx / total_bits, 1.0))

    out = Image.new("RGB", (w, h))
    out.putdata(new_pixels)
    if progress_callback:
        progress_callback(1.0)
    return out

def extract_bytes_from_image(img: Image.Image, progress_callback=None) -> bytes:
    img_rgb = img.convert("RGB")
    pixels = list(img_rgb.getdata())
    bits = []
    total = len(pixels)
    for i, (r, g, b) in enumerate(pixels):
        bits.extend([str(r & 1), str(g & 1), str(b & 1)])
        if progress_callback and i % 5000 == 0:
            progress_callback(min(i / total, 1.0))
    return bits_to_bytes("".join(bits))
