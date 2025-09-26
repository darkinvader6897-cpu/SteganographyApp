# steg_utils.py
"""
Helper functions for Streamlit steganography app.
Includes:
- AES-GCM password encryption (pycryptodome)
- Reed-Solomon ECC (reedsolo) optional
- LSB embedding/extraction using Pillow
"""

from PIL import Image
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Reed-Solomon library
from reedsolo import RSCodec, ReedSolomonError

MAGIC = b"STEG"  # 4 bytes to identify our payload

# ---------------- Encryption helpers ----------------

def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypt data with AES-256-GCM using password-derived key."""
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=200_000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # structure: salt (16) | nonce (16) | tag (16) | ciphertext (...)
    return salt + cipher.nonce + tag + ciphertext

def decrypt_data(enc_data: bytes, password: str) -> bytes:
    """Decrypt data previously encrypted with encrypt_data."""
    if len(enc_data) < 48:
        raise ValueError("Encrypted data too short")
    salt = enc_data[:16]
    nonce = enc_data[16:32]
    tag = enc_data[32:48]
    ciphertext = enc_data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=200_000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---------------- ECC helpers (Reed-Solomon) ----------------

def add_ecc(data: bytes, parity_symbols: int) -> bytes:
    """
    Add Reed-Solomon parity symbols to data using reedsolo.RSCodec.
    parity_symbols is number of parity bytes (e.g. 16, 32). Must be >= 0.
    """
    if parity_symbols <= 0:
        return data
    rsc = RSCodec(parity_symbols)
    return rsc.encode(data)

def remove_ecc(data_with_parity: bytes, parity_symbols: int) -> bytes:
    """
    Attempt to decode and correct Reed-Solomon parity. Returns the original
    message bytes or raises ReedSolomonError on failure.
    """
    if parity_symbols <= 0:
        return data_with_parity
    rsc = RSCodec(parity_symbols)
    # rsc.decode returns a tuple (message, ecc) in some versions, sometimes returns message only.
    decoded = rsc.decode(data_with_parity)
    # If decode returns tuple/list, take first element
    if isinstance(decoded, (list, tuple)):
        return bytes(decoded[0])
    return bytes(decoded)

# ---------------- Bit helpers ----------------

def bytes_to_bits(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def bits_to_bytes(bitstr: str) -> bytes:
    n = len(bitstr)
    if n % 8 != 0:
        bitstr = bitstr + "0" * (8 - (n % 8))
    return bytes(int(bitstr[i:i+8], 2) for i in range(0, len(bitstr), 8))

def capacity_bits(img: Image.Image) -> int:
    w, h = img.size
    return w * h * 3  # using LSB of R, G, B

# ---------------- Payload packing ----------------
# Header layout (bytes):
# 4 bytes MAGIC | 4 bytes payload_len | 2 bytes filename_len |
# 1 byte encrypted_flag (0/1) | 2 bytes ecc_parity_symbols (unsigned short)
# => total header = 13 bytes

def pack_payload(filename: str, payload_bytes: bytes, encrypted: bool, ecc_parity: int) -> bytes:
    filename_bytes = filename.encode("utf-8")
    if len(filename_bytes) > 65535:
        raise ValueError("Filename too long")
    header = (
        MAGIC
        + struct.pack(">I", len(payload_bytes))
        + struct.pack(">H", len(filename_bytes))
        + (b"\x01" if encrypted else b"\x00")
        + struct.pack(">H", ecc_parity)
    )
    return header + filename_bytes + payload_bytes

def unpack_payload(data: bytes):
    if len(data) < 13:
        raise ValueError("Data too short for header")
    if data[:4] != MAGIC:
        raise ValueError("No STEG payload found (magic mismatch)")
    payload_len = struct.unpack(">I", data[4:8])[0]
    filename_len = struct.unpack(">H", data[8:10])[0]
    encrypted_flag = data[10] == 1
    ecc_parity = struct.unpack(">H", data[11:13])[0]
    expected_total = 13 + filename_len + payload_len
    if len(data) < expected_total:
        raise ValueError("Incomplete payload / header indicates more data than present")
    filename = data[13:13+filename_len].decode("utf-8", errors="replace")
    payload = data[13+filename_len:13+filename_len+payload_len]
    return filename, payload, encrypted_flag, ecc_parity

# ---------------- Embedding / Extraction ----------------

def embed_bytes_into_image(img: Image.Image, data_bytes: bytes, progress_callback=None) -> Image.Image:
    """
    Embed data_bytes into the LSBs of an RGB image. Progress callback accepts fraction 0..1.
    """
    img_rgb = img.convert("RGB")
    w, h = img_rgb.size
    capacity = capacity_bits(img_rgb)
    needed = len(data_bytes) * 8
    if needed > capacity:
        raise ValueError(f"Payload too large ({needed} bits) for image capacity ({capacity} bits)")

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
                if ch == 0:
                    r_new = (r & ~1) | bit
                elif ch == 1:
                    g_new = (g & ~1) | bit
                else:
                    b_new = (b & ~1) | bit
                bit_idx += 1
        new_pixels.append((r_new, g_new, b_new))
        # Update progress occasionally
        if progress_callback and (i % 5000 == 0):
            progress_callback(min(bit_idx / total_bits, 1.0))

    out = Image.new("RGB", (w, h))
    out.putdata(new_pixels)
    if progress_callback:
        progress_callback(1.0)
    return out

def extract_bytes_from_image(img: Image.Image, progress_callback=None) -> bytes:
    """
    Extract raw bytes from the LSBs. Returns raw byte array beginning with our header.
    """
    img_rgb = img.convert("RGB")
    pixels = list(img_rgb.getdata())
    bits = []
    total = len(pixels)
    for i, (r, g, b) in enumerate(pixels):
        bits.append(str(r & 1))
        bits.append(str(g & 1))
        bits.append(str(b & 1))
        if progress_callback and (i % 5000 == 0):
            progress_callback(min(i / total, 1.0))

    bitstr = "".join(bits)
    # read header (13 bytes) to determine how much to extract
    header_bits = bitstr[:13*8]
    header_bytes = bits_to_bytes(header_bits)
    if len(header_bytes) < 13 or header_bytes[:4] != MAGIC:
        raise ValueError("No valid STEG header found (image likely does not contain payload)")

    payload_len = struct.unpack(">I", header_bytes[4:8])[0]
    filename_len = struct.unpack(">H", header_bytes[8:10])[0]
    ecc_parity = struct.unpack(">H", header_bytes[11:13])[0]
    total_bytes = 13 + filename_len + payload_len
    total_bits = total_bytes * 8
    if len(bitstr) < total_bits:
        raise ValueError("Image does not contain full payload (incomplete)")

    all_bits = bitstr[:total_bits]
    if progress_callback:
        progress_callback(1.0)
    return bits_to_bytes(all_bits)