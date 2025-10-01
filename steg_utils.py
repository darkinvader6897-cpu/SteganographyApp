# steg_utils.py
"""
OOP-based helpers for Steganography app.

Provides:
 - CryptoManager: AES-GCM password-based encryption
 - ECCManager: Reed–Solomon ECC wrappers
 - PayloadManager: packing/unpacking of payload + metadata
 - StegoEngine: LSB embedding/extraction into RGB images
 - Utility bit helpers

Extension points are clearly marked with `# === Feature Extension Point ... ===`
"""

from PIL import Image
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from reedsolo import RSCodec, ReedSolomonError

MAGIC = b"STEG"  # 4 bytes

# ---------------- Bit helpers ----------------
def bytes_to_bits(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def bits_to_bytes(bitstr: str) -> bytes:
    n = len(bitstr)
    if n % 8 != 0:
        bitstr = bitstr + "0" * (8 - (n % 8))
    return bytes(int(bitstr[i:i+8], 2) for i in range(0, len(bitstr), 8))

# ---------------- CryptoManager ----------------
class CryptoManager:
    """
    Handles encryption / decryption.

    Current implementation: AES-256-GCM with PBKDF2-derived key.
    """

    def __init__(self, kdf_iterations: int = 200_000):
        self.kdf_iterations = kdf_iterations

    def encrypt(self, data: bytes, password: str) -> bytes:
        """
        Returns: salt(16) | nonce(16) | tag(16) | ciphertext(...)
        """
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=self.kdf_iterations)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return salt + cipher.nonce + tag + ciphertext

    def decrypt(self, enc_data: bytes, password: str) -> bytes:
        if len(enc_data) < 48:
            raise ValueError("Encrypted data too short")
        salt = enc_data[:16]
        nonce = enc_data[16:32]
        tag = enc_data[32:48]
        ciphertext = enc_data[48:]
        key = PBKDF2(password, salt, dkLen=32, count=self.kdf_iterations)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    # === Feature Extension Point: Add new encryption algorithms here ===
    # Example: add methods for RSA, ChaCha20-Poly1305, or integrate external KMS.

# ---------------- ECCManager ----------------
class ECCManager:
    """
    Reed–Solomon ECC manager.

    Uses reedsolo.RSCodec under the hood. parity_symbols = number of parity bytes.
    """

    def add_ecc(self, data: bytes, parity_symbols: int) -> bytes:
        if parity_symbols <= 0:
            return data
        rsc = RSCodec(parity_symbols)
        return rsc.encode(data)

    def remove_ecc(self, data_with_parity: bytes, parity_symbols: int) -> bytes:
        if parity_symbols <= 0:
            return data_with_parity
        rsc = RSCodec(parity_symbols)
        decoded = rsc.decode(data_with_parity)
        # Some versions return (message, ecc), some return message only
        if isinstance(decoded, (tuple, list)):
            return bytes(decoded[0])
        return bytes(decoded)

    # === Feature Extension Point: Add alternative ECC schemes here ===
    # Example: convolutional codes, LDPC, or wrappers for other libraries.

# ---------------- PayloadManager ----------------
class PayloadManager:
    """
    Packs/unpacks payload with a small header:
    Header layout (bytes):
      4 bytes MAGIC | 4 bytes payload_len | 2 bytes filename_len |
      1 byte encrypted_flag (0/1) | 2 bytes ecc_parity_symbols (unsigned short)
    => total header = 13 bytes
    """

    HEADER_LEN = 13

    def pack(self, filename: str, payload_bytes: bytes, encrypted: bool, ecc_parity: int) -> bytes:
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

    def unpack(self, data: bytes):
        if len(data) < self.HEADER_LEN:
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

# ---------------- StegoEngine ----------------
class StegoEngine:
    """
    Handles LSB embedding/extraction into RGB images.

    Uses 1 LSB per color channel (R, G, B) => 3 bits per pixel.
    """

    def __init__(self):
        self.payload_mgr = PayloadManager()

    def capacity_bits(self, img: Image.Image) -> int:
        w, h = img.size
        return w * h * 3

    def embed_bytes_into_image(self, img: Image.Image, data_bytes: bytes, progress_callback=None) -> Image.Image:
        """
        Embed data_bytes into the LSBs of an RGB image. Progress callback accepts fraction 0..1.
        """
        img_rgb = img.convert("RGB")
        w, h = img_rgb.size
        capacity = self.capacity_bits(img_rgb)
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
            # R channel
            if bit_idx < total_bits:
                bit = int(bits[bit_idx])
                r_new = (r & ~1) | bit
                bit_idx += 1
            # G channel
            if bit_idx < total_bits:
                bit = int(bits[bit_idx])
                g_new = (g & ~1) | bit
                bit_idx += 1
            # B channel
            if bit_idx < total_bits:
                bit = int(bits[bit_idx])
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

    def extract_bytes_from_image(self, img: Image.Image, progress_callback=None) -> bytes:
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
        header_bits = bitstr[:PayloadManager.HEADER_LEN * 8]
        header_bytes = bits_to_bytes(header_bits)
        if len(header_bytes) < PayloadManager.HEADER_LEN or header_bytes[:4] != MAGIC:
            raise ValueError("No valid STEG header found (image likely does not contain payload)")

        payload_len = struct.unpack(">I", header_bytes[4:8])[0]
        filename_len = struct.unpack(">H", header_bytes[8:10])[0]
        ecc_parity = struct.unpack(">H", header_bytes[11:13])[0]
        total_bytes = PayloadManager.HEADER_LEN + filename_len + payload_len
        total_bits = total_bytes * 8
        if len(bitstr) < total_bits:
            raise ValueError("Image does not contain full payload (incomplete)")

        all_bits = bitstr[:total_bits]
        if progress_callback:
            progress_callback(1.0)
        return bits_to_bytes(all_bits)

    # === Feature Extension Point: Add new embedding algorithms here ===
    # Examples:
    # - DCT/transform-domain embedding (resilient to PNG->JPEG transformations)
    # - Audio/video steganography
    # - Adaptive LSB using noise-levels
