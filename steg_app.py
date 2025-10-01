# steg_app.py
import streamlit as st
from PIL import Image
import io

from steg_utils import (
    CryptoManager, ECCManager, StegoEngine, PayloadManager, ReedSolomonError
)

class StegoAppUI:
    """Streamlit UI controller that uses OOP utilities for logic."""

    def __init__(self):
        st.set_page_config(page_title="Stego + AES + ECC", layout="wide")
        self.crypto = CryptoManager()
        self.ecc = ECCManager()
        self.stego = StegoEngine()
        self.payload_mgr = PayloadManager()

        # Initialize session_state keys to avoid key errors
        if "stego_bytes" not in st.session_state:
            st.session_state["stego_bytes"] = None
        if "stego_preview" not in st.session_state:
            st.session_state["stego_preview"] = None

    def run(self):
        st.title("🛡️ Advanced Image Steganography — AES + Reed–Solomon ECC")

        st.markdown("""
        Hide text or files inside images with **optional AES-GCM encryption** and **optional Reed–Solomon ECC**.
        - Use the ECC option for robustness to small image corruptions.
        - App outputs PNG (lossless) to preserve hidden data.
        """)

        left, right = st.columns(2)

        with left:
            self.encode_section()

        with right:
            self.decode_section()

        st.write("---")
        st.subheader("Sample cover image")
        sample = Image.new("RGB", (640, 400), color=(200, 220, 255))
        buf = io.BytesIO()
        sample.save(buf, format="PNG")
        buf.seek(0)
        st.image(sample, "Sample cover (use to test)")
        st.download_button("Download sample_cover.png", data=buf.getvalue(), file_name="sample_cover.png", mime="image/png")

        st.markdown("""
        **Notes**
        - ECC (Reed–Solomon) helps recover from small corruptions (e.g. minor bit flips or cropping artifacts)
          but cannot recover if too many errors occur. Use reasonable parity (e.g. 16, 32).
        - Always save stego images as PNG (lossless). Saving as JPEG after embedding will very likely destroy hidden data.
        - Encryption is AES-GCM (authenticated) — wrong password leads to a decryption failure.
        """)

    def encode_section(self):
        st.header("Encode (Hide)")
        cover = st.file_uploader("Cover image (drag & drop)", type=["png", "jpg", "jpeg", "bmp"], key="cover")
        hide_type = st.radio("Hide:", ["Text", "File"], key="hide_type")
        secret_bytes = b""
        filename = ""

        if hide_type == "Text":
            txt = st.text_area("Message to hide", height=150)
            filename = st.text_input("Filename to store inside image", value="secret.txt")
            if txt:
                secret_bytes = txt.encode("utf-8")
        else:
            uploaded = st.file_uploader("Secret file to hide", key="secret_file")
            if uploaded:
                secret_bytes = uploaded.read()
                filename = uploaded.name or "secret.bin"

        password = st.text_input("Password (optional — AES-GCM)", type="password")
        st.write("ECC (optional): Reed–Solomon parity bytes increase redundancy and resilience. More parity = more robustness but larger payload.")
        ecc_enabled = st.checkbox("Enable Reed–Solomon ECC", value=False)
        ecc_parity = st.number_input("Parity bytes (e.g. 16 or 32). Must be even integer >=0", min_value=0, max_value=65535, value=32, step=2)

        encode_btn = st.button("Encode → Create stego image")

        if encode_btn:
            if cover is None:
                st.error("Please upload a cover image.")
                return
            if not secret_bytes:
                st.error("Please provide text or a file to hide.")
                return

            try:
                img = Image.open(cover)
            except Exception as e:
                st.error(f"Cannot open cover image: {e}")
                return

            # optionally encrypt
            encrypted_flag = False
            payload = secret_bytes
            if password:
                try:
                    payload = self.crypto.encrypt(secret_bytes, password)
                    encrypted_flag = True
                except Exception as e:
                    st.error(f"Encryption failed: {e}")
                    return

            # optionally add ECC (after encryption)
            parity = int(ecc_parity) if ecc_enabled else 0
            if parity > 0:
                try:
                    payload_with_ecc = self.ecc.add_ecc(payload, parity)
                except Exception as e:
                    st.error(f"Adding ECC failed: {e}")
                    return
            else:
                payload_with_ecc = payload

            # pack payload
            try:
                packed = self.payload_mgr.pack(filename or "secret.bin", payload_with_ecc, encrypted_flag, parity)
            except Exception as e:
                st.error(f"Packing payload failed: {e}")
                return

            cap = self.stego.capacity_bits(img) // 8
            st.info(f"Image capacity: {cap} bytes. Payload size: {len(packed)} bytes.")
            if len(packed) > cap:
                st.error("Payload too large for this cover image. Try a larger image or reduce payload/ECC.")
                return

            prog = st.progress(0.0)
            try:
                out_img = self.stego.embed_bytes_into_image(img, packed, progress_callback=prog.progress)
            except Exception as e:
                st.error(f"Embedding failed: {e}")
                return

            # Save image into session state to persist after rerun
            buf = io.BytesIO()
            out_img.save(buf, format="PNG")
            buf.seek(0)
            st.session_state["stego_bytes"] = buf.getvalue()
            st.session_state["stego_preview"] = out_img

        # Always render download section if we have generated image
        if st.session_state["stego_bytes"]:
            st.success("Stego image created.")
            st.image(st.session_state["stego_preview"], caption="Stego preview", use_container_width=True)

            output_name = st.text_input("Output filename (with .png)", value="stego.png", key="output_name")
            st.download_button(
                "Download stego image",
                data=st.session_state["stego_bytes"],
                file_name=output_name if output_name.strip() else "stego.png",
                mime="image/png"
            )

        # === Feature Extension Point: Add UI controls for voice notes, direct sharing, or alternative carriers here ===

    def decode_section(self):
        st.header("Decode (Recover)")
        stego_file = st.file_uploader("Stego image (drag & drop)", type=["png", "jpg", "jpeg", "bmp"], key="stego_img")
        pwd = st.text_input("Password (if used)", type="password", key="pwd_decode")
        decode_btn = st.button("Decode")

        if decode_btn:
            if not stego_file:
                st.error("Please upload a stego image.")
                return

            try:
                img = Image.open(stego_file)
            except Exception as e:
                st.error(f"Cannot open image: {e}")
                return

            prog = st.progress(0.0)
            try:
                raw = self.stego.extract_bytes_from_image(img, progress_callback=prog.progress)
            except Exception as e:
                st.error(f"Extraction failed: {e}")
                return

            try:
                filename, payload_with_ecc, encrypted_flag, parity = self.payload_mgr.unpack(raw)
            except Exception as e:
                st.error(f"Payload unpack failed: {e}")
                return

            # if ECC present, try to correct
            if parity and parity > 0:
                try:
                    payload = self.ecc.remove_ecc(payload_with_ecc, parity)
                    st.success(f"ECC applied: parity={parity} bytes. Decoding/correction succeeded.")
                except ReedSolomonError:
                    st.error("Reed–Solomon failed to correct payload (too many errors).")
                    return
                except Exception as e:
                    st.error(f"ECC decoding error: {e}")
                    return
            else:
                payload = payload_with_ecc

            # if encrypted, decrypt
            if encrypted_flag:
                if not pwd:
                    st.error("This payload is encrypted. Please provide the password used during encoding.")
                    return
                try:
                    payload = self.crypto.decrypt(payload, pwd)
                except Exception:
                    st.error("Decryption failed — wrong password or corrupted ciphertext.")
                    return

            # try to interpret as UTF-8 text
            try:
                text = payload.decode("utf-8")
                st.success("Recovered text:")
                st.text_area("Recovered message", text, height=240)
                st.download_button("Download recovered as file", data=payload, file_name=filename)
            except Exception:
                st.info("Recovered binary payload — download below.")
                st.download_button("Download recovered file", data=payload, file_name=filename)

if __name__ == "__main__":
    app = StegoAppUI()
    app.run()
