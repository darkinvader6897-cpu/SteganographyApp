# steg_app.py
import streamlit as st
from PIL import Image
import io
import zlib

from steg_utils import (
    pack_payload, unpack_payload,
    embed_bytes_into_image, extract_bytes_from_image,
    capacity_bits, encrypt_data, decrypt_data,
    add_ecc, remove_ecc
)

st.set_page_config(page_title="Stego + AES + ECC", layout="wide")

st.title("🛡️ Advanced Image Steganography — AES + Reed–Solomon ECC")

st.markdown("""
Hide text or files inside images with **optional AES-GCM encryption** and **optional Reed–Solomon ECC**.
- Use the ECC option for robustness to small image corruptions.
- App outputs PNG (lossless) to preserve hidden data.
""")

left, right = st.columns(2)

with left:
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
        elif not secret_bytes:
            st.error("Please provide text or a file to hide.")
        else:
            try:
                img = Image.open(cover)
            except Exception as e:
                st.error(f"Cannot open cover image: {e}")
            else:
                # optionally encrypt
                encrypted_flag = False
                payload = secret_bytes
                if password:
                    try:
                        payload = encrypt_data(secret_bytes, password)
                        encrypted_flag = True
                    except Exception as e:
                        st.error(f"Encryption failed: {e}")
                        st.stop()

                # optionally add ECC (after encryption)
                parity = int(ecc_parity) if ecc_enabled else 0
                if parity > 0:
                    try:
                        payload_with_ecc = add_ecc(payload, parity)
                    except Exception as e:
                        st.error(f"Adding ECC failed: {e}")
                        st.stop()
                else:
                    payload_with_ecc = payload

                # pack payload
                packed = pack_payload(filename or "secret.bin", payload_with_ecc, encrypted_flag, parity)

                cap = capacity_bits(img) // 8
                st.info(f"Image capacity: {cap} bytes. Payload size: {len(packed)} bytes.")
                if len(packed) > cap:
                    st.error("Payload too large for this cover image. Try a larger image or reduce payload/ECC.")
                else:
                    prog = st.progress(0.0)
                    try:
                        out_img = embed_bytes_into_image(img, packed, progress_callback=prog.progress)
                    except Exception as e:
                        st.error(f"Embedding failed: {e}")
                    else:
                        buf = io.BytesIO()
                        out_img.save(buf, format="PNG")
                        buf.seek(0)
                        st.success("Stego image created.")
                        st.image(out_img, caption="Stego preview", use_column_width=True)
                        st.download_button("Download stego.png", data=buf.getvalue(), file_name="stego.png", mime="image/png")

with right:
    st.header("Decode (Recover)")
    stego = st.file_uploader("Stego image (drag & drop)", type=["png", "jpg", "jpeg", "bmp"], key="stego_img")
    pwd = st.text_input("Password (if used)", type="password", key="pwd_decode")
    decode_btn = st.button("Decode")

    if decode_btn:
        if not stego:
            st.error("Please upload a stego image.")
        else:
            try:
                img = Image.open(stego)
            except Exception as e:
                st.error(f"Cannot open image: {e}")
            else:
                prog = st.progress(0.0)
                try:
                    raw = extract_bytes_from_image(img, progress_callback=prog.progress)
                except Exception as e:
                    st.error(f"Extraction failed: {e}")
                else:
                    try:
                        filename, payload_with_ecc, encrypted_flag, parity = unpack_payload(raw)
                    except Exception as e:
                        st.error(f"Payload unpack failed: {e}")
                        st.stop()

                    # if ECC present, try to correct
                    if parity and parity > 0:
                        try:
                            payload = remove_ecc(payload_with_ecc, parity)
                            st.success(f"ECC applied: parity={parity} bytes. Decoding/correction succeeded.")
                        except ReedSolomonError:
                            st.error("Reed–Solomon failed to correct payload (too many errors).")
                            st.stop()
                        except Exception as e:
                            st.error(f"ECC decoding error: {e}")
                            st.stop()
                    else:
                        payload = payload_with_ecc

                    # if encrypted, decrypt
                    if encrypted_flag:
                        if not pwd:
                            st.error("This payload is encrypted. Please provide the password used during encoding.")
                            st.stop()
                        try:
                            payload = decrypt_data(payload, pwd)
                        except Exception:
                            st.error("Decryption failed — wrong password or corrupted ciphertext.")
                            st.stop()

                    # try to interpret as UTF-8 text
                    try:
                        text = payload.decode("utf-8")
                        st.success("Recovered text:")
                        st.text_area("Recovered message", text, height=240)
                        st.download_button("Download recovered as file", data=payload, file_name=filename)
                    except Exception:
                        st.info("Recovered binary payload — download below.")
                        st.download_button("Download recovered file", data=payload, file_name=filename)

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
