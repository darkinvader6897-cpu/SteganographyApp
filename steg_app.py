# steg_app.py
import streamlit as st
from PIL import Image
import io

from steg_utils import (
    pack_payload, unpack_payload,
    embed_bytes_into_image, extract_bytes_from_image,
    capacity_bits, encrypt_data, decrypt_data,
    add_ecc
)

st.set_page_config(page_title="Stego + AES + ECC + Tamper", layout="wide")
st.title("🛡️ Advanced Image Steganography with Tamper Detection")

left, right = st.columns(2)

# ---------------- Encode ----------------
with left:
    st.header("Encode (Hide)")
    cover = st.file_uploader("Cover image", type=["png","jpg","jpeg","bmp"], key="cover")
    hide_type = st.radio("Hide", ["Text", "File"], key="hide_type")
    secret_bytes = b""
    filename = ""

    if hide_type == "Text":
        txt = st.text_area("Message to hide", height=150)
        filename = st.text_input("Filename inside image", value="secret.txt")
        if txt:
            secret_bytes = txt.encode("utf-8")
    else:
        uploaded = st.file_uploader("Secret file", key="secret_file")
        if uploaded:
            secret_bytes = uploaded.read()
            filename = uploaded.name or "secret.bin"

    password = st.text_input("Password (optional)", type="password")
    ecc_enabled = st.checkbox("Enable Reed–Solomon ECC", value=False)
    ecc_parity = st.number_input("Parity bytes (e.g. 16 or 32)", min_value=0, max_value=65535, value=32, step=2)

    if st.button("Encode → Create stego image"):
        if cover is None or not secret_bytes:
            st.error("Upload image and text/file.")
        else:
            img = Image.open(cover)
            payload = secret_bytes
            encrypted_flag = False
            if password:
                payload = encrypt_data(secret_bytes, password)
                encrypted_flag = True
            parity = int(ecc_parity) if ecc_enabled else 0
            if parity > 0:
                payload = add_ecc(payload, parity)
            packed = pack_payload(filename, payload, encrypted_flag, parity)
            cap = capacity_bits(img)//8
            if len(packed) > cap:
                st.error("Payload too large for cover image.")
            else:
                prog = st.progress(0.0)
                out_img = embed_bytes_into_image(img, packed, progress_callback=prog.progress)
                buf = io.BytesIO()
                out_img.save(buf, format="PNG")
                buf.seek(0)
                st.success("Stego image created.")
                st.image(out_img, caption="Stego preview", use_column_width=True)
                st.download_button("Download stego.png", data=buf.getvalue(), file_name="stego.png", mime="image/png")

# ---------------- Decode ----------------
with right:
    st.header("Decode (Recover)")
    stego = st.file_uploader("Stego image", type=["png","jpg","jpeg","bmp"], key="stego_img")
    pwd = st.text_input("Password (if used)", type="password", key="pwd_decode")
    if st.button("Decode"):
        if not stego:
            st.error("Upload a stego image.")
        else:
            img = Image.open(stego)
            prog = st.progress(0.0)
            raw = extract_bytes_from_image(img, progress_callback=prog.progress)
            try:
                filename, payload, encrypted_flag, tampered, tamper_fraction = unpack_payload(raw)
            except Exception as e:
                st.error(f"Payload unpack failed: {e}")
            else:
                if encrypted_flag:
                    if not pwd:
                        st.error("Password required for decryption.")
                        st.stop()
                    try:
                        payload = decrypt_data(payload, pwd)
                    except Exception:
                        st.error("Decryption failed (wrong password or corrupted).")
                        st.stop()

                if tampered:
                    if 0 < tamper_fraction < 1:
                        st.warning(f"⚠️ Partial tampering detected (~{tamper_fraction*100:.1f}% of ECC corrected).")
                    else:
                        st.error("❌ Tampering detected! Payload integrity compromised.")
                else:
                    st.success("✅ Data integrity verified (no tampering).")

                # Try to show as text
                try:
                    text = payload.decode("utf-8")
                    st.text_area("Recovered message", text, height=240)
                    st.download_button("Download recovered file", data=payload, file_name=filename)
                except:
                    st.info("Recovered binary payload")
                    st.download_button("Download recovered file", data=payload, file_name=filename)

# ---------------- Sample cover ----------------
st.write("---")
st.subheader("Sample cover image")
sample = Image.new("RGB",(640,400), color=(200,220,255))
buf = io.BytesIO()
sample.save(buf, format="PNG")
buf.seek(0)
st.image(sample, "Sample cover")
st.download_button("Download sample_cover.png", data=buf.getvalue(), file_name="sample_cover.png", mime="image/png")
