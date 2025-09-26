# 🛡️ Advanced Image Steganography App

A Streamlit app to hide text or files inside images using LSB steganography,
with optional AES-GCM encryption and Reed–Solomon error correction (ECC).

## Features
- Hide text or any file in PNG/JPG/BMP images
- AES-256-GCM password encryption
- Reed–Solomon ECC for robustness against corruption
- Drag & drop uploads
- Progress bars for embedding/extraction
- Downloadable stego images & recovered files
- Sample cover image included

## Run locally
```bash
pip install -r requirements.txt
streamlit run steg_app.py
