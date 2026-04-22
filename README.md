# RSA Learning Lab

A Python web app for learning and presenting RSA cryptography through two main sections:

- RSA Lab: key generation, encryption, decryption, signing, and signature verification.
- Secure Transfer Demo: a secure file transfer simulation based on hybrid encryption `RSA + AES`.

## Highlights

- Python backend with Flask.
- Custom RSA core implementation without using an RSA library.
- Supports `1024`, `1536`, `2048`, `3072`, and `4096` bit keys.
- Block-based RSA encryption with `OAEP + SHA-256`.
- Digital signatures using `SHA-256` and a learning-oriented signature block.
- Secure file transfer simulation:
- RSA encrypts the session key.
- AES-256 CTR encrypts the data.
- HMAC-SHA256 verifies integrity.

## Structure

- `app.py`: Flask entry point.
- `rsa_demo/routes.py`: web routes and request orchestration.
- `rsa_demo/crypto/rsa_core.py`: RSA key generation, OAEP, encryption/decryption, signing/verification.
- `rsa_demo/crypto/aes_ctr.py`: AES-256 CTR and HMAC for the hybrid simulation.
- `rsa_demo/templates/`: HTML templates.
- `rsa_demo/static/`: CSS.
- `tests/test_crypto.py`: basic round-trip tests.

## Run

1. Create a Python virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
python app.py
```

4. Open `http://127.0.0.1:5000` in your browser.

## Notes

- This application is intended for demos and learning, not for production security use.
- RSA was reimplemented to make the algorithm easier to study, explain, and present.
- Real production systems typically rely on audited cryptographic libraries and standardized protocols.
