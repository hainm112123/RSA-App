# RSA Lab

A web app for learning and presenting RSA cryptography through two main sections:

- RSA Lab: key generation, encryption, decryption, signing, and signature verification.
- Secure Transfer Demo: a secure file transfer simulation based on hybrid encryption `RSA + AES`.

## Highlights

- React + TypeScript + Vite frontend with modern UI.
- Python backend with Flask.
- Custom RSA core implementation without using an RSA library.
- Supports `1024`, `1536`, `2048`, `3072`, `4096`, and `8192` bit keys.
- Block-based RSA encryption with `OAEP + SHA-256`.
- Modern Digital Signatures using **`RSA-PSS`** (Probabilistic Signature Scheme).
- Interactive pedagogical simulations for key workflows.
- Performance-optimized backend with asynchronous key generation.

## Run

### Backend

1. Create a Python virtual environment and activate it.
2. Install dependencies:

```bash
cd backend
pip install -r requirements.txt
```

3. Run the API server:

```bash
python app.py
```
The backend API will be available at `http://127.0.0.1:5000`.

### Frontend

1. Open a new terminal and navigate to the frontend directory:

```bash
cd frontend
```

2. Install dependencies:

```bash
npm install
```

3. Run the development server:

```bash
npm run dev
```

4. Open the displayed URL (typically `http://localhost:5173`) in your browser.
