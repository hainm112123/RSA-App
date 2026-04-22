import base64
import time
from typing import Any, Dict, Optional, Tuple

from flask import Flask, render_template, request

from .crypto import (
    decrypt_bytes,
    decrypt_payload,
    encrypt_bytes,
    encrypt_payload,
    export_private_key_pem,
    export_public_key_pem,
    generate_keypair,
    load_private_key_pem,
    load_public_key_pem,
    sign_bytes,
    verify_signature,
)


DEFAULT_BITS = 2048
BIT_OPTIONS = [1024, 1536, 2048, 3072, 4096]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("Invalid Base64 input.") from exc


def _timed_call(action, *args, **kwargs) -> Tuple[Any, float]:
    start = time.perf_counter()
    result = action(*args, **kwargs)
    elapsed = time.perf_counter() - start
    return result, elapsed


def _page_context(active_tab: str = "lab", result: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> Dict[str, Any]:
    return {
        "active_tab": active_tab,
        "bit_options": BIT_OPTIONS,
        "default_bits": DEFAULT_BITS,
        "result": result or {},
        "error": error,
    }


def register_routes(app: Flask) -> None:
    @app.get("/")
    def index():
        return render_template("index.html", **_page_context())

    @app.post("/generate-keys")
    def generate_keys():
        bits = int(request.form.get("bits", DEFAULT_BITS))
        try:
            (public_key, private_key), elapsed = _timed_call(generate_keypair, bits)
            result = {
                "mode": "keys",
                "bits": bits,
                "elapsed": elapsed,
                "public_key": export_public_key_pem(public_key),
                "private_key": export_private_key_pem(private_key),
            }
            return render_template("index.html", **_page_context("lab", result=result))
        except Exception as exc:
            return render_template("index.html", **_page_context("lab", error=str(exc)))

    @app.post("/rsa-action")
    def rsa_action():
        mode = request.form.get("mode", "encrypt")
        payload = request.form.get("payload", "").encode("utf-8")

        try:
            if mode == "encrypt":
                public_key = load_public_key_pem(request.form.get("public_key", ""))
                ciphertext, elapsed = _timed_call(encrypt_bytes, payload, public_key)
                result = {
                    "mode": "encrypt",
                    "elapsed": elapsed,
                    "plaintext": payload.decode("utf-8", errors="replace"),
                    "ciphertext_b64": _b64(ciphertext),
                }
            elif mode == "decrypt":
                private_key = load_private_key_pem(request.form.get("private_key", ""))
                ciphertext = _unb64(request.form.get("ciphertext_b64", ""))
                plaintext, elapsed = _timed_call(decrypt_bytes, ciphertext, private_key)
                result = {
                    "mode": "decrypt",
                    "elapsed": elapsed,
                    "plaintext": plaintext.decode("utf-8", errors="replace"),
                    "ciphertext_b64": _b64(ciphertext),
                }
            elif mode == "sign":
                private_key = load_private_key_pem(request.form.get("private_key", ""))
                signature, elapsed = _timed_call(sign_bytes, payload, private_key)
                result = {
                    "mode": "sign",
                    "elapsed": elapsed,
                    "message": payload.decode("utf-8", errors="replace"),
                    "signature_b64": _b64(signature),
                }
            elif mode == "verify":
                public_key = load_public_key_pem(request.form.get("public_key", ""))
                signature = _unb64(request.form.get("signature_b64", ""))
                verified, elapsed = _timed_call(verify_signature, payload, signature, public_key)
                result = {
                    "mode": "verify",
                    "elapsed": elapsed,
                    "message": payload.decode("utf-8", errors="replace"),
                    "signature_b64": _b64(signature),
                    "verified": verified,
                }
            else:
                raise ValueError("Invalid RSA action.")
            return render_template("index.html", **_page_context("lab", result=result))
        except Exception as exc:
            return render_template("index.html", **_page_context("lab", error=str(exc)))

    @app.post("/hybrid-demo")
    def hybrid_demo():
        file = request.files.get("payload_file")
        if file is None or file.filename == "":
            return render_template("index.html", **_page_context("hybrid", error="Please choose a file for the secure transfer simulation."))

        data = file.read()
        if not data:
            return render_template("index.html", **_page_context("hybrid", error="The selected file is empty."))

        sender_bits = int(request.form.get("sender_bits", DEFAULT_BITS))
        receiver_bits = int(request.form.get("receiver_bits", DEFAULT_BITS))

        try:
            (sender_public, sender_private), sender_elapsed = _timed_call(generate_keypair, sender_bits)
            (receiver_public, receiver_private), receiver_elapsed = _timed_call(generate_keypair, receiver_bits)

            package, sym_elapsed = _timed_call(encrypt_payload, data)
            encrypted_session_key, wrap_elapsed = _timed_call(encrypt_bytes, package["session_key"], receiver_public)
            signature, sign_elapsed = _timed_call(sign_bytes, package["ciphertext"], sender_private)
            unwrapped_key, unwrap_elapsed = _timed_call(decrypt_bytes, encrypted_session_key, receiver_private)
            verified, verify_elapsed = _timed_call(verify_signature, package["ciphertext"], signature, sender_public)
            restored_data, dec_elapsed = _timed_call(
                decrypt_payload,
                unwrapped_key,
                package["nonce"],
                package["ciphertext"],
                package["tag"],
            )

            result = {
                "mode": "hybrid",
                "filename": file.filename,
                "input_size": len(data),
                "receiver_bits": receiver_bits,
                "sender_bits": sender_bits,
                "session_key_b64": _b64(package["session_key"]),
                "encrypted_session_key_b64": _b64(encrypted_session_key),
                "nonce_b64": _b64(package["nonce"]),
                "tag_b64": _b64(package["tag"]),
                "ciphertext_preview_b64": _b64(package["ciphertext"][:96]),
                "signature_b64": _b64(signature),
                "verified": verified,
                "restored_matches": restored_data == data,
                "timings": {
                    "sender_keygen": sender_elapsed,
                    "receiver_keygen": receiver_elapsed,
                    "hybrid_encrypt": sym_elapsed,
                    "rsa_wrap": wrap_elapsed,
                    "sign": sign_elapsed,
                    "rsa_unwrap": unwrap_elapsed,
                    "verify": verify_elapsed,
                    "hybrid_decrypt": dec_elapsed,
                },
            }
            return render_template("index.html", **_page_context("hybrid", result=result))
        except Exception as exc:
            return render_template("index.html", **_page_context("hybrid", error=str(exc)))
