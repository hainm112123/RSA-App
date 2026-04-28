import base64
import time
from typing import Any, Dict, Optional, Tuple

from flask import Flask, jsonify, request

from .crypto import (
    PublicKey,
    PrivateKey,
    decrypt_bytes,
    encrypt_bytes,
    export_private_key_pem,
    export_public_key_pem,
    generate_keypair,
    load_private_key_pem,
    load_public_key_pem,
    sign_bytes,
    verify_signature,
)
from .crypto.key_pool import key_pool


DEFAULT_BITS = 2048
BIT_OPTIONS = [1024, 1536, 2048, 3072, 4096, 8192]


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


def _get_keypair(bits: int, e_type: str = "standard") -> Tuple[Tuple[PublicKey, PrivateKey], float, bool]:
    """Helper to get a keypair from pool or generate it."""
    pooled = key_pool.get_key(bits, e_type)
    if pooled:
        # Reconstruct objects for internal logic if needed
        pub = load_public_key_pem(pooled["public_key_pem"])
        priv = load_private_key_pem(pooled["private_key_pem"])
        return (pub, priv), 0.0, True
    
    e = 65537 if e_type == "standard" else None
    (pub, priv), elapsed = _timed_call(generate_keypair, bits, e=e)
    return (pub, priv), elapsed, False


def register_routes(app: Flask) -> None:
    @app.post("/api/generate-keys")
    def generate_keys():
        data = request.get_json() or {}
        bits = int(data.get("bits", DEFAULT_BITS))
        e_type = data.get("e_type", "standard")
        try:
            (public_key, private_key), elapsed, pooled = _get_keypair(bits, e_type)
            result = {
                "bits": bits,
                "e_type": e_type,
                "elapsed": elapsed,
                "pooled": pooled,
                "public_key_pem": export_public_key_pem(public_key),
                "private_key_pem": export_private_key_pem(private_key),
                "public_key_n": str(public_key.n),
                "public_key_e": str(public_key.e),
                "private_key_n": str(private_key.n),
                "private_key_d": str(private_key.d),
                "private_key_p": str(private_key.p),
                "private_key_q": str(private_key.q),
                "private_key_e": str(private_key.e),
            }
            return jsonify({"success": True, "data": result})
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @app.post("/api/rsa-action")
    def rsa_action():
        # ... (no changes needed to rsa_action as it doesn't generate keys)
        data = request.get_json() or {}
        mode = data.get("mode", "encrypt")
        display_mode = data.get("display_mode", "encoded")
        payload = data.get("payload", "").encode("utf-8")

        def get_pub():
            if display_mode == "numerical":
                return PublicKey(n=int(data.get("public_key_n", "0")), e=int(data.get("public_key_e", "0")))
            return load_public_key_pem(data.get("public_key", ""))

        def get_priv():
            if display_mode == "numerical":
                return PrivateKey(n=int(data.get("private_key_n", "0")), d=int(data.get("private_key_d", "0")), p=0, q=0, e=0)
            return load_private_key_pem(data.get("private_key", ""))

        def get_cipher(k: int):
            if display_mode == "numerical":
                num = int(data.get("ciphertext_num", "0"))
                return num.to_bytes(k, "big")
            return _unb64(data.get("ciphertext_b64", ""))

        def get_sig(k: int):
            if display_mode == "numerical":
                num = int(data.get("signature_num", "0"))
                return num.to_bytes(k, "big")
            return _unb64(data.get("signature_b64", ""))

        try:
            if mode == "encrypt":
                public_key = get_pub()
                ciphertext, elapsed = _timed_call(encrypt_bytes, payload, public_key)
                result = {
                    "mode": "encrypt",
                    "elapsed": elapsed,
                    "plaintext": payload.decode("utf-8", errors="replace"),
                }
                if display_mode == "numerical":
                    result["ciphertext_num"] = str(int.from_bytes(ciphertext, "big"))
                else:
                    result["ciphertext_b64"] = _b64(ciphertext)
            elif mode == "decrypt":
                private_key = get_priv()
                ciphertext = get_cipher(private_key.byte_size)
                plaintext, elapsed = _timed_call(decrypt_bytes, ciphertext, private_key)
                result = {
                    "mode": "decrypt",
                    "elapsed": elapsed,
                    "plaintext": plaintext.decode("utf-8", errors="replace"),
                }
                if display_mode == "numerical":
                    result["ciphertext_num"] = str(int.from_bytes(ciphertext, "big"))
                else:
                    result["ciphertext_b64"] = _b64(ciphertext)
            elif mode == "sign":
                private_key = get_priv()
                signature, elapsed = _timed_call(sign_bytes, payload, private_key)
                result = {
                    "mode": "sign",
                    "elapsed": elapsed,
                    "message": payload.decode("utf-8", errors="replace"),
                }
                if display_mode == "numerical":
                    result["signature_num"] = str(int.from_bytes(signature, "big"))
                else:
                    result["signature_b64"] = _b64(signature)
            elif mode == "verify":
                public_key = get_pub()
                signature = get_sig(public_key.byte_size)
                verified, elapsed = _timed_call(verify_signature, payload, signature, public_key)
                result = {
                    "mode": "verify",
                    "elapsed": elapsed,
                    "message": payload.decode("utf-8", errors="replace"),
                    "verified": verified,
                }
                if display_mode == "numerical":
                    result["signature_num"] = str(int.from_bytes(signature, "big"))
                else:
                    result["signature_b64"] = _b64(signature)
            else:
                raise ValueError("Invalid RSA action.")
            return jsonify({"success": True, "data": result})
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
