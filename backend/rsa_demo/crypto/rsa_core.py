import base64
import hashlib
import json
import math
import secrets
from dataclasses import dataclass
from typing import Dict, Tuple


PUBLIC_EXPONENT = 65537
HASH_NAME = "sha256"
HASH_SIZE = hashlib.new(HASH_NAME).digest_size


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def byte_size(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    p: int
    q: int
    e: int

    @property
    def byte_size(self) -> int:
        return (self.n.bit_length() + 7) // 8


def _int_to_b64(value: int) -> str:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return base64.b64encode(raw).decode("ascii")


def _b64_to_int(value: str) -> int:
    return int.from_bytes(base64.b64decode(value.encode("ascii")), "big")


def export_public_key_pem(key: PublicKey) -> str:
    payload = {
        "type": "rsa-public",
        "n": _int_to_b64(key.n),
        "e": _int_to_b64(key.e),
    }
    body = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return f"-----BEGIN RSA LAB PUBLIC KEY-----\n{body}\n-----END RSA LAB PUBLIC KEY-----"


def export_private_key_pem(key: PrivateKey) -> str:
    payload = {
        "type": "rsa-private",
        "n": _int_to_b64(key.n),
        "d": _int_to_b64(key.d),
        "p": _int_to_b64(key.p),
        "q": _int_to_b64(key.q),
        "e": _int_to_b64(key.e),
    }
    body = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return f"-----BEGIN RSA LAB PRIVATE KEY-----\n{body}\n-----END RSA LAB PRIVATE KEY-----"


def _load_pem_block(pem: str, header: str, footer: str) -> Dict[str, str]:
    text = pem.strip()
    if not text.startswith(header) or not text.endswith(footer):
        raise ValueError("Invalid key format.")
    body = text[len(header): -len(footer)].strip()
    try:
        payload = json.loads(base64.b64decode(body.encode("ascii")).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Unable to read key contents.") from exc
    return payload


def load_public_key_pem(pem: str) -> PublicKey:
    payload = _load_pem_block(
        pem,
        "-----BEGIN RSA LAB PUBLIC KEY-----",
        "-----END RSA LAB PUBLIC KEY-----",
    )
    return PublicKey(n=_b64_to_int(payload["n"]), e=_b64_to_int(payload["e"]))


def load_private_key_pem(pem: str) -> PrivateKey:
    payload = _load_pem_block(
        pem,
        "-----BEGIN RSA LAB PRIVATE KEY-----",
        "-----END RSA LAB PRIVATE KEY-----",
    )
    return PrivateKey(
        n=_b64_to_int(payload["n"]),
        d=_b64_to_int(payload["d"]),
        p=_b64_to_int(payload["p"]),
        q=_b64_to_int(payload["q"]),
        e=_b64_to_int(payload["e"]),
    )


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _mod_inverse(a: int, n: int) -> int:
    g, x, _ = _egcd(a, n)
    if g != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % n


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_keypair(bits: int = 2048, e: int = PUBLIC_EXPONENT) -> Tuple[PublicKey, PrivateKey]:
    if bits not in (1024, 1536, 2048, 3072, 4096, 8192):
        raise ValueError("Key size must be 1024, 1536, 2048, 3072, 4096, or 8192 bits.")

    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            break

    n = p * q
    d = _mod_inverse(e, phi)
    return PublicKey(n=n, e=e), PrivateKey(n=n, d=d, p=p, q=q, e=e)


def _mgf1(seed: bytes, length: int, hash_name: str = HASH_NAME) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output.extend(hashlib.new(hash_name, seed + c).digest())
        counter += 1
    return bytes(output[:length])


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _oaep_encode(message: bytes, k: int, label: bytes = b"", hash_name: str = HASH_NAME) -> bytes:
    hlen = hashlib.new(hash_name).digest_size
    if len(message) > k - 2 * hlen - 2:
        raise ValueError("Message is too long for the current key size.")

    lhash = hashlib.new(hash_name, label).digest()
    ps = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message
    seed = secrets.token_bytes(hlen)
    db_mask = _mgf1(seed, k - hlen - 1, hash_name)
    masked_db = _xor_bytes(db, db_mask)
    seed_mask = _mgf1(masked_db, hlen, hash_name)
    masked_seed = _xor_bytes(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def _oaep_decode(encoded: bytes, label: bytes = b"", hash_name: str = HASH_NAME) -> bytes:
    hlen = hashlib.new(hash_name).digest_size
    if len(encoded) < 2 * hlen + 2 or encoded[0] != 0:
        raise ValueError("Invalid OAEP block.")
    masked_seed = encoded[1: 1 + hlen]
    masked_db = encoded[1 + hlen:]
    seed_mask = _mgf1(masked_db, hlen, hash_name)
    seed = _xor_bytes(masked_seed, seed_mask)
    db_mask = _mgf1(seed, len(masked_db), hash_name)
    db = _xor_bytes(masked_db, db_mask)
    lhash = hashlib.new(hash_name, label).digest()
    if db[:hlen] != lhash:
        raise ValueError("OAEP label hash mismatch.")

    idx = db.find(b"\x01", hlen)
    if idx == -1:
        raise ValueError("OAEP separator byte not found.")
    if any(db[hlen:idx]):
        raise ValueError("OAEP padding is corrupted.")
    return db[idx + 1:]


def encrypt_bytes(message: bytes, public_key: PublicKey) -> bytes:
    k = public_key.byte_size
    max_block = k - 2 * HASH_SIZE - 2
    if max_block <= 0:
        raise ValueError("Key is too short for OAEP with SHA-256.")

    encrypted = bytearray()
    for offset in range(0, len(message), max_block):
        block = message[offset: offset + max_block]
        encoded = _oaep_encode(block, k)
        cipher_int = pow(int.from_bytes(encoded, "big"), public_key.e, public_key.n)
        encrypted.extend(cipher_int.to_bytes(k, "big"))
    return bytes(encrypted)


def decrypt_bytes(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    k = private_key.byte_size
    if len(ciphertext) % k != 0:
        raise ValueError("Ciphertext length is not aligned to the RSA block size.")

    decrypted = bytearray()
    for offset in range(0, len(ciphertext), k):
        block = ciphertext[offset: offset + k]
        plain_int = pow(int.from_bytes(block, "big"), private_key.d, private_key.n)
        encoded = plain_int.to_bytes(k, "big")
        decrypted.extend(_oaep_decode(encoded))
    return bytes(decrypted)


def sign_bytes(message: bytes, private_key: PrivateKey) -> bytes:
    digest = hashlib.sha256(message).digest()
    digest_info = b"RSA-LAB-SHA256|" + digest
    k = private_key.byte_size
    if len(digest_info) + 11 > k:
        raise ValueError("Key is too short for signing.")

    padding = b"\xff" * (k - len(digest_info) - 3)
    block = b"\x00\x01" + padding + b"\x00" + digest_info
    sig_int = pow(int.from_bytes(block, "big"), private_key.d, private_key.n)
    return sig_int.to_bytes(k, "big")


def verify_signature(message: bytes, signature: bytes, public_key: PublicKey) -> bool:
    k = public_key.byte_size
    if len(signature) != k:
        return False

    sig_int = int.from_bytes(signature, "big")
    block = pow(sig_int, public_key.e, public_key.n).to_bytes(k, "big")
    if not block.startswith(b"\x00\x01"):
        return False
    separator = block.find(b"\x00", 2)
    if separator == -1:
        return False
    digest_info = block[separator + 1:]
    if not digest_info.startswith(b"RSA-LAB-SHA256|"):
        return False
    expected = hashlib.sha256(message).digest()
    return secrets.compare_digest(digest_info[len(b"RSA-LAB-SHA256|"):], expected)
