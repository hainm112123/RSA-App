import hashlib
import hmac
import secrets
from typing import Dict


AES_BLOCK = 16
S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(value: int) -> int:
    return ((value << 1) ^ 0x1B) & 0xFF if value & 0x80 else (value << 1) & 0xFF


def _mix_single_column(column):
    t = column[0] ^ column[1] ^ column[2] ^ column[3]
    u = column[0]
    column[0] ^= t ^ _xtime(column[0] ^ column[1])
    column[1] ^= t ^ _xtime(column[1] ^ column[2])
    column[2] ^= t ^ _xtime(column[2] ^ column[3])
    column[3] ^= t ^ _xtime(column[3] ^ u)


def _sub_word(word):
    return [S_BOX[value] for value in word]


def _rot_word(word):
    return word[1:] + word[:1]


def _expand_key(master_key: bytes):
    if len(master_key) != 32:
        raise ValueError("This AES module only supports 256-bit keys.")

    nk = 8
    nr = 14
    words = [list(master_key[index:index + 4]) for index in range(0, len(master_key), 4)]
    total_words = 4 * (nr + 1)

    for index in range(nk, total_words):
        temp = words[index - 1].copy()
        if index % nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[(index // nk) - 1]
        elif index % nk == 4:
            temp = _sub_word(temp)
        words.append([words[index - nk][i] ^ temp[i] for i in range(4)])

    round_keys = []
    for offset in range(0, len(words), 4):
        block = bytearray()
        for word in words[offset: offset + 4]:
            block.extend(word)
        round_keys.append(bytes(block))
    return round_keys


def _bytes_to_state(block: bytes):
    return [list(block[row::4]) for row in range(4)]


def _state_to_bytes(state) -> bytes:
    output = bytearray(16)
    for row in range(4):
        for column in range(4):
            output[column * 4 + row] = state[row][column]
    return bytes(output)


def _add_round_key(state, round_key: bytes):
    for row in range(4):
        for column in range(4):
            state[row][column] ^= round_key[column * 4 + row]


def _sub_bytes(state):
    for row in range(4):
        for column in range(4):
            state[row][column] = S_BOX[state[row][column]]


def _shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def _mix_columns(state):
    for column in range(4):
        values = [state[row][column] for row in range(4)]
        _mix_single_column(values)
        for row in range(4):
            state[row][column] = values[row]


def _encrypt_block(block: bytes, round_keys) -> bytes:
    if len(block) != AES_BLOCK:
        raise ValueError("AES blocks must be exactly 16 bytes.")

    state = _bytes_to_state(block)
    _add_round_key(state, round_keys[0])

    for round_index in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_index])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[14])
    return _state_to_bytes(state)


def _ctr_transform(data: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(nonce) != AES_BLOCK:
        raise ValueError("CTR nonce must be exactly 16 bytes.")

    round_keys = _expand_key(key)
    output = bytearray()
    counter = int.from_bytes(nonce, "big")

    for offset in range(0, len(data), AES_BLOCK):
        block = data[offset: offset + AES_BLOCK]
        keystream = _encrypt_block(counter.to_bytes(AES_BLOCK, "big"), round_keys)
        output.extend(bytes(a ^ b for a, b in zip(block, keystream)))
        counter = (counter + 1) % (1 << 128)
    return bytes(output)


def _derive_keys(session_key: bytes):
    material = hashlib.sha512(session_key + b"|rsa-lab-hybrid|").digest()
    return material[:32], material[32:]


def encrypt_payload(data: bytes) -> Dict[str, bytes]:
    session_key = secrets.token_bytes(32)
    aes_key, mac_key = _derive_keys(session_key)
    nonce = secrets.token_bytes(AES_BLOCK)
    ciphertext = _ctr_transform(data, aes_key, nonce)
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return {
        "session_key": session_key,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
    }


def decrypt_payload(session_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    aes_key, mac_key = _derive_keys(session_key)
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Integrity check failed. The data may have been modified.")
    return _ctr_transform(ciphertext, aes_key, nonce)
