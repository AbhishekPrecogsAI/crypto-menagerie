"""symmetric.py — a spectrum of symmetric ciphers, weak to modern.

Expected CBOM findings:
  DES / 3DES (deprecated), RC4 (broken), Blowfish (legacy),
  AES-128-CBC without a MAC (unauthenticated), AES-256-GCM (modern),
  ChaCha20-Poly1305 (modern).
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import os


def des_encrypt(key8: bytes, data: bytes) -> bytes:
    # DES — 56-bit effective key, deprecated everywhere.
    cipher = Cipher(algorithms.TripleDES(key8), modes.CBC(b"\x00" * 8))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def triple_des_encrypt(key24: bytes, iv: bytes, data: bytes) -> bytes:
    # 3DES / TDEA — SP 800-131A disallowed after 2023.
    cipher = Cipher(algorithms.TripleDES(key24), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def rc4_stream(key: bytes, data: bytes) -> bytes:
    # RC4 (ARC4) — biased keystream, prohibited (RFC 7465).
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    enc = cipher.encryptor()
    return enc.update(data)


def blowfish_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    # Blowfish — 64-bit block, Sweet32-vulnerable.
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def aes_cbc_unauthenticated(key16: bytes, iv: bytes, data: bytes) -> bytes:
    # AES-128-CBC with no MAC — malleable/padding-oracle risk.
    cipher = Cipher(algorithms.AES(key16), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def aes_gcm_encrypt(key32: bytes, data: bytes, aad: bytes = b"") -> bytes:
    # AES-256-GCM — authenticated, the migration target.
    nonce = os.urandom(12)
    return nonce + AESGCM(key32).encrypt(nonce, data, aad)


def chacha_encrypt(key32: bytes, data: bytes, aad: bytes = b"") -> bytes:
    # ChaCha20-Poly1305 — modern AEAD.
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key32).encrypt(nonce, data, aad)
