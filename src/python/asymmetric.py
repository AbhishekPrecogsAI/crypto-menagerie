"""asymmetric.py — public-key crypto, weak to modern.

Expected CBOM: RSA-1024 (quantum + classically weak), RSA-4096, DSA-1024
(deprecated), ECDSA P-256 / P-384, Ed25519, finite-field DH-2048. Every
asymmetric primitive here is Shor-breakable → drives the quantum-readiness
score and the PQC migration requirement (PQC-001).
"""
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, dh
from cryptography.hazmat.primitives import hashes


def weak_rsa_1024():
    # RSA-1024 — below the 2048 floor, must be rotated now.
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def strong_rsa_4096():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def legacy_dsa_1024():
    # DSA-1024 — deprecated (FIPS 186-5 removes DSA).
    return dsa.generate_private_key(key_size=1024)


def ecdsa_p256():
    return ec.generate_private_key(ec.SECP256R1())


def ecdsa_p384():
    return ec.generate_private_key(ec.SECP384R1())


def ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


def finite_field_dh():
    # Classic finite-field Diffie-Hellman — Shor-breakable.
    params = dh.generate_parameters(generator=2, key_size=2048)
    return params.generate_private_key()


def rsa_sign_sha1(key, message: bytes) -> bytes:
    # RSA signature over SHA-1 — deprecated signature algorithm.
    from cryptography.hazmat.primitives.asymmetric import padding
    return key.sign(message, padding.PKCS1v15(), hashes.SHA1())
