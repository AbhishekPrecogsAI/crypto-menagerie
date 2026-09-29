"""pqc.py — post-quantum algorithms (the migration target).

Expected CBOM: ML-KEM-768 (FIPS 203, ex-Kyber), ML-DSA-65 (FIPS 204,
ex-Dilithium), SLH-DSA-SHA2-128s (FIPS 205, ex-SPHINCS+), plus a
hybrid X25519 + ML-KEM-768 key establishment. These are what PQC-001
conformance looks like once the deprecated asymmetric crypto is replaced.

Uses liboqs' python bindings (`oqs`). Install: pip install liboqs-python
"""
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519


def ml_kem_768_encapsulate():
    """ML-KEM-768 (FIPS 203) key encapsulation."""
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return public_key, ciphertext, shared_secret


def ml_dsa_65_sign(message: bytes):
    """ML-DSA-65 (FIPS 204) signature."""
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)
        return public_key, signature


def slh_dsa_sign(message: bytes):
    """SLH-DSA-SHA2-128s (FIPS 205) hash-based signature."""
    with oqs.Signature("SPHINCS+-SHA2-128s-simple") as signer:
        public_key = signer.generate_keypair()
        return public_key, signer.sign(message)


def hybrid_x25519_mlkem768():
    """Hybrid: classical X25519 ECDH combined with ML-KEM-768.

    Matches the TLS 1.3 `X25519MLKEM768` group — safe against both a
    classical break of ML-KEM and a quantum break of X25519.
    """
    classical = x25519.X25519PrivateKey.generate()
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pq_public = kem.generate_keypair()
    return classical.public_key(), pq_public
