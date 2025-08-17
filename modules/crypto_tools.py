"""
modules/crypto_tools.py
Symmetric (Fernet) and Asymmetric (RSA) encryption helpers.
"""
from __future__ import annotations
from typing import Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class CryptoTool:
    # --- Fernet ---
    def fernet_generate_key(self) -> bytes:
        return Fernet.generate_key()

    def fernet_encrypt(self, key: bytes, data: bytes) -> bytes:
        return Fernet(key).encrypt(data)

    def fernet_decrypt(self, key: bytes, token: bytes) -> bytes:
        return Fernet(key).decrypt(token)

    # --- RSA ---
    def rsa_generate_keys(self, bits: int = 2048) -> Tuple[bytes, bytes]:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pub = priv.public_key()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return priv_pem, pub_pem

    def rsa_encrypt(self, pub_pem: bytes, data: bytes) -> bytes:
        pub = serialization.load_pem_public_key(pub_pem)
        return pub.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def rsa_decrypt(self, priv_pem: bytes, ct: bytes) -> bytes:
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        return priv.decrypt(
            ct,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
