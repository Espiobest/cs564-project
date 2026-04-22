"""
helper.py - Crypto primitives shared by c2_server, implant_client, and operator.

Hybrid RSA-OAEP + Fernet encryption + XOR/base64 obfuscation layer.
  - encrypt_message(plaintext, recipient_pub_key)  → ciphertext bytes
  - decrypt_message(ciphertext, own_priv_key)      → plaintext bytes
  - obfuscate / deobfuscate                        → lightweight wire obfuscation
"""
import base64
import itertools

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_XOR_KEY = b"cs564_c2_key"


def obfuscate(data: bytes) -> bytes:
    xored = bytes(b ^ k for b, k in zip(data, itertools.cycle(_XOR_KEY)))
    return base64.b64encode(xored)[::-1]


def deobfuscate(data: bytes) -> bytes:
    b64 = data[::-1]
    xored = base64.b64decode(b64)
    return bytes(b ^ k for b, k in zip(xored, itertools.cycle(_XOR_KEY)))


def generate_keypair():
    """Return (private_key, public_key) RSA-2048 pair."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def serialize_public_key(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def encrypt_message(plaintext: bytes, pub_key) -> bytes:
    fernet_key = Fernet.generate_key()
    wrapped_key = pub_key.encrypt(
        fernet_key,
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None),
    )
    return wrapped_key + Fernet(fernet_key).encrypt(plaintext)


def decrypt_message(data: bytes, priv_key) -> bytes:
    wrapped_key, ciphertext = data[:256], data[256:]
    fernet_key = priv_key.decrypt(
        wrapped_key,
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None),
    )
    return Fernet(fernet_key).decrypt(ciphertext)
