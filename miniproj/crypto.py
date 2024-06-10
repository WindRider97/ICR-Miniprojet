from nacl.public import Box
from nacl.signing import VerifyKey

import nacl.utils
import nacl.secret
import nacl.pwhash


def symmetric_enc(data: bytes, key: bytes) -> bytes:
    """Uses XSalsa20 from Libsodium and Poly1305 for authentication."""
    box = nacl.secret.SecretBox(key)
    return box.encrypt(data)


def symmetric_dec(data: bytes, key: bytes) -> bytes:
    """Uses XSalsa20 from Libsodium and Poly1305 for authentication."""
    box = nacl.secret.SecretBox(key)
    return box.decrypt(data)


def asymmetric_enc(data: bytes, my_priv_key: bytes, their_pub_key: bytes) -> bytes:
    """Uses Curve25519 from the Libsodium library."""
    box = Box(my_priv_key, their_pub_key)
    return box.encrypt(data)


def asymmetric_dec(data: bytes, my_priv_key: bytes, their_pub_key: bytes) -> bytes:
    """Uses Curve25519 from the Libsodium library."""
    box = Box(my_priv_key, their_pub_key)
    return box.decrypt(data)


def encrypt_keys_sym(keys: dict, key: bytes) -> dict:
    """Is called when encrypting the users key folder with the master key to store them on the server"""
    encrypted_keys = {}
    for k, v in keys.items():
        encrypted_key = symmetric_enc(k, key)
        encrypted_value = symmetric_enc(v, key)
        encrypted_keys[encrypted_key] = encrypted_value
    return encrypted_keys


def encrypt_keys_asym(keys: dict, my_priv_key: bytes, their_pub_key: bytes) -> dict:
    """Is called when sharing keys with another user"""
    encrypted_keys = {}
    for k, v in keys.items():
        encrypted_key = asymmetric_enc(k, my_priv_key, their_pub_key)
        encrypted_value = asymmetric_enc(v, my_priv_key, their_pub_key)
        encrypted_keys[encrypted_key] = encrypted_value
    return encrypted_keys


def decrypt_keys_sym(keys: dict, key: bytes) -> dict:
    """Is called when receiving the users key folder from the server"""
    decrypted_keys = {}
    for k, v in keys.items():
        decrypted_key = symmetric_dec(k, key)
        decrypted_value = symmetric_dec(v, key)
        decrypted_keys[decrypted_key] = decrypted_value
    return decrypted_keys


def decrypt_keys_asym(keys: dict, my_priv_key: bytes, their_pub_key: bytes) -> dict:
    """Is called when receiving keys from another user"""
    decrypted_keys = {}
    for k, v in keys.items():
        decrypted_key = asymmetric_dec(k, my_priv_key, their_pub_key)
        decrypted_value = asymmetric_dec(v, my_priv_key, their_pub_key)
        decrypted_keys[decrypted_key] = decrypted_value
    return decrypted_keys


def sign(data: str, sign_key: VerifyKey, verif_key: VerifyKey) -> tuple:
    byte_data = repr(data).encode('utf-8')
    return sign_key.sign(byte_data), verif_key.encode()


def verify(signature: bytes, pub_key: bytes) -> bool:
    verif_key = VerifyKey(pub_key)
    return verif_key.verify(signature.message, signature.signature)


def hash_password(password: str, salt: bytes = None) -> tuple:
    """Returns a password hash of 32 bytes and a salt of 16 bytes. Uses Argon2id from Libsodium."""
    if salt is None:
        salt = nacl.utils.random(16)
    # SENSITIVE are the basic parameters for Argon2id
    pwd_hash = nacl.pwhash.argon2id.kdf(32, password, salt)
    return pwd_hash, salt
