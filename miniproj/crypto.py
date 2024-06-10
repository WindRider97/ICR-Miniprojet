import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey, VerifyKey
import nacl.pwhash


def symmetric_enc(data, key):
    """Uses XSalsa20 from Libsodium and Poly1305 for authentication."""
    box = nacl.secret.SecretBox(key)
    return box.encrypt(data)

def symmetric_dec(data, key):
    """Uses XSalsa20 from Libsodium and Poly1305 for authentication."""
    box = nacl.secret.SecretBox(key)
    return box.decrypt(data)

def asymmetric_enc(data, my_priv_key, their_pub_key):
    """Uses Curve25519 from the Libsodium library."""
    box = Box(my_priv_key, their_pub_key)
    return box.encrypt(data)

def asymmetric_dec(data, my_priv_key, their_pub_key):
    """Uses Curve25519 from the Libsodium library."""
    box = Box(my_priv_key, their_pub_key)
    return box.decrypt(data)

def encrypt_keys_sym(keys, key):
    """Is called when encrypting the users key folder with the master key to store them on the server"""
    encrypted_keys = {}
    for k, v in keys.items():
        try:
            encrypted_key = symmetric_enc(k.encode(), key)
        except:
            encrypted_key = symmetric_enc(k, key)
        try:
            encrypted_value = symmetric_enc(v, key)
        except:
            encrypted_value = symmetric_enc(v.encode(), key)
        encrypted_keys[encrypted_key] = encrypted_value
    return encrypted_keys

def encrypt_keys_asym(keys, my_priv_key, their_pub_key):
    """Is called when sharing keys with another user"""
    encrypted_keys = {}
    for k, v in keys.items():
        encrypted_key = asymmetric_enc(k.encode(), my_priv_key, their_pub_key)
        try:
            encrypted_value = asymmetric_enc(v, my_priv_key, their_pub_key)
        except:
            encrypted_value = asymmetric_enc(v.encode(), my_priv_key, their_pub_key)
        encrypted_keys[encrypted_key] = encrypted_value
    return encrypted_keys

def decrypt_keys_sym(keys, key):
    """Is called when recieving the users key folder from the server"""
    decrypted_keys = {}
    for k, v in keys.items():
        decrypted_key = symmetric_dec(k, key)
        decrypted_value = symmetric_dec(v, key)
        decrypted_keys[decrypted_key.decode()] = decrypted_value
    return decrypted_keys

def decrypt_keys_asym(keys, my_priv_key, their_pub_key):
    """Is called when recieving keys from another user"""
    decrypted_keys = {}
    for k, v in keys.items():
        decrypted_key = asymmetric_dec(k, my_priv_key, their_pub_key)
        decrypted_value = asymmetric_dec(v, my_priv_key, their_pub_key)
        decrypted_keys[decrypted_key.decode()] = decrypted_value
    return decrypted_keys

def sign(data, sign_key, verif_key):
    byte_data = repr(data).encode('utf-8')
    return sign_key.sign(byte_data), verif_key.encode()

def verify(signature, pub_key):
    verif_key = VerifyKey(pub_key)
    return verif_key.verify(signature.message, signature.signature) 

def hash_password(password, salt = None):
    """Returns a password hahs of 32 bytes and a salt of 16 bytes. Uses Argon2id from Libsodium."""
    if(salt is None):
        salt = nacl.utils.random(16)
    try:
        pwd_hash = nacl.pwhash.argon2id.kdf(32, password.encode(), salt)
    except:
        pwd_hash = nacl.pwhash.argon2id.kdf(32, password, salt)
    return pwd_hash, salt
