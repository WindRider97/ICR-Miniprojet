import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, Box


def symmetric_enc(data, key):
    box = nacl.secret.SecretBox(key)
    return box.encrypt(data)

def symmetric_dec(data, key):
    box = nacl.secret.SecretBox(key)
    return box.decrypt(data)

def asymmetric_enc(data, my_priv_key, their_pub_key):
    box = Box(my_priv_key, their_pub_key)
    return box.encrypt(data)

def asymmetric_dec(data, my_priv_key, their_pub_key):
    box = Box(my_priv_key, their_pub_key)
    return box.decrypt(data)

def encrypt_keys_sym(keys, key):
    encrypted_keys = {}
    for k, v in keys.items():
        encrypted_key = symmetric_enc(k.encode(), key)
        encrypted_value = symmetric_enc(v, key)
        encrypted_keys[encrypted_key] = encrypted_value
    return encrypted_keys

def encrypt_keys_asym(keys, my_priv_key, their_pub_key):
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
    decrypted_keys = {}
    for k, v in keys.items():
        decrypted_key = symmetric_dec(k, key)
        decrypted_value = symmetric_dec(v, key)
        decrypted_keys[decrypted_key.decode()] = decrypted_value
    return decrypted_keys

def decrypt_keys_asym(keys, my_priv_key, their_pub_key):
    decrypted_keys = {}
    for k, v in keys.items():
        decrypted_key = asymmetric_dec(k, my_priv_key, their_pub_key)
        decrypted_value = asymmetric_dec(v, my_priv_key, their_pub_key)
        decrypted_keys[decrypted_key.decode()] = decrypted_value
    return decrypted_keys
