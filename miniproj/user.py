import os
import uuid
import nacl.pwhash
import nacl.utils
import nacl.secret
import crypto
import shutil
from nacl.public import PrivateKey, Box
from my_tools import display_tree
from nacl.signing import SigningKey
import pickle

class User():
    def __init__(self, name, passw):
        """The user is assigned a uid and empty key and mappinp dictionaries.
         The pwd hash, salt and challenge hash are generated as well as the sharing and signing keys.
            The pwd hash is used as the master key for the user.
           """
        self.uid = nacl.utils.random(16)
        self.passw = passw
        self.name = name
        self.pwd_hash, self.pwd_salt = crypto.hash_password(passw)
        self.challenge_hash, _ = crypto.hash_password(self.pwd_hash, self.uid)
        self.folder_keys = {}
        self.shared_keys = {}
        self.folder_mapping = {}
        self.enc_folder_mapping = {}
        self.shared_mapping = {}
        self.shared_folders_root = []
        self.master_key = self.pwd_hash
        os.makedirs(os.path.join('./files', self.name), exist_ok=True)
        uid = str(uuid.uuid4())
        self.folder_mapping[self.name] = uid 
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

    def add_folder(self, folder_path):
        """Makes sure the whole path is created and assigns a unique id and key to each folders created."""
        folder_names = folder_path.split('/')
        current_path = './'
        for folder_name in folder_names:
            if folder_name != '':
                current_path = os.path.join(current_path, folder_name)
                if not os.path.exists(current_path):
                    uid = str(uuid.uuid4())
                    self.folder_mapping[folder_name] = uid
                    os.makedirs(current_path, exist_ok=True)
                    self.folder_keys[uid] = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    
    def add_file(self, file_path, content):
        """First calls the make folder to be sure the path is properly mapped and keyed"""
        file_dirname = os.path.dirname(file_path)
        self.add_folder(file_dirname)
        with open(file_path, 'wb') as file:
            file.write(content)

    def encrypt_root(self):
        """Encrypts the root folder and all its content using a breadth first search algorithm.
        Each folder is encrypted with its key (the root folder is encrypted with the master key)
        Each file is encrypted with the key of its parent folder
        The file mapping is updated to reflect the new encrypted names associated with the uid of the folder"""
        destination = './files/server'    
        source = os.path.join('./files', self.name)
        enc_root = crypto.symmetric_enc(self.name.encode(), self.master_key)
        try:
            self.enc_folder_mapping[self.folder_mapping[self.name].encode()] = enc_root
        except:
            self.enc_folder_mapping[self.folder_mapping[self.name]] = enc_root
        destination = os.path.join(destination, enc_root.hex())

        queue = [(source, destination)]

        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                if os.path.isdir(source_item):
                    # We do not want to encrypt the shared folder
                    if item == "shared":
                        continue
                    encrypted_name = crypto.symmetric_enc(item.encode(), self.folder_keys[self.folder_mapping[item]])
                    self.enc_folder_mapping[self.folder_mapping[item]] = encrypted_name
                    destination_item = os.path.join(destination, encrypted_name.hex())
                    queue.append((source_item, destination_item))
                else:
                    encrypted_name = crypto.symmetric_enc(item.encode(), self.folder_keys[self.folder_mapping[os.path.split(os.path.basename(source))[-1]]])
                    destination_item = os.path.join(destination, encrypted_name.hex())
                    with open(source_item, 'rb') as file:
                        content = file.read()
                    encrypted_content = crypto.symmetric_enc(content + " enc then dec".encode(), self.folder_keys[self.folder_mapping[os.path.split(os.path.basename(source))[-1]]])
                    with open(destination_item, 'wb') as file:
                        file.write(encrypted_content)
    
    def decrypt_root(self):
        destination = './files'

        source = os.path.join('./files/server', self.enc_folder_mapping[self.folder_mapping[self.name]].hex())

        dec_root = crypto.symmetric_dec(self.enc_folder_mapping[self.folder_mapping[self.name]], self.master_key)
        destination = os.path.join(destination, dec_root.decode())
        queue = [(source, destination)]

        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                if os.path.isdir(source_item):
                    try:
                        decrypted_name = crypto.symmetric_dec(bytes.fromhex(item), self.folder_keys[self.get_key_from_value(self.enc_folder_mapping, bytes.fromhex(item))])
                    except:
                        decrypted_name = crypto.symmetric_dec(bytes.fromhex(item), self.folder_keys[self.get_key_from_value(self.enc_folder_mapping, bytes.fromhex(item)).encode()])
                    destination_item = os.path.join(destination, decrypted_name.decode())
                    queue.append((source_item, destination_item))
                else:
                    try:
                        key = self.folder_keys[self.get_key_from_value(self.enc_folder_mapping, bytes.fromhex(os.path.split(os.path.basename(source))[-1])).encode()]
                    except:
                        key = self.folder_keys[self.get_key_from_value(self.enc_folder_mapping, bytes.fromhex(os.path.split(os.path.basename(source))[-1]))]
                    decrypted_name = crypto.symmetric_dec(bytes.fromhex(item), key)
                    destination_item = os.path.join(destination, decrypted_name.decode())
                    with open(source_item, 'rb') as file:
                        content = file.read()
                    decrypted_content = crypto.symmetric_dec(content, key)
                    with open(destination_item, 'wb') as file:
                        file.write(decrypted_content)

    def get_key_from_value(self, dict, value):
        for key, val in dict.items():
            if val == value:
                return key
        return None
    
    def share_folder(self, folder_path, other_user_pub_key):
        """Lists the necessary keys and mapping to share a folder with another user.
        Encrypts the keys and mapping with the other user's public key.
        Signs the data to ensure the integrity of the data."""
        folder_name = folder_path.split('/')[-1]
        shared_keys = {}
        shared_keys[self.folder_mapping[folder_name]] = self.folder_keys[self.folder_mapping[folder_name]]
        shared_mapping = {}
        shared_mapping[folder_name] = self.folder_mapping[folder_name]
        try:
            shared_mapping[self.folder_mapping[folder_name]] = self.enc_folder_mapping[self.folder_mapping[folder_name]]
        except:
            shared_mapping[self.folder_mapping[folder_name]] = self.enc_folder_mapping[self.folder_mapping[folder_name].encode()]
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for dirname in dirnames:
                shared_keys[self.folder_mapping[dirname]] = self.folder_keys[self.folder_mapping[dirname]]
                shared_mapping[dirname] = self.folder_mapping[dirname]
                print(self.enc_folder_mapping)
                shared_mapping[self.folder_mapping[dirname]] = self.enc_folder_mapping[self.folder_mapping[dirname]]    
        shared_keys = crypto.encrypt_keys_asym(shared_keys, self.private_key, other_user_pub_key)
        shared_mapping = crypto.encrypt_keys_asym(shared_mapping, self.private_key, other_user_pub_key)
        data_to_sign = (shared_keys, shared_mapping, self.folder_mapping[folder_name])
        signed_data, verif_key = crypto.sign(data_to_sign, self.signing_key, self.verify_key)
        return shared_keys, shared_mapping, self.folder_mapping[folder_name], signed_data, verif_key
    
    def receive_folder(self, keys, shared_mapping, other_user_pub_key, folder_uid, signed_data, verif_key):
        """First checks the integrity of the data by verifying the signature.
        Decrypts the keys and mapping with the other user's public key
        Adds the keys and mapping to the user's data."""
        crypto.verify(signed_data, verif_key)
        keys = crypto.decrypt_keys_asym(keys, self.private_key, other_user_pub_key)
        for key, value in keys.items():
            self.shared_keys[key] = value
        shared_mapping = crypto.decrypt_keys_asym(shared_mapping, self.private_key, other_user_pub_key)
        for key, value in shared_mapping.items():
            self.shared_mapping[key] = value
        self.shared_folders_root.append(folder_uid)

    def fetch_shared_folder(self, folder_uid, server):
        """Needs to be called after calling the receive_folder method.
        Decrypts the shared folder and its content using the shared keys and mapping.
        The shared folder is then added to the user's shared"""
        destination = os.path.join('./files', self.name, 'shared')
        enc_folder_name = server[folder_uid]
        dec_root = crypto.symmetric_dec(enc_folder_name, self.shared_keys[self.get_key_from_value(self.shared_mapping, enc_folder_name)])
        destination = os.path.join(destination, dec_root.decode())
        print(enc_folder_name.hex())
        source = self.find_folder(enc_folder_name.hex())
        print(source)
        queue = [(source, destination)]

        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                if os.path.isdir(source_item):
                    print("shared keys", self.shared_keys)
                    print("shared mapping", self.shared_mapping)
                    print(item.encode())
                    decrypted_name = crypto.symmetric_dec(bytes.fromhex(item), self.shared_keys[self.get_key_from_value(self.shared_mapping, bytes.fromhex(item))])

                    destination_item = os.path.join(destination, decrypted_name.decode())
                    queue.append((source_item, destination_item))
                else:
                    key = self.shared_keys[self.get_key_from_value(self.shared_mapping, bytes.fromhex(os.path.split(os.path.basename(source))[-1]))]
                    decrypted_name = crypto.symmetric_dec(bytes.fromhex(item), key)
                    destination_item = os.path.join(destination, decrypted_name.decode())
                    with open(source_item, 'rb') as file:
                        content = file.read()
                    decrypted_content = crypto.symmetric_dec(content, key)
                    with open(destination_item, 'wb') as file:
                        file.write(decrypted_content)


    def find_folder(self, folder_name):
        for root, dirs, files in os.walk('./files/server'):
            if folder_name in dirs:
                print("found")
                return os.path.join(root, folder_name)
        print("not found")
        return None
    
    def upload_data(self):
        self.encrypt_root()
        folder_keys = crypto.encrypt_keys_sym(self.folder_keys, self.master_key)
        shared_keys = crypto.encrypt_keys_sym(self.shared_keys, self.master_key)
        folder_mapping = crypto.encrypt_keys_sym(self.folder_mapping, self.master_key)
        shared_mapping = crypto.encrypt_keys_sym(self.shared_mapping, self.master_key)
        return folder_keys, shared_keys, folder_mapping, shared_mapping, self.enc_folder_mapping

    def download_data(self, folder_keys, shared_keys, folder_mapping, shared_mapping, enc_folder_mapping):
        dec_folder_keys = crypto.decrypt_keys_sym(folder_keys, self.master_key)
        folder_keys = {}
        for k, v in dec_folder_keys.items():
            try:
                folder_keys[k.encode()] = v
            except:
                folder_keys[k] = v
        self.folder_keys = folder_keys
        self.shared_keys = crypto.decrypt_keys_sym(shared_keys, self.master_key)
        self.folder_mapping = crypto.decrypt_keys_sym(folder_mapping, self.master_key)
        self.shared_mapping = crypto.decrypt_keys_sym(shared_mapping, self.master_key)    
        self.enc_folder_mapping = enc_folder_mapping
        self.decrypt_root()

    def prepare_login(self, salt_from_server):
        pwd_hash, _ = crypto.hash_password(self.passw, salt_from_server)
        challenge_hash, _ = crypto.hash_password(pwd_hash, self.uid)
        return challenge_hash
    
    def change_password(self, new_password):
        self.passw = new_password
        self.pwd_hash, self.pwd_salt = crypto.hash_password(new_password)
        self.challenge_hash, _ = crypto.hash_password(self.pwd_hash, self.uid)
        self.master_key = self.pwd_hash

    

if __name__ == '__main__':
    alice = User('Alice', 'Password123')
    alice.add_file('./files/Alice/Documents/Files/hello.txt', b'Hello World!')
    alice.add_file('./files/Alice/Documents/Secret/secret.txt', b'Hello World?')

    bob = User('Bob', 'Password456')
    bob.add_file('./files/Bob/SharedFolder/Files/hello.txt', b'Hello World!')
    bob.add_file('./files/Bob/SharedFolder2/Secret/secret.txt', b'Hello World?')
    bob.encrypt_root()
    shared_keys, shared_mapping, folder_uid, signature, verif_key = bob.share_folder('./files/Bob/SharedFolder', alice.public_key)
    shared_keys2, shared_mapping2, folder_uid2, signature2, verif_key2 = bob.share_folder('./files/Bob/SharedFolder2', alice.public_key)
    alice.receive_folder(shared_keys, shared_mapping, bob.public_key, folder_uid, signature, verif_key)
    alice.receive_folder(shared_keys2, shared_mapping2, bob.public_key, folder_uid2, signature2, verif_key2)
    alice.fetch_shared_folder(folder_uid, bob.folder_mapping)
    alice.fetch_shared_folder(folder_uid2, bob.folder_mapping)
    alice.encrypt_root()
    alice.decrypt_root()