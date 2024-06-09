import os
import uuid
import nacl.utils
import nacl.secret
import crypto
import shutil
from nacl.public import PrivateKey, Box
from my_tools import display_tree
from nacl.signing import SigningKey
import pickle

class User():
    def __init__(self, name):
        self.name = name
        self.folder_keys = {}
        self.shared_keys = {}
        self.folder_mapping = {}
        self.shared_mapping = {}
        self.shared_folders_root = []
        self.master_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        os.makedirs(os.path.join('./files', self.name), exist_ok=True)
        uid = str(uuid.uuid4())
        self.folder_mapping[self.name] = uid
        self.folder_keys[uid] = self.master_key    
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

    def add_folder(self, folder_path):
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
        file_dirname = os.path.dirname(file_path)
        self.add_folder(file_dirname)
        with open(file_path, 'wb') as file:
            file.write(content)

    def encrypt_root(self):
        destination = './files/server'    
        source = os.path.join('./files', self.name)
        enc_root = crypto.symmetric_enc(self.name.encode(), self.master_key)
        self.folder_mapping[self.folder_mapping[self.name]] = enc_root.hex()
        destination = os.path.join(destination, enc_root.hex())

        queue = [(source, destination)]

        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                if os.path.isdir(source_item):
                    if item == "shared":
                        continue
                    encrypted_name = crypto.symmetric_enc(item.encode(), self.folder_keys[self.folder_mapping[item]])
                    self.folder_mapping[self.folder_mapping[item]] = encrypted_name.hex()
                    destination_item = os.path.join(destination, encrypted_name.hex())
                    queue.append((source_item, destination_item))
                else:
                    encrypted_name = crypto.symmetric_enc(item.encode(), self.folder_keys[self.folder_mapping[os.path.split(os.path.basename(source))[-1]]])
                    destination_item = os.path.join(destination, encrypted_name.hex())
                    with open(source_item, 'rb') as file:
                        content = file.read()
                    encrypted_content = crypto.symmetric_enc(content + "enc".encode(), self.folder_keys[self.folder_mapping[os.path.split(os.path.basename(source))[-1]]])
                    with open(destination_item, 'wb') as file:
                        file.write(encrypted_content)
    
        source = os.path.join('./files', self.name)
        # shutil.rmtree(source)

    def decrypt_root(self):
        destination = './files'
        source = os.path.join('./files/server', self.folder_mapping[self.folder_mapping[self.name]])
        dec_root = crypto.symmetric_dec(bytes.fromhex(self.folder_mapping[self.folder_mapping[self.name]]), self.master_key)
        destination = os.path.join(destination, dec_root.decode())
        queue = [(source, destination)]

        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                if os.path.isdir(source_item):
                    decrypted_name = crypto.symmetric_dec(bytes.fromhex(item), self.folder_keys[self.get_key_from_value(self.folder_mapping, item)])
                    destination_item = os.path.join(destination, decrypted_name.decode())
                    queue.append((source_item, destination_item))
                else:
                    key = self.folder_keys[self.get_key_from_value(self.folder_mapping, os.path.split(os.path.basename(source))[-1])]
                    decrypted_name = crypto.symmetric_dec(bytes.fromhex(item), key)
                    destination_item = os.path.join(destination, decrypted_name.decode())
                    with open(source_item, 'rb') as file:
                        content = file.read()
                    decrypted_content = crypto.symmetric_dec(content, key)
                    with open(destination_item, 'wb') as file:
                        file.write(decrypted_content)

        source = os.path.join('./files/server', self.folder_mapping[self.folder_mapping[self.name]])
        #  shutil.rmtree(source)
    
    def get_key_from_value(self, dict, value):
        for key, val in dict.items():
            if val == value:
                return key
        return None
    
    def share_folder(self, folder_path, other_user_pub_key):
        folder_name = folder_path.split('/')[-1]
        shared_keys = {}
        shared_keys[self.folder_mapping[folder_name]] = self.folder_keys[self.folder_mapping[folder_name]]
        shared_mapping = {}
        shared_mapping[folder_name] = self.folder_mapping[folder_name]
        shared_mapping[self.folder_mapping[folder_name]] = self.folder_mapping[self.folder_mapping[folder_name]]
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for dirname in dirnames:
                shared_keys[self.folder_mapping[dirname]] = self.folder_keys[self.folder_mapping[dirname]]
                shared_mapping[dirname] = self.folder_mapping[dirname]
                shared_mapping[self.folder_mapping[dirname]] = self.folder_mapping[self.folder_mapping[dirname]]    
        shared_keys = crypto.encrypt_keys_asym(shared_keys, self.private_key, other_user_pub_key)
        shared_mapping = crypto.encrypt_keys_asym(shared_mapping, self.private_key, other_user_pub_key)
        data_to_sign = (shared_keys, shared_mapping, self.folder_mapping[folder_name])
        signed_data, verif_key = crypto.sign(data_to_sign, self.signing_key, self.verify_key)
        return shared_keys, shared_mapping, self.folder_mapping[folder_name], signed_data, verif_key
    
    def receive_folder(self, keys, shared_mapping, other_user_pub_key, folder_uid, signed_data, verif_key):
        crypto.verify(signed_data, verif_key)
        keys = crypto.decrypt_keys_asym(keys, self.private_key, other_user_pub_key)
        for key, value in keys.items():
            self.shared_keys[key] = value
        shared_mapping = crypto.decrypt_keys_asym(shared_mapping, self.private_key, other_user_pub_key)
        for key, value in shared_mapping.items():
            self.shared_mapping[key] = value
        self.shared_folders_root.append(folder_uid)





    
    def fetch_shared_folder(self, folder_uid, server):
        destination = os.path.join('./files', self.name, 'shared')
        enc_folder_name = server[folder_uid]
        dec_root = crypto.symmetric_dec(bytes.fromhex(enc_folder_name), self.shared_keys[self.get_key_from_value(self.shared_mapping, enc_folder_name.encode())])
        destination = os.path.join(destination, dec_root.decode())
        source = self.find_folder(enc_folder_name)
        queue = [(source, destination)]

        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                if os.path.isdir(source_item):
                    decrypted_name = crypto.symmetric_dec(bytes.fromhex(item), self.shared_keys[self.get_key_from_value(self.shared_mapping, item.encode())])
                    destination_item = os.path.join(destination, decrypted_name.decode())
                    queue.append((source_item, destination_item))
                else:
                    key = self.shared_keys[self.get_key_from_value(self.shared_mapping, os.path.split(os.path.basename(source))[-1].encode())]
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
                return os.path.join(root, folder_name)
        return None
    
    def upload_data(self):
        self.encrypt_root()
        folder_keys = crypto.encrypt_keys_sym(self.folder_keys, self.master_key)
        shared_keys = crypto.encrypt_keys_asym(self.shared_keys, self.private_key, self.public_key)
        return folder_keys, shared_keys, self.folder_mapping, self.shared_mapping

    def download_data(self, folder_keys, shared_keys, folder_mapping, shared_mapping):
        folder_keys = crypto.decrypt_keys_sym(folder_keys, self.master_key)
        shared_keys = crypto.decrypt_keys_asym(shared_keys, self.private_key, self.public_key)
        self.folder_keys = folder_keys
        self.shared_keys = shared_keys
        self.folder_mapping = folder_mapping
        self.shared_mapping = shared_mapping    
        self.decrypt_root()
    

if __name__ == '__main__':
    alice = User('Alice')
    alice.add_file('./files/Alice/Documents/Files/hello.txt', b'Hello World!')
    alice.add_file('./files/Alice/Documents/Secret/secret.txt', b'Hello World?')

    bob = User('Bob')
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