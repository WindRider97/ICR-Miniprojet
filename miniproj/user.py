import os
import uuid
import nacl.pwhash
import nacl.utils
import nacl.secret
import crypto
from nacl.public import PrivateKey
from nacl.signing import SigningKey


class User():
    def __init__(self, name: str, passw: str):
        """The user is assigned a uid and empty key and mappinp dictionaries.
        The pwd hash, salt and challenge hash are generated as well as the sharing and signing keys.
        The pwd hash is used as the master key for the user.
        """
        self.uid = nacl.utils.random(16)
        self.passw = passw.encode()
        self.name = name.encode()
        self.pwd_hash, self.pwd_salt = crypto.hash_password(self.passw)
        self.challenge_hash, _ = crypto.hash_password(self.pwd_hash, self.uid)
        self.folder_keys = {}  # The folder keys [uid] = key
        self.shared_keys = {}  # The shared folder keys [uid] = key
        self.folder_mapping = {}  # The folder mapping [folder_name] = uid
        # The encrypted folder mapping [uid] = enc_name
        self.enc_folder_mapping = {}
        # The shared folder mapping [folder_name] = uid and [uid] = enc_name
        self.shared_mapping = {}
        self.shared_folders_root = []  # The shared folders root
        self.master_key = self.pwd_hash
        os.makedirs(os.path.join('./files', self.name.decode()), exist_ok=True)
        self.folder_mapping[self.name] = uuid.uuid4().bytes
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

    def add_folder(self, folder_path: str) -> None:
        """Makes sure the whole path is created and assigns a unique id and key to each folders created."""
        folder_names = folder_path.split('/')
        current_path = './'
        for folder_name in folder_names:
            if folder_name != '':
                current_path = os.path.join(current_path, folder_name)
                if not os.path.exists(current_path):
                    uid = uuid.uuid4().bytes
                    self.folder_mapping[folder_name.encode()] = uid
                    os.makedirs(current_path, exist_ok=True)
                    self.folder_keys[uid] = nacl.utils.random(
                        nacl.secret.SecretBox.KEY_SIZE)

    def add_file(self, file_path: str, content: str) -> None:
        """First calls the make folder to be sure the path is properly mapped and keyed"""
        file_dirname = os.path.dirname(file_path)
        self.add_folder(file_dirname)
        with open(file_path, 'wb') as file:
            file.write(content)

    def encrypt_root(self) -> None:
        """Encrypts the root folder and all its content using a breadth first search algorithm.
        Each folder is encrypted with its key (the root folder is encrypted with the master key)
        Each file is encrypted with the key of its parent folder
        The file mapping is updated to reflect the new encrypted names associated with the uid of the folder"""
        destination = './files/server'
        source = os.path.join('./files', self.name.decode())
        enc_root = crypto.symmetric_enc(self.name, self.master_key)
        self.enc_folder_mapping[self.folder_mapping[self.name]] = enc_root
        destination = os.path.join(destination, enc_root.hex())

        queue = [(source, destination)]
        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                item = item.encode()
                if os.path.isdir(source_item):
                    # We do not want to encrypt the shared folder
                    if item.decode() == "shared":
                        continue
                    encrypted_name = crypto.symmetric_enc(
                        item, self.folder_keys[self.folder_mapping[item]])
                    self.enc_folder_mapping[self.folder_mapping[item]
                                            ] = encrypted_name
                    destination_item = os.path.join(
                        destination, encrypted_name.hex())
                    queue.append((source_item, destination_item))
                else:
                    parent_key = self.folder_keys[self.folder_mapping[os.path.split(
                        os.path.basename(source))[-1].encode()]]
                    encrypted_name = crypto.symmetric_enc(item, parent_key)
                    destination_item = os.path.join(
                        destination, encrypted_name.hex())
                    with open(source_item, 'rb') as file:
                        content = file.read()
                    encrypted_content = crypto.symmetric_enc(
                        content, parent_key)
                    with open(destination_item, 'wb') as file:
                        file.write(encrypted_content)

    def decrypt_root(self) -> None:
        destination = './files'

        source = os.path.join(
            './files/server', self.enc_folder_mapping[self.folder_mapping[self.name]].hex())

        dec_root = crypto.symmetric_dec(
            self.enc_folder_mapping[self.folder_mapping[self.name]], self.master_key)
        destination = os.path.join(destination, dec_root.decode())
        queue = [(source, destination)]

        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                if os.path.isdir(source_item):
                    decrypted_name = crypto.symmetric_dec(bytes.fromhex(
                        item), self.folder_keys[self.get_key_from_value(self.enc_folder_mapping, bytes.fromhex(item))])
                    destination_item = os.path.join(
                        destination, decrypted_name.decode())
                    queue.append((source_item, destination_item))
                else:
                    key = self.folder_keys[self.get_key_from_value(
                        self.enc_folder_mapping, bytes.fromhex(os.path.split(os.path.basename(source))[-1]))]
                    decrypted_name = crypto.symmetric_dec(
                        bytes.fromhex(item), key)
                    destination_item = os.path.join(
                        destination, decrypted_name.decode())
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

    def share_folder(self, folder_path: str, other_user_pub_key: bytes) -> tuple:
        """Lists the necessary keys and mapping to share a folder with another user.
        Encrypts the keys and mapping with the other user's public key.
        Signs the data to ensure the integrity of the data."""
        folder_name = folder_path.split('/')[-1].encode()
        shared_keys = {}
        shared_keys[self.folder_mapping[folder_name]
                    ] = self.folder_keys[self.folder_mapping[folder_name]]
        shared_mapping = {}
        shared_mapping[folder_name] = self.folder_mapping[folder_name]
        shared_mapping[self.folder_mapping[folder_name]
                       ] = self.enc_folder_mapping[self.folder_mapping[folder_name]]
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for dirname in dirnames:
                dirname = dirname.encode()
                shared_keys[self.folder_mapping[dirname]
                            ] = self.folder_keys[self.folder_mapping[dirname]]
                shared_mapping[dirname] = self.folder_mapping[dirname]
                shared_mapping[self.folder_mapping[dirname]
                               ] = self.enc_folder_mapping[self.folder_mapping[dirname]]
        shared_keys = crypto.encrypt_keys_asym(
            shared_keys, self.private_key, other_user_pub_key)
        shared_mapping = crypto.encrypt_keys_asym(
            shared_mapping, self.private_key, other_user_pub_key)
        data_to_sign = (shared_keys, shared_mapping,
                        self.folder_mapping[folder_name])
        signed_data, verif_key = crypto.sign(
            data_to_sign, self.signing_key, self.verify_key)
        return shared_keys, shared_mapping, self.folder_mapping[folder_name], signed_data, verif_key

    def receive_folder(self, keys: dict, shared_mapping: dict, other_user_pub_key: bytes, folder_uid: bytes, signed_data: bytes, verif_key: bytes) -> None:
        """First checks the integrity of the data by verifying the signature.
        Decrypts the keys and mapping with the other user's public key
        Adds the keys and mapping to the user's data."""
        crypto.verify(signed_data, verif_key)
        keys = crypto.decrypt_keys_asym(
            keys, self.private_key, other_user_pub_key)
        for key, value in keys.items():
            self.shared_keys[key] = value
        shared_mapping = crypto.decrypt_keys_asym(
            shared_mapping, self.private_key, other_user_pub_key)
        for key, value in shared_mapping.items():
            self.shared_mapping[key] = value
        self.shared_folders_root.append(folder_uid)

    def fetch_shared_folder(self, folder_uid: bytes, server: dict) -> None:
        """Needs to be called after calling the receive_folder method.
        Decrypts the shared folder and its content using the shared keys and mapping.
        The shared folder is then added to the user's shared"""
        destination = os.path.join('./files', self.name.decode(), 'shared')
        enc_folder_name = server[folder_uid]
        dec_root = crypto.symmetric_dec(enc_folder_name, self.shared_keys[self.get_key_from_value(
            self.shared_mapping, enc_folder_name)])
        destination = os.path.join(destination, dec_root.decode())
        source = self.find_folder(enc_folder_name.hex())
        queue = [(source, destination)]

        while queue:
            source, destination = queue.pop(0)
            os.makedirs(destination, exist_ok=True)
            for item in os.listdir(source):
                source_item = os.path.join(source, item)
                destination_item = os.path.join(destination, item)
                if os.path.isdir(source_item):
                    decrypted_name = crypto.symmetric_dec(bytes.fromhex(
                        item), self.shared_keys[self.get_key_from_value(self.shared_mapping, bytes.fromhex(item))])

                    destination_item = os.path.join(
                        destination, decrypted_name.decode())
                    queue.append((source_item, destination_item))
                else:
                    key = self.shared_keys[self.get_key_from_value(
                        self.shared_mapping, bytes.fromhex(os.path.split(os.path.basename(source))[-1]))]
                    decrypted_name = crypto.symmetric_dec(
                        bytes.fromhex(item), key)
                    destination_item = os.path.join(
                        destination, decrypted_name.decode())
                    with open(source_item, 'rb') as file:
                        content = file.read()
                    decrypted_content = crypto.symmetric_dec(content, key)
                    with open(destination_item, 'wb') as file:
                        file.write(decrypted_content)

    def fetch_shared_folders(self) -> None:
        """Fetches all the shared folders from the server. Called when dowloading the user's data from the server."""
        for folder_uid in self.shared_folders_root:
            self.fetch_shared_folder(folder_uid, self.shared_mapping)

    def find_folder(self, folder_name: str) -> str:
        for root, dirs, files in os.walk('./files/server'):
            if folder_name in dirs:
                return os.path.join(root, folder_name)
        return None

    def upload_data(self) -> tuple:
        self.encrypt_root()
        folder_keys = crypto.encrypt_keys_sym(
            self.folder_keys, self.master_key)
        shared_keys = crypto.encrypt_keys_sym(
            self.shared_keys, self.master_key)
        folder_mapping = crypto.encrypt_keys_sym(
            self.folder_mapping, self.master_key)
        shared_mapping = crypto.encrypt_keys_sym(
            self.shared_mapping, self.master_key)
        return folder_keys, shared_keys, folder_mapping, shared_mapping, self.enc_folder_mapping

    def download_data(self, folder_keys: dict, shared_keys: dict, folder_mapping: dict, shared_mapping: dict, enc_folder_mapping: dict) -> None:
        self.folder_keys = crypto.decrypt_keys_sym(
            folder_keys, self.master_key)
        self.shared_keys = crypto.decrypt_keys_sym(
            shared_keys, self.master_key)
        self.folder_mapping = crypto.decrypt_keys_sym(
            folder_mapping, self.master_key)
        self.shared_mapping = crypto.decrypt_keys_sym(
            shared_mapping, self.master_key)
        self.enc_folder_mapping = enc_folder_mapping
        self.decrypt_root()
        self.fetch_shared_folders()

    def prepare_login(self, salt_from_server: bytes) -> bytes:
        pwd_hash, _ = crypto.hash_password(self.passw, salt_from_server)
        challenge_hash, _ = crypto.hash_password(pwd_hash, self.uid)
        return challenge_hash

    def change_password(self, new_password: bytes) -> None:
        self.passw = new_password.encode()
        self.pwd_hash, self.pwd_salt = crypto.hash_password(self.passw)
        self.challenge_hash, _ = crypto.hash_password(self.pwd_hash, self.uid)
        self.master_key = self.pwd_hash
