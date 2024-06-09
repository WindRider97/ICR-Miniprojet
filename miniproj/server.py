import os
import nacl.pwhash
from user import User
from my_tools import display_tree
class Server():
    def __init__(self):
        self.users_keys = {}
        self.users_folders_mapping = {}
        self.users_shared_keys = {}
        self.users_shared_mapping = {}
        self.users = {}
    
    def upload_data(self, user):
        self.users_keys[user.uid], self.users_shared_keys[user.uid], self.users_folders_mapping[user.uid], self.users_shared_mapping[user.uid] = user.upload_data()
        
    def download_data(self, user):
        user.download_data(self.users_keys[user.uid], self.users_shared_keys[user.uid], self.users_folders_mapping[user.uid], self.users_shared_mapping[user.uid])

    def register_user(self, user):
        print("pwd_salt", user.pwd_salt)
        print("challenge_hash", user.challenge_hash)
        self.users[user.uid] = (user.pwd_salt, user.challenge_hash)
        self.upload_data(user)
    
    def login_user(self, user):
        print("pwd_salt", self.users[user.uid][0]   )
        chall_hash_computed = user.prepare_login(self.users[user.uid][0])
        print("computed chall hash", chall_hash_computed)
        print("stored chall hash", self.users[user.uid][1])
        if(chall_hash_computed == self.users[user.uid][1]):
            print("Login successful")
            self.download_data(user)
        else:
            print("Login failed")
        
    def logout(self, user):
        self.users[user.uid] = (user.pwd_salt, user.challenge_hash)
        self.upload_data(user)
        print("Logout successful")

    

if __name__ == '__main__':
    server = Server()
    alice = User("Alice", "Password123")
    bob = User("Bob", "Password456")
    alice.add_file('./files/Alice/Documents/Files/hello.txt', b'Hello World!')
    alice.add_file('./files/Alice/Documents/Secret/secret.txt', b'Hello World?')
    bob.add_file('./files/Bob/SharedFolder/Files/hello.txt', b'Hello World!')
    bob.add_file('./files/Bob/SharedFolder2/Secret/secret.txt', b'Hello World?')
    server.register_user(alice)
    server.register_user(bob)
    shared_keys, shared_mapping, folder_uid, signature, verif_key = bob.share_folder('./files/Bob/SharedFolder', alice.public_key)
    shared_keys2, shared_mapping2, folder_uid2, signature2, verif_key2 = bob.share_folder('./files/Bob/SharedFolder2', alice.public_key)
    alice.receive_folder(shared_keys, shared_mapping, bob.public_key, folder_uid, signature, verif_key)
    alice.receive_folder(shared_keys2, shared_mapping2, bob.public_key, folder_uid2, signature2, verif_key2)
    alice.fetch_shared_folder(folder_uid, server.users_folders_mapping[bob.uid])
    alice.fetch_shared_folder(folder_uid2, server.users_folders_mapping[bob.uid])
    server.logout(alice)
    server.login_user(alice)
    server.logout(alice)
    server.login_user(alice)
    alice.change_password("Password789")
    server.logout(alice)
    server.login_user(alice)
    server.logout(alice)
    # display_tree('./files')
    # print()
    # server.upload_data(bob)
    # display_tree('./files')
    # print()
    # shared_keys, shared_mapping, folder_uid, signature, verif_key = bob.share_folder('./files/Bob/SharedFolder', alice.public_key)
    # shared_keys2, shared_mapping2, folder_uid2, signature2, verif_key2 = bob.share_folder('./files/Bob/SharedFolder2', alice.public_key)
    # alice.receive_folder(shared_keys, shared_mapping, bob.public_key, folder_uid, signature, verif_key)
    # alice.receive_folder(shared_keys2, shared_mapping2, bob.public_key, folder_uid2, signature2, verif_key2)
    # alice.fetch_shared_folder(folder_uid, server.users_folders_mapping[bob])
    # alice.fetch_shared_folder(folder_uid2, server.users_folders_mapping[bob])
    # display_tree('./files')
    # print()
    # server.upload_data(alice)
    # display_tree('./files')
    # print()
    # server.download_data(alice)
    # display_tree('./files')
    # print()