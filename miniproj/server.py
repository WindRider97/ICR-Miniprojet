from user import User
from my_tools import display_tree
class Server():
    def __init__(self):
        self.users_keys = {}
        self.users_folders_mapping = {}
        self.users_shared_keys = {}
        self.users_shared_mapping = {}
    
    def upload_data(self, user):
        self.users_keys[user], self.users_shared_keys[user], self.users_folders_mapping[user], self.users_shared_mapping[user] = user.upload_data()
        
    def download_data(self, user):
        user.download_data(self.users_keys[user], self.users_shared_keys[user], self.users_folders_mapping[user], self.users_shared_mapping[user])

if __name__ == '__main__':
    server = Server()
    alice = User("Alice")
    bob = User("Bob")
    alice.add_file('./files/Alice/Documents/Files/hello.txt', b'Hello World!')
    alice.add_file('./files/Alice/Documents/Secret/secret.txt', b'Hello World?')
    bob.add_file('./files/Bob/SharedFolder/Files/hello.txt', b'Hello World!')
    bob.add_file('./files/Bob/SharedFolder2/Secret/secret.txt', b'Hello World?')
    display_tree('./files')
    print()
    server.upload_data(bob)
    display_tree('./files')
    print()
    shared_keys, shared_mapping, folder_uid = bob.share_folder('./files/Bob/SharedFolder', alice.public_key)
    shared_keys2, shared_mapping2, folder_uid2 = bob.share_folder('./files/Bob/SharedFolder2', alice.public_key)
    alice.receive_folder(shared_keys, shared_mapping, bob.public_key, folder_uid)
    alice.receive_folder(shared_keys2, shared_mapping2, bob.public_key, folder_uid2)
    alice.fetch_shared_folder(folder_uid, server.users_folders_mapping[bob])
    alice.fetch_shared_folder(folder_uid2, server.users_folders_mapping[bob])
    display_tree('./files')
    print()
    server.upload_data(alice)
    display_tree('./files')
    print()
    server.download_data(alice)
    display_tree('./files')
    print()