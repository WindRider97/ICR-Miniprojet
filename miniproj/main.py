from server import Server
from user import User
from my_tools import display_tree, clean_up

ascii_art = r"""
  ___ ____ ____            __  __ _       _                 _      _   
 |_ _/ ___|  _ \          |  \/  (_)_ __ (_)_ __  _ __ ___ (_) ___| |_ 
  | | |   | |_) |  _____  | |\/| | | '_ \| | '_ \| '__/ _ \| |/ _ \ __|
  | | |___|  _ <  |_____| | |  | | | | | | | |_) | | | (_) | |  __/ |_ 
 |___\____|_| \_\         |_|  |_|_|_| |_|_| .__/|_|  \___// |\___|\__|
                                           |_|           |__/          
"""

print(ascii_art)
print("Benjamin Mouchet - SP2024\n")
print("\n=====================================")
print("\nWelcome to the secure file sharing system demonstration!\n")
print("=====================================\n")
try:
    clean_up()
except FileNotFoundError:
    pass
print("Here is the initial file tree:")
display_tree('./files')
print("\nSetting up the server")
server = Server()
print("Setting up Alice and Bob (patience...)\n")
alice = User("Alice", "Password123")
bob = User("Bob", "Password456")
alice.add_file('./files/Alice/Documents/Files/hello.txt', b'Hello World!')
alice.add_file('./files/Alice/Documents/Secret/secret.txt',
               b'Hello World?')
bob.add_file('./files/Bob/SharedFolder/Files/hello.txt', b'Hello World!')
bob.add_file('./files/Bob/SharedFolder2/Secret/secret.txt',
             b'Hello World?')

print("New file tree:")
display_tree('./files')
input("Press Enter to continue...")
print("\n=====================================")
print("\nRegistering Alice and Bob, uploading their data to the server\n")
print("=====================================\n")

server.register_user(alice)
server.register_user(bob)
display_tree('./files')
print("\n=====================================")
print("\nBob shares two folders with Alice\n")
print("=====================================\n")
shared_keys, shared_mapping, folder_uid, signature, verif_key = bob.share_folder(
    './files/Bob/SharedFolder', alice.public_key)
shared_keys2, shared_mapping2, folder_uid2, signature2, verif_key2 = bob.share_folder(
    './files/Bob/SharedFolder2', alice.public_key)
alice.receive_folder(shared_keys, shared_mapping,
                     bob.public_key, folder_uid, signature, verif_key)
alice.receive_folder(shared_keys2, shared_mapping2,
                     bob.public_key, folder_uid2, signature2, verif_key2)
alice.fetch_shared_folder(
    folder_uid, server.users_enc_folder_mapping[bob.uid])
alice.fetch_shared_folder(
    folder_uid2, server.users_enc_folder_mapping[bob.uid])
print("New file tree for Alice:")
display_tree('./files/Alice')

input("Press Enter to continue...")
print("\n=====================================")
print("\nAlice logs out and back in\n")
print("=====================================\n")
server.logout(alice)
server.login_user(alice)
print("\nAlice's tree again:")
display_tree('./files/Alice')

input("Press Enter to continue...")
print("\n=====================================")
print("\nAlice changes her password\n")
print("=====================================\n")
alice.change_password("Password789")
print("\n=====================================")
print("\nAlice logs out and back in\n")
print("=====================================\n")
server.logout(alice)
server.login_user(alice)
print("\nAlice's tree again:")
display_tree('./files/Alice')
print("\n=====================================")
print("\nAlice's final logout\n")
print("=====================================\n")
server.logout(alice)

input("Press Enter to continue and see the server data (raw data.)")

print("\nServer data:")
print("Users:", server.users, "\n")
print("Users keys:", server.users_keys, "\n")
print("Folder mapping:", server.users_folders_mapping, "\n")
print("Shared keys:", server.users_shared_keys, "\n")
print("Shared mapping:", server.users_shared_mapping, "\n")
print("Encrypted folder mapping:", server.users_enc_folder_mapping, "\n")
print("\n=====================================")
print("\nYou can find the artifacts in the 'files' folder. It will be wiped at the next execution.\n")
print("=====================================\n")
