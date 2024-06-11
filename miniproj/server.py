from user import User
from my_tools import display_tree


class Server():
    def __init__(self):
        self.users_keys = {}
        self.users_folders_mapping = {}
        self.users_shared_keys = {}
        self.users_shared_mapping = {}
        self.users_enc_folder_mapping = {}
        self.users = {}

    def upload_data(self, user):
        self.users_keys[user.uid], self.users_shared_keys[user.uid], self.users_folders_mapping[
            user.uid], self.users_shared_mapping[user.uid], self.users_enc_folder_mapping[user.uid] = user.upload_data()

    def download_data(self, user):
        user.download_data(self.users_keys[user.uid], self.users_shared_keys[user.uid], self.users_folders_mapping[user.uid],
                           self.users_shared_mapping[user.uid], self.users_enc_folder_mapping[user.uid])

    def register_user(self, user):
        self.users[user.uid] = (user.pwd_salt, user.challenge_hash)
        self.upload_data(user)

    def login_user(self, user):
        chall_hash_computed = user.prepare_login(self.users[user.uid][0])
        if (chall_hash_computed == self.users[user.uid][1]):
            print("Login successful")
            self.download_data(user)
        else:
            print("Login failed")

    def logout(self, user):
        self.users[user.uid] = (user.pwd_salt, user.challenge_hash)
        self.upload_data(user)
        print("Logout successful")
