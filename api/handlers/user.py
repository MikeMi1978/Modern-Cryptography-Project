# Modern Cryptography Project
# Michael Mitchell Student # C00255151
from .auth import AuthHandler
from tornado.web import authenticated
import bcrypt
from .auth import AuthHandler
from passlib.hash import sha256_crypt

class UserHandler(AuthHandler):
    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['fullName'] = self.current_user['fullName']
        self.response['address'] = self.current_user['address']
        self.response['dateOfBirth'] = self.current_user['dateOfBirth']
        self.response['phoneNumber'] = self.current_user['phoneNumber']
        self.response['disabilities'] = self.current_user['disabilities']
        if 'password' in self.current_user:
            hashed_password = sha256_crypt.hash(self.current_user['password'])
            self.response['password'] = hashed_password
        self.write_json()