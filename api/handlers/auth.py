# Modern Cryptography Project
# Michael Mitchell Student # C00255151
from datetime import datetime
from time import mktime
from tornado.gen import coroutine
from cryptography.fernet import Fernet

from .base import BaseHandler

class AuthHandler(BaseHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fernet = None

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'fullName': 1,
            'dateOfBirth': 1,
            'phoneNumber': 1,
            'disabilities': 1,
            'address': 1,
            'expiresIn': 1,
            'encryptionKey': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return
#Encryption key stored as part of the registration process is used to decrypt the data.
        self.fernet = Fernet(user['encryptionKey'])
        self.current_user = {
            'email': user['email'],
            'fullName': self.decrypt(user['fullName']),
            'dateOfBirth': self.decrypt(user['dateOfBirth']),
            'phoneNumber': self.decrypt(user['phoneNumber']),
            'disabilities': self.decrypt(user['disabilities']),
            'address': self.decrypt(user['address'])
        }

    def decrypt(self, value):
        if value is None:
            return None
        return self.fernet.decrypt(value).decode()