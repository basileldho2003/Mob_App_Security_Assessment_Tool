import os
from cryptography.fernet import Fernet

def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key.encode())
    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    USERNAME = ''
    PASSWORD = ''
    KEY = ''
    DPASSWORD = decrypt_password(PASSWORD, KEY)
    SQLALCHEMY_DATABASE_URI = f'mysql+mariadb://{USERNAME}:{PASSWORD}@localhost/mobile_security_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
