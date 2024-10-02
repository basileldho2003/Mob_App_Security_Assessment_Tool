import os
from cryptography.fernet import Fernet

def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key.encode())
    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    USERNAME = 'basilsvm'
    PASSWORD = 'gAAAAABm_QVJd6SMRh7k-h4J3GL456URfX2fQ8PDlgPN12gys0EZh9TdRQlNRTQ_7AMcWrC2UX89wemVkCwo7psaTfLzZJxtZQ=='
    KEY = 'pQeD_Ddd-hShxUs7JgnXen6sb48UHEUIefH5a1o37C0='
    DPASSWORD = decrypt_password(PASSWORD, KEY)
    SQLALCHEMY_DATABASE_URI = f'mariadb+mariadbconnector://{USERNAME}:{DPASSWORD}@localhost/mobile_security_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
