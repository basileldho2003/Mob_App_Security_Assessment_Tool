import os
from cryptography.fernet import Fernet

# Decrypts an encrypted password using a fernet key.
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key.encode())
    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

# Database credentials
user='basilsvm'
epasswd='gAAAAABnD5wrT2gnHbzWJZUbqav8QKUebOgJfIREJaAMkSpK7QWv6XkPHSBYAkvwe-OzVTLtzPDNmrM5pQDckilXQxLvG5VNSQ=='
fkey='VNzCN2GykeLKEfFL2qXi6wO02duDAYS0noVLtZ3Sd-k='
passwd=decrypt_password(epasswd, fkey)
database='mobile_security_db'

# Configuration classes for the application.
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'mysql+mysqlconnector://{user}:{passwd}@localhost/{database}?charset=utf8mb4&collation=utf8mb4_general_ci')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv('TEST_DATABASE_URL', 'sqlite:///:memory:')
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'mysql+mysqlconnector://{user}:{passwd}@localhost/{database}?charset=utf8mb4&collation=utf8mb4_general_ci')

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}