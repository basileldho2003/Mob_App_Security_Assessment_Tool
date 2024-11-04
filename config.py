import os
from cryptography.fernet import Fernet

def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key.encode())
    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

class Config:
    # Basic Flask settings
    SECRET_KEY = os.urandom(24)  # Generates a 24-byte random secret key
    USER = 'basilsvm'
    EPASSWORD = 'gAAAAABnHvZYipuvrDOLB4EHnqG50eum_PLESmlEEdHhDU0FZfRIBV6ILSKtv9iWm98ItC8G45BJS_a6b01yCyk1oDECzBiMjQ=='
    FKEY = '2P-elDYJNuMBG0efI825Y9aR61fAwA408ievaoUAVaI='
    PASSWORD = decrypt_password(EPASSWORD, FKEY)
    DATABASE_NAME = 'mobile_security_db'
    # SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = (
        f'mysql+mysqlconnector://{USER}:{PASSWORD}@localhost/{DATABASE_NAME}?charset=utf8mb4&collation=utf8mb4_general_ci'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload folder
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    MAX_CONTENT_LENGTH = 150 * 1024 * 1024  # Maximum file size of 150MB
    YARA_RULES_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'yara_rules')  # Path to YARA rules folder
    REPORT_FOLDER = os.path.join(os.getcwd(), 'reports')