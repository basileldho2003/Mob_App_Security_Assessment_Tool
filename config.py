import os
from cryptography.fernet import Fernet

class Config:
    # General Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))
    DEBUG = os.getenv('DEBUG', False)

    # Database Configuration (MariaDB with mysql-connector-python library)
    DB_PASSWORD_ENCRYPTED = os.getenv('DB_PASSWORD_ENCRYPTED', 'gAAAAABnBK-tEtLSJDZZ1m71Df7xgG-UkWVquQXTUElxYhCy949wIfvCZ0EDXVyZABRhJccw1qKXZcv4vmtsWwazn6DM1hE1XQ==')
    fernet_key = os.getenv('FERNET_KEY', '3l0Dglp2n4t327cU32jtCzBBcS6pq_uEYRDbBvz_cqo=')
    cipher_suite = Fernet(fernet_key)
    DB_PASSWORD = cipher_suite.decrypt(DB_PASSWORD_ENCRYPTED.encode()).decode()

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+mysqlconnector://{os.getenv('DB_USERNAME', 'user')}:"
        f"{DB_PASSWORD}@"
        f"{os.getenv('DB_HOST', 'localhost')}/"
        f"{os.getenv('DB_NAME', 'mobile_security_db')}"
        f"?charset=utf8mb4&collation=utf8mb4_general_ci"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # APK File Uploads
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    MAX_CONTENT_LENGTH = 150 * 1024 * 1024  # Max file size: 150MB

    # Logging
    LOG_TO_STDOUT = os.getenv('LOG_TO_STDOUT')

    # PDF Configuration
    PDF_GENERATION_PATH = os.path.join(os.getcwd(), 'reports')

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    DB_PASSWORD_ENCRYPTED = os.getenv('TEST_DB_PASSWORD_ENCRYPTED', 'gAAAAABnBK-tEtLSJDZZ1m71Df7xgG-UkWVquQXTUElxYhCy949wIfvCZ0EDXVyZABRhJccw1qKXZcv4vmtsWwazn6DM1hE1XQ==')
    DB_PASSWORD = Config.cipher_suite.decrypt(DB_PASSWORD_ENCRYPTED.encode()).decode()
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+mysqlconnector://{os.getenv('TEST_DB_USERNAME', 'test_user')}:"
        f"{DB_PASSWORD}@"
        f"{os.getenv('TEST_DB_HOST', 'localhost')}/"
        f"{os.getenv('TEST_DB_NAME', 'mobile_security_db')}"
        f"?charset=utf8mb4&collation=utf8mb4_general_ci"
    )

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

# Load config based on environment
config_by_name = dict(
    dev=DevelopmentConfig,
    test=TestingConfig,
    prod=ProductionConfig
)

key = Config.SECRET_KEY