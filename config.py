import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    USERNAME = ''
    PASSWORD = ''
    DPASSWORD = ''
    SQLALCHEMY_DATABASE_URI = f'mysql+mariadb://{USERNAME}:{PASSWORD}@localhost/mobile_security_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
