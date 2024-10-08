from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import config_by_name

# Initialize SQLAlchemy
db = SQLAlchemy()

# Function to create the Flask app
def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Initialize extensions
    db.init_app(app)
    Migrate(app, db)

    return app