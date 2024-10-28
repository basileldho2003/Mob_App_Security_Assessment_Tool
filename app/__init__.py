from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

# Initialize the database
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize the database with the app
    db.init_app(app)

    # Import routes and register them without using blueprints
    with app.app_context():
        from . import routes

    return app
