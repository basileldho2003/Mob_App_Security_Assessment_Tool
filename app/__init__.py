from flask import Flask
from config import Config
from app.database import init_db
# Initialize the database

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize the database with the app
    init_db(app)

    # Import routes and register them without using blueprints
    with app.app_context():
        from . import routes

    return app
