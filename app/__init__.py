from flask import Flask
from config import Config
from app.database import db
from flask_migrate import Migrate
# Initialize the database

migrate=Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize the database with the app
    db.init_app(app)
    migrate.init_app(app, db)

    # Import routes and register them without using blueprints
    with app.app_context():
        from . import routes

    return app
