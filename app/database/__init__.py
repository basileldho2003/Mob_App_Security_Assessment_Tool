from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Initialize the database object
db = SQLAlchemy()

def init_db(app):
    """
    Initialize the database and bind it to the Flask app.
    
    Parameters:
    - app: The Flask application instance.
    """
    db.init_app(app)
    Migrate(app, db)  # Setup Flask-Migrate for handling database migrations

    # Import models here to ensure they are registered with SQLAlchemy
    from app.database import models
