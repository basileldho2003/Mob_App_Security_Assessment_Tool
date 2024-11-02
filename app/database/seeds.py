import sys
import os

# Add the root directory of the project to the sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from app import create_app
from app.database import db
from app.database.models import User
from werkzeug.security import generate_password_hash

def seed_data():
    """Create all tables and seed only the admin user into the database."""

    # Create all tables if they don't exist
    db.create_all()

    # Add an admin user if not already present
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),  # Default password for admin
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully.")
    else:
        print("Admin user already exists.")

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        seed_data()
