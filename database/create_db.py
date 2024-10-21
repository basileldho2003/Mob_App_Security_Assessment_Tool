from app import db, create_app
from app.models import *  # Ensure models are imported so that tables can be created

def create_database():
    app = create_app()
    with app.app_context():
        db.create_all()
        print("Database tables created successfully.")

if __name__ == "__main__":
    create_database()
