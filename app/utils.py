import os

from werkzeug.security import generate_password_hash
from app.database import db
from app.database.models import User, Log
from datetime import datetime
from logger import logger

def create_admin_user(username, email, password):
    """Utility function to create an admin user if not already existing."""
    if not User.query.filter_by(username=username).first():
        hashed_password = generate_password_hash(password)
        admin = User(username=username, email=email, password_hash=hashed_password, role='admin')
        db.session.add(admin)
        db.session.commit()
        logger.info(f"Admin user '{username}' created successfully.")
    else:
        logger.info(f"Admin user '{username}' already exists.")

def save_log(scan_id, message):
    """Utility function to save a log entry for a given scan."""
    log = Log(scan_id=scan_id, log_message=message, log_time=datetime.utcnow())
    db.session.add(log)
    db.session.commit()

def allowed_file(filename, allowed_extensions):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_uploaded_file(file, upload_folder):
    """Save an uploaded file to the specified folder and return its path."""
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)
    return file_path
