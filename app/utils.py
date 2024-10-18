import os
import logging
from datetime import datetime
from werkzeug.utils import secure_filename
from app import db
from app.models import Log

# Set up logging
logging.basicConfig(filename='logs/app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def save_file(upload_folder, file):
    """
    Save uploaded file to the specified folder with a secure filename.
    """
    filename = secure_filename(file.filename)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)
    return filename

def log_message(scan_id, message):
    """
    Save a log message to the database and log it to a file.
    """
    log_entry = Log(scan_id=scan_id, log_message=message, log_time=datetime.utcnow())
    db.session.add(log_entry)
    db.session.commit()
    logging.info(f"Scan {scan_id}: {message}")

def allowed_file(filename):
    """
    Check if the uploaded file has an allowed extension (only .apk).
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'apk'
