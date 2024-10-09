import os
import logging
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FileHandler:
    def __init__(self, upload_folder, allowed_extensions=None):
        self.upload_folder = upload_folder
        self.allowed_extensions = allowed_extensions if allowed_extensions else {"apk", "xapk"}

    def allowed_file(self, filename):
        """
        Check if the uploaded file has an allowed extension.
        """
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in self.allowed_extensions

    def save_file(self, file):
        """
        Save the uploaded file to the specified upload folder.
        """
        if not self.allowed_file(file.filename):
            logger.error(f"File type not allowed: {file.filename}")
            raise ValueError("File type not allowed.")

        if not os.path.exists(self.upload_folder):
            os.makedirs(self.upload_folder)

        filename = secure_filename(file.filename)
        file_path = os.path.join(self.upload_folder, filename)
        try:
            file.save(file_path)
            logger.info(f"File saved successfully at {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to save file: {e}")
            raise Exception(f"Failed to save file: {e}")
