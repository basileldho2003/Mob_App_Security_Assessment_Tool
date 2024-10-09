import logging
import os

# Set up the logging configuration
LOG_FOLDER = os.path.join(os.getcwd(), 'logs')
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

LOG_FILE = os.path.join(LOG_FOLDER, 'app.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Get the logger instance
logger = logging.getLogger(__name__)
