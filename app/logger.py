import logging
import os
from datetime import datetime

# Directory to store log files
LOG_DIR = os.path.join(os.getcwd(), 'logs')

# Ensure the log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Generate a unique log filename based on the current timestamp
LOG_FILENAME = os.path.join(LOG_DIR, f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configure logging
logging.basicConfig(
    filename=LOG_FILENAME,
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.DEBUG,
)

# Create a logger instance
logger = logging.getLogger(__name__)

def cleanup_logs(log_directory, retain_count=5):
    """
    Remove older log files to retain only the latest `retain_count` log files.

    Parameters:
    - log_directory: Path to the directory containing log files.
    - retain_count: Number of recent log files to keep.
    """
    try:
        # List all log files in the directory, sorted by creation time
        logs = sorted(
            [os.path.join(log_directory, f) for f in os.listdir(log_directory) if f.endswith(".log")],
            key=os.path.getmtime,
        )
        # Remove older log files if count exceeds retain_count
        if len(logs) > retain_count:
            for log_file in logs[:-retain_count]:
                os.remove(log_file)
                logger.info(f"Deleted old log file: {log_file}")
    except Exception as e:
        logger.error(f"Error during log cleanup: {e}")

# Cleanup old logs while retaining the latest 5 files
cleanup_logs(LOG_DIR, retain_count=5)
