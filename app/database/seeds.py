import sys
import os

# Add the root directory of the project to the sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from app import create_app
from app.database import db
from app.database.models import User, Upload, Scan, Payload, SourceCodeIssue
from werkzeug.security import generate_password_hash
from datetime import datetime

def seed_data():
    """Seed initial data into the database."""

    # Add an admin user if not already present
    user = User.query.filter_by(id=1).first()
    if not user:
        admin_user = User(
            id=1,  # Explicitly set the ID to 1 for demonstration purposes
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),  # Default password
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()  # Commit to get the new user ID

    # Create an upload record if not already present
    upload = Upload.query.filter_by(id=1).first()
    if not upload:
        new_upload = Upload(
            id=1,  # Explicitly set the ID to 1 for demonstration purposes
            user_id=1,  # Ensure this user ID also exists
            apk_file_name="example.apk"
        )
        db.session.add(new_upload)
        db.session.commit()  # Commit to get the new upload ID

    # Create a scan record if not already present
    scan = Scan.query.filter_by(id=1).first()
    if not scan:
        new_scan = Scan(
            id=1,  # Explicitly set the ID to 1 for demonstration purposes
            upload_id=1,  # Make sure this ID matches an existing upload record
            scan_date=datetime.now(),
            status='completed'
        )
        db.session.add(new_scan)
        db.session.commit()  # Commit to get the new scan ID

    # Add sample payloads for testing
    if not Payload.query.first():
        sample_payloads = [
            {
                "payload_name": "SQL Injection",
                "pattern": "SELECT * FROM users WHERE",
                "description": "Checks for common SQL injection vulnerabilities",
                "severity": "high"
            },
            {
                "payload_name": "XSS",
                "pattern": "<script>alert('XSS')</script>",
                "description": "Checks for cross-site scripting vulnerabilities",
                "severity": "medium"
            },
            {
                "payload_name": "Hardcoded API Key",
                "pattern": "api_key=",
                "description": "Detects hardcoded API keys in the source code",
                "severity": "high"
            }
        ]

        for payload_data in sample_payloads:
            payload = Payload(
                payload_name=payload_data['payload_name'],
                pattern=payload_data['pattern'],
                description=payload_data['description'],
                severity=payload_data['severity']
            )
            db.session.add(payload)

    # Add sample source code issues for demonstration (ensure a scan ID of 1 exists)
    if not SourceCodeIssue.query.first():
        sample_issues = [
            {
                "scan_id": 1,  # Ensure a scan with ID 1 exists
                "file_path": "MainActivity.java",
                "line_number": 45,
                "issue_type": "JavaScript Enabled",
                "issue_detail": "JavaScript is enabled in WebView, which may expose the app to security risks.",
                "severity": "high",
                "issue_category": "webview",
                "recommendation": "Disable JavaScript if not required, or ensure untrusted content is not loaded."
            },
            {
                "scan_id": 1,
                "file_path": "MainActivity.java",
                "line_number": 60,
                "issue_type": "Empty Catch Block",
                "issue_detail": "Method 'handleLogin' contains an empty catch block, which may hide exceptions.",
                "severity": "low",
                "issue_category": "logic",
                "recommendation": "Add logging or error handling inside the catch block to prevent hidden exceptions."
            }
        ]

        for issue_data in sample_issues:
            issue = SourceCodeIssue(
                scan_id=issue_data['scan_id'],
                file_path=issue_data['file_path'],
                line_number=issue_data['line_number'],
                issue_type=issue_data['issue_type'],
                issue_detail=issue_data['issue_detail'],
                severity=issue_data['severity'],
                issue_category=issue_data['issue_category'],
                recommendation=issue_data['recommendation']
            )
            db.session.add(issue)

    # Commit all changes to the database
    db.session.commit()
    print("Seeding completed successfully.")

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        seed_data()
