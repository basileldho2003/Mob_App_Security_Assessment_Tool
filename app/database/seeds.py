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

    # Add a regular user if not already present
    regular_user = User.query.filter_by(username='user').first()
    if not regular_user:
        regular_user = User(
            username='user',
            email='user@example.com',
            password_hash=generate_password_hash('user123'),  # Default password for regular user
            role='user'
        )
        db.session.add(regular_user)
        db.session.commit()

    # Create an upload and scan record for the admin user if not already present
    admin_upload = Upload.query.filter_by(user_id=admin_user.id).first()
    if not admin_upload:
        admin_upload = Upload(
            user_id=admin_user.id,
            apk_file_name="admin_example.apk",
            upload_date=datetime.now()
        )
        db.session.add(admin_upload)
        db.session.commit()

        admin_scan = Scan(
            upload_id=admin_upload.id,
            scan_date=datetime.now(),
            status='completed'
        )
        db.session.add(admin_scan)
        db.session.commit()

    # Create an upload and scan record for the regular user if not already present
    regular_upload = Upload.query.filter_by(user_id=regular_user.id).first()
    if not regular_upload:
        regular_upload = Upload(
            user_id=regular_user.id,
            apk_file_name="user_example.apk",
            upload_date=datetime.now()
        )
        db.session.add(regular_upload)
        db.session.commit()

        regular_scan = Scan(
            upload_id=regular_upload.id,
            scan_date=datetime.now(),
            status='in_progress'
        )
        db.session.add(regular_scan)
        db.session.commit()

    # Add sample payloads for testing if not already present
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

    # Add sample source code issues for demonstration (ensure a scan exists)
    if not SourceCodeIssue.query.first():
        sample_issues = [
            {
                "scan_id": admin_scan.id,  # Assign to admin's scan
                "file_path": "MainActivity.java",
                "line_number": 45,
                "issue_type": "JavaScript Enabled",
                "issue_detail": "JavaScript is enabled in WebView, which may expose the app to security risks.",
                "severity": "high",
                "issue_category": "webview",
                "recommendation": "Disable JavaScript if not required, or ensure untrusted content is not loaded."
            },
            {
                "scan_id": admin_scan.id,
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
