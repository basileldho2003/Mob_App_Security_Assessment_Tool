from app.database import db
from app.database.models import User, Payload
from werkzeug.security import generate_password_hash

def seed_data():
    """Seed initial data into the database."""
    
    # Add an admin user if not already present
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),  # Default password
            role='admin'
        )
        db.session.add(admin_user)

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

    # Commit all changes to the database
    db.session.commit()
    print("Seeding completed successfully.")


if __name__ == "__main__":
    from app import create_app

    app = create_app()
    with app.app_context():
        seed_data()
