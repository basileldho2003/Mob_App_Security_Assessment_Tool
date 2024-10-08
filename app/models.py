# models.py
from datetime import datetime
import pytz
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
import enum

db = SQLAlchemy()

# Enums for role and severity
class UserRole(enum.Enum):
    admin = 'admin'
    user = 'user'

class Severity(enum.Enum):
    low = 'low'
    medium = 'medium'
    high = 'high'
    critical = 'critical'

# User model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))
    role = db.Column(Enum(UserRole), default=UserRole.user, nullable=False)

# Upload model
class Upload(db.Model):
    __tablename__ = 'uploads'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    apk_file_name = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))

    user = db.relationship('User', backref=db.backref('uploads', lazy=True))

# Scan model
class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'), nullable=False)
    scan_date = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))
    status = db.Column(Enum('queued', 'in_progress', 'completed', 'failed'), default='queued', nullable=False)
    result = db.Column(db.Text, nullable=True)

    upload = db.relationship('Upload', backref=db.backref('scans', lazy=True))

# Manifest Issues model
class ManifestIssue(db.Model):
    __tablename__ = 'manifest_issues'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    issue_type = db.Column(db.String(255), nullable=False)
    issue_detail = db.Column(db.Text, nullable=False)
    severity = db.Column(Enum(Severity), nullable=False)

    scan = db.relationship('Scan', backref=db.backref('manifest_issues', lazy=True))

# Source Code Issues model
class SourceCodeIssue(db.Model):
    __tablename__ = 'source_code_issues'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    issue_type = db.Column(db.String(255), nullable=False)
    issue_detail = db.Column(db.Text, nullable=False)
    severity = db.Column(Enum(Severity), nullable=False)

    scan = db.relationship('Scan', backref=db.backref('source_code_issues', lazy=True))

# Payload model
class Payload(db.Model):
    __tablename__ = 'payloads'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    payload_name = db.Column(db.String(255), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(Enum(Severity), nullable=False)

# Scan Payload Matches model
class ScanPayloadMatch(db.Model):
    __tablename__ = 'scan_payload_matches'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    payload_id = db.Column(db.Integer, db.ForeignKey('payloads.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    match_detail = db.Column(db.Text, nullable=False)

    scan = db.relationship('Scan', backref=db.backref('scan_payload_matches', lazy=True))
    payload = db.relationship('Payload', backref=db.backref('scan_payload_matches', lazy=True))

# Log model
class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    log_message = db.Column(db.Text, nullable=False)
    log_time = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))

    scan = db.relationship('Scan', backref=db.backref('logs', lazy=True))