from app.database import db
from datetime import *
import pytz

def get_ist_time():
    utc_time = datetime.now(timezone.utc)
    ist_time = utc_time.replace(tzinfo=pytz.utc).astimezone(pytz.timezone('Asia/Kolkata'))
    return ist_time

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=get_ist_time)
    role = db.Column(db.Enum('admin', 'user', name='user_roles'), default='user', nullable=False)

    uploads = db.relationship('Upload', backref='user', lazy=True)


class Upload(db.Model):
    __tablename__ = 'uploads'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    apk_file_name = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=get_ist_time)

    scans = db.relationship('Scan', backref='upload', lazy=True)


class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'), nullable=False)
    scan_date = db.Column(db.DateTime, default=get_ist_time)
    status = db.Column(db.Enum('queued', 'in_progress', 'completed', 'failed', name='scan_status'), default='queued', nullable=False)
    result = db.Column(db.Text, nullable=True)

    manifest_issues = db.relationship('ManifestIssue', backref='scan', lazy=True)
    source_code_issues = db.relationship('SourceCodeIssue', backref='scan', lazy=True)
    scan_payload_matches = db.relationship('ScanPayloadMatch', backref='scan', lazy=True)
    logs = db.relationship('Log', backref='scan', lazy=True)


class ManifestIssue(db.Model):
    __tablename__ = 'manifest_issues'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    issue_type = db.Column(db.String(255), nullable=False)
    issue_detail = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Enum('low', 'medium', 'high', 'critical', name='severity_levels'), nullable=False)


class SourceCodeIssue(db.Model):
    __tablename__ = 'source_code_issues'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    issue_type = db.Column(db.String(255), nullable=False)
    issue_detail = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Enum('low', 'medium', 'high', 'critical', name='severity_levels'), nullable=False)
    issue_category = db.Column(db.Enum('webview', 'logic', 'security', 'performance', name='issue_categories'), nullable=True)
    recommendation = db.Column(db.Text, nullable=True)

    def __init__(self, scan_id, file_path, line_number, issue_type, issue_detail, severity, issue_category=None, recommendation=None):
        self.scan_id = scan_id
        self.file_path = file_path
        self.line_number = line_number
        self.issue_type = issue_type
        self.issue_detail = issue_detail
        self.severity = severity
        self.issue_category = issue_category
        self.recommendation = recommendation


class Payload(db.Model):
    __tablename__ = 'payloads'
    
    id = db.Column(db.Integer, primary_key=True)
    payload_name = db.Column(db.String(255), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Enum('low', 'medium', 'high', 'critical', name='severity_levels'), nullable=False)

    scan_payload_matches = db.relationship('ScanPayloadMatch', backref='payload', lazy=True)


class ScanPayloadMatch(db.Model):
    __tablename__ = 'scan_payload_matches'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    payload_id = db.Column(db.Integer, db.ForeignKey('payloads.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    line_number = db.Column(db.Integer, nullable=True)
    match_detail = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Enum('low', 'medium', 'high', 'critical', name='severity_levels'), nullable=True)


class Log(db.Model):
    __tablename__ = 'logs'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    log_message = db.Column(db.Text, nullable=False)
    log_time = db.Column(db.DateTime, default=get_ist_time)
