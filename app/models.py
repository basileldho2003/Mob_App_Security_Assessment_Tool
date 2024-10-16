from app import db
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import Enum

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(Enum('admin', 'user', name='user_roles'), default='user')

    def __repr__(self):
        return f"<User {self.username}>"

class Upload(db.Model):
    __tablename__ = 'uploads'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    apk_file_name = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('uploads', lazy=True))

    def __repr__(self):
        return f"<Upload {self.apk_file_name}>"

class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(Enum('queued', 'in_progress', 'completed', 'failed', name='scan_status'), default='queued')
    result = db.Column(db.Text, nullable=True)
    upload = db.relationship('Upload', backref=db.backref('scans', lazy=True))

    def __repr__(self):
        return f"<Scan {self.id} - {self.status}>"

class ManifestIssue(db.Model):
    __tablename__ = 'manifest_issues'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    issue_type = db.Column(db.String(255), nullable=False)
    issue_detail = db.Column(db.Text, nullable=False)
    severity = db.Column(Enum('low', 'medium', 'high', 'critical', name='issue_severity'), nullable=False)
    scan = db.relationship('Scan', backref=db.backref('manifest_issues', lazy=True))

    def __repr__(self):
        return f"<ManifestIssue {self.issue_type} - {self.severity}>"

class SourceCodeIssue(db.Model):
    __tablename__ = 'source_code_issues'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    issue_type = db.Column(db.String(255), nullable=False)
    issue_detail = db.Column(db.Text, nullable=False)
    severity = db.Column(Enum('low', 'medium', 'high', 'critical', name='issue_severity'), nullable=False)
    scan = db.relationship('Scan', backref=db.backref('source_code_issues', lazy=True))

    def __repr__(self):
        return f"<SourceCodeIssue {self.file_path}:{self.line_number} - {self.severity}>"

class Payload(db.Model):
    __tablename__ = 'payloads'
    id = db.Column(db.Integer, primary_key=True)
    payload_name = db.Column(db.String(255), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(Enum('low', 'medium', 'high', 'critical', name='payload_severity'), nullable=False)

    def __repr__(self):
        return f"<Payload {self.payload_name} - {self.severity}>"

class ScanPayloadMatch(db.Model):
    __tablename__ = 'scan_payload_matches'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    payload_id = db.Column(db.Integer, db.ForeignKey('payloads.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    match_detail = db.Column(db.Text, nullable=False)
    scan = db.relationship('Scan', backref=db.backref('scan_payload_matches', lazy=True))
    payload = db.relationship('Payload', backref=db.backref('scan_payload_matches', lazy=True))

    def __repr__(self):
        return f"<ScanPayloadMatch {self.file_path}:{self.line_number}>"

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    log_message = db.Column(db.Text, nullable=False)
    log_time = db.Column(db.DateTime, default=datetime.utcnow)
    scan = db.relationship('Scan', backref=db.backref('logs', lazy=True))

    def __repr__(self):
        return f"<Log {self.log_time} - {self.log_message[:20]}>"