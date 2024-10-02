from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class ScanResults(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    apk_name = db.Column(db.String(256), nullable=False)
    manifest_issues = db.Column(db.Text)
    code_issues = db.Column(db.Text)
    report_date = db.Column(db.DateTime, default=db.func.current_timestamp())
