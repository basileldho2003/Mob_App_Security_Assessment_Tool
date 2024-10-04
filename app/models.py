from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    apk_name = db.Column(db.String(100))
    issues_found = db.Column(db.Text)
    scan_date = db.Column(db.DateTime)
