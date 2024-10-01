from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        from app.models import User, ScanResults
        db.create_all()
        
        from app.routes import main
        app.register_blueprint(main)
    
    return app
