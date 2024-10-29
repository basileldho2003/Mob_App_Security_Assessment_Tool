from app import create_app, db
from flask_migrate import Migrate, MigrateCommand

# Initialize the app
app = create_app()

# Initialize Flask-Migrate for database migrations
migrate = Migrate(app, db)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
