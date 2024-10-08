import os
from app import create_app

# Load configuration based on the environment
config_name = os.getenv('FLASK_ENV', 'dev')
app = create_app(config_name)

if __name__ == "__main__":
    if config_name == 'prod':
        # Run the application in production mode, listening on all interfaces.
        app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False)
    elif config_name == 'dev':
        # Run the application in development mode, listening on localhost only.
        app.run(host='127.0.0.1', port=int(os.getenv('PORT', 5000)), debug=app.config['DEBUG'])
