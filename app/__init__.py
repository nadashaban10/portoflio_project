# Import necessary modules
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from datetime import timedelta

# Initialize Flask application
app = Flask(__name__)
# Load configuration from Config class
app.config.from_object(Config)
# Configure JWT settings
# Set the secret key used to sign JWTs
app.config['JWT_SECRET_KEY'] = 'your_very_secret_key'
# Set the duration that an access token is valid for (30 minutes in this case)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=40)
# Set the duration that a refresh token is valid for (30 days in this case)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=300)

# Initialize JWTManager with the Flask app
jwt = JWTManager(app)

# Initialize SQLAlchemy with the Flask app
db = SQLAlchemy(app)
# Initialize Flask-Migrate with the Flask app and the database
migrate = Migrate(app, db)

# Initialize Flask-Login with the Flask app
login = LoginManager(app)
# Set the name of the login view
# If a user tries to access a protected page, they'll be redirected to this view for login
login.login_view = 'login'

# Import the API blueprint and register it with the Flask app
from app.api import bp as api_bp
app.register_blueprint(api_bp, url_prefix='/api')




# Run the Flask app if this script is run directly
if __name__ == '__main__':
    app.run(debug=True)