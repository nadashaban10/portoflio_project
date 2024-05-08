from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from datetime import timedelta


app = Flask(__name__)
app.config.from_object(Config)
app.config['JWT_SECRET_KEY'] = 'your_very_secret_key'
# Set the duration that an access token is valid for (30 minutes in this case)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=40)
# Set the duration that a refresh token is valid for (30 days in this case)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=300)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
jwt = JWTManager(app)



from app.api import bp as api_bp
app.register_blueprint(api_bp, url_prefix='/api')


from app import routes, models
