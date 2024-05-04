from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_jwt_extended import JWTManager


app = Flask(__name__)
app.config.from_object(Config)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'your_very_strong_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

from app.api import bp as api_bp
app.register_blueprint(api_bp, url_prefix='/api')


from app import routes, models
if __name__ == '__main__':
    app.run(debug=True)