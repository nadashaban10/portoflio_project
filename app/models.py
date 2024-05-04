from datetime import datetime, timezone
from typing import Optional
import sqlalchemy as sa
import sqlalchemy.orm as so
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import login
from sqlalchemy import ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from werkzeug.exceptions import BadRequestKeyError
from flask import url_for


# UserMixin is a class provided by Flask-Login that includes generic implementations
# of methods that Flask-Login expects user objects to have.
# db.Model is the base class for all models from Flask-SQLAlchemy.
class User(UserMixin, db.Model):
    # Define the columns for the table 'user'
    # so.Mapped is a SQLAlchemy-Utils class for type hinting SQLAlchemy mapped attributes.
    id: so.Mapped[int] = so.mapped_column(primary_key=True)  # An integer column that is the primary key
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)  # A string column for the username, which is unique and indexed for efficient lookups
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True, unique=True)  # A string column for the email, which is unique and indexed
    password_hash: so.Mapped[str] = so.mapped_column(sa.String(256))  # A string column for the hashed password

    # Define relationships to other tables
    # 'Bookmark' and 'Folder' are other models that have a foreign key to User
    # 'backref' creates a virtual column on the related model that can be used to access the user
    # 'lazy' defines when SQLAlchemy will load the data from the database
    bookmarks = relationship('Bookmark', backref='user', lazy='dynamic')
    folders = relationship('Folder', backref='user', lazy='dynamic')
    
    # Define a property 'password' that raises an error when read
    # This is to prevent accidental access to the password hash
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    # Define a setter for 'password' that hashes the password and stores it in 'password_hash'
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    # Define a method 'verify_password' that checks if a password matches the stored hash
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # Define a method 'to_dict' that returns a dictionary representation of the user
    # This can be useful for serializing the user to JSON
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'folders': [folder.to_dict() for folder in self.folders],
            'bookmarks': [bookmark.to_dict() for bookmark in self.bookmarks]
        }

    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
   
    def __repr__(self):
        return '<User {}>'.format(self.username)

class Bookmark(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    url: so.Mapped[str] = so.mapped_column(sa.String(256), nullable=False)
    user_id: so.Mapped[int] = so.mapped_column(sa.Integer, ForeignKey('user.id'))
    folder_id: so.Mapped[int] = so.mapped_column(sa.Integer, ForeignKey('folder.id'), nullable=True)
    created_at: so.Mapped[datetime] = so.mapped_column(DateTime, default=datetime.utcnow)

    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'user_id': self.user_id,
            'folder_id': self.folder_id,
            'created_at': self.created_at
        }

class Folder(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    name: so.Mapped[str] = so.mapped_column(sa.String(64))
    user_id: so.Mapped[int] = so.mapped_column(sa.Integer, ForeignKey('user.id'))
    created_at: so.Mapped[datetime] = so.mapped_column(DateTime, default=datetime.utcnow)
    bookmarks = relationship('Bookmark', backref='folder', lazy='dynamic')
    
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id,
            'created_at': self.created_at,
            'bookmarks': [bookmark.to_dict() for bookmark in self.bookmarks]
        }
@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))