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

class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True) 
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)  
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True, unique=True)
    password_hash: so.Mapped[str] = so.mapped_column(sa.String(256))
    bookmarks = relationship('Bookmark', backref='user', lazy='dynamic')
    folders = relationship('Folder', backref='user', lazy='dynamic')
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
    
    # Define a method 'to_dict' returns representation of the User model
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
    preview_data: so.Mapped[dict] = so.mapped_column(sa.JSON)
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'user_id': self.user_id,
            
            'created_at': self.created_at,
            'preview_data': self.preview_data
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