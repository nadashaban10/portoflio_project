from os import abort
from flask_login import current_user
from app.api import bp
from flask import jsonify, make_response
from app import db
from app.models import User, Folder, Bookmark
from flask import request
from werkzeug.exceptions import BadRequest
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

@bp.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()

    # Validate required fields
    if 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Username, email and password are required!'}), 400

    # Check for existing username or email (case-insensitive)
    user = User.query.filter(
        (User.username.ilike(data['username'])) | (User.email.ilike(data['email']))
    ).first()
    if user is not None:
        return jsonify({'message': 'User with this username or email already exists!'}), 400
    # Create user with hashed password
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    # Generate access token (replace with appropriate claims)
    access_token = create_access_token(identity=user.id)
    response = {
    'status': 'success',
    'message': 'User was created successfully.',
    'your_token_key': access_token,
    'id': user.id,
    'username': user.username
}

    return jsonify(response), 201

@bp.route('/users', methods=['GET'])
def get_user_with_email_and_password():
    # Get email and password from the request arguments
    email = request.args.get('email')
    password = request.args.get('password')

    # Check if email and password were provided
    if not email or not password:
        raise BadRequest(description='Email and password must be provided')

    # Query the user by email
    user = User.query.filter_by(email=email).first()

    # If the user doesn't exist, return an error
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # If the password is incorrect, return an error
    if not user.verify_password(password):
        return jsonify({'message': 'Invalid password'}), 401

    # If the email and password are correct, return the user's data
    return jsonify(user.to_dict())


@bp.route('/users', methods=['PUT'])
def update_user():
    # Fetch the user based on email and password
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Update specific fields selectively using partial updates
    for field, value in data.items():
        if field in ('username', 'email', 'password'):  # Whitelist allowed fields
            setattr(user, field, value)
            if field == 'password':  # Hash new password securely
                user.set_password(value)

    db.session.commit()
    return jsonify({'message': 'User updated successfully.'}), 200

@bp.route('/users', methods=['DELETE'])
def delete_user():
    email = request.json.get('email')
    password = request.json.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = verify_user(email, password)
    if user is not None:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

def verify_user(email, password):
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        return user
    return None

def authenticate(email, password):
    user = User.query.filter_by(email=email).first()
    if user and user.verify_password(password):
        return user
    return None

@bp.route('/folders', methods=['POST'])
def create_folder():
    email = request.headers.get('email')
    password = request.headers.get('password')
    user = authenticate(email, password)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)
    data = request.get_json()
    folder = Folder(name=data['name'], user_id=user.id)
    db.session.add(folder)
    db.session.commit()
    return jsonify(folder.to_dict()), 201

@bp.route('/folders/<string:name>', methods=['GET'])
def get_folder(name):
    email = request.headers.get('email')
    password = request.headers.get('password')
    user = authenticate(email, password)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)
    folder = Folder.query.filter_by(name=name, user_id=user.id).first_or_404()
    return jsonify(folder.to_dict())


@bp.route('/folders', methods=['GET'])
def get_folders():
    email = request.headers.get('email')
    password = request.headers.get('password')
    user = authenticate(email, password)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)
    folders = Folder.query.filter_by(user_id=user.id).all()
    return jsonify([folder.to_dict() for folder in folders])


@bp.route('/folders/<string:name>', methods=['PUT'])
def update_folder(name):
    email = request.headers.get('email')
    password = request.headers.get('password')
    user = authenticate(email, password)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)
    folder = Folder.query.filter_by(name=name, user_id=user.id).first_or_404()
    data = request.get_json()
    folder.name = data['name']
    db.session.commit()
    return jsonify(folder.to_dict())



@bp.route('/folders/<string:name>', methods=['DELETE'])
def delete_folder(name):
    email = request.headers.get('email')
    password = request.headers.get('password')
    user = authenticate(email, password)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)
    folder = Folder.query.filter_by(name=name, user_id=user.id).first_or_404()

    # Delete bookmarks in the folder
    bookmarks = Bookmark.query.filter_by(folder_id=folder.id).all()
    for bookmark in bookmarks:
        db.session.delete(bookmark)

    db.session.delete(folder)
    db.session.commit()
    return jsonify({'message': 'Folder deleted successfully'}), 200

@bp.route('/bookmarks', methods=['POST'])
def create_bookmark():
    data = request.get_json()
    bookmark = Bookmark(url=data['url'], user_id=data['user_id'], folder_id=data['folder_id'])
    db.session.add(bookmark)
    db.session.commit()
    return jsonify(bookmark.to_dict()), 201

@bp.route('/bookmarks/<int:id>', methods=['GET'])
def get_bookmark(id):
    bookmark = Bookmark.query.get_or_404(id)
    return jsonify(bookmark.to_dict())

@bp.route('/bookmarks/<int:id>', methods=['PUT'])
def update_bookmark(id):
    bookmark = Bookmark.query.get_or_404(id)
    data = request.get_json()
    bookmark.url = data['url']
    bookmark.user_id = data['user_id']
    bookmark.folder_id = data['folder_id']
    db.session.commit()
    return jsonify(bookmark.to_dict())

@bp.route('/bookmarks/<int:id>', methods=['DELETE'])
def delete_bookmark(id):
    bookmark = Bookmark.query.get_or_404(id)
    db.session.delete(bookmark)
    db.session.commit()
    return '', 204




'''
from flask import jsonify, request
from flask_jwt_extended import (
    jwt_refresh_token_required,
    create_access_token,
    get_jwt_identity
)

@bp.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    # Get the identity from the refresh token
    current_user_id = get_jwt_identity()
    # Generate a new access token
    new_token = create_access_token(identity=current_user_id)

    return jsonify({'access_token': new_token}), 200
'''
