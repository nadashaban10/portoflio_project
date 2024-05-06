from os import abort
from flask_login import current_user
from app.api import bp
from flask import jsonify, make_response
from app import db
from app import app
import app.models
from app.models import User, Folder, Bookmark
from flask import request
from werkzeug.exceptions import BadRequest
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity, create_refresh_token
from werkzeug.security import generate_password_hash, check_password_hash
import re
    

@bp.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()

    # Username validation (regex) - minimum 3 characters
    username_regex = r"^[a-zA-Z0-9_.-]{3,}$"
    if not re.match(username_regex, data.get('username')):
        return jsonify({'message': 'Username must be at least 3 characters and contain letters, numbers, underscores, hyphens, and periods.'}), 400

    
    email_regex = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.(com|org)$"
    if not re.match(email_regex, data.get('email')):
        return jsonify({'message': 'Invalid email format!'}), 400
    password_regex = r"^(?=.*[a-zA-Z])(?=.*[@$!%*?&])[^\s]{8,}$"
    if not re.match(password_regex, data.get('password')):
        return jsonify({'message': 'Password must be at least 8 characters and include a letter, a special symbol, and no spaces.'}), 400

    if 're_password' not in data or data.get('password') != data.get('re_password'):
        return jsonify({'message': 'Passwords do not match.'}), 400
    
    if 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Username, email and password are required!'}), 400


    user = User.query.filter(
        (User.username.ilike(data['username'])) | (User.email.ilike(data['email']))
    ).first()
    if user is not None:
        return jsonify({'message': 'User with this username or email already exists!'}), 400

    user = User(username=data['username'], email=data['email'], password=generate_password_hash(data['password']))
    db.session.add(user)
    db.session.commit()
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    response = {
        'status': 'success',
        'message': 'User was created successfully.',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'id': user.id,
        'username': user.username
    }

    return jsonify(response), 201



@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()  # Get user ID from refresh token
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': new_access_token})

@bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required() # ensuring that a valid JWT is present in the request.
def get_user(user_id):
    current_user_id = get_jwt_identity()  # Get user ID from access token
    if current_user_id != user_id:
        return jsonify({'message': ' Unauthorized user access'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    return jsonify(user.to_dict())


@bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
#ensures only authorized users with valid access tokens FOR THE SPECIFIC USER
def update_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({'message': 'Unauthorized user update'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    data = request.get_json()
    for field, value in data.items():
        if field in ('username', 'email'):
            setattr(user, field, value)
    db.session.commit()
    return jsonify({'message': 'User updated successfully.'}), 200

@bp.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({'message': 'Unauthorized user deletion'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200


@bp.route('/folders', methods=['POST'])
@jwt_required()  # This decorator requires a valid access token in the request
def create_folder():
    # get_jwt_identity() retrieves the identity (user ID) from the access token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)
    data = request.get_json()
    name = data.get('name')
    folder = Folder(name=name, user_id=user.id)
    db.session.add(folder)
    db.session.commit()
    return jsonify(folder.to_dict()), 201

@bp.route('/folders/<int:folder_id>', methods=['DELETE'])
@jwt_required()  # This decorator requires a valid access token in the request
def delete_folder(folder_id):
    # get_jwt_identity() retrieves the identity (user ID) from the access token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)

    # Get the folder
    folder = Folder.query.filter_by(id=folder_id, user_id=user.id).first()
    if not folder:
        return make_response(jsonify({'error': 'Folder not found'}), 404)

    # Delete the folder
    db.session.delete(folder)
    db.session.commit()

    # Return a success message
    return jsonify({'message': 'Folder deleted successfully'}), 200


@bp.route('/folders/<int:folder_id>', methods=['PUT'])
@jwt_required()  # This decorator requires a valid access token in the request
def update_folder(folder_id):
    # get_jwt_identity() retrieves the identity (user ID) from the access token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)
    folder = Folder.query.filter_by(id=folder_id, user_id=user.id).first()
    if not folder:
        return make_response(jsonify({'error': 'Folder not found'}), 404)
    data = request.get_json()
    name = data.get('name')
    folder.name = name
    db.session.commit()
    return jsonify(folder.to_dict()), 200

@bp.route('/folders/<int:folder_id>', methods=['GET'])
@jwt_required()  # This decorator requires a valid access token in the request
def get_folder(folder_id):
    # get_jwt_identity() retrieves the identity (user ID) from the access token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)
    folder = Folder.query.filter_by(id=folder_id, user_id=user.id).first_or_404()
    return jsonify(folder.to_dict())

@bp.route('/bookmarks', methods=['POST'])
@jwt_required()  # This decorator requires a valid access token in the request
def create_bookmark():
    # get_jwt_identity() retrieves the identity (user ID) from the access token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)

    # Get the bookmark data from the request
    data = request.get_json()
    url = data['url']
    folder_id = data['folder_id']

    # Create a new bookmark
    bookmark = Bookmark(url=url, user_id=user.id, folder_id=folder_id)
    db.session.add(bookmark)
    db.session.commit()

    # Return the new bookmark's data
    return jsonify(bookmark.to_dict()), 201

@bp.route('/bookmarks/<int:bookmark_id>', methods=['GET'])
@jwt_required()  # This decorator requires a valid access token in the request
def get_bookmark(bookmark_id):
    # get_jwt_identity() retrieves the identity (user ID) from the access token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)

    # Get the bookmark
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return make_response(jsonify({'error': 'Bookmark not found'}), 404)

    # Return the bookmark's data
    return jsonify(bookmark.to_dict())

@bp.route('/bookmarks/<int:bookmark_id>', methods=['PUT'])
@jwt_required()  # This decorator requires a valid access token in the request
def update_bookmark(bookmark_id):
    # get_jwt_identity() retrieves the identity (user ID) from the access token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)

    # Get the bookmark
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return make_response(jsonify({'error': 'Bookmark not found'}), 404)

    # Get the new data from the request
    data = request.get_json()
    url = data['url']
    folder_id = data['folder_id']

    # Update the bookmark
    bookmark.url = url
    bookmark.folder_id = folder_id
    db.session.commit()

    # Return the updated bookmark's data
    return jsonify(bookmark.to_dict())

@bp.route('/bookmarks/<int:bookmark_id>', methods=['DELETE'])
@jwt_required()  # This decorator requires a valid access token in the request
def delete_bookmark(bookmark_id):
    # get_jwt_identity() retrieves the identity (user ID) from the access token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return make_response(jsonify({'error': 'Unauthorized'}), 401)

    # Get the bookmark
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return make_response(jsonify({'error': 'Bookmark not found'}), 404)

    # Delete the bookmark
    db.session.delete(bookmark)
    db.session.commit()

    # Return a success message
    return jsonify({'message': 'Bookmark deleted successfully'}), 200
