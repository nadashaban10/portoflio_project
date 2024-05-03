from os import abort
from flask_login import current_user
from app.api import bp
from flask import jsonify
from app import db
from app.models import User, Folder, Bookmark
from flask import request


@bp.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    user = User(username=data['username'], email=data['email'])
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201

@bp.route('/users/<int:id>', methods=['GET'])
def get_user(id):
    user = User.query.get_or_404(id)
    return jsonify(user.to_dict())

@bp.route('/users/<int:id>', methods=['PUT'])
def update_user(id):
    user = User.query.get_or_404(id)
    data = request.get_json()
    user.username = data['username']
    user.email = data['email']
    db.session.commit()
    return jsonify(user.to_dict())

@bp.route('/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return '', 204

@bp.route('/folders', methods=['POST'])
def create_folder():
    data = request.get_json()
    folder = Folder(name=data['name'])
    db.session.add(folder)
    db.session.commit()
    return jsonify(folder.to_dict()), 201

@bp.route('/folders/<int:id>', methods=['GET'])
def get_folder(id):
    folder = Folder.query.get_or_404(id)
    return jsonify(folder.to_dict())

@bp.route('/folders/<int:id>', methods=['PUT'])
def update_folder(id):
    folder = Folder.query.get_or_404(id)
    data = request.get_json()
    folder.name = data['name']
    db.session.commit()
    return jsonify(folder.to_dict())

@bp.route('/folders/<int:id>', methods=['DELETE'])
def delete_folder(id):
    folder = Folder.query.get_or_404(id)
    db.session.delete(folder)
    db.session.commit()
    return '', 204

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
