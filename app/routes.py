from urllib.parse import urlsplit
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
import sqlalchemy as sa
from app import app, db
from app.forms import LoginForm, RegistrationForm
from app.models import User, Bookmark, Folder
from datetime import datetime


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home', user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/profile')
@login_required
def profile():
    user = current_user
    return render_template('profile.html', title='Profile', user=user)

@app.route('/add_bookmark', methods=['POST'])
@login_required
def add_bookmark():
    url = request.form.get('url')
    folder_name = request.form.get('folder_name')

    # If no folder name is provided, use "Other"
    if not folder_name:
        folder_name = "Other"

    # Check if a folder with the given name already exists for the user
    folder = Folder.query.filter_by(name=folder_name, user_id=current_user.id).first()

    # If not, create a new folder
    if folder is None:
        folder = Folder(name=folder_name, user_id=current_user.id, created_at=datetime.utcnow())
        db.session.add(folder)
        db.session.commit()

    # Create new bookmark
    bookmark = Bookmark(url=url, user_id=current_user.id, folder_id=folder.id, created_at=datetime.utcnow())

    # Add and commit the new bookmark to the database
    db.session.add(bookmark)
    db.session.commit()

    # Redirect to the new folder page
    return redirect(url_for('folder', folder_id=folder.id))
@app.route('/folder/<int:folder_id>')
def folder(folder_id):
    folder = Folder.query.get(folder_id)
    return render_template('folder.html', folder=folder)