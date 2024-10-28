from flask import render_template, redirect, url_for, flash, request, session
from app import db
from app.models import User, Upload, Scan  # Import necessary models
from app.forms import LoginForm, SignupForm, UploadForm  # Import necessary forms
from werkzeug.security import check_password_hash, generate_password_hash
from flask import current_app as app
import os

# Route for the home page
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
    return render_template('login.html', form=form)

# Route for user signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Your account has been created! You can now log in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

# Route for the dashboard (after login)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# Route for uploading APK files
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form = UploadForm()
    if 'user_id' not in session:
        flash("Please log in to upload files.", "warning")
        return redirect(url_for('login'))

    if form.validate_on_submit():
        # Handle file upload
        file = form.apk_file.data
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Create a new upload record in the database
        new_upload = Upload(
            user_id=session['user_id'],
            apk_file_name=filename
        )
        db.session.add(new_upload)
        db.session.commit()
        
        flash("File uploaded successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('upload.html', form=form)

# Route for logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="404 Not Found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="500 Internal Server Error"), 500
