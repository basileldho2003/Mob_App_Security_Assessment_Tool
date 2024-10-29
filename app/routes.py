from flask import render_template, redirect, url_for, flash, session
from app.database import db
from app.database.models import User, Upload, Scan, SourceCodeIssue  # Import necessary models
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

    if session.get('role') == 'admin':
        # Fetch all uploads for admin view
        all_uploads = Upload.query.all()
        return render_template('dashboard.html', all_uploads=all_uploads)
    else:
        # Fetch uploads for the logged-in user
        uploads = Upload.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', uploads=uploads)

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

        # Create a new scan record in the database and set the initial status to "queued"
        new_scan = Scan(
            upload_id=new_upload.id,
            status='queued'
        )
        db.session.add(new_scan)
        db.session.commit()

        # Initiate the scanning process here (if applicable)
        # e.g., trigger a background task to analyze the APK file

        flash("File uploaded and scan initiated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('upload.html', form=form)

# Route for viewing the results of a specific scan
@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    if 'user_id' not in session:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))

    scan = Scan.query.get_or_404(scan_id)
    source_code_issues = SourceCodeIssue.query.filter_by(scan_id=scan_id).all()

    return render_template('scan_results.html', scan=scan, source_code_issues=source_code_issues)

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
