from flask import Blueprint, render_template, url_for, flash, redirect, request, current_app
from flask_login import login_user, current_user, logout_user, login_required
from app import db, bcrypt
from app.models import User, Upload, Scan
from app.forms import RegistrationForm, LoginForm
from app.utils import save_file, log_message, allowed_file

# Blueprints
auth = Blueprint('auth', __name__)
scanner = Blueprint('scanner', __name__)
report = Blueprint('report', __name__)

# Authentication Routes
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('scanner.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('auth.login'))
    return render_template('signup.html', title='Register', form=form)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('scanner.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('scanner.dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

# Scanner Routes
@scanner.route('/dashboard')
@login_required
def dashboard():
    user_uploads = Upload.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', title='Dashboard', uploads=user_uploads)

@scanner.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = save_file(current_app.config['UPLOAD_FOLDER'], file)
            new_upload = Upload(user_id=current_user.id, apk_file_name=filename)
            db.session.add(new_upload)
            db.session.commit()
            flash('File uploaded successfully', 'success')
            return redirect(url_for('scanner.dashboard'))
        else:
            flash('Only APK files are allowed', 'danger')
    return render_template('upload.html', title='Upload')

# Report Routes
@report.route('/report/<int:scan_id>')
@login_required
def view_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.upload.user_id != current_user.id:
        flash('You do not have permission to view this report', 'danger')
        return redirect(url_for('scanner.dashboard'))
    return render_template('report.html', title='Report', scan=scan)
