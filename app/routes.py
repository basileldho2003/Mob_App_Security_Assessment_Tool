from flask import render_template, redirect, url_for, flash, session
from app.database import db
from app.database.models import AndroguardAnalysis, ManifestIssue, ScanPayloadMatch, User, Upload, Scan, SourceCodeIssue  # Import necessary models
from app.decompilation.andro import analyze_apk_with_androguard
from app.forms import LoginForm, SignupForm, UploadForm  # Import necessary forms
from werkzeug.security import check_password_hash, generate_password_hash
from flask import current_app as app
from datetime import *
from app.decompilation.decompile import decompile_apk
from app.decompilation.manifest_scanner import analyze_manifest
from app.decompilation.source_code_analyzer import analyze_source_code
from app.security.payload_scanner import load_yara_rules, scan_with_yara
import os, pytz

def get_ist_time():
    utc_time = datetime.now(timezone.utc)
    ist_time = utc_time.replace(tzinfo=pytz.utc).astimezone(pytz.timezone('Asia/Kolkata'))
    return ist_time

# Route for the home page
@app.route('/')
@app.route('/home')
def home():
    """
    Render the home page of the application.
    """
    return render_template('home.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Log in a user by verifying username and password.
    If successful, store user info in session and redirect to dashboard.
    """
    form = LoginForm()
    if form.validate_on_submit():
        # Fetch user by username
        user = User.query.filter_by(username=form.username.data).first()
        # Check password and authenticate user
        if user and check_password_hash(user.password_hash, form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
    return render_template('login.html', form=form)

# Route for user signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Register a new user by collecting username, email, and password.
    Checks for existing username or email before creating the account.
    """
    form = SignupForm()
    if form.validate_on_submit():
        # Check for existing username or email
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            flash('Username or email already exists. Please choose another one.', 'danger')
        else:
            # Hash password and create new user record
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_password,
                role='user'
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html', form=form)

# Route for the dashboard (after login)
@app.route('/dashboard')
def dashboard():
    """
    Display the dashboard with user-specific or admin-specific uploads.
    Redirects to login if the user is not authenticated.
    """
    if 'user_id' not in session:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))

    # Display all uploads for admin or specific uploads for a normal user
    if session.get('role') == 'admin':
        all_uploads = Upload.query.all()
        return render_template('dashboard.html', all_uploads=all_uploads)
    else:
        uploads = Upload.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', uploads=uploads)

# Route for uploading APK files
@app.route('/upload_and', methods=['GET', 'POST'])
def upload_and():
    form = UploadForm()
    if 'user_id' not in session:
        flash("Please log in to upload files.", "warning")
        return redirect(url_for('login'))

    if form.validate_on_submit():
        file = form.apk_file.data
        filename = file.filename
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        new_upload = Upload(
            user_id=session['user_id'],
            apk_file_name=filename
        )
        db.session.add(new_upload)
        db.session.commit()

        new_scan = Scan(
            upload_id=new_upload.id,
            status='queued'
        )
        db.session.add(new_scan)
        db.session.commit()

        try:
            new_scan.status = 'in_progress'
            db.session.commit()

            # Call Androguard script for analysis and save results
            issues = analyze_apk_with_androguard(upload_path, new_scan.id)

            # Save issues to AndroguardAnalysis table
            for issue in issues:
                new_issue = AndroguardAnalysis(
                    scan_id=new_scan.id,
                    issue_type=issue['type'],
                    issue_detail=issue['detail'],
                    severity=issue['severity']
                )
                db.session.add(new_issue)
            db.session.commit()

            # Mark scan as completed
            new_scan.status = 'completed'
            new_scan.scan_date = get_ist_time()
            db.session.commit()

            flash("File uploaded and analyzed successfully!", "success")
        except Exception as e:
            new_scan.status = 'failed'
            db.session.commit()
            print(f"Error during APK analysis: {e}")
            flash("An error occurred during the scan. Please try again.", "danger")

        return redirect(url_for('dashboard'))

    return render_template('upload_and.html', form=form)


@app.route('/upload_jadx', methods=['GET', 'POST'])
def upload_jadx():
    """
    Handle APK file upload, create an upload record, initiate scan, and redirect to dashboard.
    """
    form = UploadForm()
    if 'user_id' not in session:
        flash("Please log in to upload files.", "warning")
        return redirect(url_for('login'))

    if form.validate_on_submit():
        # Save uploaded file
        file = form.apk_file.data
        filename = file.filename
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        # Create an upload record in the database
        new_upload = Upload(
            user_id=session['user_id'],
            apk_file_name=filename
        )
        db.session.add(new_upload)
        db.session.commit()
        # File uploaded
        # Create scan record and set initial status
        new_scan = Scan(
            upload_id=new_upload.id,
            status='queued'
        )
        db.session.add(new_scan)
        db.session.commit()

        # Process the uploaded APK file synchronously
        process_apk(new_scan.id)

        flash("File uploaded and analyzed successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('upload_jadx.html', form=form)

def process_apk(scan_id):
    """
    Process the APK file for security analysis.
    - Decompile APK with apktool and JADX
    - Analyze AndroidManifest.xml
    - Analyze Java source code
    - Apply YARA rules for payload scanning
    - Generate consolidated results
    """
    scan = Scan.query.get(scan_id)
    if not scan:
        return

    try:
        # Update scan status to in_progress
        scan.status = 'in_progress'
        db.session.commit()

        # Get upload path for decompilation
        upload = scan.upload
        apk_file_path = os.path.join(app.config['UPLOAD_FOLDER'], upload.apk_file_name)

        # Define output directory for decompiled files
        output_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"decompiled_{upload.id}")
        os.makedirs(output_dir, exist_ok=True)

        # Step 1: Decompile the APK file using both apktool and JADX
        apktool_output_dir, jadx_output_dir = decompile_apk(apk_file_path, output_dir)

        # Ensure decompilation was successful
        if not apktool_output_dir or not jadx_output_dir:
            scan.status = 'failed'
            db.session.commit()
            print("Decompilation failed. Exiting APK processing.")
            return

        # Step 2: Scan the AndroidManifest.xml file for issues
        manifest_path = os.path.join(apktool_output_dir, 'AndroidManifest.xml')
        manifest_issues = analyze_manifest(manifest_path)
        for issue in manifest_issues:
            manifest_issue = ManifestIssue(
                scan_id=scan.id,
                issue_type=issue['issue_type'],
                issue_detail=issue['issue_detail'],
                severity=issue['severity']
            )
            db.session.add(manifest_issue)

        # Step 3: Analyze Java source code for security vulnerabilities
        source_code_issues = analyze_source_code(jadx_output_dir)
        for issue in source_code_issues:
            source_code_issue = SourceCodeIssue(
                scan_id=scan.id,
                file_path=issue['file_path'],
                line_number=issue['line_number'],
                issue_type=issue['issue_type'],
                issue_detail=issue['description'],
                severity=issue['severity'],
                issue_category=issue.get('category', 'general'),
                recommendation=issue.get('recommendation', '')
            )
            db.session.add(source_code_issue)

        # Step 4: Apply YARA rules to detect specific payloads
        rules_dir = app.config['YARA_RULES_FOLDER']
        yara_rules, payload_map = load_yara_rules(rules_dir)  # Load both rules and payload_map
        payload_matches = scan_with_yara(jadx_output_dir, yara_rules, payload_map)  # Pass payload_map here
        for match in payload_matches:
            payload_match = ScanPayloadMatch(
                scan_id=scan.id,
                payload_id=match['payload_id'],
                file_path=match['file_path'],
                line_number=match.get('line_number', -1),  # Provide a default value if line_number is None
                match_detail=match['match_detail'],
                severity=match['severity']
            )
            db.session.add(payload_match)


        # Mark scan as completed and save scan date
        scan.status = 'completed'
        scan.scan_date = get_ist_time()
        db.session.commit()
    except Exception as e:
        # Mark scan as failed if any error occurs
        scan.status = 'failed'
        db.session.commit()
        print(f"Error processing APK: {e}")

# Route for viewing scan results
@app.route('/view_scan/<int:scan_id>')
def view_scan(scan_id):
    """
    Render the scan results page for a specific scan ID, displaying manifest issues, source code issues, and payload matches.
    """
    scan = Scan.query.get_or_404(scan_id)
    manifest_issues = ManifestIssue.query.filter_by(scan_id=scan.id).all()
    source_code_issues = SourceCodeIssue.query.filter_by(scan_id=scan.id).all()
    payload_matches = ScanPayloadMatch.query.filter_by(scan_id=scan.id).all()
    
    return render_template('scan_results.html', scan_id=scan.id, 
                           manifest_issues=manifest_issues, 
                           source_code_issues=source_code_issues, 
                           payload_matches=payload_matches)

@app.route('/view_androguard_scan/<int:scan_id>')
def view_androguard_scan(scan_id):
    """
    Render the Androguard scan results page for a specific scan ID, displaying Androguard analysis issues.
    """
    scan = Scan.query.get_or_404(scan_id)
    androguard_issues = AndroguardAnalysis.query.filter_by(scan_id=scan.id).all()
    
    return render_template('scan_results_and.html', scan_id=scan.id, scan=scan, androguard_issues=androguard_issues)

# Route for logout
@app.route('/logout')
def logout():
    """
    Log out the current user by clearing the session and redirecting to the home page.
    """
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    """
    Render a custom 404 error page.
    """
    return render_template('error.html', error="404 Not Found"), 404

@app.errorhandler(500)
def internal_error(error):
    """
    Render a custom 500 error page for internal server errors.
    """
    return render_template('error.html', error="500 Internal Server Error"), 500
