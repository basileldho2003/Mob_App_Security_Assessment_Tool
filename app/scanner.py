from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
from app.utils.apk_analysis import analyze_apk
from app.utils.report_generator import generate_pdf_report
from app import create_app, db
from app.models import ScanResult
from datetime import datetime

app = create_app()

# Define the folder to store uploaded APK files
UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'apk'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Utility function to check if the file is an APK
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the file part is available
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']

        # If no file is selected
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        # Check if the file is allowed (APK format)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Perform the APK analysis
            scan_result = analyze_apk(file_path)

            # Save result to database
            save_scan_result_to_db(scan_result)

            # Generate report
            report_path = f'reports/{filename.replace(".apk", "")}_report.pdf'
            generate_pdf_report(scan_result, report_path)

            return redirect(url_for('report', apk_name=filename))

    return render_template('upload.html')

@app.route('/report/<apk_name>')
def report(apk_name):
    # Query the database for the scan result
    scan_result = ScanResult.query.filter_by(apk_name=apk_name).first_or_404()
    return render_template('report.html', result=scan_result)

def save_scan_result_to_db(scan_result):
    result = ScanResult(
        apk_name=scan_result['apk_name'],
        issues_found='\n'.join(scan_result['issues']),
        scan_date=datetime.now()
    )
    db.session.add(result)
    db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
