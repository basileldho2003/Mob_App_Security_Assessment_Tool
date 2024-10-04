from flask import render_template, request, redirect, url_for
from app import db
from app.models import ScanResult
from app.utils.apk_analysis import analyze_apk
from app.utils.report_generator import generate_pdf_report
import os

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_apk():
    if request.method == 'POST':
        if 'apk_file' not in request.files:
            return redirect(request.url)
        
        apk_file = request.files['apk_file']
        if apk_file.filename == '':
            return redirect(request.url)
        
        apk_path = os.path.join('uploads', apk_file.filename)
        apk_file.save(apk_path)

        scan_result = analyze_apk(apk_path)
        save_scan_result_to_db(scan_result)

        return redirect(url_for('report', apk_name=apk_file.filename))

    return render_template('upload.html')

@app.route('/report/<apk_name>')
def report(apk_name):
    scan_result = ScanResult.query.filter_by(apk_name=apk_name).first_or_404()
    return render_template('report.html', result=scan_result)

def save_scan_result_to_db(scan_result):
    result = ScanResult(apk_name=scan_result['apk_name'],
                        issues_found=scan_result['issues'],
                        scan_date=scan_result['date'])
    db.session.add(result)
    db.session.commit()
