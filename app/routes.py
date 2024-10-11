from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
from .analysis.decompiler import Decompiler
from .analysis.manifest_scanner import ManifestScanner
from .analysis.source_code_analyzer import SourceCodeAnalyzer
from .analysis.yara_scanner import YaraScanner
from .reports.html_report import HTMLReportGenerator
from .reports.pdf_report import PDFReportGenerator
from .utils.file_handler import FileHandler
from .utils.logger import logger

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

UPLOAD_FOLDER = 'uploads/'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

file_handler = FileHandler(upload_folder=UPLOAD_FOLDER)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_apk():
    if request.method == 'POST':
        if 'apk_file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['apk_file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and file_handler.allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Run analysis
            output_dir = os.path.join(app.config['UPLOAD_FOLDER'], filename.split('.')[0])
            decompiler = Decompiler(apk_path=file_path, output_dir=output_dir)
            decompiler.decompile()

            manifest_path = os.path.join(output_dir, 'AndroidManifest.xml')
            manifest_scanner = ManifestScanner(manifest_path)
            manifest_scanner.scan()

            source_code_analyzer = SourceCodeAnalyzer(source_code_dir=output_dir)
            source_code_analyzer.analyze_files()

            yara_scanner = YaraScanner(rules_path='path/to/yara/rules.yar', target_dir=output_dir)
            yara_scanner.scan_files()

            flash('File uploaded and analysis completed successfully')
            return redirect(url_for('results', filename=filename))
    return render_template('upload.html')

@app.route('/results/<filename>')
def results(filename):
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], filename.split('.')[0])
    # Example context for results page
    context = {
        "summary": "This report contains the findings of the APK security assessment.",
        "findings": [
            {"type": "Dangerous Permission", "detail": "android.permission.READ_SMS"},
            {"type": "Exported Activity", "detail": "com.example.MainActivity"}
        ]
    }
    return render_template('results.html', **context, scan_id=filename)

@app.route('/download/<report_type>/<scan_id>')
def download_report(report_type, scan_id):
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], scan_id.split('.')[0])
    context = {
        "title": "Security Assessment Report",
        "summary": "This report contains the findings of the APK security assessment.",
        "findings": [
            {"type": "Dangerous Permission", "detail": "android.permission.READ_SMS"},
            {"type": "Exported Activity", "detail": "com.example.MainActivity"}
        ]
    }
    if report_type == 'pdf':
        pdf_generator = PDFReportGenerator(output_dir=output_dir)
        pdf_generator.generate_report(context)
        return redirect(url_for('static', filename=f'uploads/{scan_id.split(".")[0]}/report.pdf'))
    elif report_type == 'html':
        html_generator = HTMLReportGenerator(template_dir='templates', output_dir=output_dir)
        html_generator.generate_report(template_name='report_template.html', context=context)
        return redirect(url_for('static', filename=f'uploads/{scan_id.split(".")[0]}/report.html'))
    else:
        flash('Invalid report type')
        return redirect(url_for('results', filename=scan_id))

if __name__ == '__main__':
    app.run(debug=True)