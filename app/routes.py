from flask import Blueprint, render_template, request, jsonify
from app.utils.apk_scanner import scan_apk

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('dashboard.html')

@main.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file uploaded", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    file.save(f"/tmp/{file.filename}")
    result = scan_apk(f"/tmp/{file.filename}")
    return jsonify(result)
