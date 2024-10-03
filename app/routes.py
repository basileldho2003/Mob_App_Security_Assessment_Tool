from flask import Blueprint, render_template, request, jsonify

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('dashboard.html')

@main.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Save the file to a temporary directory
    file.save(f"/tmp/{file.filename}")

    # Simulate scanning and returning results
    result = {'status': 'success', 'message': f'Successfully scanned {file.filename}'}

    return jsonify(result)
