import os
import sys

print("Python version:", sys.version)
print("Current working dir:", os.getcwd())
print("Flask should start now...")
from flask import Flask, request, jsonify
from flask_cors import CORS
from webscanner import run_all_scans

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests (for React)

@app.route('/')
def home():
    return "✅ WebSafe Sentinel API is running!"

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL cannot be empty."}), 400

    if not url.startswith(('http://', 'https://')):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    if url.endswith('/'):
        url = url[:-1]  # Remove trailing slash

    result = run_all_scans(url)
    return jsonify(result)

if __name__ == '__main__':
    print("🚀 Starting Flask API...")
    app.run(debug=True, port=5000)
