```python
"""
app.py — LogSentinel Flask Backend
"""

import os
import json
from datetime import datetime

from flask import Flask, request, jsonify, Response

from log_parser import LogParser
from log_analyzer import LogAnalyzer
from chart_generator import ChartGenerator
from report_generator import generate_report

# ─────────────────────────────────────────────────────────────
# Flask App Setup
# ─────────────────────────────────────────────────────────────

app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {'log', 'txt', 'out', 'access', 'syslog'}


# ─────────────────────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────────────────────

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


@app.route('/', methods=['OPTIONS'])
@app.route('/analyze', methods=['OPTIONS'])
@app.route('/analyze/no-charts', methods=['OPTIONS'])
@app.route('/report', methods=['OPTIONS'])
def handle_options():
    return Response(status=200)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    if '.' not in filename:
        return True

    ext = filename.rsplit('.', 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS


def safe_serialize(obj):
    import numpy as np
    import math

    if isinstance(obj, (np.integer,)):
        return int(obj)

    if isinstance(obj, (np.floating,)):
        value = float(obj)

        if math.isnan(value):
            return None

        return value

    if isinstance(obj, (np.bool_,)):
        return bool(obj)

    if isinstance(obj, float) and math.isnan(obj):
        return None

    raise TypeError(f'Not serializable: {type(obj)}')


# ─────────────────────────────────────────────────────────────
# Home Route (Google Verification Enabled)
# ─────────────────────────────────────────────────────────────

@app.route('/', methods=['GET'])
def index():
    return """
    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <meta name="google-site-verification"
              content="-tlyVf8lKGkJk_LYOHOYgmVvw3o-1xxPsiHvarWOHbA" />

        <title>Abhay Poonia - LogSentinel</title>

        <style>
            body{
                background:#0f172a;
                color:white;
                font-family:Arial;
                display:flex;
                justify-content:center;
                align-items:center;
                height:100vh;
                flex-direction:column;
                text-align:center;
            }

            h1{
                color:#00d4ff;
            }

            p{
                color:#94a3b8;
            }
        </style>
    </head>

    <body>
        <h1>🚀 LogSentinel Backend Running</h1>

        <p>Cybersecurity Project by Abhay Poonia</p>

        <p>Flask API Successfully Running on Vercel</p>
    </body>

    </html>
    """


# ─────────────────────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'LogSentinel',
        'ts': datetime.utcnow().isoformat()
    })


# ─────────────────────────────────────────────────────────────
# Analyze Endpoint
# ─────────────────────────────────────────────────────────────

@app.route('/analyze', methods=['POST'])
def analyze():

    if 'file' not in request.files:
        return jsonify({
            'error': 'No file uploaded.'
        }), 400

    f = request.files['file']

    if f.filename == '':
        return jsonify({
            'error': 'No file selected.'
        }), 400

    if not allowed_file(f.filename):
        return jsonify({
            'error': 'Invalid file type.'
        }), 400

    try:
        content = f.read().decode('utf-8', errors='replace')

    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 400

    if not content.strip():
        return jsonify({
            'error': 'Empty file.'
        }), 400

    try:
        parser = LogParser()

        df = parser.parse(content)

        analyzer = LogAnalyzer(df)

        analysis = analyzer.analyze()

        chart_gen = ChartGenerator(analysis)

        charts = chart_gen.generate_all()

        report_text = generate_report(
            analysis,
            filename=f.filename,
            fmt=parser.format_detected
        )

    except Exception as e:
        import traceback

        return jsonify({
            'error': str(e),
            'trace': traceback.format_exc()
        }), 500

    response_data = {
        'meta': {
            'filename': f.filename,
            'format': parser.format_detected,
            'total_lines': parser.total_lines,
            'parsed_lines': parser.parsed_lines,
            'analyzed_at': datetime.utcnow().isoformat(),
        },

        'analysis': analysis,

        'charts': charts,

        'report': report_text
    }

    return Response(
        json.dumps(response_data, default=safe_serialize),
        mimetype='application/json'
    )


# ─────────────────────────────────────────────────────────────
# Report Endpoint
# ─────────────────────────────────────────────────────────────

@app.route('/report', methods=['POST'])
def report_only():

    if 'file' not in request.files:
        return jsonify({
            'error': 'No file uploaded.'
        }), 400

    f = request.files['file']

    try:
        content = f.read().decode('utf-8', errors='replace')

        parser = LogParser()

        df = parser.parse(content)

        analysis = LogAnalyzer(df).analyze()

        report = generate_report(
            analysis,
            filename=f.filename,
            fmt=parser.format_detected
        )

    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

    return Response(
        report,
        mimetype='text/plain',
        headers={
            'Content-Disposition':
            'attachment; filename="logsentinel_report.txt"'
        }
    )


# ─────────────────────────────────────────────────────────────
# Run App
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':

    port = int(os.environ.get('PORT', 5000))

    debug = os.environ.get(
        'FLASK_ENV',
        'production'
    ) == 'development'

    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )
```
