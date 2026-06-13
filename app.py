"""
app.py — LogSentinel Flask Backend
Handles file upload, runs the full analysis pipeline, returns JSON.
Deploy-ready for Render / Railway.
"""

import os
import io
import json
from datetime import datetime

from flask import Flask, request, jsonify, Response

from modules.log_parser       import LogParser
from modules.log_analyzer     import LogAnalyzer
from modules.chart_generator  import ChartGenerator
from modules.report_generator import generate_report

# ─── App Setup ───────────────────────────────────────────────────────────────

app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    """Add CORS headers to every response — allows any frontend to call this API."""
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


@app.route('/', methods=['OPTIONS'])
@app.route('/analyze', methods=['OPTIONS'])
@app.route('/analyze/no-charts', methods=['OPTIONS'])
@app.route('/report', methods=['OPTIONS'])
def handle_options():
    """Handle pre-flight CORS requests."""
    return Response(status=200)

app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024   # 50 MB upload limit

ALLOWED_EXTENSIONS = {'log', 'txt', 'out', 'access', 'syslog'}


def allowed_file(filename: str) -> bool:
    if '.' not in filename:
        return True   # allow files without extension (e.g. "access")
    ext = filename.rsplit('.', 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS


# ─── Health Check ─────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'LogSentinel', 'ts': datetime.utcnow().isoformat()})


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'service' : 'LogSentinel API',
        'version' : '1.0.0',
        'endpoints': {
            'POST /analyze'          : 'Upload a log file — returns full analysis + charts',
            'POST /analyze/no-charts': 'Upload a log file — returns analysis only (faster)',
            'POST /report'           : 'Upload a log file — returns plain-text report',
            'GET  /health'           : 'Health check',
        }
    })


# ─── Main Analysis Endpoint ───────────────────────────────────────────────────

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    POST /analyze
    Form field: file  (multipart/form-data)
    Returns: JSON with stats, threats, charts (base64 PNGs), risk score
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request. Use form-data with key "file".'}), 400

    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    if not allowed_file(f.filename):
        return jsonify({'error': f'File type not allowed. Accepted: {ALLOWED_EXTENSIONS}'}), 400

    try:
        content = f.read().decode('utf-8', errors='replace')
    except Exception as e:
        return jsonify({'error': f'Could not read file: {str(e)}'}), 400

    if not content.strip():
        return jsonify({'error': 'Uploaded file is empty.'}), 400

    # ── Pipeline ──────────────────────────────────────────────────────────
    try:
        # Stage 1 + 2 + 3 + 4: Parse
        parser = LogParser()
        df = parser.parse(content)

        # Stage 5: Analyze + Threat Detection
        analyzer = LogAnalyzer(df)
        analysis = analyzer.analyze()

        # Stage 6a: Charts
        chart_gen = ChartGenerator(analysis)
        charts = chart_gen.generate_all()

        # Stage 6b: Report text
        report_text = generate_report(analysis, filename=f.filename, fmt=parser.format_detected)

    except Exception as e:
        import traceback
        return jsonify({'error': f'Analysis failed: {str(e)}', 'trace': traceback.format_exc()}), 500

    # ── Serialize safely ──────────────────────────────────────────────────
    def safe_serialize(obj):
        """Convert non-JSON-serializable types."""
        import numpy as np
        import math
        if isinstance(obj, (np.integer,)):           return int(obj)
        if isinstance(obj, (np.floating,)):          return float(obj)
        if isinstance(obj, (np.bool_,)):             return bool(obj)
        if isinstance(obj, float) and math.isnan(obj): return None
        raise TypeError(f'Not serializable: {type(obj)}')

    response_data = {
        'meta': {
            'filename'      : f.filename,
            'format'        : parser.format_detected,
            'total_lines'   : parser.total_lines,
            'parsed_lines'  : parser.parsed_lines,
            'analyzed_at'   : datetime.utcnow().isoformat(),
        },
        'analysis': analysis,
        'charts'  : charts,    # base64 PNG strings
        'report'  : report_text,
    }

    return Response(
        json.dumps(response_data, default=safe_serialize),
        mimetype='application/json'
    )


# ─── No-Charts Variant (faster) ───────────────────────────────────────────────

@app.route('/analyze/no-charts', methods=['POST'])
def analyze_no_charts():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part.'}), 400

    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    try:
        content = f.read().decode('utf-8', errors='replace')
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    try:
        parser   = LogParser()
        df       = parser.parse(content)
        analyzer = LogAnalyzer(df)
        analysis = analyzer.analyze()
        report   = generate_report(analysis, filename=f.filename, fmt=parser.format_detected)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    def safe_serialize(obj):
        import numpy as np
        import math
        if isinstance(obj, (np.integer,)): return int(obj)
        if isinstance(obj, (np.floating,)): return float(obj)
        if isinstance(obj, (np.bool_,)): return bool(obj)
        if isinstance(obj, float) and math.isnan(obj): return None
        raise TypeError(f'Not serializable: {type(obj)}')

    return Response(
        json.dumps({
            'meta'    : {'filename': f.filename, 'format': parser.format_detected,
                         'total_lines': parser.total_lines, 'parsed_lines': parser.parsed_lines},
            'analysis': analysis,
            'report'  : report,
        }, default=safe_serialize),
        mimetype='application/json'
    )


# ─── Report-only Endpoint ─────────────────────────────────────────────────────

@app.route('/report', methods=['POST'])
def report_only():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part.'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No file selected.'}), 400
    try:
        content = f.read().decode('utf-8', errors='replace')
        parser  = LogParser()
        df      = parser.parse(content)
        analysis= LogAnalyzer(df).analyze()
        report  = generate_report(analysis, filename=f.filename, fmt=parser.format_detected)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return Response(
        report,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="logsentinel_report.txt"'}
    )


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'production') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
