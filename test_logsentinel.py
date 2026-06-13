"""
tests/test_logsentinel.py
Run with: pytest tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import json
import io
from app import app

# ─── Sample Log Data ──────────────────────────────────────────────────────────

SYSLOG_SAMPLE = """\
2024-01-15 03:12:01 ERROR 192.168.1.10 Failed password for root from 192.168.1.10
2024-01-15 03:12:02 ERROR 192.168.1.10 Failed password for root from 192.168.1.10
2024-01-15 03:12:03 ERROR 192.168.1.10 Failed password for root from 192.168.1.10
2024-01-15 03:12:04 ERROR 192.168.1.10 Failed password for root from 192.168.1.10
2024-01-15 03:12:05 ERROR 192.168.1.10 Failed password for root from 192.168.1.10
2024-01-15 03:12:06 ERROR 192.168.1.10 Failed password for root from 192.168.1.10
2024-01-15 08:00:00 INFO  10.0.0.1 System startup complete
2024-01-15 09:15:00 WARNING 10.0.0.2 Disk usage at 85%
2024-01-15 10:30:00 CRITICAL 10.0.0.3 Out of memory: Kill process
2024-01-15 11:00:00 INFO  10.0.0.1 Scheduled task completed
"""

APACHE_SAMPLE = """\
192.168.1.5 - - [15/Jan/2024:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.6 - - [15/Jan/2024:08:00:02 +0000] "GET /../etc/passwd HTTP/1.1" 403 512
192.168.1.7 - - [15/Jan/2024:08:00:03 +0000] "GET /page HTTP/1.1" 404 256
192.168.1.8 - - [15/Jan/2024:08:00:04 +0000] "POST /login HTTP/1.1" 500 128
192.168.1.9 - - [15/Jan/2024:08:00:05 +0000] "GET /admin HTTP/1.1" 200 2048
"""

EMPTY_LOG = "   \n\n   \n"


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


# ─── Health & Index ───────────────────────────────────────────────────────────

def test_health(client):
    r = client.get('/health')
    assert r.status_code == 200
    data = json.loads(r.data)
    assert data['status'] == 'ok'


def test_index(client):
    r = client.get('/')
    assert r.status_code == 200
    data = json.loads(r.data)
    assert 'endpoints' in data


# ─── /analyze Endpoint ────────────────────────────────────────────────────────

def _upload(client, content: str, filename='test.log', endpoint='/analyze'):
    return client.post(
        endpoint,
        data={'file': (io.BytesIO(content.encode()), filename)},
        content_type='multipart/form-data'
    )


def test_analyze_syslog(client):
    r = _upload(client, SYSLOG_SAMPLE)
    assert r.status_code == 200
    data = json.loads(r.data)
    assert 'analysis' in data
    assert 'meta' in data
    assert data['meta']['format'] == 'syslog'


def test_analyze_apache(client):
    r = _upload(client, APACHE_SAMPLE, filename='access.log')
    assert r.status_code == 200
    data = json.loads(r.data)
    assert data['meta']['format'] == 'apache'


def test_brute_force_detected(client):
    r = _upload(client, SYSLOG_SAMPLE)
    data = json.loads(r.data)
    bf = data['analysis']['brute_force']
    assert bf['total_failed_logins'] >= 6
    assert len(bf['flagged_ips']) >= 1
    assert bf['flagged_ips'][0]['ip_address'] == '192.168.1.10'


def test_critical_detected(client):
    r = _upload(client, SYSLOG_SAMPLE)
    data = json.loads(r.data)
    crit = data['analysis']['critical_events']
    assert crit['event_count'] >= 1


def test_intrusion_detected(client):
    r = _upload(client, APACHE_SAMPLE, filename='access.log')
    data = json.loads(r.data)
    intr = data['analysis']['intrusion']
    assert intr['event_count'] >= 1   # /../etc/passwd should be caught


def test_risk_score_range(client):
    r = _upload(client, SYSLOG_SAMPLE)
    data = json.loads(r.data)
    score = data['analysis']['risk_score']
    assert 0 <= score <= 100


def test_charts_returned(client):
    r = _upload(client, SYSLOG_SAMPLE)
    data = json.loads(r.data)
    charts = data.get('charts', {})
    # At least one chart should be non-empty
    non_empty = [k for k, v in charts.items() if v]
    assert len(non_empty) >= 1


def test_report_in_response(client):
    r = _upload(client, SYSLOG_SAMPLE)
    data = json.loads(r.data)
    assert 'report' in data
    assert 'LogSentinel' in data['report']


# ─── Edge Cases ───────────────────────────────────────────────────────────────

def test_no_file(client):
    r = client.post('/analyze', data={}, content_type='multipart/form-data')
    assert r.status_code == 400


def test_empty_file(client):
    r = _upload(client, EMPTY_LOG)
    assert r.status_code == 400


def test_no_charts_endpoint(client):
    r = _upload(client, SYSLOG_SAMPLE, endpoint='/analyze/no-charts')
    assert r.status_code == 200
    data = json.loads(r.data)
    assert 'charts' not in data
    assert 'analysis' in data


def test_report_endpoint_plain_text(client):
    r = _upload(client, SYSLOG_SAMPLE, endpoint='/report')
    assert r.status_code == 200
    assert b'LogSentinel' in r.data
    assert r.content_type.startswith('text/plain')


# ─── Parser Unit Tests ────────────────────────────────────────────────────────

def test_parser_format_detection():
    from modules.log_parser import LogParser
    p = LogParser()
    df = p.parse(APACHE_SAMPLE)
    assert p.format_detected == 'apache'
    assert len(df) > 0


def test_parser_syslog_columns():
    from modules.log_parser import LogParser
    p = LogParser()
    df = p.parse(SYSLOG_SAMPLE)
    for col in ('timestamp', 'level', 'message', 'is_error', 'is_failed_login'):
        assert col in df.columns


# ─── Analyzer Unit Tests ──────────────────────────────────────────────────────

def test_analyzer_stats():
    from modules.log_parser import LogParser
    from modules.log_analyzer import LogAnalyzer
    df = LogParser().parse(SYSLOG_SAMPLE)
    result = LogAnalyzer(df).analyze()
    assert result['stats']['total_lines'] > 0
    assert 'level_dist' in result['stats']


def test_analyzer_risk_score_high_on_brute_force():
    from modules.log_parser import LogParser
    from modules.log_analyzer import LogAnalyzer
    # Lots of failed logins → high risk
    many_fails = '\n'.join(
        f'2024-01-15 03:12:{i:02d} ERROR 1.2.3.4 Failed password for root'
        for i in range(20)
    )
    df = LogParser().parse(many_fails)
    result = LogAnalyzer(df).analyze()
    assert result['risk_score'] > 20
