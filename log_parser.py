"""
LogParser — Detects format, parses lines, returns structured DataFrame.
Supports: System logs, Apache Combined Log Format, Nginx access logs.
"""

import re
import pandas as pd
from datetime import datetime


# ─── Regex Patterns ──────────────────────────────────────────────────────────

SYSLOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
    r'\s+(?P<level>INFO|WARNING|WARN|ERROR|CRITICAL|DEBUG|NOTICE)'
    r'(?:\s+(?P<ip_address>\d{1,3}(?:\.\d{1,3}){3}))?'
    r'\s+(?P<message>.+)',
    re.IGNORECASE
)

APACHE_PATTERN = re.compile(
    r'(?P<ip_address>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status_code>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

SYSLOG_ALT_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>\S+):\s+'
    r'(?P<message>.+)'
)


def detect_format(lines: list[str]) -> str:
    """Probe first 20 non-empty lines to decide log format."""
    sample = [l for l in lines if l.strip()][:20]
    apache_hits = sum(1 for l in sample if APACHE_PATTERN.search(l))
    syslog_hits = sum(1 for l in sample if SYSLOG_PATTERN.search(l))
    alt_hits    = sum(1 for l in sample if SYSLOG_ALT_PATTERN.search(l))

    if apache_hits >= max(syslog_hits, alt_hits, 1):
        return 'apache'
    if syslog_hits >= alt_hits:
        return 'syslog'
    return 'syslog_alt'


def _parse_apache_ts(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, '%d/%b/%Y:%H:%M:%S %z').replace(tzinfo=None)
    except Exception:
        return None


def _parse_syslog_ts(ts: str) -> datetime | None:
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(ts.strip(), fmt)
        except Exception:
            continue
    return None


def parse_lines(lines: list[str], fmt: str) -> list[dict]:
    records = []
    for line in lines:
        line = line.rstrip('\n')
        if not line.strip():
            continue

        rec: dict = {
            'raw': line,
            'timestamp': None,
            'level': 'INFO',
            'ip_address': None,
            'method': None,
            'path': None,
            'status_code': None,
            'message': line,
        }

        if fmt == 'apache':
            m = APACHE_PATTERN.search(line)
            if m:
                g = m.groupdict()
                rec['ip_address']  = g.get('ip_address')
                rec['method']      = g.get('method')
                rec['path']        = g.get('path', '')
                sc = g.get('status_code', '200')
                rec['status_code'] = int(sc) if sc and sc.isdigit() else 200
                rec['timestamp']   = _parse_apache_ts(g.get('timestamp', ''))
                rec['message']     = f"{g.get('method','')} {g.get('path','')} {sc}"
                # Derive level from status code
                code = rec['status_code'] or 200
                rec['level'] = 'ERROR' if code >= 500 else ('WARNING' if code >= 400 else 'INFO')

        elif fmt == 'syslog':
            m = SYSLOG_PATTERN.search(line)
            if m:
                g = m.groupdict()
                rec['timestamp']   = _parse_syslog_ts(g.get('timestamp', ''))
                rec['level']       = (g.get('level') or 'INFO').upper()
                rec['ip_address']  = g.get('ip_address')
                rec['message']     = g.get('message', line)

        else:  # syslog_alt
            m = SYSLOG_ALT_PATTERN.search(line)
            if m:
                g = m.groupdict()
                rec['message'] = g.get('message', line)
                # Try to detect level from message
                msg_up = rec['message'].upper()
                for lvl in ('CRITICAL', 'ERROR', 'WARNING', 'WARN', 'INFO', 'DEBUG'):
                    if lvl in msg_up:
                        rec['level'] = lvl
                        break
                # Try to extract IP
                ip_m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
                if ip_m:
                    rec['ip_address'] = ip_m.group(1)

        records.append(rec)
    return records


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    """Add derived boolean columns and time parts."""
    msg = df['message'].fillna('').str.upper()
    path = df.get('path', pd.Series([''] * len(df))).fillna('').str.upper()
    lvl  = df['level'].fillna('INFO').str.upper()

    df['is_error']  = (lvl.isin(['ERROR', 'CRITICAL'])) | \
                      (df.get('status_code', pd.Series([None]*len(df))).ge(400).fillna(False))

    df['is_warning'] = lvl.isin(['WARNING', 'WARN'])

    df['is_critical'] = lvl == 'CRITICAL'

    df['is_failed_login'] = msg.str.contains(
        r'FAILED|INVALID|FAILURE|AUTHENTICATION FAIL|LOGIN FAIL|WRONG PASSWORD', na=False
    )

    df['hour'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.hour
    df['date'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.date

    return df


class LogParser:
    def __init__(self):
        self.format_detected: str = 'unknown'
        self.total_lines: int = 0
        self.parsed_lines: int = 0

    def parse(self, content: str) -> pd.DataFrame:
        lines = content.splitlines()
        self.total_lines = len(lines)

        self.format_detected = detect_format(lines)
        records = parse_lines(lines, self.format_detected)
        self.parsed_lines = len(records)

        df = pd.DataFrame(records)
        df = enrich(df)
        return df
