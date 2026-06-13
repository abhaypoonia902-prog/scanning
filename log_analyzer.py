"""
LogAnalyzer — Runs statistical analysis + four rule-based threat detectors.
Detectors: Brute-force, Port Scan, Intrusion, Critical Events.
Risk Score: heuristic 0–100 composite.
"""

import re
import pandas as pd


# ─── Configurable Thresholds ─────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5          # failed logins per IP
PORT_SCAN_THRESHOLD   = 3          # scan-related events per IP
INTRUSION_PATTERNS    = [
    r'\.\./|\.\.\\',               # directory traversal
    r'/cgi-bin/',                  # CGI exploit paths
    r'(?:union\s+select|select\s+\*|drop\s+table)',  # SQL injection
    r'<script|javascript:|onerror=',                  # XSS
    r'/etc/passwd|/etc/shadow',                       # LFI
    r'cmd\.exe|powershell',                           # RCE
]
PORT_SCAN_KEYWORDS = [
    'port scan', 'portscan', 'nmap', 'masscan',
    'syn flood', 'reconnaissance', 'scan detected',
    'connection refused', 'connection reset',
]
CRITICAL_KEYWORDS = [
    'kernel panic', 'oom kill', 'out of memory', 'segfault',
    'disk full', 'disk error', 'filesystem error',
    'hardware error', 'fatal error', 'system crash',
    'service unavailable',
]


class LogAnalyzer:
    def __init__(self, df: pd.DataFrame):
        self.df = df.copy()
        self.results: dict = {}

    # ── Statistics ─────────────────────────────────────────────────────────

    def _basic_stats(self) -> dict:
        df = self.df
        total = len(df)
        errors   = int(df.get('is_error',   pd.Series([False]*total)).sum())
        warnings = int(df.get('is_warning', pd.Series([False]*total)).sum())
        criticals= int(df.get('is_critical',pd.Series([False]*total)).sum())

        # Status code distribution (apache)
        status_dist = {}
        if 'status_code' in df.columns:
            counts = df['status_code'].value_counts().head(10)
            status_dist = {str(k): int(v) for k, v in counts.items()}

        # Top IPs
        top_ips = {}
        if 'ip_address' in df.columns:
            counts = df['ip_address'].dropna().value_counts().head(10)
            top_ips = {k: int(v) for k, v in counts.items()}

        # Hourly distribution
        hourly = {}
        if 'hour' in df.columns:
            counts = df['hour'].dropna().value_counts().sort_index()
            hourly = {str(int(k)): int(v) for k, v in counts.items()}

        # Level distribution
        level_dist = {}
        if 'level' in df.columns:
            counts = df['level'].fillna('UNKNOWN').value_counts()
            level_dist = {k: int(v) for k, v in counts.items()}

        return {
            'total_lines'    : total,
            'error_count'    : errors,
            'warning_count'  : warnings,
            'critical_count' : criticals,
            'info_count'     : total - errors - warnings,
            'status_dist'    : status_dist,
            'top_ips'        : top_ips,
            'hourly_dist'    : hourly,
            'level_dist'     : level_dist,
        }

    # ── Detector 1: Brute-force ─────────────────────────────────────────────

    def _detect_brute_force(self) -> dict:
        df = self.df
        if 'is_failed_login' not in df.columns or 'ip_address' not in df.columns:
            return {'flagged_ips': [], 'total_failed_logins': 0}

        failed = df[df['is_failed_login'] & df['ip_address'].notna()]
        if failed.empty:
            return {'flagged_ips': [], 'total_failed_logins': 0}

        grouped = failed.groupby('ip_address').size().reset_index(name='attempt_count')
        flagged = grouped[grouped['attempt_count'] >= BRUTE_FORCE_THRESHOLD]
        flagged = flagged.sort_values('attempt_count', ascending=False)

        return {
            'flagged_ips'       : flagged.to_dict('records'),
            'total_failed_logins': int(failed.shape[0]),
            'threshold_used'    : BRUTE_FORCE_THRESHOLD,
        }

    # ── Detector 2: Port Scan ───────────────────────────────────────────────

    def _detect_port_scan(self) -> dict:
        df = self.df
        if 'message' not in df.columns:
            return {'events': [], 'event_count': 0}

        pattern = '|'.join(re.escape(k) for k in PORT_SCAN_KEYWORDS)
        mask = df['message'].str.lower().str.contains(pattern, na=False)
        scan_events = df[mask]

        # Aggregate by IP if available
        by_ip = {}
        if 'ip_address' in df.columns:
            ip_counts = scan_events['ip_address'].dropna().value_counts()
            by_ip = {k: int(v) for k, v in ip_counts.items()
                     if v >= PORT_SCAN_THRESHOLD}

        events = []
        for _, row in scan_events.head(50).iterrows():
            events.append({
                'ip'      : row.get('ip_address'),
                'message' : str(row.get('message', ''))[:200],
                'timestamp': str(row.get('timestamp', '')),
            })

        return {
            'events'     : events,
            'event_count': int(len(scan_events)),
            'by_ip'      : by_ip,
        }

    # ── Detector 3: Intrusion / Injection ──────────────────────────────────

    def _detect_intrusion(self) -> dict:
        df = self.df
        combined = df.get('message', pd.Series(dtype=str)).fillna('') + ' ' + \
                   df.get('path',    pd.Series(dtype=str)).fillna('')
        combined = combined.str.lower()

        all_matches = pd.Series([False] * len(df), index=df.index)
        pattern_hits: dict[str, int] = {}

        for pat in INTRUSION_PATTERNS:
            mask = combined.str.contains(pat, na=False, regex=True)
            hits = int(mask.sum())
            if hits:
                pattern_hits[pat] = hits
            all_matches = all_matches | mask

        flagged = df[all_matches]
        events = []
        for _, row in flagged.head(50).iterrows():
            events.append({
                'ip'      : row.get('ip_address'),
                'path'    : str(row.get('path', ''))[:200],
                'message' : str(row.get('message', ''))[:200],
                'timestamp': str(row.get('timestamp', '')),
            })

        return {
            'events'      : events,
            'event_count' : int(all_matches.sum()),
            'pattern_hits': pattern_hits,
        }

    # ── Detector 4: Critical Events ─────────────────────────────────────────

    def _detect_critical(self) -> dict:
        df = self.df
        lvl_mask = df.get('is_critical', pd.Series([False]*len(df)))

        keyword_pattern = '|'.join(re.escape(k) for k in CRITICAL_KEYWORDS)
        msg_mask = df.get('message', pd.Series(dtype=str)) \
                     .str.lower().str.contains(keyword_pattern, na=False)

        combined_mask = lvl_mask | msg_mask
        flagged = df[combined_mask]

        events = []
        for _, row in flagged.head(50).iterrows():
            events.append({
                'level'    : str(row.get('level', '')),
                'message'  : str(row.get('message', ''))[:300],
                'timestamp': str(row.get('timestamp', '')),
            })

        return {
            'events'     : events,
            'event_count': int(combined_mask.sum()),
        }

    # ── Risk Score ──────────────────────────────────────────────────────────

    def _compute_risk_score(self, bf: dict, ps: dict, intr: dict, crit: dict, stats: dict) -> int:
        score = 0
        total = max(stats['total_lines'], 1)

        # Brute-force: up to 35 pts
        bf_ips = len(bf.get('flagged_ips', []))
        score += min(bf_ips * 7, 35)

        # Port scan: up to 20 pts
        ps_count = ps.get('event_count', 0)
        score += min(ps_count * 4, 20)

        # Intrusion: up to 25 pts
        intr_count = intr.get('event_count', 0)
        score += min(intr_count * 5, 25)

        # Critical: up to 15 pts
        crit_count = crit.get('event_count', 0)
        score += min(crit_count * 3, 15)

        # General error volume: up to 5 pts
        err_ratio = stats['error_count'] / total
        score += min(int(err_ratio * 20), 5)

        return min(score, 100)

    # ── Main Entry ──────────────────────────────────────────────────────────

    def analyze(self) -> dict:
        stats = self._basic_stats()
        bf    = self._detect_brute_force()
        ps    = self._detect_port_scan()
        intr  = self._detect_intrusion()
        crit  = self._detect_critical()
        score = self._compute_risk_score(bf, ps, intr, crit, stats)

        self.results = {
            'stats'          : stats,
            'brute_force'    : bf,
            'port_scan'      : ps,
            'intrusion'      : intr,
            'critical_events': crit,
            'risk_score'     : score,
        }
        return self.results
