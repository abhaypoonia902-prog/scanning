"""
ReportGenerator — Compiles a plain-text summary report.
"""

from datetime import datetime


def _divider(char='-', width=70):
    return char * width


def generate_report(analysis: dict, filename: str = 'log_file', fmt: str = 'unknown') -> str:
    now    = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    stats  = analysis.get('stats', {})
    bf     = analysis.get('brute_force', {})
    ps     = analysis.get('port_scan', {})
    intr   = analysis.get('intrusion', {})
    crit   = analysis.get('critical_events', {})
    score  = analysis.get('risk_score', 0)

    lines = [
        '=' * 70,
        '  LogSentinel — Automated Log Analyzer',
        '  Security Analysis Report',
        '=' * 70,
        f'  Generated : {now}',
        f'  Log File  : {filename}',
        f'  Format    : {fmt.upper()}',
        _divider(),
        '',
        '[ RISK SCORE ]',
        f'  Overall Risk Score: {score}/100',
        _risk_label(score),
        '',
        _divider(),
        '[ STATISTICS ]',
        f'  Total log lines   : {stats.get("total_lines", 0):,}',
        f'  ERROR entries     : {stats.get("error_count", 0):,}',
        f'  WARNING entries   : {stats.get("warning_count", 0):,}',
        f'  CRITICAL entries  : {stats.get("critical_count", 0):,}',
        '',
    ]

    # Top IPs
    top_ips = stats.get('top_ips', {})
    if top_ips:
        lines += ['[ TOP SOURCE IPs ]']
        for ip, cnt in sorted(top_ips.items(), key=lambda x: -x[1])[:10]:
            lines.append(f'  {ip:<20} {cnt:>6} requests')
        lines.append('')

    # Brute-force
    lines += [_divider(), '[ BRUTE-FORCE DETECTION ]']
    bf_ips = bf.get('flagged_ips', [])
    if bf_ips:
        lines.append(f'  ⚠  {len(bf_ips)} IP(s) exceeded threshold of {bf.get("threshold_used",5)} failed logins.')
        lines.append(f'  Total failed login attempts: {bf.get("total_failed_logins", 0):,}')
        lines.append('')
        lines.append(f'  {"IP Address":<20} {"Attempts":>8}')
        lines.append(f'  {"-"*20} {"-"*8}')
        for r in bf_ips[:20]:
            lines.append(f'  {str(r["ip_address"]):<20} {r["attempt_count"]:>8}')
    else:
        lines.append('  ✓  No brute-force sources detected.')
    lines.append('')

    # Port Scan
    lines += [_divider(), '[ PORT SCAN DETECTION ]']
    ps_count = ps.get('event_count', 0)
    if ps_count:
        lines.append(f'  ⚠  {ps_count} port-scan related events detected.')
        for ev in ps.get('events', [])[:10]:
            lines.append(f'  [{ev.get("timestamp","?")}] {ev.get("ip","?")} — {ev.get("message","")[:80]}')
    else:
        lines.append('  ✓  No port-scan indicators detected.')
    lines.append('')

    # Intrusion
    lines += [_divider(), '[ INTRUSION / INJECTION DETECTION ]']
    intr_count = intr.get('event_count', 0)
    if intr_count:
        lines.append(f'  ⚠  {intr_count} suspicious request(s) matched intrusion patterns.')
        for ev in intr.get('events', [])[:10]:
            lines.append(f'  [{ev.get("timestamp","?")}] {ev.get("ip","?")} — {ev.get("path","") or ev.get("message","")[:80]}')
    else:
        lines.append('  ✓  No intrusion patterns detected.')
    lines.append('')

    # Critical Events
    lines += [_divider(), '[ CRITICAL EVENT DETECTION ]']
    crit_count = crit.get('event_count', 0)
    if crit_count:
        lines.append(f'  ⚠  {crit_count} critical system event(s) found.')
        for ev in crit.get('events', [])[:10]:
            lines.append(f'  [{ev.get("timestamp","?")}] [{ev.get("level","?")}] {ev.get("message","")[:100]}')
    else:
        lines.append('  ✓  No critical system events detected.')
    lines.append('')

    lines += [
        '=' * 70,
        '  LogSentinel — BCA Project · Graphic Era Hill University · 2026',
        '  Developer: Abhay Poonia | Supervisor: Mrs. Nidhi Joshi',
        '=' * 70,
    ]

    return '\n'.join(lines)


def _risk_label(score: int) -> str:
    if score >= 80:
        return f'  *** CRITICAL RISK — Immediate investigation required ***'
    if score >= 60:
        return f'  **  HIGH RISK — Review flagged events promptly **'
    if score >= 40:
        return f'  *   MEDIUM RISK — Monitor closely *'
    if score >= 20:
        return f'      LOW RISK — Some anomalies present'
    return '      MINIMAL RISK — System appears normal'
