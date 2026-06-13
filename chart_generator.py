"""
ChartGenerator — Generates PNG charts using Matplotlib.
All charts use a dark theme to match the LogSentinel frontend.
"""

import os
import io
import base64
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np


# ─── Dark Theme Defaults ──────────────────────────────────────────────────────

BG      = '#0f1420'
CARD    = '#141927'
ACCENT  = '#00d4ff'
ACCENT2 = '#7c3aed'
ACCENT3 = '#10b981'
WARN    = '#f59e0b'
DANGER  = '#ef4444'
TEXT    = '#e2e8f0'
MUTED   = '#64748b'

plt.rcParams.update({
    'figure.facecolor' : BG,
    'axes.facecolor'   : CARD,
    'axes.edgecolor'   : '#1e2a3a',
    'axes.labelcolor'  : MUTED,
    'xtick.color'      : MUTED,
    'ytick.color'      : MUTED,
    'text.color'       : TEXT,
    'grid.color'       : '#1e2a3a',
    'grid.linewidth'   : 0.5,
    'font.family'      : 'monospace',
    'axes.spines.top'  : False,
    'axes.spines.right': False,
})

FIGSIZE = (8, 4)


def _fig_to_b64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', dpi=120, facecolor=BG)
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return data


class ChartGenerator:
    def __init__(self, analysis: dict):
        self.stats = analysis.get('stats', {})
        self.bf    = analysis.get('brute_force', {})
        self.ps    = analysis.get('port_scan', {})
        self.intr  = analysis.get('intrusion', {})
        self.crit  = analysis.get('critical_events', {})

    # ── 1. Level Distribution Pie ─────────────────────────────────────────

    def level_pie(self) -> str:
        dist = self.stats.get('level_dist', {})
        if not dist:
            return ''

        labels = list(dist.keys())
        values = list(dist.values())
        colors = {
            'CRITICAL': DANGER, 'ERROR': '#f87171',
            'WARNING': WARN, 'WARN': WARN,
            'INFO': ACCENT, 'DEBUG': MUTED,
        }
        clrs = [colors.get(l.upper(), ACCENT2) for l in labels]

        fig, ax = plt.subplots(figsize=(6, 4), facecolor=BG)
        wedges, texts, autotexts = ax.pie(
            values, labels=labels, colors=clrs,
            autopct='%1.0f%%', startangle=140,
            wedgeprops=dict(linewidth=1, edgecolor=BG)
        )
        for t in texts:      t.set_color(MUTED); t.set_fontsize(9)
        for a in autotexts:  a.set_color(TEXT);  a.set_fontsize(8)
        ax.set_title('Log Level Distribution', color=TEXT, fontsize=11, pad=12)
        return _fig_to_b64(fig)

    # ── 2. Hourly Activity Bar ────────────────────────────────────────────

    def hourly_bar(self) -> str:
        dist = self.stats.get('hourly_dist', {})
        if not dist:
            return ''

        hours  = [str(h) for h in range(24)]
        counts = [dist.get(h, 0) for h in hours]

        fig, ax = plt.subplots(figsize=FIGSIZE, facecolor=BG)
        bars = ax.bar(hours, counts, color=ACCENT, alpha=0.7, width=0.7)
        ax.set_xlabel('Hour of Day')
        ax.set_ylabel('Log Entries')
        ax.set_title('Hourly Activity Distribution', color=TEXT, fontsize=11)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)

        # Highlight top bar
        if counts:
            peak = max(counts)
            for bar, c in zip(bars, counts):
                if c == peak:
                    bar.set_color(WARN)
                    bar.set_alpha(1.0)

        return _fig_to_b64(fig)

    # ── 3. Top IPs Bar ────────────────────────────────────────────────────

    def top_ips_bar(self) -> str:
        top = self.stats.get('top_ips', {})
        if not top:
            return ''

        items = sorted(top.items(), key=lambda x: x[1], reverse=True)[:10]
        ips    = [i[0] for i in items]
        counts = [i[1] for i in items]

        # Flag brute-force IPs in red
        bf_ips = {r['ip_address'] for r in self.bf.get('flagged_ips', [])}
        colors = [DANGER if ip in bf_ips else ACCENT for ip in ips]

        fig, ax = plt.subplots(figsize=FIGSIZE, facecolor=BG)
        ax.barh(ips[::-1], counts[::-1], color=colors[::-1], alpha=0.85)
        ax.set_xlabel('Request Count')
        ax.set_title('Top Source IPs', color=TEXT, fontsize=11)
        ax.xaxis.grid(True)
        ax.set_axisbelow(True)
        return _fig_to_b64(fig)

    # ── 4. Status Code Distribution (Apache) ─────────────────────────────

    def status_bar(self) -> str:
        dist = self.stats.get('status_dist', {})
        if not dist:
            return ''

        items  = sorted(dist.items(), key=lambda x: int(x[0]))
        codes  = [i[0] for i in items]
        counts = [i[1] for i in items]

        def code_color(c):
            n = int(c)
            if n >= 500: return DANGER
            if n >= 400: return WARN
            if n >= 300: return ACCENT2
            return ACCENT3

        colors = [code_color(c) for c in codes]

        fig, ax = plt.subplots(figsize=FIGSIZE, facecolor=BG)
        ax.bar(codes, counts, color=colors, alpha=0.85, width=0.6)
        ax.set_xlabel('HTTP Status Code')
        ax.set_ylabel('Count')
        ax.set_title('HTTP Status Code Distribution', color=TEXT, fontsize=11)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
        return _fig_to_b64(fig)

    # ── 5. Threat Summary Bar ─────────────────────────────────────────────

    def threat_summary_bar(self) -> str:
        categories = [
            'Brute-force IPs',
            'Port Scan Events',
            'Intrusion Events',
            'Critical Events',
        ]
        values = [
            len(self.bf.get('flagged_ips', [])),
            self.ps.get('event_count', 0),
            self.intr.get('event_count', 0),
            self.crit.get('event_count', 0),
        ]
        colors = [DANGER, WARN, ACCENT2, '#f97316']

        fig, ax = plt.subplots(figsize=FIGSIZE, facecolor=BG)
        bars = ax.bar(categories, values, color=colors, alpha=0.85, width=0.5)

        for bar, val in zip(bars, values):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                        str(val), ha='center', va='bottom', color=TEXT, fontsize=9)

        ax.set_ylabel('Count')
        ax.set_title('Threat Detection Summary', color=TEXT, fontsize=11)
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(categories, fontsize=8)
        return _fig_to_b64(fig)

    def generate_all(self) -> dict:
        return {
            'level_pie'         : self.level_pie(),
            'hourly_bar'        : self.hourly_bar(),
            'top_ips_bar'       : self.top_ips_bar(),
            'status_bar'        : self.status_bar(),
            'threat_summary_bar': self.threat_summary_bar(),
        }
