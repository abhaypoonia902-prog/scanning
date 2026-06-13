# ⬡ LogSentinel — Backend

Flask-based REST API for the LogSentinel automated log analyzer.
Parses system + web server logs, runs 4 threat detectors, generates charts & reports.

---

## 📁 Project Structure

```
logsentinel/
├── app.py                    ← Flask entry point
├── requirements.txt
├── Procfile                  ← For Render / Railway
├── runtime.txt               ← Python 3.11
├── .gitignore
├── modules/
│   ├── log_parser.py         ← Format detection + parsing → DataFrame
│   ├── log_analyzer.py       ← Stats + 4 threat detectors + risk score
│   ├── chart_generator.py    ← Matplotlib charts (base64 PNG)
│   └── report_generator.py   ← Plain-text report
└── tests/
    └── test_logsentinel.py   ← pytest suite
```

---

## 🚀 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Info + endpoint list |
| GET | `/health` | Health check |
| POST | `/analyze` | Upload log → full analysis + charts + report |
| POST | `/analyze/no-charts` | Upload log → analysis + report only (faster) |
| POST | `/report` | Upload log → download plain-text `.txt` report |

### POST `/analyze` — Request

```
Content-Type: multipart/form-data
Field: file  (your .log or .txt file)
```

### POST `/analyze` — Response

```json
{
  "meta": {
    "filename": "access.log",
    "format": "apache",
    "total_lines": 5000,
    "parsed_lines": 4987,
    "analyzed_at": "2026-05-01T12:00:00"
  },
  "analysis": {
    "stats": {
      "total_lines": 4987,
      "error_count": 120,
      "warning_count": 45,
      "critical_count": 3,
      "top_ips": { "192.168.1.10": 342 },
      "hourly_dist": { "3": 89, "14": 210 },
      "level_dist": { "INFO": 4822, "ERROR": 120 },
      "status_dist": { "200": 4200, "404": 87 }
    },
    "brute_force": {
      "flagged_ips": [{ "ip_address": "1.2.3.4", "attempt_count": 47 }],
      "total_failed_logins": 47,
      "threshold_used": 5
    },
    "port_scan": { "events": [...], "event_count": 0 },
    "intrusion":  { "events": [...], "event_count": 2, "pattern_hits": {...} },
    "critical_events": { "events": [...], "event_count": 3 },
    "risk_score": 72
  },
  "charts": {
    "level_pie":          "<base64 PNG>",
    "hourly_bar":         "<base64 PNG>",
    "top_ips_bar":        "<base64 PNG>",
    "status_bar":         "<base64 PNG>",
    "threat_summary_bar": "<base64 PNG>"
  },
  "report": "====== LogSentinel Report ====== ..."
}
```

---

## 🛠️ Local Development

```bash
# 1. Clone / download this folder
cd logsentinel

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run in dev mode
FLASK_ENV=development python app.py

# API is now at: http://localhost:5000
```

### Test with curl

```bash
curl -X POST http://localhost:5000/analyze \
  -F "file=@/path/to/your/access.log" \
  | python -m json.tool
```

### Run tests

```bash
pytest tests/ -v
```

---

## ☁️ Deploy on Render (Free Tier)

1. Push this folder to a **GitHub repo** (public or private).

2. Go to [render.com](https://render.com) → **New → Web Service**.

3. Connect your GitHub repo.

4. Fill in settings:
   | Field | Value |
   |-------|-------|
   | **Environment** | Python 3 |
   | **Build Command** | `pip install -r requirements.txt` |
   | **Start Command** | `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120` |
   | **Plan** | Free |

5. Click **Deploy**. Render will give you a URL like:
   `https://logsentinel-xxxx.onrender.com`

6. Update your frontend to call this URL.

> ⚠️ Free Render instances **spin down after 15 min** of inactivity. First request after sleep takes ~30s. Upgrade to a paid plan to avoid this.

---

## 🚂 Deploy on Railway

1. Push to GitHub.

2. Go to [railway.app](https://railway.app) → **New Project → Deploy from GitHub Repo**.

3. Select your repo. Railway auto-detects Python + `Procfile`.

4. In **Variables**, add if needed:
   ```
   PORT=5000
   ```

5. Railway gives you a URL like:
   `https://logsentinel-production.up.railway.app`

6. Railway's free tier gives **500 hours/month** — enough for a project demo.

---

## 🔗 Connecting Frontend to Backend

In your `logsentinel.html` frontend, add a file upload form and call the API:

```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);

const response = await fetch('https://YOUR-BACKEND-URL.onrender.com/analyze', {
  method: 'POST',
  body: formData
});

const data = await response.json();
console.log('Risk Score:', data.analysis.risk_score);

// Show a chart
const img = document.createElement('img');
img.src = 'data:image/png;base64,' + data.charts.threat_summary_bar;
document.body.appendChild(img);
```

---

## 🧩 Supported Log Formats

| Format | Example |
|--------|---------|
| System log | `2024-01-15 03:12:01 ERROR 1.2.3.4 Failed password for root` |
| Apache Combined | `1.2.3.4 - - [15/Jan/2024:08:00:01 +0000] "GET / HTTP/1.1" 200 1234` |
| Nginx access | Same as Apache Combined Log Format |

---

## 🛡️ Threat Detectors

| Detector | Logic |
|----------|-------|
| **Brute-force** | Failed login count per IP ≥ 5 (configurable) |
| **Port Scan** | Keywords: nmap, masscan, SYN flood, etc. |
| **Intrusion** | Patterns: `../`, `/etc/passwd`, SQL injection, XSS |
| **Critical Events** | CRITICAL level + kernel panic, OOM kill, disk errors |

**Risk Score** is a heuristic 0–100 computed from all four detectors + error volume.

---

## 👨‍💻 Developer

**Abhay Poonia** — BCA, Graphic Era Hill University, Dehradun (2026)  
Supervisor: **Mrs. Nidhi Joshi**, School of Computing, GEHU
