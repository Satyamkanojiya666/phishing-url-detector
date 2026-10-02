# 🛡️ PHISH//HUNTER — AI Phishing & Scam Detector

> Created by **Satyam Kanojiya**

[![CI](https://github.com/Satyamkanojiya666/phishing-url-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/Satyamkanojiya666/phishing-url-detector/actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Author](https://img.shields.io/badge/author-Satyam%20Kanojiya-00ff66)

A hybrid **machine-learning + rule-based** system that detects phishing and scam messages (SMS, email, WhatsApp) and analyses suspicious links — with a visual Flask dashboard, a CLI and a JSON API.

## ✨ Features

**Detection**
- Hybrid engine: TF-IDF (word + character n-grams) + Logistic Regression, blended with a rule engine
- Advanced URL analysis: raw-IP hosts, link shorteners, suspicious TLDs, **typosquatting** (`amaz0n`, `paypa1`), **punycode/homograph** domains, `@` tricks, odd ports, percent-encoding, long URLs, random-looking domains
- Pattern detection: urgency, OTP/PIN/KYC requests, prize & fee bait, account-block threats
- **Hinglish** support (`turant`, `khata band`, `inaam` ...)
- **Explainable AI**: shows the words that pushed the model towards "scam", plus human-readable reasons and safety advice

**Dashboard (Flask) — hacker-terminal UI**
- Matrix-rain background, CRT scanlines, glitch title, boot sequence and a live console log
- 3 switchable themes: 🟢 Matrix · 🟣 Cyber · 🔴 Red-team
- **IOC extractor**: emails, UPI IDs, phone numbers, IPs and crypto wallets pulled out of every message, with **sender e-mail analysis** (look-alike domains, brand impersonation on free mail)
- One-click **threat report** download (.txt / .json)
- Message analyzer, standalone **URL scanner**, **batch analysis** (paste or upload .txt/.csv, download results)
- Persistent **SQLite history**, click any row to re-open the result, export to CSV, clear history
- 👍/👎 feedback on verdicts, risk gauge, usage stats

**Quality & security**
- Metrics: hold-out accuracy, precision, recall, F1, 5-fold cross-validation
- XSS-safe UI, CSP + security headers, input limits, per-IP rate limiting, CSV formula-injection protection
- Unit tests (pytest), GitHub Actions CI, Dockerfile

## 📁 Project structure
```
phishing-detector/
├── app.py                 # Flask server + JSON API
├── detector.py            # ML + rule engine + URL analysis
├── cli.py                 # command-line interface
├── templates/index.html   # dashboard
├── static/                # style.css, script.js
├── tests/                 # pytest suite
├── data/                  # SQLite history + optional custom dataset
├── Dockerfile
├── .github/workflows/ci.yml
└── LICENSE
```

## 🚀 Quick start
```bash
pip install -r requirements.txt
python app.py            # open http://127.0.0.1:5000
```
On Windows you can just double-click `start_dashboard.bat`.

### Docker
```bash
docker build -t phishing-detector .
docker run -p 5000:5000 phishing-detector
```

### CLI
```bash
python cli.py "Your account is blocked, verify at http://bit.ly/abc"
python cli.py --url http://paypa1-login.xyz
python cli.py --file messages.txt --json
python cli.py --eval
```

## 🔌 API
| Method | Endpoint | Body | Description |
|---|---|---|---|
| POST | `/api/analyze` | `{"text": "..."}` | Analyze a message |
| POST | `/api/url` | `{"url": "..."}` | Scan a URL |
| POST | `/api/batch` | `{"messages": [...]}` or file upload | Analyze up to 200 messages |
| GET | `/api/history` | – | Last 50 checks |
| DELETE | `/api/history` | – | Clear history |
| GET | `/api/export` | – | Download history as CSV |
| POST | `/api/feedback` | `{"id": 1, "correct": true}` | Rate a verdict |
| GET | `/api/stats` | – | Model metrics + usage |
| GET | `/api/health` | – | Health check |

```bash
curl -X POST http://127.0.0.1:5000/api/analyze -H "Content-Type: application/json" \
     -d '{"text":"URGENT: verify KYC at http://sbi-kyc.xyz"}'
```

## ⚙️ Configuration
Environment variables: `PORT`, `HOST`, `FLASK_DEBUG=1`, `PHISH_DB`, `RATE_LIMIT` (requests/min/IP).

## 📈 Improve the model
The built-in set is small (~66 samples, demo purposes). Add your own labeled data in `data/custom_dataset.csv`
(see `data/custom_dataset.example.csv`; columns `text,label`, label `1` = scam, `0` = safe). It is merged automatically.
Public datasets like the SMS Spam Collection or Kaggle phishing datasets work well.

## 🧪 Tests
```bash
pip install -r requirements-dev.txt
pytest
```

## ⚠️ Disclaimer
Educational project — not a replacement for professional security tools. Never share OTP/PIN/passwords with anyone.

## 👤 Author
**Satyam Kanojiya**

## 📄 License
[MIT](LICENSE) © 2026 Satyam Kanojiya
