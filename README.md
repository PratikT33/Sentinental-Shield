# 🛡️ Sentinel Shield

> **Advanced Intrusion Detection and Web Protection System**

A Python-based Web Application Firewall (WAF) that detects and blocks real-time web attacks including SQL injection, XSS, path traversal, command injection, and brute-force attempts — with a live REST API dashboard and structured JSON logging.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Attack Rules](#attack-rules)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Running Locally](#running-locally)
- [Docker Deployment](#docker-deployment)
- [API Endpoints](#api-endpoints)
- [Sample Output](#sample-output)
- [Tech Stack](#tech-stack)
- [Practical Workflow](#practical-workflow)

---

## Overview

Sentinel Shield is a fully functional WAF and intrusion detection system built in Python. It inspects every incoming HTTP request against a library of attack signatures, enforces rate limiting, auto-blocks repeat offenders, writes structured logs, and exposes a live security dashboard via REST API.

Built as a practical network security project covering:
- Rule-based threat detection
- Behavioural analysis (rate limiting + IP auto-blocking)
- Structured JSON logging
- REST API with live statistics

---

## Features

| Feature | Description |
|---|---|
| 🔍 SQL Injection Detection | UNION-based, tautology, and comment-stripping attacks |
| ⚡ XSS Detection | Script tags, event handlers, javascript: URI |
| 📁 Path Traversal Detection | `../` sequences and sensitive file access |
| 💻 Command Injection Detection | Shell metacharacters with dangerous commands |
| 🔒 Rate Limiting | Sliding-window per-IP request throttling |
| 🚫 IP Auto-Blocking | Permanent block after repeated violations |
| 📊 Live Dashboard | Real-time JSON security statistics |
| 📝 Structured Logging | JSON log entries for all traffic and attacks |
| 🐳 Docker Ready | Full containerised deployment with Gunicorn |
| 🌐 Nginx Proxy | HTTPS-ready reverse proxy configuration |

---

## System Architecture

```
HTTP Request
     │
     ▼
┌─────────────────┐
│   WAF Engine    │  ← rules.py + waf.py
│  Rule matching  │
│  Rate limiting  │
│  IP blocklist   │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
 BLOCKED   ALLOWED
  (403)     (200)
    │         │
    └────┬────┘
         │
         ▼
┌─────────────────┐
│  Logger         │  ← logger.py
│  attack.log     │
│  traffic.log    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Dashboard      │  ← dashboard.py + app.py
│  /dashboard     │
│  /logs          │
└─────────────────┘
```

---

## Attack Rules

| Rule ID | Name | Category | Severity |
|---|---|---|---|
| SQLI-001 | Basic SQL injection | SQL_INJECTION | 🔴 CRITICAL |
| SQLI-002 | SQL tautology (OR 1=1) | SQL_INJECTION | 🟠 HIGH |
| SQLI-003 | SQL comment stripping | SQL_INJECTION | 🟡 MEDIUM |
| XSS-001 | Script tag injection | XSS | 🟠 HIGH |
| XSS-002 | Event handler injection | XSS | 🟠 HIGH |
| XSS-003 | JavaScript URI | XSS | 🟠 HIGH |
| PATH-001 | Directory traversal | PATH_TRAVERSAL | 🟠 HIGH |
| PATH-002 | Sensitive file access | PATH_TRAVERSAL | 🔴 CRITICAL |
| CMD-001 | Shell command injection | COMMAND_INJECTION | 🔴 CRITICAL |
| BF-001 | Admin panel probing | BRUTE_FORCE | 🟡 MEDIUM |
| LFI-001 | Local file inclusion | LFI | 🟠 HIGH |

---

## Project Structure

```
sentinel_shield_deploy/
│
├── sentinel_shield/          # Core WAF engine
│   ├── rules.py              # Attack signature definitions
│   ├── waf.py                # WAF engine + rate limiter
│   ├── logger.py             # JSON logging system
│   └── dashboard.py          # Stats and reporting
│
├── app.py                    # Flask REST API server
├── main.py                   # Simulation runner
│
├── Dockerfile                # Docker image definition
├── docker-compose.yml        # Multi-container setup with Nginx
├── requirements.txt          # Python dependencies
├── .env.example              # Environment config template
│
├── nginx/
│   └── sentinel.conf         # Nginx reverse proxy config
│
└── logs/                     # Auto-created at runtime
    ├── traffic.log           # All requests (JSON lines)
    └── attack.log            # Blocked requests only
```

---

## Installation

### Requirements

- Python 3.12+
- Docker Desktop
- Git

### Clone the repository

```bash
git clone https://github.com/PratikT33/sentinel-shield.git
cd sentinel-shield
```

### Create environment config

```bash
# Linux / macOS
cp .env.example .env

# Windows
copy .env.example .env
```

Edit `.env` and remove all inline comments:

```env
PORT=5000
FLASK_DEBUG=false
RATE_LIMIT=15
RATE_WINDOW=60
BLOCK_THRESHOLD=3
ADMIN_KEY=your_secret_key_here
```

---

## Running Locally

```bash
# Create virtual environment
python -m venv venv

# Activate — Linux/macOS
source venv/bin/activate

# Activate — Windows
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python app.py
```

Server starts at **http://localhost:5000**

---

## Docker Deployment

```bash
# Build the Docker image
docker build -t sentinel-shield .

# Run the container
docker run -d \
  --name sentinel \
  -p 8000:8000 \
  --env-file .env \
  sentinel-shield

# Check it is running
docker ps

# View logs
docker logs sentinel
```

Server starts at **http://localhost:8000**

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/inspect` | Submit request for WAF inspection |
| GET | `/dashboard` | Live JSON security statistics |
| GET | `/logs` | Recent log entries |
| GET | `/blocked-ips` | List currently blocked IPs |
| DELETE | `/blocked-ips/<ip>` | Unblock a specific IP |

### Example — test a SQL injection

**Windows PowerShell:**
```powershell
Invoke-WebRequest -Uri http://localhost:8000/inspect `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"method":"GET","path":"/search?q=1 UNION SELECT * FROM users--","ip":"192.168.1.100"}' `
  -UseBasicParsing -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Content
```

**Linux / macOS curl:**
```bash
curl -X POST http://localhost:8000/inspect \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/search?q=1 UNION SELECT * FROM users--","ip":"192.168.1.100"}'
```

### Example — view live dashboard

```bash
curl http://localhost:8000/dashboard
```

---

## Sample Output

### Blocked request (SQL injection)

```json
{
  "allowed": false,
  "reason": "Attack detected: SQL_INJECTION",
  "rules_hit": [
    {
      "id": "SQLI-001",
      "name": "Basic SQL injection",
      "category": "SQL_INJECTION",
      "severity": "CRITICAL"
    },
    {
      "id": "SQLI-003",
      "name": "SQL comment stripping",
      "category": "SQL_INJECTION",
      "severity": "MEDIUM"
    }
  ],
  "timestamp": "2026-05-25T04:21:57",
  "ip": "192.168.1.100"
}
```

### Allowed request (normal)

```json
{
  "allowed": true,
  "reason": "",
  "rules_hit": [],
  "timestamp": "2026-05-25T04:21:58",
  "ip": "10.0.0.1"
}
```

### Dashboard statistics

```json
{
  "summary": {
    "total": 36,
    "allowed": 14,
    "blocked": 22,
    "block_pct": 61.1
  },
  "categories": {
    "SQL_INJECTION": 8,
    "XSS": 5,
    "PATH_TRAVERSAL": 4,
    "BRUTE_FORCE": 3,
    "COMMAND_INJECTION": 2
  },
  "blocked_ips": ["10.99.99.99", "203.0.113.10"]
}
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Web framework | Flask 3.1 |
| WSGI server | Gunicorn 22 |
| Containerisation | Docker + Docker Compose |
| Reverse proxy | Nginx 1.27 |
| Pattern matching | Python `re` module |
| Logging | JSON lines format |
| Config | python-dotenv |

---

## Practical Workflow

This project follows a 6-step practical security workflow:

1. **System Architecture** — WAF, Analyzer, Logger, and Dashboard interaction
2. **Rule Definitions** — predefined attack signatures and severity levels
3. **Simulating HTTP Requests** — normal, malicious, and brute-force requests
4. **Observing Detection** — compare allowed vs blocked outcomes
5. **Log File Examination** — analyse `attack.log` and `traffic.log`
6. **Reporting and Analysis** — security dashboard with patterns and improvements

---

## Security Notice

- Never commit your `.env` file — it is excluded by `.gitignore`
- Change `ADMIN_KEY` before deploying to a public server
- The `/logs/clear` and `/blocked-ips` admin endpoints should be IP-restricted in production (see `nginx/sentinel.conf`)

---

*Sentinel Shield — Network Security Practical Project*
