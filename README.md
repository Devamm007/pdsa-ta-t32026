---
title: DSA Challenge Arena
emoji: 🔥
colorFrom: indigo
colorTo: purple
sdk: docker
pinned: false
license: mit
short_description: Holistic LeetCode/NeetCode repository analyzer and leaderboard
---

# DSA Challenge Arena & GitHub Guides

A high-performance, secure web platform built with **FastAPI**, **SQLite**, and modern glassmorphic Vanilla CSS/JS. Features deep AST repository inspection, holistic algorithmic ranking, interactive GitHub & DSA setup guides, past submission history backfill tutorials, personalized step/notes tracking, and cryptographic Google OAuth audit log controls.

---

## 🗄️ Database Architecture (Dual Mode)

The application automatically adapts its database engine based on the execution environment:

| Environment | Database Backend | Storage | Configuration |
| :--- | :--- | :--- | :--- |
| **Local Development** | **SQLite** (`app.db`) | Zero-config local file | Automatic when `PRODUCTION=false` or unset. |
| **Production (Render / HuggingFace)** | **PostgreSQL** (Neon DB) | Serverless Neon pooler | Automatic when `PRODUCTION=true` or deployed to cloud. |

- **Local Development**: Runs out of the box with SQLite. No local Postgres server or credentials required.
- **Production Cloud**: Automatically connects to Neon PostgreSQL with connection pool pre-ping and recycle to gracefully handle serverless auto-suspension.
- **Optional Local Override**: Set `FORCE_POSTGRES=true` in `.env` if you want to test against Neon DB locally.

---

## 🚀 Deployment

### HuggingFace Spaces (Docker)
This app runs as a Docker Space on HuggingFace. Set the following secrets in your Space settings:
- `GOOGLE_CLIENT_ID` — Your Google OAuth 2.0 Web Client ID
- `SESSION_SECRET` — A strong random hex string (generate with `python -c "import secrets; print(secrets.token_hex(32))"`)
- `PRODUCTION` — Set to `"true"`
- `DATABASE_URL` — Your Neon DB connection string (optional fallback is pre-configured)

### Render (Docker)
Deploy using the included `render.yaml`. The Blueprint automatically configures:
- `PRODUCTION=true` (enabling Neon PostgreSQL & HTTPS cookie security)
- `DATABASE_URL` (pre-configured with Neon DB pooled instance)
- Auto-generated `SESSION_SECRET`

### Local Development
```powershell
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start development server (uses local SQLite app.db automatically)
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Open: **http://127.0.0.1:8000**
Health Check: **http://127.0.0.1:8000/health** (displays `"database": "sqlite"`)

---

## 🏆 Holistic Leaderboard & Ranking Methodology

Unlike naive commit-counting scripts that can be gamed by repeated attempts or synthetic commit spam, the Arena's **Holistic Analyzer** inspects the repository's code structure and commit cadence:

1. **Unique Problem Deduplication:** Multiple attempts or submissions for the same problem (e.g. `submission-0.py`, `submission-4.py`) are collapsed into **1 unique solved problem**.
2. **Calibrated Difficulty Weights:**
   - **Easy:** 1.0 pt
   - **Medium:** 2.5 pts
   - **Hard:** 5.0 pts
3. **Consistency Habit Curve (Diminishing Burst Returns):**
   - `Daily Credit = min(25, Daily Points) ^ 0.72`
   - Solving 2 problems daily across 15 days yields a vastly higher score than dumping 30 problems in a single afternoon.
4. **Holistic Multipliers:**
   - **Active Day Cadence Multiplier:** `1.0 + min(0.40, active_days × 0.025)`
   - **Breadth Multiplier:** `1.0 + min(0.30, unique_problems × 0.008)`
   - **Topic Diversity Bonus (+6%):** Rewarded for covering 4+ distinct DSA topics.
   - **Polyglot Multiplier (+5%):** Rewarded for multi-language solutions (e.g. Python + C++).
   - **Documentation Bonus (+6%):** Rewarded for algorithmic notes and READMEs.

---

## 🕒 24-Hour Automated Refresh & Incremental Commit Cache

1. **Scheduled Daily Sync at 7:00 PM IST (GMT +5:30)** — Background daemon automatically updates every registered repository.
2. **Zero Duplicate Work** — `analyzed_commits` and `analyzed_problems` SQLite tables cache all inspected commits and file SHA-256 fingerprints, ensuring no re-analysis of already-seen data.
3. **Repo-Agnostic Intelligent Classifier** — Supports arbitrary directory layouts, NeetCode sync format, LeetCode extension sync, and manual structured repositories.

---

## 🛡️ Security Guardrails & Access Controls

1. **Mandatory Google OAuth for Submissions** — Repository submissions require valid Google OAuth verification. Token audience and email verification enforced.
2. **Tamper-Proof HMAC-SHA256 Sessions** — Cryptographically signed session tokens with 7-day expiration.
3. **Strict Audit Log Restrictions** — Live system audit logs are strictly locked to authorized Google admin accounts.
4. **Sandboxed Subprocess Execution** — Ephemeral temp directories, 60-second timeouts, regex-sanitized URLs.
5. **Non-Root Docker User** — Container runs as `appuser` (UID 1000) for reduced attack surface.

---

## 📚 DSA & Git Playbook

Includes full interactive guides for Git/GitHub onboarding, curated YouTube video walkthroughs, workflow comparison (NeetCode Auto-Sync vs LeetCode Extension vs Manual Git), and a personal Steps & Notes journal with cloud sync.
