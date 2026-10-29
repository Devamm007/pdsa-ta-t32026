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

A high-performance, secure web platform built with **FastAPI**, **SQLAlchemy** (Dual-mode: SQLite & Neon PostgreSQL), and modern glassmorphic Vanilla CSS/JS. Features deep AST and regex repository inspection, asynchronous background analysis queues with real-time progress tracking, holistic algorithmic ranking, interactive GitHub & DSA setup guides, past submission history backfill tutorials, personalized step/notes tracking, and cryptographic Google OAuth audit log controls.

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
- **High-Concurrency Bulk Upsert**: Utilizes dialect-specific atomic `ON CONFLICT DO NOTHING` (`pg_insert` on PostgreSQL / `sqlite_insert` on SQLite) with in-memory SHA-256 deduplication to guarantee zero primary key collision errors during concurrent repository scans.

---

## ⚡ Asynchronous Analysis Engine (v1.5)

Repository analysis runs entirely asynchronously in the background so HTTP requests never time out:

1. **Non-Blocking Background Worker**: When a user submits a repository, the server generates a unique `job_id`, records the task in `analysis_jobs`, and spawns an asynchronous worker task (`run_analysis_job`).
2. **Real-Time Polling & Stage Tracking**: The UI polls `/api/jobs/{job_id}` and updates a live progress indicator through 6 distinct stages:
   - `10%` — Verifying cache & repository
   - `20%` — Shallow cloning repository via Git (`--depth 50`)
   - `40%` — Scanning codebase & identifying genuine code files
   - `60%` — Classifying problems & analyzing algorithmic complexity
   - `75%` — Parsing git commits & timeline activity
   - `85%` — Computing calibrated holistic rank scores
   - `100%` — Complete & leaderboard updated
3. **Active Job Recovery**: Users can refresh or navigate across pages without losing progress; `/api/user/active-job` automatically re-binds the active progress bar upon re-login.

---

## 🧠 Deterministic Algorithmic Classifier (No LLM Required)

Repository analysis and classification are **100% deterministic, offline-capable, and code-based** — no external AI or LLM API calls are required:

1. **Strict Non-DSA Code Filtering**:
   - Skips build scripts, test suites, bundlers, and configuration files via `KNOWN_NON_DSA_FILENAMES` and `BUILD_AND_TOOL_PREFIXES`.
   - Prevents scanning non-code vendor directories (`node_modules`, `.venv`, `dist`, `.git`, `coverage`, etc.).
2. **Platform-Agnostic Candidate Detection (`is_dsa_candidate`)**:
   - Supports directory-per-problem layouts (LeetHub, LeetCode Sync, NeetCode, Striver, CP).
   - Supports flat repositories with numerical prefixes (e.g., `0001-two-sum.py`, `1. Two Sum.cpp`, `lc-15.py`).
   - Content signature fallback: inspects code for DSA constructs (`class Solution`, `ListNode`, `TreeNode`, `#include <bits/stdc++.h>`).
3. **Problem Catalog & Heuristic Fallback**:
   - **Canonical Catalog**: Direct O(1) lookup in `PROBLEM_CATALOG` for 150+ canonical LeetCode & NeetCode problems.
   - **Rule-Based Heuristic Classifier (`classify_problem_with_heuristics`)**: For problems outside the standard catalog, classifies topics (Trees, Graphs, DP, Sliding Window, etc.) and Big-O complexity via AST and code token pattern heuristics.
4. **Content Fingerprint Caching**:
   - Files are hashed with SHA-256. Unchanged solution files retrieve previously analyzed metadata directly from the database cache, skipping redundant classification.

---

## 🏆 Holistic Leaderboard & Ranking Methodology

Unlike naive commit-counting scripts that can be gamed by artificial commit spam, the Arena's **Holistic Analyzer** evaluates code structure, problem difficulty, and consistency over time:

1. **Unique Problem Deduplication:** Multiple attempts or submissions for the same problem (e.g. `submission-0.py`, `submission-4.py`) are collapsed into **1 unique solved problem**.
2. **Calibrated Difficulty Weights:**
   - **Easy:** 1.0 pt
   - **Medium:** 2.5 pts
   - **Hard:** 5.0 pts
3. **Anti-Burst Consistency Curve (Diminishing Burst Returns):**
   `Daily Credit = min(25, Daily Points)^0.72`
   - Solving 2 problems daily across 15 days yields a significantly higher score than dumping 30 problems in a single afternoon.
4. **Holistic Calibrated Multipliers:**
   - **Active Day Cadence Multiplier:** `1.0 + min(0.40, active_days * 0.03)` (up to +40%)
   - **Breadth Multiplier:** `1.0 + min(0.30, unique_problems * 0.015)` (up to +30%)
   - **Topic Diversity Bonus (+6%):** Rewarded for covering 3+ distinct DSA topics.
   - **Polyglot Multiplier (+5%):** Rewarded for multi-language solutions (e.g. Python + C++).
   - **Documentation Bonus (+4%):** Rewarded for algorithmic notes and README documentation.

---

## 🕒 Automated Refresh & Incremental Cache

1. **Scheduled Daily Sync at 7:00 PM IST (GMT +5:30)** — Background daemon automatically re-analyzes every registered repository to capture new commits.
2. **Zero Duplicate Work** — `analyzed_commits` and `analyzed_problems` tables cache inspected commits and file SHA-256 fingerprints, processing only net-new commits.
3. **Repository Management** — Authenticated users can manage or de-link their synced repository anytime through the user portal.

---

## 🛡️ Security Guardrails & Access Controls

1. **Mandatory Google OAuth for Submissions** — Repository submissions require Google OAuth token verification. Token audience and verified email status are strictly checked.
2. **Tamper-Proof HMAC-SHA256 Sessions** — Cryptographically signed session tokens with secure 7-day expiration cookies.
3. **Strict Audit Log Restrictions** — Live system audit logs (`/api/admin/audit-logs`) are restricted to authorized administrator accounts.
4. **Sandboxed Subprocess Execution** — Shallow git clones execute in ephemeral temporary directories with 60-second timeouts, disabled git hooks (`core.hooksPath=/dev/null`), and disabled symlinks (`core.symlinks=false`).
5. **Non-Root Docker User** — Docker containers execute under `appuser` (UID 1000) for security hardening.

---

## 🚀 Deployment & Local Development

### Environment Variables

| Variable | Required | Description |
| :--- | :--- | :--- |
| `GOOGLE_CLIENT_ID` | Recommended | Google OAuth 2.0 Web Client ID for user login and submissions. |
| `SESSION_SECRET` | Recommended | Random secret for HMAC-SHA256 session token signing. |
| `PRODUCTION` | Cloud Only | Set to `"true"` in production (enables Neon DB and HTTPS cookies). |
| `DATABASE_URL` | Cloud Only | PostgreSQL connection string (Neon DB pooled URL). |
| `FORCE_POSTGRES` | Optional | Set to `"true"` to test PostgreSQL locally instead of SQLite. |
| `PORT` | Optional | Port for the web server (defaults to `8000` locally, `7860` on HuggingFace). |
| `GEMINI_API_KEY` | Optional | Reserved placeholder for optional AI code explanation features. |

### Local Development Setup

```powershell
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start development server (uses local SQLite app.db automatically)
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

- **App URL**: `http://127.0.0.1:8000`
- **Health Check**: `http://127.0.0.1:8000/health` (displays `"database": "sqlite"` locally)

### HuggingFace Spaces (Docker)
This app runs as a Docker Space on HuggingFace. Configure the following environment secrets in Space settings:
- `GOOGLE_CLIENT_ID`
- `SESSION_SECRET`
- `PRODUCTION=true`
- `DATABASE_URL`

### Render (Docker)
Deploy directly using `render.yaml`. The blueprint configures:
- `PRODUCTION=true`
- `DATABASE_URL` (Neon DB pooled instance)
- Auto-generated `SESSION_SECRET`

---

## 📚 DSA & Git Playbook

Includes interactive guides and tools directly in the interface:
- **Interactive Git/GitHub Onboarding**: Step-by-step repository setup, credential management, and commit workflows.
- **Workflow Comparison**: In-depth comparison of NeetCode Auto-Sync vs LeetCode Extension vs Manual Git workflows.
- **Backfill Tutorials**: Instructions for syncing past submissions with preserved original timestamps.
- **Steps & Notes Journal**: Cloud-persisted checklist and personal algorithmic notes tracker.
