import os
import re
import math
import json
import time
import hmac
import base64
import hashlib
import asyncio
import logging
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set, Tuple
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator
from sqlalchemy import func
from sqlalchemy.orm import Session
import httpx
from dotenv import load_dotenv

# Load environment variables (.env with persistent SESSION_SECRET & DATABASE_URL)
load_dotenv()

# Import SQLAlchemy Models, Database Session, Init & Engine Info
from database import (
    get_db, init_db, User, Submission, UserNote, AnalyzedCommit, AnalyzedProblem,
    DB_BACKEND, IS_PRODUCTION
)

# Directories
BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Cloud-Native Logging (Captured directly by Render / HuggingFace stdout)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("dsa_challenge")
logger.info(f"Application initialized - Database Backend: {DB_BACKEND} (Production Mode: {IS_PRODUCTION}) & Holistic DSA Ranking active.")

# ---------------------------------------------------------------------------
# Config & Environment
# ---------------------------------------------------------------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")

# ---------------------------------------------------------------------------
# Authorized Administrators
# ---------------------------------------------------------------------------
ADMIN_EMAILS = {
    "shahdevam49@gmail.com",
    "24f2000828@ds.study.iitm.ac.in"
}

SESSION_SECRET = os.getenv("SESSION_SECRET", "")
if not SESSION_SECRET:
    import secrets
    SESSION_SECRET = secrets.token_hex(32)
    logger.warning("SESSION_SECRET not set in environment. Using a temporary random secret.")

# Concurrency & Rate Limiting Controls
ANALYSIS_SEMAPHORE = asyncio.Semaphore(2)
SUBMISSION_RATE_LIMITS: Dict[str, float] = {}
SUBMISSION_COOLDOWN_SECONDS = 15.0

def create_session_token(user_data: Dict[str, Any]) -> str:
    """Generate a tamper-proof cryptographically signed HMAC-SHA256 session token."""
    payload = {
        "sub": user_data.get("google_id") or user_data.get("id"),
        "email": user_data.get("email", "").lower().strip(),
        "name": user_data.get("name", "User"),
        "picture": user_data.get("picture", ""),
        "iat": int(time.time()),
        "exp": int(time.time()) + (7 * 24 * 3600)  # 7-day expiration
    }
    raw_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    b64_payload = base64.urlsafe_b64encode(raw_json).decode('utf-8').rstrip('=')
    sig = hmac.new(SESSION_SECRET.encode('utf-8'), b64_payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{sig}"

def verify_session_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Verify session token signature and check expiration."""
    if not token or "." not in token:
        return None
    try:
        last_dot = token.rfind(".")
        if last_dot == -1:
            return None
        b64_payload = token[:last_dot]
        signature = token[last_dot + 1:]

        expected_sig = hmac.new(SESSION_SECRET.encode('utf-8'), b64_payload.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            logger.warning("Session token verification failed: invalid HMAC signature")
            return None

        padded_b64 = b64_payload + "=" * ((4 - len(b64_payload) % 4) % 4)
        raw_json = base64.urlsafe_b64decode(padded_b64.encode('utf-8')).decode('utf-8')
        payload = json.loads(raw_json)

        if payload.get("exp", 0) < time.time():
            logger.warning(f"Session token expired for {payload.get('email')}")
            return None
        return payload
    except Exception as e:
        logger.error(f"Error parsing session token: {str(e)}")
        return None

def get_current_user_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """Extract authenticated user from Authorization header or Cookie."""
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "session_token" in request.cookies:
        token = request.cookies.get("session_token")

    if not token:
        return None
    return verify_session_token(token)

def require_authenticated_user(request: Request) -> Dict[str, Any]:
    """Ensure request has valid Google OAuth session."""
    user = get_current_user_from_request(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Google OAuth sign-in is mandatory to perform this action."
        )
    return user

def require_admin_user(request: Request) -> Dict[str, Any]:
    """Strictly enforce that user is authenticated via Google and is in ADMIN_EMAILS."""
    user = get_current_user_from_request(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Google OAuth sign-in is required to perform administrative actions."
        )

    email = user.get("email", "").lower().strip()
    if email not in ADMIN_EMAILS:
        logger.warning(f"Forbidden admin access attempt by: '{email}'")
        raise HTTPException(
            status_code=403,
            detail="Access Denied: Action restricted to authorized administrators."
        )
    return user

# Initialize database schema and benchmark seeds on startup
init_db()

# ---------------------------------------------------------------------------
# Problem Catalog & Repo-Agnostic Classifier
# ---------------------------------------------------------------------------
GITHUB_REPO_REGEX = re.compile(r"^https://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+?)(?:\.git|/)?$")

CODE_EXTENSIONS = {
    ".py": "Python", ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    ".java": "Java", ".js": "JavaScript", ".ts": "TypeScript",
    ".go": "Go", ".rs": "Rust", ".c": "C", ".cs": "C#"
}

PROBLEM_CATALOG: Dict[str, Tuple[str, str]] = {
    "two-sum": ("Easy", "Arrays & Hashing"),
    "two-integer-sum": ("Easy", "Arrays & Hashing"),
    "duplicate-integer": ("Easy", "Arrays & Hashing"),
    "contains-duplicate": ("Easy", "Arrays & Hashing"),
    "is-anagram": ("Easy", "Arrays & Hashing"),
    "valid-anagram": ("Easy", "Arrays & Hashing"),
    "concatenation-of-array": ("Easy", "Arrays & Hashing"),
    "longest-common-prefix": ("Easy", "Arrays & Hashing"),
    "replace-elements-with-greatest-element-on-right-side": ("Easy", "Arrays & Hashing"),
    "is-subsequence": ("Easy", "Arrays & Hashing"),
    "length-of-last-word": ("Easy", "Arrays & Hashing"),
    "pascals-triangle": ("Easy", "Arrays & Hashing"),
    "pascal-triangle": ("Easy", "Arrays & Hashing"),
    "anagram-groups": ("Medium", "Arrays & Hashing"),
    "group-anagrams": ("Medium", "Arrays & Hashing"),
    "top-k-elements-in-list": ("Medium", "Arrays & Hashing"),
    "top-k-frequent-elements": ("Medium", "Arrays & Hashing"),
    "string-encode-and-decode": ("Medium", "Arrays & Hashing"),
    "encode-and-decode-strings": ("Medium", "Arrays & Hashing"),
    "products-of-array-discluding-self": ("Medium", "Arrays & Hashing"),
    "product-of-array-except-self": ("Medium", "Arrays & Hashing"),
    "valid-sudoku": ("Medium", "Arrays & Hashing"),
    "longest-consecutive-sequence": ("Medium", "Arrays & Hashing"),
    "is-palindrome": ("Easy", "Two Pointers"),
    "valid-palindrome": ("Easy", "Two Pointers"),
    "two-integer-sum-ii": ("Medium", "Two Pointers"),
    "two-sum-ii-input-array-is-sorted": ("Medium", "Two Pointers"),
    "three-integer-sum": ("Medium", "Two Pointers"),
    "3sum": ("Medium", "Two Pointers"),
    "max-water-container": ("Medium", "Two Pointers"),
    "container-with-most-water": ("Medium", "Two Pointers"),
    "trapping-rain-water": ("Hard", "Two Pointers"),
    "best-time-to-buy-and-sell-stock": ("Easy", "Sliding Window"),
    "longest-substring-without-duplicates": ("Medium", "Sliding Window"),
    "longest-substring-without-repeating-characters": ("Medium", "Sliding Window"),
    "longest-repeating-substring-with-replacement": ("Medium", "Sliding Window"),
    "longest-repeating-character-replacement": ("Medium", "Sliding Window"),
    "permutation-string": ("Medium", "Sliding Window"),
    "permutation-in-string": ("Medium", "Sliding Window"),
    "minimum-window-with-characters": ("Hard", "Sliding Window"),
    "minimum-window-substring": ("Hard", "Sliding Window"),
    "sliding-window-maximum": ("Hard", "Sliding Window"),
    "validate-parentheses": ("Easy", "Stack"),
    "valid-parentheses": ("Easy", "Stack"),
    "minimum-stack": ("Medium", "Stack"),
    "min-stack": ("Medium", "Stack"),
    "evaluate-reverse-polish-notation": ("Medium", "Stack"),
    "generate-parentheses": ("Medium", "Stack"),
    "daily-temperatures": ("Medium", "Stack"),
    "car-fleet": ("Medium", "Stack"),
    "largest-rectangle-in-histogram": ("Hard", "Stack"),
    "binary-search": ("Easy", "Binary Search"),
    "search-2d-matrix": ("Medium", "Binary Search"),
    "search-a-2d-matrix": ("Medium", "Binary Search"),
    "koko-eating-bananas": ("Medium", "Binary Search"),
    "find-minimum-in-rotated-sorted-array": ("Medium", "Binary Search"),
    "find-target-in-rotated-sorted-array": ("Medium", "Binary Search"),
    "search-in-rotated-sorted-array": ("Medium", "Binary Search"),
    "time-based-key-value-store": ("Medium", "Binary Search"),
    "median-of-two-sorted-arrays": ("Hard", "Binary Search"),
    "reverse-a-linked-list": ("Easy", "Linked List"),
    "reverse-linked-list": ("Easy", "Linked List"),
    "merge-two-sorted-linked-lists": ("Easy", "Linked List"),
    "merge-two-sorted-lists": ("Easy", "Linked List"),
    "linked-list-cycle-detection": ("Easy", "Linked List"),
    "linked-list-cycle": ("Easy", "Linked List"),
    "reorder-linked-list": ("Medium", "Linked List"),
    "reorder-list": ("Medium", "Linked List"),
    "add-two-numbers": ("Medium", "Linked List"),
    "find-the-duplicate-number": ("Medium", "Linked List"),
    "lru-cache": ("Medium", "Linked List"),
    "merge-k-sorted-linked-lists": ("Hard", "Linked List"),
    "merge-k-sorted-lists": ("Hard", "Linked List"),
    "reverse-nodes-in-k-group": ("Hard", "Linked List"),
    "invert-a-binary-tree": ("Easy", "Trees"),
    "invert-binary-tree": ("Easy", "Trees"),
    "maximum-depth-of-binary-tree": ("Easy", "Trees"),
    "diameter-of-binary-tree": ("Easy", "Trees"),
    "balanced-binary-tree": ("Easy", "Trees"),
    "same-binary-tree": ("Easy", "Trees"),
    "same-tree": ("Easy", "Trees"),
    "subtree-of-a-binary-tree": ("Easy", "Trees"),
    "subtree-of-another-tree": ("Easy", "Trees"),
    "lowest-common-ancestor-in-binary-search-tree": ("Medium", "Trees"),
    "level-order-traversal-of-binary-tree": ("Medium", "Trees"),
    "binary-tree-level-order-traversal": ("Medium", "Trees"),
    "binary-tree-right-side-view": ("Medium", "Trees"),
    "count-good-nodes-in-binary-tree": ("Medium", "Trees"),
    "valid-binary-search-tree": ("Medium", "Trees"),
    "validate-binary-search-tree": ("Medium", "Trees"),
    "kth-smallest-integer-in-bst": ("Medium", "Trees"),
    "construct-binary-tree-from-preorder-and-inorder-traversal": ("Medium", "Trees"),
    "binary-tree-maximum-path-sum": ("Hard", "Trees"),
    "serialize-and-deserialize-binary-tree": ("Hard", "Trees"),
    "implement-trie-prefix-tree": ("Medium", "Tries"),
    "design-add-and-search-words-data-structure": ("Medium", "Tries"),
    "word-search-ii": ("Hard", "Tries"),
    "kth-largest-element-in-a-stream": ("Easy", "Heap"),
    "last-stone-weight": ("Easy", "Heap"),
    "k-closest-points-to-origin": ("Medium", "Heap"),
    "kth-largest-element-in-an-array": ("Medium", "Heap"),
    "task-scheduler": ("Medium", "Heap"),
    "find-median-from-data-stream": ("Hard", "Heap"),
    "subsets": ("Medium", "Backtracking"),
    "combination-target-sum": ("Medium", "Backtracking"),
    "combination-sum": ("Medium", "Backtracking"),
    "permutations": ("Medium", "Backtracking"),
    "subsets-ii": ("Medium", "Backtracking"),
    "word-search": ("Medium", "Backtracking"),
    "palindrome-partitioning": ("Medium", "Backtracking"),
    "n-queens": ("Hard", "Backtracking"),
    "number-of-islands": ("Medium", "Graphs"),
    "max-area-of-island": ("Medium", "Graphs"),
    "clone-graph": ("Medium", "Graphs"),
    "rotting-fruit": ("Medium", "Graphs"),
    "rotting-oranges": ("Medium", "Graphs"),
    "course-schedule": ("Medium", "Graphs"),
    "course-schedule-ii": ("Medium", "Graphs"),
    "word-ladder": ("Hard", "Graphs"),
    "climbing-stairs": ("Easy", "Dynamic Programming"),
    "min-cost-climbing-stairs": ("Easy", "Dynamic Programming"),
    "house-robber": ("Medium", "Dynamic Programming"),
    "house-robber-ii": ("Medium", "Dynamic Programming"),
    "coin-change": ("Medium", "Dynamic Programming"),
    "maximum-product-subarray": ("Medium", "Dynamic Programming"),
    "word-break": ("Medium", "Dynamic Programming"),
    "longest-increasing-subsequence": ("Medium", "Dynamic Programming"),
    "unique-paths": ("Medium", "Dynamic Programming"),
    "longest-common-subsequence": ("Medium", "Dynamic Programming"),
    "edit-distance": ("Medium", "Dynamic Programming"),
    "burst-balloons": ("Hard", "Dynamic Programming"),
    "maximum-subarray": ("Medium", "Greedy"),
    "jump-game": ("Medium", "Greedy"),
    "insert-interval": ("Medium", "Intervals"),
    "merge-intervals": ("Medium", "Intervals"),
    "single-number": ("Easy", "Bit Manipulation"),
    "number-of-1-bits": ("Easy", "Bit Manipulation"),
    "counting-bits": ("Easy", "Bit Manipulation"),
    "reverse-bits": ("Easy", "Bit Manipulation"),
}

CANONICAL_ALIASES = {
    "0001-two-sum": "two-sum",
    "0002-add-two-numbers": "add-two-numbers",
    "0003-longest-substring-without-repeating-characters": "longest-substring-without-repeating-characters",
    "0020-valid-parentheses": "valid-parentheses",
    "0021-merge-two-sorted-lists": "merge-two-sorted-lists",
    "0023-merge-k-sorted-lists": "merge-k-sorted-lists",
    "0033-search-in-rotated-sorted-array": "search-in-rotated-sorted-array",
    "0042-trapping-rain-water": "trapping-rain-water",
    "0070-climbing-stairs": "climbing-stairs",
    "0121-best-time-to-buy-and-sell-stock": "best-time-to-buy-and-sell-stock",
    "0125-valid-palindrome": "valid-palindrome",
    "0141-linked-list-cycle": "linked-list-cycle",
    "0206-reverse-linked-list": "reverse-linked-list",
    "0217-contains-duplicate": "contains-duplicate",
    "0242-valid-anagram": "valid-anagram",
}

def is_genuine_code_file(filepath: str, ext: str) -> bool:
    """Validate that the file contains actual runnable DSA code."""
    try:
        size = os.path.getsize(filepath)
        if size < 35 or size > 500 * 1024:
            return False

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]

        if len(lines) < 3:
            return False

        code_lines = 0
        for l in lines:
            if l.startswith("#") or l.startswith("//") or l.startswith("/*") or l.startswith("*"):
                continue
            if l.startswith('"""') or l.startswith("'''"):
                continue
            code_lines += 1

        if code_lines < 2:
            return False
        return True
    except Exception:
        return False

def sanitize_github_url(raw_url: str) -> Optional[str]:
    match = GITHUB_REPO_REGEX.match(raw_url.strip())
    if not match:
        return None
    owner, repo = match.groups()
    if owner.startswith("-") or repo.startswith("-"):
        return None
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{owner}/{repo}"

def normalize_slug(raw_name: str) -> str:
    cleaned = re.sub(r"^\d+[\-_.]*", "", raw_name.strip().lower())
    cleaned = re.sub(r"[\W_]+", "-", cleaned).strip("-")
    return CANONICAL_ALIASES.get(cleaned, cleaned)

def compute_file_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def classify_problem_with_heuristics(code_text: str, slug: str, file_path_str: str) -> Dict[str, str]:
    """Repo-agnostic AST and pattern classifier when file is not in standard LeetCode catalog."""
    code_lower = code_text.lower()
    path_lower = file_path_str.lower()

    # Determine topic
    topic = "General DSA"
    if any(k in code_lower or k in path_lower for k in ["dp[", "memo", "tabulation", "fibonacci", "knapsack", "longest common", "coin_change"]):
        topic = "Dynamic Programming"
    elif any(k in code_lower or k in path_lower for k in ["dijkstra", "bfs", "dfs", "graph", "adj[", "visited", "cycle", "topo", "bellman"]):
        topic = "Graphs"
    elif any(k in code_lower or k in path_lower for k in ["treenode", "inorder", "preorder", "postorder", "binary tree", "bst", "lca"]):
        topic = "Trees"
    elif any(k in code_lower or k in path_lower for k in ["linkedlist", "listnode", "next.next", "prev", "head", "tail"]):
        topic = "Linked List"
    elif any(k in code_lower or k in path_lower for k in ["sliding", "window", "left < right", "two_pointer", "twopointer"]):
        topic = "Two Pointers & Sliding Window"
    elif any(k in code_lower or k in path_lower for k in ["binary_search", "binarysearch", "bisect", "low <= high", "mid ="]):
        topic = "Binary Search"
    elif any(k in code_lower or k in path_lower for k in ["heapq", "priorityqueue", "max_heap", "min_heap"]):
        topic = "Heap / Priority Queue"
    elif any(k in code_lower or k in path_lower for k in ["backtrack", "permutations", "combinations", "n_queens", "sudoku"]):
        topic = "Backtracking"
    elif any(k in code_lower or k in path_lower for k in ["trie", "segment_tree", "fenwick", "bit_tree"]):
        topic = "Advanced Data Structures"
    elif any(k in code_lower or k in path_lower for k in ["hash", "dict", "map", "set", "anagram", "frequency"]):
        topic = "Arrays & Hashing"

    # Determine difficulty based on complexity patterns
    difficulty = "Medium"
    time_comp = "O(N)"
    space_comp = "O(N)"

    if "hard" in path_lower or any(k in code_lower for k in ["segment_tree", "fenwick", "tarjan", "flow", "triplet", "n_queens", "k-group", "alien_dict"]):
        difficulty = "Hard"
        time_comp = "O(N^2)"
        space_comp = "O(N)"
    elif "easy" in path_lower or (len(code_text.splitlines()) < 25 and not any(k in code_lower for k in ["recursion", "dfs", "dp[", "matrix"])):
        difficulty = "Easy"
        time_comp = "O(N)"
        space_comp = "O(1)"
    else:
        difficulty = "Medium"
        time_comp = "O(N log N)"
        space_comp = "O(N)"

    clean_name = slug.replace("-", " ").replace("_", " ").title()
    return {
        "problem_slug": slug,
        "problem_name": clean_name or "Custom DSA Problem",
        "difficulty": difficulty,
        "topic": topic,
        "time_complexity": time_comp,
        "space_complexity": space_comp,
        "analysis_source": "heuristic"
    }

def get_or_classify_problem_info(file_path: str, slug: str, session: Session) -> Dict[str, str]:
    """Retrieve problem analysis from SQLAlchemy / Neon cache or run repo-agnostic classifier."""
    file_sha = compute_file_sha256(file_path)

    # 1. Check database cache
    cached = session.query(AnalyzedProblem).filter(AnalyzedProblem.file_sha256 == file_sha).first()
    if cached:
        return {
            "problem_slug": cached.problem_slug,
            "problem_name": cached.problem_name,
            "difficulty": cached.difficulty,
            "topic": cached.topic,
            "time_complexity": cached.time_complexity,
            "space_complexity": cached.space_complexity,
            "analysis_source": cached.analysis_source
        }

    # 2. Check canonical catalogue
    if slug in PROBLEM_CATALOG:
        diff, top = PROBLEM_CATALOG[slug]
        info = {
            "problem_slug": slug,
            "problem_name": slug.replace("-", " ").title(),
            "difficulty": diff,
            "topic": top,
            "time_complexity": "O(N)" if diff == "Easy" else ("O(N log N)" if diff == "Medium" else "O(N^2)"),
            "space_complexity": "O(1)" if diff == "Easy" else "O(N)",
            "analysis_source": "catalog"
        }
    else:
        # 3. Run repo-agnostic code analysis
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code_text = f.read(5000)
        except Exception:
            code_text = ""
        info = classify_problem_with_heuristics(code_text, slug, file_path)

    # Cache into Neon DB / SQLAlchemy
    new_prob = AnalyzedProblem(
        file_sha256=file_sha,
        problem_slug=info["problem_slug"],
        problem_name=info["problem_name"],
        difficulty=info["difficulty"],
        topic=info["topic"],
        time_complexity=info["time_complexity"],
        space_complexity=info["space_complexity"],
        analysis_source=info["analysis_source"]
    )
    session.merge(new_prob)
    return info

# ---------------------------------------------------------------------------
# Holistic Incremental Repository Analyzer
# ---------------------------------------------------------------------------
def analyze_repo_holistic(repo_url: str) -> Dict[str, Any]:
    """
    Incremental Holistic Analysis:
    1. Shallow-clones repo using secure git parameters and size limits.
    2. Validates genuine code files, ignoring empty stubs, comments, and automated templates.
    3. Analyzes git commit history with file associations.
    4. Caches problem fingerprints in Neon DB via SQLAlchemy.
    5. Computes calibrated consistency score and problem difficulty points.
    6. Ensures repos with zero code files receive 0 points and 0 solved problems.
    """
    clean_url = sanitize_github_url(repo_url)
    if not clean_url:
        logger.warning(f"Rejected invalid repo URL: {repo_url}")
        raise ValueError("Invalid GitHub repository URL format. Example: https://github.com/username/repository")

    logger.info(f"Starting incremental holistic analysis for: {clean_url}")

    with get_db() as session:
        # Query already-seen commits for this repo
        seen_rows = session.query(AnalyzedCommit).filter(AnalyzedCommit.repo_url == clean_url).all()
        seen_commits_db: Dict[str, Tuple[str, str]] = {r.commit_hash: (r.commit_date or "", r.commit_message or "") for r in seen_rows}
        logger.info(f"Loaded {len(seen_commits_db)} previously analyzed commits from cache for {clean_url}")

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                subprocess.run(
                    ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "clone", "--depth", "50", "--single-branch", "--no-tags", clean_url, temp_dir],
                    check=True,
                    capture_output=True,
                    timeout=45
                )
            except subprocess.TimeoutExpired:
                logger.error(f"Clone timed out for {clean_url}")
                raise RuntimeError("Repository clone timed out (45s). Please ensure the repository is public and accessible.")
            except subprocess.CalledProcessError as e:
                err_msg = e.stderr.decode('utf-8', errors='ignore') if e.stderr else "Git error"
                logger.error(f"Git clone error for {clean_url}: {err_msg}")
                raise RuntimeError("Failed to clone repository. Please check if the repository URL is public and valid.")

            # Security check: Enforce maximum repository disk size (50 MB)
            total_size = sum(
                os.path.getsize(os.path.join(dirpath, filename))
                for dirpath, _, filenames in os.walk(temp_dir)
                for filename in filenames
            )
            if total_size > 50 * 1024 * 1024:
                logger.warning(f"Repository {clean_url} exceeded 50MB size limit ({total_size} bytes). Rejected.")
                raise RuntimeError("Repository size exceeds the 50 MB security limit for automated analysis.")

            # --- Phase 1: File Analysis with SQLAlchemy Cache & Strict Code Validation ---
            detected_problems: Dict[str, Dict[str, Any]] = {}
            detected_languages: Set[str] = set()
            has_documentation = False

            for root, dirs, files in os.walk(temp_dir):
                if ".git" in root.split(os.sep):
                    continue

                for f in files:
                    ext = Path(f).suffix.lower()
                    stem = Path(f).stem.lower()
                    file_path = os.path.join(root, f)

                    if ext in CODE_EXTENSIONS:
                        if not is_genuine_code_file(file_path, ext):
                            continue

                        lang = CODE_EXTENSIONS[ext]
                        detected_languages.add(lang)

                        parent_dir = Path(root).name.lower()
                        slug = ""
                        if parent_dir and parent_dir != Path(temp_dir).name.lower() and not parent_dir.startswith("sub") and parent_dir != "data structures & algorithms":
                            slug = normalize_slug(parent_dir)
                        else:
                            slug = normalize_slug(stem)

                        if slug and len(slug) >= 3:
                            p_info = get_or_classify_problem_info(file_path, slug, session)
                            if slug not in detected_problems:
                                detected_problems[slug] = {
                                    "slug": slug,
                                    "name": p_info["problem_name"],
                                    "difficulty": p_info["difficulty"],
                                    "topic": p_info["topic"],
                                    "time_complexity": p_info["time_complexity"],
                                    "space_complexity": p_info["space_complexity"],
                                    "source": p_info["analysis_source"],
                                    "languages": set()
                                }
                            detected_problems[slug]["languages"].add(lang)

                    elif ext == ".md" and f.lower() not in {"license.md"}:
                        has_documentation = True

            # --- Phase 2: Git Commit Parsing with Code-File Associations ---
            try:
                log_proc = subprocess.run(
                    ["git", "-C", temp_dir, "log", "--pretty=format:COMMIT:%H|%ad|%s", "--name-only", "--date=short"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=True
                )
            except Exception as e:
                logger.error(f"Error reading git log for {clean_url}: {str(e)}")
                raise RuntimeError("Failed to parse git commits from repository.")

            new_commits_to_insert = []
            daily_code_days: Set[str] = set()
            daily_problems_map: Dict[str, Set[str]] = {}
            current_commit = None

            for line in log_proc.stdout.split("\n"):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("COMMIT:"):
                    parts = line[7:].split("|", 2)
                    if len(parts) == 3:
                        c_hash, c_date, c_msg = parts
                        current_commit = (c_hash, c_date, c_msg)
                        if c_hash not in seen_commits_db:
                            new_commits_to_insert.append((c_hash, clean_url, c_date, c_msg))
                elif current_commit:
                    ext = Path(line).suffix.lower()
                    if ext in CODE_EXTENSIONS:
                        c_hash, c_date, c_msg = current_commit
                        daily_code_days.add(c_date)
                        if c_date not in daily_problems_map:
                            daily_problems_map[c_date] = set()
                        matched = None
                        for s in detected_problems:
                            if s in c_msg.lower() or s in line.lower() or s.replace("-", " ") in c_msg.lower():
                                matched = s
                                break
                        if matched:
                            daily_problems_map[c_date].add(matched)
                        else:
                            daily_problems_map[c_date].add(f"code_{len(daily_problems_map[c_date])}")

            # Insert new commits into database
            for c_hash, c_url, c_date, c_msg in new_commits_to_insert:
                session.merge(AnalyzedCommit(
                    commit_hash=c_hash,
                    repo_url=c_url,
                    commit_date=c_date,
                    commit_message=c_msg
                ))
            if new_commits_to_insert:
                logger.info(f"Recorded {len(new_commits_to_insert)} new unique commits into cache for {clean_url}")

            # --- Phase 3: Mathematical Holistic Ranking ---
            total_unique = len(detected_problems)

            if total_unique == 0:
                final_score = 0.0
                active_days = 0
                easy_count = 0
                medium_count = 0
                hard_count = 0
                consistency_base = 0.0
                problem_difficulty_pts = 0.0
                active_day_mult = 1.0
                breadth_mult = 1.0
                topic_mult = 1.0
                doc_mult = 1.0
                polyglot_mult = 1.0
                problem_summary_list = []
                topics_covered = set()
                logger.warning(f"Repository {clean_url} has 0 verifiable DSA solutions. Evaluated score: 0.00")
            else:
                easy_count = sum(1 for p in detected_problems.values() if p["difficulty"] == "Easy")
                medium_count = sum(1 for p in detected_problems.values() if p["difficulty"] == "Medium")
                hard_count = sum(1 for p in detected_problems.values() if p["difficulty"] == "Hard")

                problem_difficulty_pts = (easy_count * 1.0) + (medium_count * 2.5) + (hard_count * 5.0)

                # Anti-burst consistency points: (Daily Pts)^0.72 capped at 25 pts/day
                consistency_base = 0.0
                for dt, pset in daily_problems_map.items():
                    pts_day = 0.0
                    for item in pset:
                        if item in detected_problems:
                            diff = detected_problems[item]["difficulty"]
                            pts_day += 1.0 if diff == "Easy" else (2.5 if diff == "Medium" else 5.0)
                        else:
                            pts_day += 1.0
                    pts_day = min(25.0, pts_day)
                    consistency_base += math.pow(pts_day, 0.72)

                active_days = max(1, len(daily_code_days))
                active_day_mult = 1.0 + min(0.40, active_days * 0.03)
                breadth_mult = 1.0 + min(0.30, total_unique * 0.015)
                doc_mult = 1.04 if has_documentation else 1.00
                polyglot_mult = 1.05 if len(detected_languages) > 1 else 1.00

                topics_covered = {p["topic"] for p in detected_problems.values()}
                topic_mult = 1.06 if len(topics_covered) >= 3 else 1.00

                raw_composite = (0.50 * consistency_base * active_day_mult) + (0.50 * problem_difficulty_pts)
                final_score = round(raw_composite * breadth_mult * doc_mult * polyglot_mult * topic_mult, 2)

                problem_summary_list = []
                for p in detected_problems.values():
                    problem_summary_list.append({
                        "slug": p["slug"],
                        "name": p["name"],
                        "difficulty": p["difficulty"],
                        "topic": p["topic"],
                        "time_complexity": p["time_complexity"],
                        "space_complexity": p["space_complexity"],
                        "source": p["source"],
                        "languages": list(p["languages"])
                    })

            repo_name = "/".join(clean_url.split("/")[-2:])
            result = {
                "name": repo_name,
                "clean_url": clean_url,
                "score": final_score,
                "problems": total_unique,
                "active_days": active_days,
                "easy_count": easy_count,
                "medium_count": medium_count,
                "hard_count": hard_count,
                "languages": ", ".join(sorted(detected_languages)) or "None",
                "topics_covered": ", ".join(sorted(topics_covered)) or "None",
                "breakdown": {
                    "no_code_detected": bool(total_unique == 0),
                    "consistency_score": round(consistency_base, 2),
                    "raw_difficulty_points": round(problem_difficulty_pts, 2),
                    "active_days": active_days,
                    "multipliers": {
                        "active_day_multiplier": round(active_day_mult, 2),
                        "breadth_multiplier": round(breadth_mult, 2),
                        "topic_bonus": topic_mult,
                        "doc_bonus": doc_mult,
                        "polyglot_bonus": polyglot_mult
                    },
                    "problem_sample": problem_summary_list[:20]
                }
            }
            logger.info(f"Incremental analysis complete for {clean_url}: Score={final_score}, Unique={total_unique}")
            return result

# ---------------------------------------------------------------------------
# 24-Hour Scheduled Background Worker (GMT +5:30 at 7:00 PM)
# ---------------------------------------------------------------------------
def get_seconds_until_next_ist_7pm() -> Tuple[float, datetime, datetime]:
    """Calculate seconds until next 7:00 PM in Indian Standard Time (GMT+5:30)."""
    ist_offset = timedelta(hours=5, minutes=30)
    now_utc = datetime.now(timezone.utc)
    now_ist = now_utc + ist_offset

    target_ist = now_ist.replace(hour=19, minute=0, second=0, microsecond=0)
    if now_ist >= target_ist:
        target_ist += timedelta(days=1)

    diff = (target_ist - now_ist).total_seconds()
    return diff, now_ist, target_ist

async def run_scheduled_refresh_all_repos() -> int:
    """Incrementally analyze and update all registered active repositories."""
    logger.info("Executing scheduled refresh for all registered repositories...")
    with get_db() as session:
        active_submissions = session.query(Submission.repo_url).filter(Submission.is_deleted == 0).all()
        repo_urls = [row[0] for row in active_submissions]

    updated_count = 0
    for url in repo_urls:
        try:
            stats = await asyncio.to_thread(analyze_repo_holistic, url)
            with get_db() as session:
                sub = session.query(Submission).filter(Submission.repo_url == url).first()
                if sub:
                    sub.score = stats["score"]
                    sub.problems = stats["problems"]
                    sub.active_days = stats["active_days"]
                    sub.easy_count = stats["easy_count"]
                    sub.medium_count = stats["medium_count"]
                    sub.hard_count = stats["hard_count"]
                    sub.languages = stats["languages"]
                    sub.topics_covered = stats["topics_covered"]
                    sub.breakdown_json = json.dumps(stats["breakdown"])
                    sub.updated_at = datetime.utcnow()
                    updated_count += 1
        except Exception as e:
            logger.error(f"Error during scheduled refresh for {url}: {str(e)}")

    logger.info(f"Scheduled 7:00 PM IST refresh completed. Refreshed {updated_count}/{len(repo_urls)} repositories.")
    return updated_count

async def daily_scheduler_loop():
    """Background daemon sleeping until 7:00 PM IST (GMT+5:30) and running daily refresh."""
    while True:
        try:
            diff_secs, now_ist, target_ist = get_seconds_until_next_ist_7pm()
            logger.info(f"Daily scheduler armed: Next update in {int(diff_secs // 3600)}h {int((diff_secs % 3600) // 60)}m at {target_ist.strftime('%Y-%m-%d 19:00:00 IST')}")
            await asyncio.sleep(diff_secs)

            logger.info("7:00 PM IST reached! Launching automated daily repository analysis...")
            await run_scheduled_refresh_all_repos()
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            logger.info("Daily scheduler background task received cancel signal.")
            break
        except Exception as e:
            logger.error(f"Unexpected error in daily scheduler: {str(e)}")
            await asyncio.sleep(300)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Launch background scheduler
    scheduler_task = asyncio.create_task(daily_scheduler_loop())
    yield
    # Shutdown
    scheduler_task.cancel()
    try:
        await scheduler_task
    except asyncio.CancelledError:
        pass

# ---------------------------------------------------------------------------
# FastAPI App Initialization
# ---------------------------------------------------------------------------
app = FastAPI(
    title="DSA Challenge Arena",
    description="Holistic DSA repository ranking with Google OAuth and 24h incremental scheduled updates.",
    version="2.4.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ---------------------------------------------------------------------------
# API Models
# ---------------------------------------------------------------------------
class GoogleAuthRequest(BaseModel):
    credential: str

    @field_validator("credential")
    @classmethod
    def credential_must_be_nonempty(cls, v: str) -> str:
        if not v or len(v) < 10:
            raise ValueError("Invalid Google credential token")
        return v

class SubmitRepoRequest(BaseModel):
    repo_url: str

    @field_validator("repo_url")
    @classmethod
    def repo_url_must_be_github(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://github.com/"):
            raise ValueError("URL must be a valid GitHub repository URL")
        if len(v) > 200:
            raise ValueError("URL too long")
        return v

class UserStepsRequest(BaseModel):
    steps_json: str
    notes_markdown: str

    @field_validator("notes_markdown")
    @classmethod
    def notes_max_length(cls, v: str) -> str:
        if len(v) > 50000:
            raise ValueError("Notes content too large (max 50,000 characters)")
        return v

    @field_validator("steps_json")
    @classmethod
    def steps_max_length(cls, v: str) -> str:
        if len(v) > 5000:
            raise ValueError("Steps JSON too large")
        return v

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"google_client_id": client_id}
    )

@app.get("/health")
async def health_check():
    """Health check endpoint for Render, HuggingFace, and uptime monitors."""
    return {
        "status": "ok",
        "version": "2.4.0",
        "database": DB_BACKEND,
        "is_production": IS_PRODUCTION
    }

@app.get("/api/config")
async def get_config():
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    return {
        "google_client_id": client_id,
        "is_google_configured": bool(client_id and client_id != "YOUR_GOOGLE_CLIENT_ID_HERE"),
        "admin_emails": list(ADMIN_EMAILS)
    }

@app.get("/api/schedule/status")
async def get_schedule_status():
    """Return live status of the 7:00 PM IST (GMT+5:30) daily refresh."""
    diff_secs, now_ist, target_ist = get_seconds_until_next_ist_7pm()
    return {
        "timezone": "GMT+5:30 (IST)",
        "target_time": "19:00:00 (7:00 PM IST)",
        "current_time_ist": now_ist.strftime("%Y-%m-%d %H:%M:%S IST"),
        "next_run_ist": target_ist.strftime("%Y-%m-%d 19:00:00 IST"),
        "seconds_remaining": int(diff_secs),
        "hours_remaining": int(diff_secs // 3600),
        "minutes_remaining": int((diff_secs % 3600) // 60)
    }

@app.post("/api/admin/trigger-refresh")
async def admin_trigger_refresh(request: Request):
    """Allow authorized Google admins to manually trigger the incremental refresh immediately."""
    admin_user = require_admin_user(request)
    admin_email = admin_user["email"]
    logger.info(f"Manual repository refresh triggered by authorized admin: {admin_email}")
    updated_count = await run_scheduled_refresh_all_repos()
    return {
        "success": True,
        "message": f"Successfully executed incremental refresh for {updated_count} repositories.",
        "updated_count": updated_count
    }

@app.post("/api/auth/google")
async def auth_google(payload: GoogleAuthRequest, request: Request):
    token = payload.credential
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={token}")
            if resp.status_code != 200:
                logger.warning(f"Google token verification failed: {resp.status_code}")
                raise HTTPException(status_code=401, detail="Invalid Google ID token. Please try signing in again.")

            user_info = resp.json()

            token_aud = user_info.get("aud", "")
            if client_id and token_aud != client_id:
                logger.warning(f"Google token audience mismatch: expected {client_id}, got {token_aud}")
                raise HTTPException(status_code=401, detail="Token audience mismatch. Please sign in again.")

            exp = int(user_info.get("exp", 0))
            if exp < int(time.time()):
                raise HTTPException(status_code=401, detail="Google token has expired. Please sign in again.")

            google_id = user_info.get("sub")
            email = user_info.get("email", "").lower().strip()
            name = user_info.get("name", email.split("@")[0] if email else "User")
            picture = user_info.get("picture", "")

            if not google_id or not email:
                raise HTTPException(status_code=401, detail="Incomplete user information from Google.")

            if not user_info.get("email_verified", False):
                raise HTTPException(status_code=401, detail="Google account email is not verified.")

            # Record or update user in Neon DB / SQLAlchemy
            with get_db() as session:
                existing_user = session.query(User).filter(User.email == email).first()
                if existing_user:
                    existing_user.name = name
                    existing_user.picture = picture
                    existing_user.last_login = datetime.utcnow()
                    if google_id:
                        existing_user.google_id = google_id
                else:
                    new_user = User(
                        google_id=google_id,
                        email=email,
                        name=name,
                        picture=picture,
                        last_login=datetime.utcnow()
                    )
                    session.add(new_user)

            is_admin = email in ADMIN_EMAILS
            user_data = {
                "google_id": google_id,
                "email": email,
                "name": name,
                "picture": picture,
                "is_admin": is_admin
            }
            session_token = create_session_token(user_data)
            logger.info(f"User authenticated via Google OAuth: {email} (Admin: {is_admin})")

            proto = request.headers.get("x-forwarded-proto", request.url.scheme)
            is_secure = bool(IS_PRODUCTION or proto == "https")

            response = JSONResponse(content={
                "success": True,
                "token": session_token,
                "user": user_data
            })
            response.set_cookie(
                key="session_token",
                value=session_token,
                httponly=True,
                secure=is_secure,
                samesite="lax",
                max_age=7 * 24 * 3600
            )
            return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google OAuth verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication server error during Google verification.")

@app.get("/api/auth/me")
async def get_current_user_profile(request: Request):
    user = get_current_user_from_request(request)
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "user": {
            "email": user["email"],
            "name": user["name"],
            "picture": user.get("picture", ""),
            "is_admin": user["email"] in ADMIN_EMAILS
        }
    }

@app.post("/api/auth/logout")
async def logout(request: Request):
    """Clear the session cookie on logout."""
    response = JSONResponse(content={"success": True})
    response.delete_cookie("session_token")
    return response

@app.get("/api/leaderboard")
async def get_leaderboard():
    with get_db() as session:
        rows = session.query(Submission)\
            .filter(Submission.is_deleted == 0)\
            .order_by(Submission.score.desc(), Submission.problems.desc(), Submission.active_days.desc(), Submission.repo_name.asc())\
            .all()

        leaderboard = []
        for rank, r in enumerate(rows, 1):
            breakdown_data = {}
            try:
                if r.breakdown_json:
                    breakdown_data = json.loads(r.breakdown_json)
            except Exception:
                pass

            leaderboard.append({
                "rank": rank,
                "id": r.id,
                "repo_url": r.repo_url,
                "repo_name": r.repo_name,
                "submitted_by": r.submitted_by_name or "Anonymous",
                "submitted_by_email": r.submitted_by_email or "",
                "score": round(float(r.score or 0.0), 2),
                "problems": r.problems or 0,
                "active_days": r.active_days or 0,
                "easy_count": r.easy_count or 0,
                "medium_count": r.medium_count or 0,
                "hard_count": r.hard_count or 0,
                "languages": r.languages or "None",
                "topics_covered": r.topics_covered or "None",
                "breakdown": breakdown_data,
                "updated_at": r.updated_at.strftime("%Y-%m-%d %H:%M:%S") if r.updated_at else ""
            })
    return {"leaderboard": leaderboard}

@app.post("/api/submit")
async def submit_repo(payload: SubmitRepoRequest, request: Request):
    user = require_authenticated_user(request)
    user_email = user["email"]
    user_name = user["name"]

    clean_url = sanitize_github_url(payload.repo_url)
    if not clean_url:
        logger.warning(f"Submission rejected: invalid format '{payload.repo_url}' by {user_email}")
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub URL. Must match https://github.com/owner/repository"
        )

    # Rate limiting: enforce cooldown between submissions per user
    now = time.time()
    last_submit = SUBMISSION_RATE_LIMITS.get(user_email, 0.0)
    if now - last_submit < SUBMISSION_COOLDOWN_SECONDS:
        remaining = int(SUBMISSION_COOLDOWN_SECONDS - (now - last_submit))
        raise HTTPException(
            status_code=429,
            detail=f"Please wait {remaining} seconds before submitting another repository."
        )

    try:
        async with ANALYSIS_SEMAPHORE:
            stats = await asyncio.to_thread(analyze_repo_holistic, clean_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        logger.error(f"Analysis failed for {clean_url}: {str(e)}")
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error during analysis for {clean_url}: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred during repository analysis.")

    # Strictly reject repositories with 0 verifiable code solutions
    if stats.get("problems", 0) == 0:
        logger.warning(f"Submission rejected: {clean_url} submitted by {user_email} has 0 verifiable DSA code solutions.")
        raise HTTPException(
            status_code=422,
            detail="No valid DSA code solutions found in this repository. Only automated templates, README.md, or non-code files were detected. Please commit and push your genuine DSA code files (.py, .cpp, .java, etc.) to GitHub before submitting to the leaderboard."
        )

    SUBMISSION_RATE_LIMITS[user_email] = now

    # Save or update submission in Neon DB via SQLAlchemy
    with get_db() as session:
        sub = session.query(Submission).filter(Submission.repo_url == clean_url).first()
        if sub:
            sub.repo_name = stats["name"]
            sub.submitted_by_email = user_email
            sub.submitted_by_name = user_name
            sub.score = stats["score"]
            sub.problems = stats["problems"]
            sub.active_days = stats["active_days"]
            sub.easy_count = stats["easy_count"]
            sub.medium_count = stats["medium_count"]
            sub.hard_count = stats["hard_count"]
            sub.languages = stats["languages"]
            sub.topics_covered = stats["topics_covered"]
            sub.breakdown_json = json.dumps(stats["breakdown"])
            sub.is_deleted = 0
            sub.deleted_at = None
            sub.updated_at = datetime.utcnow()
        else:
            sub = Submission(
                repo_url=clean_url,
                repo_name=stats["name"],
                submitted_by_email=user_email,
                submitted_by_name=user_name,
                score=stats["score"],
                problems=stats["problems"],
                active_days=stats["active_days"],
                easy_count=stats["easy_count"],
                medium_count=stats["medium_count"],
                hard_count=stats["hard_count"],
                languages=stats["languages"],
                topics_covered=stats["topics_covered"],
                breakdown_json=json.dumps(stats["breakdown"]),
                is_deleted=0,
                deleted_at=None
            )
            session.add(sub)

    logger.info(f"Repository {stats['name']} successfully analyzed & recorded for {user_email}")
    return {
        "success": True,
        "message": f"Successfully analyzed {stats['name']} with incremental holistic scoring!",
        "stats": stats
    }

@app.get("/api/user/my-repo")
async def get_my_synced_repo(request: Request):
    """Retrieve the currently authenticated user's active synced repository, if any."""
    user = get_current_user_from_request(request)
    if not user:
        return {"has_repo": False}
    user_email = user.get("email", "").lower().strip()

    with get_db() as session:
        row = session.query(Submission)\
            .filter(func.lower(Submission.submitted_by_email) == user_email, Submission.is_deleted == 0)\
            .order_by(Submission.id.desc())\
            .first()

        if not row:
            return {"has_repo": False}
        return {
            "has_repo": True,
            "repo": {
                "id": row.id,
                "repo_url": row.repo_url,
                "repo_name": row.repo_name,
                "score": round(float(row.score or 0.0), 2),
                "problems": row.problems or 0,
                "active_days": row.active_days or 0,
                "easy_count": row.easy_count or 0,
                "medium_count": row.medium_count or 0,
                "hard_count": row.hard_count or 0,
                "updated_at": row.updated_at.strftime("%Y-%m-%d %H:%M:%S") if row.updated_at else ""
            }
        }

@app.post("/api/submissions/{repo_id}/unsync")
@app.delete("/api/submissions/{repo_id}")
async def unsync_repo(repo_id: int, request: Request):
    """Soft delete / unsync a repository from the arena leaderboard."""
    user = require_authenticated_user(request)
    user_email = user.get("email", "").lower().strip()
    is_admin = user_email in ADMIN_EMAILS

    with get_db() as session:
        repo = session.query(Submission).filter(Submission.id == repo_id).first()
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found.")

        owner_email = (repo.submitted_by_email or "").lower().strip()
        if not is_admin and owner_email != user_email:
            logger.warning(f"Unauthorized unsync attempt: {user_email} tried to delete repo {repo.repo_name} owned by '{owner_email}'")
            raise HTTPException(status_code=403, detail="Permission denied. You can only unsync your own repository.")

        repo.is_deleted = 1
        repo.deleted_at = datetime.utcnow()
        repo_name = repo.repo_name

    logger.info(f"Repository {repo_name} (ID: {repo_id}) successfully soft-deleted / unsynced by {user_email}")
    return {
        "success": True,
        "message": f"Repository '{repo_name}' has been unsynced and removed from the active leaderboard.",
        "repo_id": repo_id
    }

@app.get("/api/user/steps")
async def get_user_steps(request: Request):
    user = require_authenticated_user(request)
    user_email = user["email"]

    with get_db() as session:
        row = session.query(UserNote).filter(UserNote.user_email == user_email).first()
        if not row:
            return {"steps": [], "notes": "", "updated_at": None}

        steps = []
        try:
            steps = json.loads(row.steps_json)
        except Exception:
            pass

        return {
            "steps": steps,
            "notes": row.notes_markdown or "",
            "updated_at": row.updated_at.strftime("%Y-%m-%d %H:%M:%S") if row.updated_at else None
        }

@app.post("/api/user/steps")
async def save_user_steps(payload: UserStepsRequest, request: Request):
    user = require_authenticated_user(request)
    user_email = user["email"]

    with get_db() as session:
        row = session.query(UserNote).filter(UserNote.user_email == user_email).first()
        if row:
            row.steps_json = payload.steps_json
            row.notes_markdown = payload.notes_markdown
            row.updated_at = datetime.utcnow()
        else:
            new_note = UserNote(
                user_email=user_email,
                steps_json=payload.steps_json,
                notes_markdown=payload.notes_markdown,
                updated_at=datetime.utcnow()
            )
            session.add(new_note)

    logger.info(f"Updated personal steps & notes for {user_email}")
    return {"success": True, "message": "Steps and notes saved successfully!"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, workers=1)
