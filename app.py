import os
import re
import math
import json
import time
import hmac
import base64
import hashlib
import asyncio
import uuid
import logging
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set, Tuple, Callable
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
    AnalysisJob, bulk_upsert_analyzed_problems, bulk_upsert_analyzed_commits,
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

# ---------------------------------------------------------------------------
# DSA Candidate Identification & Filtering
# ---------------------------------------------------------------------------
KNOWN_NON_DSA_FILENAMES = {
    "main", "app", "server", "index", "setup", "test", "tests", "conftest",
    "manage", "wsgi", "asgi", "config", "settings", "routes", "views", "models",
    "client", "cli", "worker", "tasks", "helpers", "utils", "common", "constants",
    "train", "training", "model", "dataset", "dataloader", "evaluate", "eval",
    "inference", "gpt", "transformer", "bert", "tokenizer", "loss", "optimizer",
    "checkpoint", "vite.config", "webpack.config", "next.config", "tailwind.config",
    "postcss.config", "babel.config", "playwright.config", "jest.config", "package",
    "package-lock", "tsconfig", "env", "environment", "build", "run", "start",
    "types", "interfaces", "theme", "store", "middleware", "auth"
}

KNOWN_DSA_DIR_KEYWORDS = {
    "leetcode", "neetcode", "blind75", "striver", "problems", "solutions",
    "algorithms", "algo", "data-structures", "data_structures", "dsa",
    "codeforces", "hackerrank", "competitive-programming", "cp", "gfg",
    "geeksforgeeks", "codewars", "interview-prep", "interview"
}

DSA_SIGNATURE_KEYWORDS = [
    "class solution", "def twosum", "listnode", "treenode", "leetcode.com",
    "neetcode.io", "# leetcode", "// leetcode", "class minstack", "class lrucache",
    "#include <bits/stdc++.h>", "ios_base::sync_with_stdio", "time complexity:",
    "space complexity:", "constraints:"
]

CONTAINER_DIRS = {
    "leetcode", "neetcode", "blind75", "striver", "problems", "solutions",
    "algorithms", "algo", "data-structures", "data_structures", "dsa",
    "codeforces", "hackerrank", "competitive-programming", "cp", "gfg",
    "geeksforgeeks", "codewars", "interview-prep", "interview", "easy",
    "medium", "hard", "src", "cpp", "python", "java", "javascript", "go",
    "rust", "csharp", "ts", "daily", "sub", "submissions", "code", "contest",
    "scripts", "script", "tools", "tool", "utils", "util", "helpers", "helper",
    "lib", "bin", "core", "app", "common", "pkg", "cmd", "tests", "test",
    "examples", "example", "demos", "demo", "models", "model", "datasets",
    "dataset", "configs", "config", "docs", "doc", "static", "public"
}

def is_dsa_candidate(
    file_path: str,
    stem: str,
    parent_dir: str,
    ext: str,
    repo_root_name: str = ""
) -> Tuple[bool, str]:
    """
    Platform-agnostic problem slug resolver.
    Handles:
    - Directory-per-problem (LeetHub, LeetCode Sync, NeetCode, CP, Striver)
    - Flat problem files
    - Multi-language polyglot solutions
    - Timestamped and runtime-tagged submission files
    Returns (is_dsa, normalized_problem_slug).
    """
BUILD_AND_TOOL_PREFIXES = (
    "audit", "build", "compile", "gen", "lint", "test", "spec", "parse",
    "make", "check", "clean", "split", "deploy", "export", "import", "voice",
    "trace", "rep", "vl"
)

def is_dsa_candidate(
    file_path: str,
    stem: str,
    parent_dir: str,
    ext: str,
    repo_root_name: str = ""
) -> Tuple[bool, str]:
    """
    Platform-agnostic problem slug resolver.
    Strictly distinguishes genuine DSA problem solving solutions from:
    - Educational documentation / textbooks (e.g. dsa-docs)
    - Build, audit, generator, and tooling scripts
    - Machine learning, web, and generic software projects
    Returns (is_dsa, normalized_problem_slug).
    """
    stem_lower = stem.lower()
    parent_lower = parent_dir.lower()
    repo_root_lower = repo_root_name.lower()

    # Reject obvious build, audit, tool, and generic scripts unless in problem catalog
    is_tool_script = (
        stem_lower in KNOWN_NON_DSA_FILENAMES
        or any(stem_lower.startswith(p) for p in BUILD_AND_TOOL_PREFIXES)
        or any(stem_lower.endswith(p) for p in ["check", "lint", "test", "spec", "audit"])
    )
    if is_tool_script and stem_lower not in PROBLEM_CATALOG:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                head_text = f.read(2048).lower()
            if not any(k in head_text for k in ["class solution", "listnode", "treenode", "leetcode.com/problems"]):
                return (False, "")
        except Exception:
            return (False, "")

    is_parent_container = (
        not parent_dir
        or parent_lower == repo_root_lower
        or parent_lower in CONTAINER_DIRS
        or parent_lower.startswith("sub")
        or any(parent_lower.startswith(p) for p in ["script", "tool", "asset", "input", "output", "doc", "skill", "trace"])
    )

    # 1. Directory-per-problem:
    # A directory is a genuine problem directory if:
    # - It matches the LeetCode Problem Catalog / Aliases (e.g. "two-sum", "reverse-linked-list")
    # - OR it has a standard numeric LeetCode prefix (e.g. "1-two-sum", "0001-two-sum", "100-same-tree")
    # - OR it starts with "lc-", "p-", "problem-" followed by a number
    if not is_parent_container and len(parent_dir) >= 2:
        norm_parent = normalize_slug(parent_dir)
        if (
            norm_parent in PROBLEM_CATALOG
            or norm_parent in CANONICAL_ALIASES
            or re.match(r"^\d+[\-_.]+", parent_dir)
            or re.match(r"^(?:lc|p|problem)[-_]?\d+", parent_dir, re.IGNORECASE)
        ):
            return (True, norm_parent)

    # 2. Flat repository structure:
    # The file stem itself defines the problem
    direct_slug = normalize_slug(stem)
    if direct_slug in PROBLEM_CATALOG or direct_slug in CANONICAL_ALIASES:
        return (True, CANONICAL_ALIASES.get(direct_slug, direct_slug))

    # Check numerical LeetCode pattern on stem (e.g. "0001-two-sum", "1. Two Sum")
    # Exclude timestamp strings (e.g. "2024-01-09 13.20.47...")
    is_timestamp = bool(re.match(r"^\d{4}-\d{2}-\d{2}", stem))
    if not is_timestamp:
        m_num = re.match(r"^(\d{1,4})[-_.]+(.+)$", stem)
        if m_num:
            num_slug = normalize_slug(m_num.group(2))
            if len(num_slug) >= 2 and num_slug not in KNOWN_NON_DSA_FILENAMES:
                return (True, num_slug)

        m_lc = re.match(r"^(?:lc|problem|p)[-_]?(\d{1,4})[-_.]*(.*)$", stem, re.IGNORECASE)
        if m_lc:
            lc_name = normalize_slug(m_lc.group(2))
            return (True, lc_name or f"leetcode-{m_lc.group(1)}")

    # 3. Content signature check (class Solution, TreeNode, ListNode, LeetCode headers)
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code_sample = f.read(3000).lower()
        if any(sig in code_sample for sig in DSA_SIGNATURE_KEYWORDS):
            slug_to_use = normalize_slug(parent_dir) if not is_parent_container else direct_slug
            if not re.match(r"^\d{4}-\d{2}-\d{2}", slug_to_use) and len(slug_to_use) >= 2:
                return (True, slug_to_use or "dsa-solution")
    except Exception:
        pass

    # If none of the above match, it is not a DSA problem solution
    return (False, "")

# ---------------------------------------------------------------------------
# Directories and Files Excluded from Recursive Code Scans (Prevents Hangs)
# ---------------------------------------------------------------------------
IGNORED_SCAN_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env",
    "__pycache__", "dist", "build", ".next", "target", ".gradle",
    "site-packages", ".idea", ".vscode", "coverage", ".turbo",
    "bin", "obj", "out", ".cargo", "Pods"
}

# ---------------------------------------------------------------------------
# Holistic Incremental Repository Analyzer
# ---------------------------------------------------------------------------
def analyze_repo_holistic(
    repo_url: str,
    progress_callback: Optional[Callable[[str, int], None]] = None
) -> Dict[str, Any]:
    """
    Incremental Holistic Analysis:
    1. Shallow-clones repo using secure git parameters, depth limit, and timeouts.
    2. Prunes vendor/build directories and validates genuine code files.
    3. Analyzes git commit history with file associations (capped to prevent timeouts).
    4. Caches problem fingerprints in Neon DB with zero duplicate key errors.
    5. Computes calibrated consistency score and problem difficulty points.
    6. Ensures all repos (big, small, DSA, and non-DSA general code) are evaluated safely.
    """
    def _notify(stage: str, percent: int):
        if progress_callback:
            try:
                progress_callback(stage, percent)
            except Exception:
                pass

    clean_url = sanitize_github_url(repo_url)
    if not clean_url:
        logger.warning(f"Rejected invalid repo URL: {repo_url}")
        raise ValueError("Invalid GitHub repository URL format. Example: https://github.com/username/repository")

    logger.info(f"Starting incremental holistic analysis for: {clean_url}")
    _notify("Verifying cache & repository...", 10)

    # Step 1: Query already-seen commits for this repo (quick, non-blocking DB query)
    seen_commits_db: Set[str] = set()
    try:
        with get_db() as session:
            seen_rows = session.query(AnalyzedCommit.commit_hash).filter(AnalyzedCommit.repo_url == clean_url).all()
            seen_commits_db = {r[0] for r in seen_rows}
        logger.info(f"Loaded {len(seen_commits_db)} previously analyzed commits from cache for {clean_url}")
    except Exception as e:
        logger.warning(f"Could not load cached commits for {clean_url}: {e}")

    # Step 2: Clone repository in a temporary directory
    _notify("Cloning repository from GitHub (shallow clone)...", 20)
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            subprocess.run(
                [
                    "git",
                    "-c", "core.hooksPath=/dev/null",
                    "-c", "core.symlinks=false",
                    "clone",
                    "--depth", "50",
                    "--single-branch",
                    "--no-tags",
                    clean_url,
                    temp_dir
                ],
                check=True,
                capture_output=True,
                timeout=60
            )
        except subprocess.TimeoutExpired:
            logger.error(f"Clone timed out for {clean_url}")
            raise RuntimeError("Repository clone timed out (60s). Please ensure the repository is public and accessible.")
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.decode('utf-8', errors='ignore') if e.stderr else "Git error"
            logger.error(f"Git clone error for {clean_url}: {err_msg}")
            raise RuntimeError("Failed to clone repository. Please check if the repository URL is public and valid.")

        _notify("Scanning codebase & identifying genuine code files...", 40)

        # Step 3: Phase 1 - Scan code files with directory pruning & DSA candidate verification
        candidates: List[Tuple[str, str, str, str]] = []  # (file_path, slug, lang, file_sha)
        has_documentation = False
        max_files_limit = 2500
        scanned_count = 0

        repo_root_name = Path(temp_dir).name.lower()

        for root, dirs, files in os.walk(temp_dir):
            # Prune vendor, build, and hidden directories in-place to avoid hanging
            dirs[:] = [d for d in dirs if d.lower() not in IGNORED_SCAN_DIRS and not d.startswith(".")]
            # Prioritize directories that look like DSA folders first
            dirs.sort(key=lambda d: 0 if any(kw in d.lower() for kw in KNOWN_DSA_DIR_KEYWORDS) else 1)

            # Sort files so clean/accepted solutions come first before failed attempts
            def _file_sort_key(filename: str) -> int:
                fn = filename.lower()
                if "accepted" in fn or fn.startswith("solution.") or "0001" in fn:
                    return 0
                if any(w in fn for w in ["wrong answer", "time limit", "compile error", "runtime error"]):
                    return 2
                return 1
            files.sort(key=_file_sort_key)

            folder_seen_slug_langs: Set[Tuple[str, str]] = set()

            for f in files:
                if scanned_count >= max_files_limit:
                    break

                ext = Path(f).suffix.lower()
                stem = Path(f).stem.lower()
                file_path = os.path.join(root, f)

                if ext in CODE_EXTENSIONS:
                    if not is_genuine_code_file(file_path, ext):
                        continue

                    parent_dir = Path(root).name.lower()
                    is_dsa, slug = is_dsa_candidate(file_path, stem, parent_dir, ext, repo_root_name)
                    if not is_dsa:
                        continue

                    lang = CODE_EXTENSIONS[ext]
                    # Collapse multiple identical language submissions for the same problem in the same folder
                    slug_lang_key = (slug, lang)
                    if slug_lang_key in folder_seen_slug_langs:
                        continue
                    folder_seen_slug_langs.add(slug_lang_key)

                    try:
                        file_sha = compute_file_sha256(file_path)
                        candidates.append((file_path, slug, lang, file_sha))
                        scanned_count += 1
                    except Exception:
                        continue

                elif ext == ".md" and f.lower() not in {"license.md"}:
                    has_documentation = True

            if scanned_count >= max_files_limit:
                logger.info(f"Reached safety file scan cap ({max_files_limit}) for {clean_url}")
                break

        _notify("Classifying problems & analyzing algorithmic complexity...", 60)

        # Step 4: Batch lookup cached problems from database in a single query
        unique_shas = {c[3] for c in candidates}
        cached_problems_map: Dict[str, Dict[str, Any]] = {}

        if unique_shas:
            try:
                with get_db() as session:
                    sha_list = list(unique_shas)
                    for i in range(0, len(sha_list), 500):
                        chunk = sha_list[i:i + 500]
                        rows = session.query(AnalyzedProblem).filter(AnalyzedProblem.file_sha256.in_(chunk)).all()
                        for r in rows:
                            cached_problems_map[r.file_sha256] = {
                                "problem_slug": r.problem_slug,
                                "problem_name": r.problem_name,
                                "difficulty": r.difficulty,
                                "topic": r.topic,
                                "time_complexity": r.time_complexity,
                                "space_complexity": r.space_complexity,
                                "analysis_source": r.analysis_source
                            }
            except Exception as e:
                logger.warning(f"Cache lookup failed for {clean_url}: {e}")

        # Step 5: Classify uncached code files with canonical catalog or heuristics
        new_problems_to_save: Dict[str, Dict[str, Any]] = {}
        detected_problems: Dict[str, Dict[str, Any]] = {}
        detected_languages: Set[str] = set()

        for file_path, slug, lang, file_sha in candidates:
            detected_languages.add(lang)

            if file_sha in cached_problems_map:
                p_info = cached_problems_map[file_sha]
            else:
                if slug in PROBLEM_CATALOG:
                    diff, top = PROBLEM_CATALOG[slug]
                    p_info = {
                        "problem_slug": slug,
                        "problem_name": slug.replace("-", " ").title(),
                        "difficulty": diff,
                        "topic": top,
                        "time_complexity": "O(N)" if diff == "Easy" else ("O(N log N)" if diff == "Medium" else "O(N^2)"),
                        "space_complexity": "O(1)" if diff == "Easy" else "O(N)",
                        "analysis_source": "catalog"
                    }
                else:
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            code_text = f.read(5000)
                    except Exception:
                        code_text = ""
                    p_info = classify_problem_with_heuristics(code_text, slug, file_path)

                cached_problems_map[file_sha] = p_info
                # Deduplicate by file_sha256 in memory before saving
                new_problems_to_save[file_sha] = {
                    "file_sha256": file_sha,
                    "problem_slug": p_info["problem_slug"],
                    "problem_name": p_info["problem_name"],
                    "difficulty": p_info["difficulty"],
                    "topic": p_info["topic"],
                    "time_complexity": p_info["time_complexity"],
                    "space_complexity": p_info["space_complexity"],
                    "analysis_source": p_info["analysis_source"],
                    "created_at": datetime.utcnow()
                }

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

        _notify("Parsing git commits & timeline activity...", 75)

        # Step 6: Phase 2 - Git Commit Parsing (capped to recent 200 commits for speed)
        try:
            log_proc = subprocess.run(
                ["git", "-C", temp_dir, "log", "-n", "200", "--pretty=format:COMMIT:%H|%ad|%s", "--name-only", "--date=short"],
                capture_output=True,
                text=True,
                timeout=15,
                check=True
            )
        except Exception as e:
            logger.error(f"Error reading git log for {clean_url}: {str(e)}")
            raise RuntimeError("Failed to parse git commits from repository.")

        new_commits_to_save: Dict[str, Dict[str, Any]] = {}
        daily_code_days: Set[str] = set()
        daily_problems_map: Dict[str, Set[str]] = {}
        current_commit = None
        slug_keys = list(detected_problems.keys())

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
                        new_commits_to_save[c_hash] = {
                            "commit_hash": c_hash,
                            "repo_url": clean_url,
                            "commit_date": c_date,
                            "commit_message": c_msg,
                            "created_at": datetime.utcnow()
                        }
            elif current_commit:
                ext = Path(line).suffix.lower()
                if ext in CODE_EXTENSIONS:
                    c_hash, c_date, c_msg = current_commit
                    daily_code_days.add(c_date)
                    if c_date not in daily_problems_map:
                        daily_problems_map[c_date] = set()

                    matched = None
                    c_msg_lower = c_msg.lower()
                    line_lower = line.lower()
                    for s in slug_keys:
                        if s in c_msg_lower or s in line_lower or s.replace("-", " ") in c_msg_lower:
                            matched = s
                            break

                    if matched:
                        daily_problems_map[c_date].add(matched)
                    else:
                        daily_problems_map[c_date].add(f"code_{len(daily_problems_map[c_date])}")

        _notify("Computing calibrated holistic rank scores...", 85)

        # Step 7: Phase 3 - Mathematical Holistic Ranking
        total_unique = len(detected_problems)

        if total_unique == 0:
            final_score = 0.0
            active_days = max(1, len(daily_code_days)) if daily_code_days else 0
            easy_count = 0
            medium_count = 0
            hard_count = 0
            consistency_base = 0.0
            problem_difficulty_pts = 0.0
            active_day_mult = 1.0
            breadth_mult = 1.0
            topic_mult = 1.0
            doc_mult = 1.04 if has_documentation else 1.00
            polyglot_mult = 1.00
            problem_summary_list = []
            topics_covered = set()
            logger.info(f"Repository {clean_url} evaluated: 0 code solution files detected. Score: 0.00")
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

        _notify("Persisting problem fingerprints & cache to database...", 95)

        # Step 8: Phase 4 - Fast Atomic Database Upsert (<20ms)
        try:
            with get_db() as session:
                if new_problems_to_save:
                    bulk_upsert_analyzed_problems(session, list(new_problems_to_save.values()))
                if new_commits_to_save:
                    bulk_upsert_analyzed_commits(session, list(new_commits_to_save.values()))
            if new_commits_to_save:
                logger.info(f"Recorded {len(new_commits_to_save)} new unique commits into cache for {clean_url}")
        except Exception as e:
            logger.error(f"Error persisting problems/commits cache for {clean_url}: {e}")

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
        _notify("Analysis complete!", 100)
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

# ---------------------------------------------------------------------------
# Background Analysis Job Worker & In-Memory Registry
# ---------------------------------------------------------------------------
ACTIVE_JOBS: Dict[str, Dict[str, Any]] = {}

async def run_analysis_job(job_id: str, repo_url: str, user_email: str, user_name: str):
    """Asynchronous background worker executing full repository analysis with live progress."""
    logger.info(f"[Job {job_id}] Started background analysis worker for {repo_url} ({user_email})")

    def _on_progress(stage: str, percent: int):
        now_iso = datetime.utcnow().isoformat()
        if job_id in ACTIVE_JOBS:
            ACTIVE_JOBS[job_id]["status"] = "analyzing"
            ACTIVE_JOBS[job_id]["progress_stage"] = stage
            ACTIVE_JOBS[job_id]["progress_percent"] = percent
            ACTIVE_JOBS[job_id]["updated_at"] = now_iso
        try:
            with get_db() as session:
                j = session.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
                if j:
                    j.status = "analyzing"
                    j.progress_stage = stage
                    j.progress_percent = percent
                    j.updated_at = datetime.utcnow()
        except Exception:
            pass

    try:
        async with ANALYSIS_SEMAPHORE:
            _on_progress("Initializing background analysis worker...", 10)
            stats = await asyncio.to_thread(analyze_repo_holistic, repo_url, _on_progress)

        # Update submission in database
        with get_db() as session:
            sub = session.query(Submission).filter(Submission.repo_url == repo_url).first()
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
                    repo_url=repo_url,
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

            db_job = session.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
            if db_job:
                db_job.status = "completed"
                db_job.progress_stage = "Analysis Complete"
                db_job.progress_percent = 100
                db_job.stats_json = json.dumps(stats)
                db_job.updated_at = datetime.utcnow()

        if job_id in ACTIVE_JOBS:
            ACTIVE_JOBS[job_id]["status"] = "completed"
            ACTIVE_JOBS[job_id]["progress_stage"] = "Analysis Complete"
            ACTIVE_JOBS[job_id]["progress_percent"] = 100
            ACTIVE_JOBS[job_id]["stats"] = stats
            ACTIVE_JOBS[job_id]["updated_at"] = datetime.utcnow().isoformat()

        logger.info(f"[Job {job_id}] Successfully finished analysis for {repo_url} (Score={stats['score']})")

    except Exception as e:
        err_msg = str(e) or "An error occurred during repository analysis."
        logger.error(f"[Job {job_id}] Analysis failed for {repo_url}: {err_msg}")
        try:
            with get_db() as session:
                db_job = session.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
                if db_job:
                    db_job.status = "failed"
                    db_job.error_message = err_msg
                    db_job.progress_stage = "Failed"
                    db_job.updated_at = datetime.utcnow()
        except Exception:
            pass

        if job_id in ACTIVE_JOBS:
            ACTIVE_JOBS[job_id]["status"] = "failed"
            ACTIVE_JOBS[job_id]["progress_stage"] = "Failed"
            ACTIVE_JOBS[job_id]["error_message"] = err_msg
            ACTIVE_JOBS[job_id]["updated_at"] = datetime.utcnow().isoformat()


@app.post("/api/admin/trigger-refresh")
async def admin_trigger_refresh(request: Request):
    """Allow authorized Google admins to trigger incremental refresh in the background."""
    admin_user = require_admin_user(request)
    admin_email = admin_user["email"]
    logger.info(f"Manual background refresh triggered by admin: {admin_email}")
    asyncio.create_task(run_scheduled_refresh_all_repos())
    return {
        "success": True,
        "message": "Incremental refresh started in the background for all registered repositories."
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

    # Check if this exact repository URL is currently analyzing for this user
    for j_id, j_data in ACTIVE_JOBS.items():
        if j_data.get("repo_url") == clean_url and j_data.get("status") in ("queued", "analyzing"):
            return {
                "success": True,
                "job_id": j_id,
                "status": j_data.get("status"),
                "message": "Repository is already being analyzed in the background.",
                "repo_url": clean_url
            }

    SUBMISSION_RATE_LIMITS[user_email] = now
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    job_record = {
        "job_id": job_id,
        "repo_url": clean_url,
        "submitted_by_email": user_email,
        "submitted_by_name": user_name,
        "status": "queued",
        "progress_stage": "Queued for analysis",
        "progress_percent": 5,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    ACTIVE_JOBS[job_id] = job_record

    # Persist job record in DB
    try:
        with get_db() as session:
            db_job = AnalysisJob(
                id=job_id,
                repo_url=clean_url,
                submitted_by_email=user_email,
                submitted_by_name=user_name,
                status="queued",
                progress_stage="Queued for analysis",
                progress_percent=5
            )
            session.add(db_job)
    except Exception as e:
        logger.warning(f"Could not write initial job record to DB: {e}")

    # Launch background task
    asyncio.create_task(run_analysis_job(job_id, clean_url, user_email, user_name))

    return {
        "success": True,
        "job_id": job_id,
        "status": "queued",
        "message": "Repository analysis queued in the background.",
        "repo_url": clean_url
    }

@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Poll the status and progress of an asynchronous analysis job."""
    job = ACTIVE_JOBS.get(job_id)
    if job:
        return {
            "job_id": job_id,
            "status": job.get("status"),
            "progress_stage": job.get("progress_stage"),
            "progress_percent": job.get("progress_percent", 0),
            "stats": job.get("stats"),
            "error": job.get("error_message"),
            "repo_url": job.get("repo_url")
        }

    with get_db() as session:
        db_job = session.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not db_job:
            raise HTTPException(status_code=404, detail="Job not found.")

        stats = None
        if db_job.stats_json:
            try:
                stats = json.loads(db_job.stats_json)
            except Exception:
                pass

        return {
            "job_id": db_job.id,
            "status": db_job.status,
            "progress_stage": db_job.progress_stage,
            "progress_percent": db_job.progress_percent,
            "stats": stats,
            "error": db_job.error_message,
            "repo_url": db_job.repo_url
        }

@app.get("/api/user/active-job")
async def get_user_active_job(request: Request):
    """Retrieve the currently active analysis job for the logged-in user, if any."""
    user = get_current_user_from_request(request)
    if not user:
        return {"has_active_job": False}
    user_email = user.get("email", "").lower().strip()

    for j_id, j_data in ACTIVE_JOBS.items():
        if j_data.get("submitted_by_email", "").lower() == user_email and j_data.get("status") in ("queued", "analyzing"):
            return {
                "has_active_job": True,
                "job": {
                    "job_id": j_id,
                    "status": j_data.get("status"),
                    "progress_stage": j_data.get("progress_stage"),
                    "progress_percent": j_data.get("progress_percent", 0),
                    "repo_url": j_data.get("repo_url")
                }
            }

    with get_db() as session:
        db_job = session.query(AnalysisJob)\
            .filter(func.lower(AnalysisJob.submitted_by_email) == user_email, AnalysisJob.status.in_(["queued", "analyzing"]))\
            .order_by(AnalysisJob.created_at.desc())\
            .first()
        if db_job:
            return {
                "has_active_job": True,
                "job": {
                    "job_id": db_job.id,
                    "status": db_job.status,
                    "progress_stage": db_job.progress_stage,
                    "progress_percent": db_job.progress_percent,
                    "repo_url": db_job.repo_url
                }
            }

    return {"has_active_job": False}

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
