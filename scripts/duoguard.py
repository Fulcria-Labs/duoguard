#!/usr/bin/env python3
"""DuoGuard - AI Security Review for GitLab Merge Requests.

Orchestrates multiple Claude-powered security analysis agents via
the GitLab Duo AI Gateway to review MR diffs for vulnerabilities,
dependency risks, and hardcoded secrets.

Supports two execution modes:
  - CI/CD mode (--mode cicd): Runs in a GitLab pipeline on merge_request_event.
    Requires --project-id and --mr-iid arguments.
  - Agent mode (--mode agent): Runs as a GitLab Duo external agent triggered by
    mention or assign_reviewer events. Reads MR context from platform environment
    variables ($AI_FLOW_CONTEXT, $AI_FLOW_INPUT, $AI_FLOW_EVENT).
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import yaml

# ── Project configuration (.duoguard.yml) ───────────────────────

DEFAULT_CONFIG: dict = {
    "version": 1,
    "severity_threshold": "HIGH",
    "agents": {
        "code_security": True,
        "dependency_audit": True,
        "secret_scan": True,
    },
    "exclude_paths": [],
    "exclude_extensions": [],
    "inline_comments": True,
    "approve": False,
    "approve_threshold": "HIGH",
    "model": "claude-sonnet-4-5",
    "max_diff_size": 200_000,
}


def load_config(config_path: str | None = None) -> dict:
    """Load DuoGuard configuration from .duoguard.yml or defaults.

    Looks for the config file in the following order:
      1. Explicit ``config_path`` argument
      2. ``$DUOGUARD_CONFIG`` environment variable
      3. ``.duoguard.yml`` in the current working directory
      4. ``.duoguard.yaml`` in the current working directory

    Returns a merged dict of defaults + file overrides.
    """
    config = dict(DEFAULT_CONFIG)
    candidates = []

    if config_path:
        candidates.append(Path(config_path))
    env_path = os.environ.get("DUOGUARD_CONFIG", "")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path(".duoguard.yml"))
    candidates.append(Path(".duoguard.yaml"))

    for p in candidates:
        if p.exists():
            with open(p) as f:
                user_config = yaml.safe_load(f)
            if isinstance(user_config, dict):
                # Deep merge agents sub-dict
                if "agents" in user_config and isinstance(user_config["agents"], dict):
                    merged_agents = dict(config.get("agents", {}))
                    merged_agents.update(user_config["agents"])
                    user_config["agents"] = merged_agents
                config.update(user_config)
                print(f"  Config loaded from {p}")
            break

    return config

# GitLab API - supports both CI/CD and agent trigger modes
GITLAB_API_URL = os.environ.get("CI_API_V4_URL", "https://gitlab.com/api/v4")
GITLAB_TOKEN = os.environ.get(
    "AI_FLOW_GITLAB_TOKEN",
    os.environ.get("CI_JOB_TOKEN", os.environ.get("GITLAB_TOKEN", "")),
)
GITLAB_HOSTNAME = os.environ.get("AI_FLOW_GITLAB_HOSTNAME", "gitlab.com")

# AI Gateway
AI_GATEWAY_URL = os.environ.get("AI_FLOW_AI_GATEWAY_URL", "")
AI_GATEWAY_TOKEN = os.environ.get("AI_FLOW_AI_GATEWAY_TOKEN", "")
AI_GATEWAY_HEADERS = os.environ.get("AI_FLOW_AI_GATEWAY_HEADERS", "{}")

# Agent trigger environment variables (set by GitLab Duo Agent Platform)
AI_FLOW_CONTEXT = os.environ.get("AI_FLOW_CONTEXT", "")
AI_FLOW_INPUT = os.environ.get("AI_FLOW_INPUT", "")
AI_FLOW_EVENT = os.environ.get("AI_FLOW_EVENT", "")
AI_FLOW_PROJECT_PATH = os.environ.get("AI_FLOW_PROJECT_PATH", "")


def _create_session(retries: int = 3, backoff: float = 1.0) -> requests.Session:
    """Create an HTTP session with automatic retry and exponential backoff."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


_session = _create_session()


def get_mr_diff(project_id: str, mr_iid: str) -> dict:
    """Fetch merge request diff from GitLab API."""
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/changes"
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN} if GITLAB_TOKEN else {}
    try:
        resp = _session.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"  ERROR: MR !{mr_iid} not found in project {project_id}")
        elif e.response is not None and e.response.status_code in (401, 403):
            print(f"  ERROR: Access denied. Check GITLAB_TOKEN permissions.")
        raise
    except requests.exceptions.ConnectionError:
        print(f"  ERROR: Cannot reach GitLab API at {GITLAB_API_URL}")
        raise
    except requests.exceptions.Timeout:
        print(f"  ERROR: GitLab API timed out fetching MR diff")
        raise


def get_mr_info(project_id: str, mr_iid: str) -> dict:
    """Fetch merge request metadata."""
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}"
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN} if GITLAB_TOKEN else {}
    try:
        resp = _session.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"  ERROR: MR !{mr_iid} not found in project {project_id}")
        elif e.response is not None and e.response.status_code in (401, 403):
            print(f"  ERROR: Access denied. Check GITLAB_TOKEN permissions.")
        raise
    except requests.exceptions.ConnectionError:
        print(f"  ERROR: Cannot reach GitLab API at {GITLAB_API_URL}")
        raise


MAX_DIFF_SIZE = 200_000  # ~200 KB; keeps token usage reasonable for large MRs


def should_exclude_path(
    file_path: str,
    exclude_paths: list[str] | None = None,
    exclude_extensions: list[str] | None = None,
) -> bool:
    """Check if a file path should be excluded from analysis.

    Supports glob-like patterns in exclude_paths (``vendor/*``, ``*.min.js``)
    and exact extension matching in exclude_extensions.
    """
    import fnmatch

    if exclude_paths:
        for pattern in exclude_paths:
            if fnmatch.fnmatch(file_path, pattern):
                return True
    if exclude_extensions:
        ext = Path(file_path).suffix.lstrip(".")
        if ext in exclude_extensions:
            return True
    return False


def filter_excluded_changes(
    changes: list[dict],
    exclude_paths: list[str] | None = None,
    exclude_extensions: list[str] | None = None,
) -> list[dict]:
    """Remove changes matching exclusion rules from the list."""
    if not exclude_paths and not exclude_extensions:
        return changes
    return [
        c for c in changes
        if not should_exclude_path(
            c.get("new_path", c.get("old_path", "")),
            exclude_paths, exclude_extensions,
        )
    ]


def format_diff_for_analysis(changes: list[dict], max_size: int = MAX_DIFF_SIZE) -> str:
    """Format MR changes into a readable diff for Claude analysis.

    When the combined diff exceeds *max_size* characters the output is
    truncated and a notice is appended so the AI agent is aware of the
    limitation.
    """
    parts = []
    total = 0
    truncated = 0
    for change in changes:
        path = change.get("new_path", change.get("old_path", "unknown"))
        diff = change.get("diff", "")
        if diff:
            chunk = f"### File: `{path}`\n```diff\n{diff}\n```\n"
            if total + len(chunk) > max_size:
                truncated += 1
                continue
            parts.append(chunk)
            total += len(chunk)
    text = "\n".join(parts)
    if truncated:
        text += (
            f"\n\n> **Note:** {truncated} file(s) omitted because the diff "
            f"exceeded the {max_size:,}-character limit.\n"
        )
    return text


def extract_dependency_files(changes: list[dict]) -> list[dict]:
    """Filter changes to only dependency-related files."""
    dep_patterns = {
        # JavaScript/TypeScript
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        # Python
        "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
        "constraints.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
        "poetry.lock", "uv.lock", "pdm.lock", "setup.py", "setup.cfg",
        # Go
        "go.mod", "go.sum",
        # Ruby
        "Gemfile", "Gemfile.lock",
        # Rust
        "Cargo.toml", "Cargo.lock",
        # Java/Kotlin
        "pom.xml", "build.gradle", "build.gradle.kts",
        # PHP
        "composer.json", "composer.lock",
        # .NET
        "packages.config", "Directory.Packages.props",
        # Elixir
        "mix.exs", "mix.lock",
        # Swift
        "Package.swift", "Package.resolved",
        # Container
        "Dockerfile",
    }
    dep_prefixes = ("requirements", "constraints")
    result = []
    for c in changes:
        name = Path(c.get("new_path", "")).name
        if name in dep_patterns:
            result.append(c)
        elif name.startswith(dep_prefixes) and name.endswith(".txt"):
            result.append(c)
    return result


def _parse_gateway_headers(raw: str) -> dict[str, str]:
    """Parse AI_FLOW_AI_GATEWAY_HEADERS (JSON or newline-separated Key: Value)."""
    if not raw:
        return {}
    # Try JSON first
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    # Fallback: newline-separated "Key: Value" pairs
    headers = {}
    for line in raw.strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    return headers


def call_ai_gateway(system_prompt: str, user_message: str, model: str = "claude-sonnet-4-5") -> str:
    """Call Claude via GitLab AI Gateway or direct Anthropic API.

    Priority order:
    1. GitLab AI Gateway (managed credentials via AI_FLOW_AI_GATEWAY_TOKEN)
    2. GitLab AI Gateway Anthropic proxy (cloud.gitlab.com/ai/v1/proxy/anthropic)
    3. Direct Anthropic API (local development fallback)
    """
    # Path 1: GitLab AI Gateway with explicit URL
    if AI_GATEWAY_URL and AI_GATEWAY_TOKEN:
        headers = {
            "Authorization": f"Bearer {AI_GATEWAY_TOKEN}",
            "Content-Type": "application/json",
        }
        headers.update(_parse_gateway_headers(AI_GATEWAY_HEADERS))

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": 4096,
            "temperature": 0.1,
        }
        try:
            resp = _session.post(
                f"{AI_GATEWAY_URL}/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=120,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "unknown"
            print(f"  WARNING: AI Gateway returned HTTP {status}")
            if status == 429:
                print("  Rate limited by AI Gateway. Consider reducing request frequency.")
            raise
        except requests.exceptions.Timeout:
            print("  WARNING: AI Gateway timed out (120s). The model may be overloaded.")
            raise

    # Path 2: GitLab managed credentials via Anthropic proxy
    if AI_GATEWAY_TOKEN and not AI_GATEWAY_URL:
        proxy_url = "https://cloud.gitlab.com/ai/v1/proxy/anthropic"
        headers = {
            "x-api-key": AI_GATEWAY_TOKEN,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        headers.update(_parse_gateway_headers(AI_GATEWAY_HEADERS))

        model_map = {
            "claude-sonnet-4-5": "claude-sonnet-4-5-20250929",
            "claude-sonnet-4": "claude-sonnet-4-20250514",
        }
        api_model = model_map.get(model, model)

        try:
            resp = _session.post(
                f"{proxy_url}/v1/messages",
                headers=headers,
                json={
                    "model": api_model,
                    "max_tokens": 4096,
                    "temperature": 0.1,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_message}],
                },
                timeout=120,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "unknown"
            print(f"  WARNING: Anthropic proxy returned HTTP {status}")
            raise

    # Path 3: Direct Anthropic API for local development
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "_AI Gateway not configured. Set AI_FLOW_AI_GATEWAY_TOKEN or ANTHROPIC_API_KEY._"

    try:
        resp = _session.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-5-20250514",
                "max_tokens": 4096,
                "temperature": 0.1,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_message}],
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        print(f"  WARNING: Anthropic API returned HTTP {status}")
        if status == 401:
            print("  Invalid ANTHROPIC_API_KEY. Check your credentials.")
        raise


def load_agent_prompt(agent_file: str) -> str:
    """Load system prompt from agent YAML config."""
    config_path = Path(__file__).parent.parent / agent_file
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
        if config and isinstance(config, dict):
            return config.get("system_prompt", "")
    return ""


def run_code_security_review(diff_text: str) -> str:
    """Run the code security reviewer agent."""
    prompt = load_agent_prompt(".gitlab/duo/agents/code-security-reviewer.yml")
    if not prompt:
        prompt = "You are a security code reviewer. Analyze the following code diff for security vulnerabilities."

    user_msg = f"Review the following merge request diff for security vulnerabilities:\n\n{diff_text}"
    return call_ai_gateway(prompt, user_msg)


def run_dependency_audit(dep_diff_text: str) -> str:
    """Run the dependency auditor agent."""
    if not dep_diff_text.strip():
        return "No dependency file changes detected in this merge request."

    prompt = load_agent_prompt(".gitlab/duo/agents/dependency-auditor.yml")
    if not prompt:
        prompt = "You are a dependency security auditor. Analyze dependency changes for risks."

    user_msg = f"Audit the following dependency file changes:\n\n{dep_diff_text}"
    return call_ai_gateway(prompt, user_msg)


def run_secret_scan(diff_text: str) -> str:
    """Run the secret scanner agent."""
    prompt = load_agent_prompt(".gitlab/duo/agents/secret-scanner.yml")
    if not prompt:
        prompt = "You are a secret scanner. Detect hardcoded secrets in code changes."

    user_msg = f"Scan the following code changes for hardcoded secrets and credentials:\n\n{diff_text}"
    return call_ai_gateway(prompt, user_msg)


# ── CWE / OWASP enrichment ────────────────────────────────────

# Map common vulnerability keywords to CWE IDs and OWASP Top 10 (2021) categories
CWE_KEYWORD_MAP: dict[str, dict] = {
    "sql injection": {"cwe": "CWE-89", "owasp": "A03:2021-Injection"},
    "xss": {"cwe": "CWE-79", "owasp": "A03:2021-Injection"},
    "cross-site scripting": {"cwe": "CWE-79", "owasp": "A03:2021-Injection"},
    "command injection": {"cwe": "CWE-78", "owasp": "A03:2021-Injection"},
    "os command": {"cwe": "CWE-78", "owasp": "A03:2021-Injection"},
    "path traversal": {"cwe": "CWE-22", "owasp": "A01:2021-Broken Access Control"},
    "directory traversal": {"cwe": "CWE-22", "owasp": "A01:2021-Broken Access Control"},
    "ssrf": {"cwe": "CWE-918", "owasp": "A10:2021-SSRF"},
    "server-side request forgery": {"cwe": "CWE-918", "owasp": "A10:2021-SSRF"},
    "deserialization": {"cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures"},
    "xml external entity": {"cwe": "CWE-611", "owasp": "A05:2021-Security Misconfiguration"},
    "xxe": {"cwe": "CWE-611", "owasp": "A05:2021-Security Misconfiguration"},
    "broken auth": {"cwe": "CWE-287", "owasp": "A07:2021-Identification and Authentication Failures"},
    "authentication bypass": {"cwe": "CWE-287", "owasp": "A07:2021-Identification and Authentication Failures"},
    "hardcoded password": {"cwe": "CWE-798", "owasp": "A07:2021-Identification and Authentication Failures"},
    "hardcoded secret": {"cwe": "CWE-798", "owasp": "A07:2021-Identification and Authentication Failures"},
    "hardcoded credential": {"cwe": "CWE-798", "owasp": "A07:2021-Identification and Authentication Failures"},
    "api key": {"cwe": "CWE-798", "owasp": "A07:2021-Identification and Authentication Failures"},
    "private key": {"cwe": "CWE-321", "owasp": "A02:2021-Cryptographic Failures"},
    "weak crypto": {"cwe": "CWE-327", "owasp": "A02:2021-Cryptographic Failures"},
    "insecure random": {"cwe": "CWE-330", "owasp": "A02:2021-Cryptographic Failures"},
    "open redirect": {"cwe": "CWE-601", "owasp": "A01:2021-Broken Access Control"},
    "csrf": {"cwe": "CWE-352", "owasp": "A01:2021-Broken Access Control"},
    "race condition": {"cwe": "CWE-362", "owasp": "A04:2021-Insecure Design"},
    "buffer overflow": {"cwe": "CWE-120", "owasp": "A06:2021-Vulnerable and Outdated Components"},
    "integer overflow": {"cwe": "CWE-190", "owasp": "A06:2021-Vulnerable and Outdated Components"},
    "missing access control": {"cwe": "CWE-862", "owasp": "A01:2021-Broken Access Control"},
    "idor": {"cwe": "CWE-639", "owasp": "A01:2021-Broken Access Control"},
    "insecure direct object": {"cwe": "CWE-639", "owasp": "A01:2021-Broken Access Control"},
    "log injection": {"cwe": "CWE-117", "owasp": "A09:2021-Security Logging and Monitoring Failures"},
    "information disclosure": {"cwe": "CWE-200", "owasp": "A01:2021-Broken Access Control"},
    "sensitive data exposure": {"cwe": "CWE-200", "owasp": "A02:2021-Cryptographic Failures"},
    "ldap injection": {"cwe": "CWE-90", "owasp": "A03:2021-Injection"},
    "xml injection": {"cwe": "CWE-91", "owasp": "A03:2021-Injection"},
    "code injection": {"cwe": "CWE-94", "owasp": "A03:2021-Injection"},
    "eval": {"cwe": "CWE-95", "owasp": "A03:2021-Injection"},
    "prototype pollution": {"cwe": "CWE-1321", "owasp": "A03:2021-Injection"},
    "mass assignment": {"cwe": "CWE-915", "owasp": "A04:2021-Insecure Design"},
    "unrestricted upload": {"cwe": "CWE-434", "owasp": "A04:2021-Insecure Design"},
    "file upload": {"cwe": "CWE-434", "owasp": "A04:2021-Insecure Design"},
    "denial of service": {"cwe": "CWE-400", "owasp": "A06:2021-Vulnerable and Outdated Components"},
    "regex dos": {"cwe": "CWE-1333", "owasp": "A06:2021-Vulnerable and Outdated Components"},
    "redos": {"cwe": "CWE-1333", "owasp": "A06:2021-Vulnerable and Outdated Components"},
}


def enrich_finding_cwe(finding: dict) -> dict:
    """Enrich a finding dict with CWE and OWASP classification based on description.

    If the finding already has a 'cwe' key (from AI output), it is preserved.
    Otherwise, the description is matched against ``CWE_KEYWORD_MAP``.
    """
    desc_lower = finding.get("description", "").lower()

    # If AI already provided a CWE, keep it
    if finding.get("cwe") and finding.get("owasp"):
        return finding

    for keyword, classification in CWE_KEYWORD_MAP.items():
        if keyword in desc_lower:
            if not finding.get("cwe"):
                finding["cwe"] = classification["cwe"]
            if not finding.get("owasp"):
                finding["owasp"] = classification["owasp"]
            return finding

    return finding


# ── Diff complexity analysis ──────────────────────────────────

def compute_diff_complexity(changes: list[dict]) -> dict:
    """Compute complexity metrics for a set of MR changes.

    Returns a dict with:
      - total_additions: number of added lines
      - total_deletions: number of deleted lines
      - total_files: number of changed files
      - high_risk_files: files with security-sensitive patterns
      - complexity_score: weighted score (0-100) indicating review priority
      - risk_factors: list of human-readable risk explanations
    """
    total_add = 0
    total_del = 0
    high_risk_files: list[str] = []
    risk_factors: list[str] = []

    # Patterns that indicate security-sensitive changes
    security_patterns = [
        (r'(?:password|secret|token|api_?key|credential)', "credential handling"),
        (r'(?:exec|eval|system|popen|subprocess)', "command execution"),
        (r'(?:sql|query|execute|cursor)', "database operations"),
        (r'(?:auth|login|session|jwt|oauth)', "authentication logic"),
        (r'(?:crypto|encrypt|decrypt|hash|hmac)', "cryptographic operations"),
        (r'(?:permission|role|acl|rbac|policy)', "access control"),
        (r'(?:deserializ|unpickle|yaml\.load|json\.loads)', "deserialization"),
        (r'(?:redirect|url|href|src=)', "URL handling"),
        (r'(?:upload|file|path|directory)', "file operations"),
        (r'(?:cookie|header|request|response)', "HTTP handling"),
    ]

    for change in changes:
        path = change.get("new_path", change.get("old_path", "unknown"))
        diff = change.get("diff", "")
        if not diff:
            continue

        file_additions = diff.count("\n+") - diff.count("\n+++")
        file_deletions = diff.count("\n-") - diff.count("\n---")
        total_add += max(0, file_additions)
        total_del += max(0, file_deletions)

        diff_lower = diff.lower()
        for pattern, label in security_patterns:
            if re.search(pattern, diff_lower):
                if path not in high_risk_files:
                    high_risk_files.append(path)
                factor = f"{label} modified in {path}"
                if factor not in risk_factors:
                    risk_factors.append(factor)
                break  # one match per file is enough

    # Compute weighted complexity score (0-100)
    size_score = min(40, (total_add + total_del) // 10)  # up to 40 for size
    file_score = min(20, len(changes) * 2)  # up to 20 for file count
    risk_score = min(40, len(high_risk_files) * 10)  # up to 40 for security risk

    return {
        "total_additions": total_add,
        "total_deletions": total_del,
        "total_files": len(changes),
        "high_risk_files": high_risk_files,
        "complexity_score": min(100, size_score + file_score + risk_score),
        "risk_factors": risk_factors,
    }


def _count_by_severity(text: str) -> dict[str, int]:
    """Count findings per severity level using strict pattern matching.

    Matches ``[SEVERITY]`` only when it appears at the start of a line,
    after markdown heading markers (``### ``), or after bullet/dash
    prefixes.  This avoids false positives from prose that merely
    *mentions* a severity word inside brackets (e.g. "see [high] above").
    """
    lower = text.lower()
    counts = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        # Match [SEV] at line start, after ### , after - , or after **
        pattern = rf'(?:^|(?<=^### )|(?<=^- )|(?<=^\*\*))[ ]*\[{sev}\]'
        counts[sev] = len(re.findall(pattern, lower, re.MULTILINE))
    return counts


def determine_severity(code_findings: str, dep_findings: str, secret_findings: str) -> str:
    """Determine overall severity from agent findings using weighted scoring."""
    combined = code_findings + dep_findings + secret_findings
    counts = _count_by_severity(combined)

    # Weighted score: critical=4, high=3, medium=2, low=1
    score = (counts["critical"] * 4 + counts["high"] * 3 +
             counts["medium"] * 2 + counts["low"] * 1)

    if score >= 8 or counts["critical"] > 0:
        return "CRITICAL"
    if score >= 5 or counts["high"] > 0:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "NONE"


def count_findings(text: str) -> int:
    """Count the number of findings in agent output."""
    counts = _count_by_severity(text)
    return sum(counts.values())


def _parse_findings(text: str, category: str = "code-security") -> list[dict]:
    """Parse structured findings from agent markdown output.

    Each returned dict contains:
        severity  - lowercase severity string
        description - finding title
        file_path - affected file (or "unknown")
        line_num  - line number (default 1)
        category  - finding category label

    The parser looks for headings of the form ``### [SEVERITY] Finding: <desc>``
    followed by a ``**File:** `<path>` (line N)`` line.
    """
    findings: list[dict] = []
    current: dict | None = None

    for line in text.split("\n"):
        if line.startswith("### ["):
            for sev in ("critical", "high", "medium", "low", "info"):
                if f"[{sev}]" in line.lower():
                    desc = line.replace(f"### [{sev.upper()}] Finding: ", "").strip()
                    current = {
                        "severity": sev,
                        "description": desc,
                        "file_path": "unknown",
                        "line_num": 1,
                        "category": category,
                    }
                    break
        elif current and line.startswith("**File:**"):
            parts = line.split("`")
            if len(parts) >= 2:
                current["file_path"] = parts[1]
                if "line" in line.lower():
                    try:
                        current["line_num"] = int(
                            "".join(c for c in line.split("line")[-1] if c.isdigit())[:5]
                        )
                    except (ValueError, IndexError):
                        pass
                # Enrich with CWE/OWASP classification
                current = enrich_finding_cwe(current)
                findings.append(current)
                current = None

    return findings


def generate_codequality_report(
    code_findings: str,
    output_path: str,
    dep_findings: str = "",
    secret_findings: str = "",
) -> None:
    """Generate a GitLab Code Quality compatible JSON report.

    Includes findings from all three scan categories (code, dependency,
    secret) so that the Code Quality widget reflects the full picture.
    """
    severity_map = {
        "critical": "blocker",
        "high": "critical",
        "medium": "major",
        "low": "minor",
        "info": "info",
    }

    all_findings = (
        _parse_findings(code_findings, "code-security")
        + _parse_findings(dep_findings, "dependency-audit")
        + _parse_findings(secret_findings, "secret-scan")
    )

    issues = []
    for f in all_findings:
        cq_sev = severity_map.get(f["severity"], "info")
        fingerprint = hashlib.md5(
            f"{f['description']}{f['file_path']}{f['category']}".encode()
        ).hexdigest()
        issues.append({
            "type": "issue",
            "check_name": f"duoguard-{f['category']}",
            "description": f["description"],
            "severity": cq_sev,
            "categories": ["Security"],
            "location": {
                "path": f["file_path"],
                "lines": {"begin": f["line_num"]},
            },
            "fingerprint": fingerprint,
        })

    with open(output_path, "w") as f:
        json.dump(issues, f, indent=2)


def generate_report(
    mr_info: dict,
    code_findings: str,
    dep_findings: str,
    secret_findings: str,
    scan_duration: float | None = None,
    files_scanned: int = 0,
    complexity: dict | None = None,
) -> str:
    """Generate the final security review report."""
    severity = determine_severity(code_findings, dep_findings, secret_findings)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    severity_emoji = {
        "CRITICAL": ":rotating_light:",
        "HIGH": ":warning:",
        "MEDIUM": ":large_orange_diamond:",
        "LOW": ":large_blue_diamond:",
        "NONE": ":white_check_mark:",
    }

    report = f"""## :shield: DuoGuard Security Review Report

**MR:** !{mr_info.get('iid', 'N/A')} - {mr_info.get('title', 'Untitled')}
**Reviewed at:** {timestamp}
**Powered by:** Claude AI via GitLab Duo Agent Platform

---

### :mag: Code Security Analysis
{code_findings}

---

### :package: Dependency Audit
{dep_findings}

---

### :key: Secret Scan
{secret_findings}

---

### Summary

| Category | Findings |
|----------|----------|
| Code Security | {count_findings(code_findings)} issue(s) |
| Dependencies | {count_findings(dep_findings)} issue(s) |
| Secrets | {count_findings(secret_findings)} issue(s) |

**Overall Risk Level:** {severity_emoji.get(severity, '')} **{severity}**
"""

    # Add complexity analysis if available
    if complexity and complexity.get("complexity_score", 0) > 0:
        score = complexity["complexity_score"]
        risk_level = "Low" if score < 30 else "Medium" if score < 60 else "High"
        report += f"\n### Diff Complexity Analysis\n\n"
        report += f"**Complexity Score:** {score}/100 ({risk_level} risk)\n\n"
        report += "| Metric | Value |\n|--------|-------|\n"
        report += f"| Lines added | {complexity.get('total_additions', 0)} |\n"
        report += f"| Lines deleted | {complexity.get('total_deletions', 0)} |\n"
        report += f"| Files changed | {complexity.get('total_files', 0)} |\n"
        report += f"| Security-sensitive files | {len(complexity.get('high_risk_files', []))} |\n"
        report += "\n"
        if complexity.get("risk_factors"):
            report += "**Risk factors:**\n"
            for factor in complexity["risk_factors"]:
                report += f"- {factor}\n"
            report += "\n"

    # Add scan metrics if available
    if scan_duration is not None or files_scanned > 0:
        report += "\n### Scan Metrics\n\n"
        report += "| Metric | Value |\n|--------|-------|\n"
        if files_scanned > 0:
            report += f"| Files scanned | {files_scanned} |\n"
        if scan_duration is not None:
            report += f"| Scan duration | {scan_duration:.1f}s |\n"
        report += "\n"

    report += """---
*DuoGuard is an open-source security review flow for GitLab Duo Agent Platform.*
*Built for the [GitLab AI Hackathon 2026](https://gitlab.devpost.com/).*
"""
    return report


def generate_sarif_report(
    code_findings: str,
    output_path: str,
    dep_findings: str = "",
    secret_findings: str = "",
) -> None:
    """Generate a SARIF 2.1.0 report for integration with security dashboards.

    Includes findings from all three scan categories and enriches the
    output with fields expected by GitLab Security Dashboard:
      - ``invocations`` with execution status
      - ``automationDetails`` with a unique run ID
      - ``fullDescription`` and ``helpUri`` on rules
      - ``partialFingerprints`` on results for cross-run deduplication
    """
    level_map = {
        "critical": "error", "high": "error",
        "medium": "warning", "low": "note", "info": "note",
    }

    category_help = {
        "code-security": "https://owasp.org/www-project-top-ten/",
        "dependency-audit": "https://owasp.org/www-project-dependency-check/",
        "secret-scan": "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    }

    all_findings = (
        _parse_findings(code_findings, "code-security")
        + _parse_findings(dep_findings, "dependency-audit")
        + _parse_findings(secret_findings, "secret-scan")
    )

    results = []
    rules = []
    rule_ids: set[str] = set()

    for f in all_findings:
        sarif_level = level_map.get(f["severity"], "note")
        rule_id = f"duoguard/{f['category']}/{f['description'].lower().replace(' ', '-')[:40]}"

        # Build partial fingerprint for deduplication across runs
        fp_input = f"{f['description']}{f['file_path']}{f['line_num']}{f['category']}"
        partial_fp = hashlib.sha256(fp_input.encode()).hexdigest()

        result_entry = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": f["description"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file_path"]},
                    "region": {"startLine": f["line_num"]},
                }
            }],
            "partialFingerprints": {
                "duoguardFindingHash/v1": partial_fp,
            },
        }
        results.append(result_entry)

        if rule_id not in rule_ids:
            help_uri = category_help.get(f["category"], "https://gitlab.devpost.com/")
            rule_entry = {
                "id": rule_id,
                "shortDescription": {"text": f["description"]},
                "fullDescription": {
                    "text": f"[{f['severity'].upper()}] {f['description']} "
                            f"(category: {f['category']})",
                },
                "helpUri": help_uri,
                "defaultConfiguration": {"level": sarif_level},
                "properties": {"category": f["category"]},
            }
            # Include CWE/OWASP in SARIF rule properties when available
            if f.get("cwe"):
                rule_entry["properties"]["cwe"] = f["cwe"]
            if f.get("owasp"):
                rule_entry["properties"]["owasp"] = f["owasp"]
            rules.append(rule_entry)
            rule_ids.add(rule_id)

    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DuoGuard",
                    "version": "1.0.0",
                    "informationUri": "https://gitlab.devpost.com/",
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": now,
            }],
            "automationDetails": {
                "id": f"duoguard/{run_id}",
            },
            "results": results,
        }],
    }

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)


def _resolve_api_url_for_agent() -> str:
    """Build GitLab API URL from agent environment variables."""
    hostname = GITLAB_HOSTNAME or "gitlab.com"
    return f"https://{hostname}/api/v4"


def _parse_agent_context() -> tuple[str, str]:
    """Extract project_id and mr_iid from agent trigger context.

    The AI_FLOW_CONTEXT contains MR diffs and metadata. The AI_FLOW_INPUT
    contains the user message. We extract the project path and MR IID from
    the context or environment variables.

    Returns:
        (project_id, mr_iid) - project_id is URL-encoded project path
    """
    project_path = AI_FLOW_PROJECT_PATH
    mr_iid = ""

    # Try to extract MR IID from context (JSON or text)
    if AI_FLOW_CONTEXT:
        try:
            ctx = json.loads(AI_FLOW_CONTEXT)
            mr_iid = str(ctx.get("merge_request", {}).get("iid", ""))
            if not project_path:
                project_path = ctx.get("project", {}).get("path_with_namespace", "")
        except (json.JSONDecodeError, TypeError):
            # Context might be plain text with MR reference
            mr_match = re.search(r'!(\d+)', AI_FLOW_CONTEXT)
            if mr_match:
                mr_iid = mr_match.group(1)

    # Also check input for MR reference
    if not mr_iid and AI_FLOW_INPUT:
        mr_match = re.search(r'!(\d+)', AI_FLOW_INPUT)
        if mr_match:
            mr_iid = mr_match.group(1)

    # URL-encode the project path for API calls
    project_id = quote_plus(project_path) if project_path else ""
    return project_id, mr_iid


def export_findings_json(
    code_findings: str,
    dep_findings: str,
    secret_findings: str,
    output_path: str,
) -> list[dict]:
    """Export all parsed findings as a JSON file for inline comment posting.

    Returns the list of finding dicts for convenience.
    """
    all_findings = (
        _parse_findings(code_findings, "code-security")
        + _parse_findings(dep_findings, "dependency-audit")
        + _parse_findings(secret_findings, "secret-scan")
    )
    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)
    return all_findings


def _run_security_scan(project_id: str, mr_iid: str, output: str, sarif: str,
                        fail_on: str, config: dict | None = None) -> None:
    """Core security scan logic shared between CI/CD and agent modes."""
    cfg = config or DEFAULT_CONFIG
    agents_cfg = cfg.get("agents", DEFAULT_CONFIG["agents"])
    exclude_paths = cfg.get("exclude_paths", [])
    exclude_extensions = cfg.get("exclude_extensions", [])
    max_diff = cfg.get("max_diff_size", MAX_DIFF_SIZE)

    scan_start = time.monotonic()

    print("DuoGuard Security Review starting...")
    print(f"  Project: {project_id}")
    print(f"  MR: !{mr_iid}")

    # Fetch MR data
    print("\n[1/5] Fetching merge request data...")
    mr_info = get_mr_info(project_id, mr_iid)
    mr_changes = get_mr_diff(project_id, mr_iid)
    changes = mr_changes.get("changes", [])
    print(f"       Found {len(changes)} changed files")

    # Apply exclusion filters
    changes = filter_excluded_changes(changes, exclude_paths, exclude_extensions)
    if exclude_paths or exclude_extensions:
        print(f"       After exclusions: {len(changes)} files")

    if not changes:
        print("No code changes to review. Exiting.")
        report = "## DuoGuard Security Review\n\nNo code changes detected in this merge request."
        Path(output).write_text(report)
        return

    # Format diffs
    diff_text = format_diff_for_analysis(changes, max_size=max_diff)
    dep_changes = extract_dependency_files(changes)
    dep_diff_text = format_diff_for_analysis(dep_changes, max_size=max_diff)

    # Run enabled agents in parallel
    print("\n[2/5] Running security agents in parallel...")
    code_findings = ""
    dep_findings = ""
    secret_findings = ""
    futures = {}

    with ThreadPoolExecutor(max_workers=3) as executor:
        if agents_cfg.get("code_security", True):
            print("       - Code Security Review")
            futures["code"] = executor.submit(run_code_security_review, diff_text)
        if agents_cfg.get("dependency_audit", True):
            print("       - Dependency Audit")
            futures["dep"] = executor.submit(run_dependency_audit, dep_diff_text)
        if agents_cfg.get("secret_scan", True):
            print("       - Secret Scan")
            futures["secret"] = executor.submit(run_secret_scan, diff_text)

        for future in as_completed(futures.values()):
            if futures.get("code") == future:
                code_findings = future.result()
                print(f"       Code Security: {count_findings(code_findings)} issue(s)")
            elif futures.get("dep") == future:
                dep_findings = future.result()
                print(f"       Dependency Audit: {count_findings(dep_findings)} issue(s)")
            elif futures.get("secret") == future:
                secret_findings = future.result()
                print(f"       Secret Scan: {count_findings(secret_findings)} issue(s)")

    # Compute diff complexity
    complexity = compute_diff_complexity(changes)
    if complexity["high_risk_files"]:
        print(f"       Security-sensitive files: {', '.join(complexity['high_risk_files'][:5])}")
    print(f"       Complexity score: {complexity['complexity_score']}/100")

    # Generate reports
    scan_duration = time.monotonic() - scan_start
    print("\n[3/5] Generating reports...")
    report = generate_report(mr_info, code_findings, dep_findings, secret_findings,
                             scan_duration=scan_duration, files_scanned=len(changes),
                             complexity=complexity)
    Path(output).write_text(report)
    print(f"       Markdown report: {output}")

    cq_path = "duoguard-codequality.json"
    generate_codequality_report(code_findings, cq_path,
                                dep_findings=dep_findings,
                                secret_findings=secret_findings)
    print(f"       Code Quality report: {cq_path}")

    sarif_path = sarif or "duoguard-sarif.json"
    generate_sarif_report(code_findings, sarif_path,
                          dep_findings=dep_findings,
                          secret_findings=secret_findings)
    print(f"       SARIF report: {sarif_path}")

    # Export findings JSON for inline comments
    print("\n[4/5] Exporting findings...")
    findings_path = "duoguard-findings.json"
    all_findings = export_findings_json(
        code_findings, dep_findings, secret_findings, findings_path)
    print(f"       {len(all_findings)} finding(s) exported to {findings_path}")

    print("\n[5/5] Evaluating risk...")
    severity = determine_severity(code_findings, dep_findings, secret_findings)
    print(f"       Overall Risk Level: {severity}")

    # Write severity to file for downstream jobs
    Path("duoguard-severity.txt").write_text(severity)

    severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if severity_order.index(severity) >= severity_order.index(fail_on):
        print(f"\n  FAIL: Severity {severity} meets/exceeds threshold {fail_on}")
        sys.exit(1)
    else:
        print(f"       PASS: Below threshold {fail_on}")


def run_agent_mode(output: str = "duoguard-report.md", sarif: str = "",
                   fail_on: str = "HIGH", config: dict | None = None) -> None:
    """Run DuoGuard in agent trigger mode using platform environment variables.

    Called when --mode agent is specified. Reads MR context from:
      $AI_FLOW_CONTEXT    - MR diffs and metadata
      $AI_FLOW_INPUT      - User's message
      $AI_FLOW_EVENT      - Trigger type (mention, assign_reviewer, etc.)
      $AI_FLOW_PROJECT_PATH - Project path
      $AI_FLOW_GITLAB_TOKEN - GitLab API token
    """
    global GITLAB_API_URL

    event = AI_FLOW_EVENT or "unknown"
    print(f"DuoGuard agent mode: triggered by {event}")

    # Configure API URL from agent environment
    GITLAB_API_URL = _resolve_api_url_for_agent()

    project_id, mr_iid = _parse_agent_context()

    if not project_id or not mr_iid:
        print("ERROR: Could not determine project ID and MR IID from agent context.")
        print(f"  AI_FLOW_PROJECT_PATH: {AI_FLOW_PROJECT_PATH!r}")
        print(f"  AI_FLOW_CONTEXT: {AI_FLOW_CONTEXT[:200]!r}...")
        sys.exit(1)

    _run_security_scan(project_id, mr_iid, output, sarif, fail_on, config=config)


def main():
    parser = argparse.ArgumentParser(description="DuoGuard - AI Security Review")
    parser.add_argument("--mode", default="cicd", choices=["cicd", "agent"],
                       help="Execution mode: cicd (pipeline) or agent (Duo trigger)")
    parser.add_argument("--project-id", help="GitLab project ID (CI/CD mode)")
    parser.add_argument("--mr-iid", help="Merge request IID (CI/CD mode)")
    parser.add_argument("--output", default="duoguard-report.md", help="Output report file")
    parser.add_argument("--sarif", default="", help="Output SARIF report file")
    parser.add_argument("--fail-on", default="",
                       choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", ""],
                       help="Minimum severity to fail the pipeline")
    parser.add_argument("--config", default=None, help="Path to .duoguard.yml config file")
    args = parser.parse_args()

    # Load project configuration
    cfg = load_config(args.config)

    # CLI --fail-on overrides config; otherwise use config value
    fail_on = args.fail_on or cfg.get("severity_threshold", "HIGH")

    if args.mode == "agent":
        run_agent_mode(output=args.output, sarif=args.sarif, fail_on=fail_on,
                       config=cfg)
    else:
        if not args.project_id or not args.mr_iid:
            parser.error("--project-id and --mr-iid are required in cicd mode")
        _run_security_scan(args.project_id, args.mr_iid, args.output,
                           args.sarif, fail_on, config=cfg)


if __name__ == "__main__":
    main()
