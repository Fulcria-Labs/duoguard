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
    "fix_suggestions": True,
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

    # Validate severity_threshold
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
    sev = config.get("severity_threshold", "HIGH")
    if isinstance(sev, str):
        sev = sev.upper()
    if sev not in valid_severities:
        print(f"  WARNING: Invalid severity_threshold {sev!r} in config. Using default HIGH.")
        config["severity_threshold"] = "HIGH"
    else:
        config["severity_threshold"] = sev

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
        print(f"  WARNING: Diff truncated — {truncated} file(s) omitted "
              f"(limit: {max_size:,} chars). "
              f"Adjust max_diff_size in .duoguard.yml to analyze more.")
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
    fix_suggestions: str | None = None,
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

    # Add fix suggestions if available
    if fix_suggestions and fix_suggestions.strip():
        report += "\n### :wrench: Fix Suggestions\n\n"
        report += fix_suggestions
        report += "\n\n"

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


# ── SBOM (Software Bill of Materials) Generation ──────────────

# Maps dependency file names to their ecosystem
ECOSYSTEM_MAP: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "requirements-prod.txt": "pypi",
    "constraints.txt": "pypi",
    "Pipfile": "pypi",
    "Pipfile.lock": "pypi",
    "pyproject.toml": "pypi",
    "poetry.lock": "pypi",
    "uv.lock": "pypi",
    "pdm.lock": "pypi",
    "setup.py": "pypi",
    "setup.cfg": "pypi",
    "go.mod": "golang",
    "go.sum": "golang",
    "Gemfile": "rubygems",
    "Gemfile.lock": "rubygems",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "composer.json": "packagist",
    "composer.lock": "packagist",
    "packages.config": "nuget",
    "Directory.Packages.props": "nuget",
    "mix.exs": "hex",
    "mix.lock": "hex",
    "Package.swift": "swift",
    "Package.resolved": "swift",
}

# Package URL (purl) type mapping per ecosystem
PURL_TYPE_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "golang": "golang",
    "rubygems": "gem",
    "cargo": "cargo",
    "maven": "maven",
    "packagist": "composer",
    "nuget": "nuget",
    "hex": "hex",
    "swift": "swift",
}


def _parse_npm_dependencies(diff_text: str) -> list[dict]:
    """Extract npm dependencies from package.json diff additions."""
    deps: list[dict] = []
    # Match lines like:  +"package-name": "^1.2.3"
    pattern = re.compile(
        r'^\+\s*"([^"]+)"\s*:\s*"([^"]*)"',
        re.MULTILINE,
    )
    for match in pattern.finditer(diff_text):
        name, version = match.group(1), match.group(2)
        # Skip metadata keys (name, version, description, etc.)
        if name in ("name", "version", "description", "main", "scripts",
                     "repository", "author", "license", "private", "type",
                     "engines", "homepage", "bugs", "keywords"):
            continue
        deps.append({
            "name": name,
            "version": version.lstrip("^~>=<! "),
            "ecosystem": "npm",
            "purl": f"pkg:npm/{name}@{version.lstrip('^~>=<! ')}",
            "scope": "runtime",
        })
    return deps


def _parse_pypi_dependencies(diff_text: str) -> list[dict]:
    """Extract Python dependencies from requirements.txt diff additions."""
    deps: list[dict] = []
    # Match lines like: +requests==2.31.0 or +flask>=3.0
    pattern = re.compile(
        r'^\+\s*([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*([><=!~]+\s*[\d][^\s,;#]*)?',
        re.MULTILINE,
    )
    for match in pattern.finditer(diff_text):
        name = match.group(1).strip()
        version_spec = (match.group(2) or "").strip()
        # Skip comment lines and pip flags
        if name.startswith(("#", "-", "git+", "http")):
            continue
        version = re.sub(r'^[><=!~]+\s*', '', version_spec) if version_spec else "unknown"
        deps.append({
            "name": name,
            "version": version,
            "ecosystem": "pypi",
            "purl": f"pkg:pypi/{name.lower()}@{version}",
            "scope": "runtime",
        })
    return deps


def _parse_go_dependencies(diff_text: str) -> list[dict]:
    """Extract Go dependencies from go.mod diff additions."""
    deps: list[dict] = []
    # Match lines like: +    github.com/gin-gonic/gin v1.9.1
    pattern = re.compile(
        r'^\+\s+([a-zA-Z0-9._/-]+\.[a-zA-Z]+[a-zA-Z0-9._/-]*)\s+(v[\d][^\s]*)',
        re.MULTILINE,
    )
    for match in pattern.finditer(diff_text):
        name, version = match.group(1), match.group(2)
        deps.append({
            "name": name,
            "version": version.lstrip("v"),
            "ecosystem": "golang",
            "purl": f"pkg:golang/{name}@{version.lstrip('v')}",
            "scope": "runtime",
        })
    return deps


def _parse_cargo_dependencies(diff_text: str) -> list[dict]:
    """Extract Rust dependencies from Cargo.toml diff additions."""
    deps: list[dict] = []
    # Match lines like: +serde = "1.0" or +tokio = { version = "1.0", features = [...] }
    simple_pattern = re.compile(
        r'^\+\s*([a-zA-Z0-9_-]+)\s*=\s*"([^"]*)"',
        re.MULTILINE,
    )
    complex_pattern = re.compile(
        r'^\+\s*([a-zA-Z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]*)"',
        re.MULTILINE,
    )
    for match in simple_pattern.finditer(diff_text):
        name, version = match.group(1), match.group(2)
        if name in ("name", "version", "edition", "description", "license",
                     "authors", "repository", "homepage"):
            continue
        deps.append({
            "name": name,
            "version": version,
            "ecosystem": "cargo",
            "purl": f"pkg:cargo/{name}@{version}",
            "scope": "runtime",
        })
    for match in complex_pattern.finditer(diff_text):
        name, version = match.group(1), match.group(2)
        deps.append({
            "name": name,
            "version": version,
            "ecosystem": "cargo",
            "purl": f"pkg:cargo/{name}@{version}",
            "scope": "runtime",
        })
    return deps


def _parse_gemfile_dependencies(diff_text: str) -> list[dict]:
    """Extract Ruby dependencies from Gemfile diff additions."""
    deps: list[dict] = []
    # Match lines like: +gem 'rails', '~> 7.0'
    pattern = re.compile(
        r"""^\+\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?""",
        re.MULTILINE,
    )
    for match in pattern.finditer(diff_text):
        name = match.group(1)
        version = (match.group(2) or "").lstrip("~>= ")
        deps.append({
            "name": name,
            "version": version or "unknown",
            "ecosystem": "rubygems",
            "purl": f"pkg:gem/{name}@{version or 'unknown'}",
            "scope": "runtime",
        })
    return deps


def _parse_maven_dependencies(diff_text: str) -> list[dict]:
    """Extract Java dependencies from pom.xml diff additions."""
    deps: list[dict] = []
    # Simple extraction of groupId/artifactId/version blocks in pom.xml
    # Match added dependency blocks
    dep_blocks = re.findall(
        r'<dependency>\s*'
        r'<groupId>([^<]+)</groupId>\s*'
        r'<artifactId>([^<]+)</artifactId>\s*'
        r'(?:<version>([^<]+)</version>)?',
        diff_text,
    )
    for group_id, artifact_id, version in dep_blocks:
        version = version or "unknown"
        deps.append({
            "name": f"{group_id}:{artifact_id}",
            "version": version,
            "ecosystem": "maven",
            "purl": f"pkg:maven/{group_id}/{artifact_id}@{version}",
            "scope": "runtime",
        })
    return deps


def parse_dependencies_from_diff(changes: list[dict]) -> list[dict]:
    """Parse all dependencies from MR diff changes across ecosystems.

    Examines each changed file, identifies its ecosystem, and extracts
    added dependencies with name, version, ecosystem, and Package URL.

    Returns a deduplicated list of dependency dicts.
    """
    all_deps: list[dict] = []
    seen: set[str] = set()

    parsers = {
        "npm": _parse_npm_dependencies,
        "pypi": _parse_pypi_dependencies,
        "golang": _parse_go_dependencies,
        "cargo": _parse_cargo_dependencies,
        "rubygems": _parse_gemfile_dependencies,
        "maven": _parse_maven_dependencies,
    }

    for change in changes:
        path = change.get("new_path", change.get("old_path", ""))
        filename = Path(path).name
        ecosystem = ECOSYSTEM_MAP.get(filename)
        if not ecosystem:
            continue

        diff = change.get("diff", "")
        if not diff:
            continue

        parser = parsers.get(ecosystem)
        if not parser:
            continue

        for dep in parser(diff):
            key = f"{dep['ecosystem']}:{dep['name']}:{dep['version']}"
            if key not in seen:
                seen.add(key)
                all_deps.append(dep)

    return all_deps


def generate_sbom(
    changes: list[dict],
    project_name: str = "unknown",
    project_version: str = "0.0.0",
    output_path: str | None = None,
) -> dict:
    """Generate a CycloneDX 1.5 SBOM from MR dependency changes.

    Produces a Software Bill of Materials in CycloneDX JSON format,
    which is the standard supported by GitLab Dependency Scanning.

    Args:
        changes: list of MR change dicts (with new_path and diff)
        project_name: name of the project for the SBOM metadata
        project_version: version string for the project
        output_path: optional file path to write the SBOM JSON

    Returns:
        The CycloneDX SBOM dict.
    """
    deps = parse_dependencies_from_diff(changes)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = f"urn:uuid:{uuid.uuid4()}"

    components = []
    for dep in deps:
        component = {
            "type": "library",
            "name": dep["name"],
            "version": dep["version"],
            "purl": dep["purl"],
            "properties": [
                {"name": "duoguard:ecosystem", "value": dep["ecosystem"]},
                {"name": "duoguard:scope", "value": dep.get("scope", "runtime")},
            ],
        }
        # Add group for Maven-style coordinates
        if ":" in dep["name"] and dep["ecosystem"] == "maven":
            parts = dep["name"].split(":", 1)
            component["group"] = parts[0]
            component["name"] = parts[1]
        components.append(component)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{
                "vendor": "DuoGuard",
                "name": "DuoGuard SBOM Generator",
                "version": "1.0.0",
            }],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": project_name,
                "dependsOn": [dep["purl"] for dep in deps],
            }
        ],
    }

    if output_path:
        with open(output_path, "w") as f:
            json.dump(sbom, f, indent=2)

    return sbom


def generate_sast_report(
    code_findings: str,
    dep_findings: str = "",
    secret_findings: str = "",
    output_path: str | None = None,
) -> dict:
    """Generate a GitLab-native SAST report (gl-sast-report.json).

    Produces a JSON report conforming to GitLab Security Report Schema v15.0.7,
    compatible with the GitLab Security Dashboard and MR Security widget.

    Args:
        code_findings: raw markdown output from code security reviewer
        dep_findings: raw markdown output from dependency auditor
        secret_findings: raw markdown output from secret scanner
        output_path: optional file path to write the JSON report

    Returns:
        The SAST report dict.
    """
    all_findings = (
        _parse_findings(code_findings, "code-security")
        + _parse_findings(dep_findings, "dependency-audit")
        + _parse_findings(secret_findings, "secret-scan")
    )

    severity_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    vulnerabilities = []
    for f in all_findings:
        vuln_id = str(uuid.uuid4())
        sast_severity = severity_map.get(f["severity"], "Info")

        # Build identifiers
        identifiers = []
        if f.get("cwe"):
            cwe_num = f["cwe"].replace("CWE-", "")
            identifiers.append({
                "type": "cwe",
                "name": f["cwe"],
                "value": cwe_num,
                "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
            })

        # Build links
        links = []
        if f.get("owasp"):
            links.append({
                "name": f["owasp"],
                "url": "https://owasp.org/Top10/",
            })

        vuln = {
            "id": vuln_id,
            "category": "sast",
            "name": f["description"],
            "message": f["description"],
            "description": f"[{f['severity'].upper()}] {f['description']} (category: {f['category']})",
            "severity": sast_severity,
            "scanner": {
                "id": "duoguard-sast",
                "name": "DuoGuard SAST",
            },
            "identifiers": identifiers,
            "location": {
                "file": f["file_path"],
                "start_line": f["line_num"],
            },
            "links": links,
        }
        vulnerabilities.append(vuln)

    report = {
        "version": "15.0.7",
        "scan": {
            "type": "sast",
            "status": "success",
            "start_time": now,
            "end_time": now,
            "scanner": {
                "id": "duoguard-sast",
                "name": "DuoGuard SAST",
                "version": "1.0.0",
                "vendor": {"name": "DuoGuard"},
            },
            "analyzer": {
                "id": "duoguard-sast-analyzer",
                "name": "DuoGuard SAST Analyzer",
                "version": "1.0.0",
                "vendor": {"name": "DuoGuard"},
            },
        },
        "vulnerabilities": vulnerabilities,
    }

    if output_path:
        with open(output_path, "w") as fh:
            json.dump(report, fh, indent=2)

    return report


def generate_dependency_scanning_report(
    sbom: dict,
    dep_findings: str = "",
    output_path: str | None = None,
) -> dict:
    """Generate a GitLab Dependency Scanning report with vulnerability entries.

    Wraps ``sbom_to_gitlab_dependency_report`` and enriches it with actual
    vulnerability entries parsed from the dependency audit findings.

    Args:
        sbom: CycloneDX SBOM dict (from ``generate_sbom``)
        dep_findings: raw markdown output from the dependency auditor agent
        output_path: optional file path to write the JSON report

    Returns:
        GitLab-compatible dependency scanning report dict.
    """
    base_report = sbom_to_gitlab_dependency_report(sbom)

    # Parse dependency findings and add as vulnerabilities
    findings = _parse_findings(dep_findings, "dependency-audit")

    severity_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    vulnerabilities = []
    for f in findings:
        vuln_id = str(uuid.uuid4())
        sast_severity = severity_map.get(f["severity"], "Info")

        identifiers = []
        if f.get("cwe"):
            cwe_num = f["cwe"].replace("CWE-", "")
            identifiers.append({
                "type": "cwe",
                "name": f["cwe"],
                "value": cwe_num,
                "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
            })

        links = []
        if f.get("owasp"):
            links.append({
                "name": f["owasp"],
                "url": "https://owasp.org/Top10/",
            })

        vuln = {
            "id": vuln_id,
            "category": "dependency_scanning",
            "name": f["description"],
            "message": f["description"],
            "description": f"[{f['severity'].upper()}] {f['description']}",
            "severity": sast_severity,
            "scanner": {
                "id": "duoguard-sbom",
                "name": "DuoGuard SBOM Scanner",
            },
            "identifiers": identifiers,
            "location": {
                "file": f["file_path"],
                "dependency": {
                    "package": {"name": f.get("file_path", "unknown")},
                },
            },
            "links": links,
        }
        vulnerabilities.append(vuln)

    base_report["vulnerabilities"] = vulnerabilities

    if output_path:
        with open(output_path, "w") as fh:
            json.dump(base_report, fh, indent=2)

    return base_report


def sbom_to_gitlab_dependency_report(sbom: dict) -> dict:
    """Convert a CycloneDX SBOM to GitLab Dependency Scanning report format.

    This allows DuoGuard SBOM output to integrate with GitLab's
    Dependency Scanning widget in the MR and Security Dashboard.

    Returns a GitLab-compatible dependency scanning report dict.
    """
    dependencies = []
    for comp in sbom.get("components", []):
        dep_entry = {
            "name": comp.get("name", "unknown"),
            "version": comp.get("version", "unknown"),
            "package_manager": "unknown",
        }
        # Extract ecosystem from properties
        for prop in comp.get("properties", []):
            if prop.get("name") == "duoguard:ecosystem":
                dep_entry["package_manager"] = prop["value"]
        if comp.get("purl"):
            dep_entry["purl"] = comp["purl"]
        dependencies.append(dep_entry)

    return {
        "version": "15.0.7",
        "schema": "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.0.7/dist/dependency-scanning-report-format.json",
        "scan": {
            "type": "dependency_scanning",
            "status": "success",
            "scanner": {
                "id": "duoguard-sbom",
                "name": "DuoGuard SBOM Scanner",
                "version": "1.0.0",
                "vendor": {"name": "DuoGuard"},
            },
            "analyzer": {
                "id": "duoguard-sbom-analyzer",
                "name": "DuoGuard Dependency Analyzer",
                "version": "1.0.0",
                "vendor": {"name": "DuoGuard"},
            },
        },
        "dependency_files": [],
        "dependencies": dependencies,
        "vulnerabilities": [],
    }


# ── Security Compliance Mapping ───────────────────────────────

# CWE to compliance control mappings
# Maps CWE IDs to relevant controls in SOC2, ISO 27001, and NIST 800-53

COMPLIANCE_CONTROLS: dict[str, dict[str, list[str]]] = {
    "CWE-89": {  # SQL Injection
        "soc2": ["CC6.1", "CC6.6", "CC7.1"],
        "iso27001": ["A.14.2.5", "A.14.1.2"],
        "nist": ["SI-10", "SI-16", "SA-11"],
        "description": "SQL Injection — Input validation and secure coding",
    },
    "CWE-79": {  # XSS
        "soc2": ["CC6.1", "CC6.6"],
        "iso27001": ["A.14.2.5", "A.14.1.2"],
        "nist": ["SI-10", "SA-11"],
        "description": "Cross-Site Scripting — Output encoding and input sanitization",
    },
    "CWE-78": {  # OS Command Injection
        "soc2": ["CC6.1", "CC6.6", "CC7.1", "CC7.2"],
        "iso27001": ["A.14.2.5", "A.12.5.1"],
        "nist": ["SI-10", "SI-3", "SA-11"],
        "description": "OS Command Injection — Input validation and least privilege",
    },
    "CWE-22": {  # Path Traversal
        "soc2": ["CC6.1", "CC6.3"],
        "iso27001": ["A.14.2.5", "A.9.4.1"],
        "nist": ["SI-10", "AC-3"],
        "description": "Path Traversal — Access control and input validation",
    },
    "CWE-918": {  # SSRF
        "soc2": ["CC6.1", "CC6.6", "CC6.7"],
        "iso27001": ["A.14.2.5", "A.13.1.1"],
        "nist": ["SI-10", "SC-7", "AC-4"],
        "description": "Server-Side Request Forgery — Network segmentation and input validation",
    },
    "CWE-502": {  # Deserialization
        "soc2": ["CC6.1", "CC7.1"],
        "iso27001": ["A.14.2.5", "A.14.1.2"],
        "nist": ["SI-10", "SI-2"],
        "description": "Insecure Deserialization — Data integrity and input validation",
    },
    "CWE-611": {  # XXE
        "soc2": ["CC6.1", "CC6.6"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SI-10", "SA-11"],
        "description": "XML External Entity — Secure XML parsing configuration",
    },
    "CWE-287": {  # Authentication Bypass
        "soc2": ["CC6.1", "CC6.2", "CC6.3"],
        "iso27001": ["A.9.4.2", "A.14.2.5"],
        "nist": ["IA-2", "IA-5", "AC-3"],
        "description": "Authentication Bypass — Strong authentication mechanisms",
    },
    "CWE-798": {  # Hardcoded Credentials
        "soc2": ["CC6.1", "CC6.2", "CC6.7"],
        "iso27001": ["A.9.2.4", "A.9.4.3", "A.14.2.5"],
        "nist": ["IA-5", "SC-12", "SC-28"],
        "description": "Hardcoded Credentials — Secrets management and key rotation",
    },
    "CWE-321": {  # Hardcoded Crypto Key
        "soc2": ["CC6.1", "CC6.7"],
        "iso27001": ["A.10.1.2", "A.14.2.5"],
        "nist": ["SC-12", "SC-13"],
        "description": "Hardcoded Cryptographic Key — Key management procedures",
    },
    "CWE-327": {  # Weak Cryptography
        "soc2": ["CC6.1", "CC6.7"],
        "iso27001": ["A.10.1.1", "A.10.1.2"],
        "nist": ["SC-12", "SC-13"],
        "description": "Weak Cryptographic Algorithm — Use approved algorithms",
    },
    "CWE-330": {  # Insecure Randomness
        "soc2": ["CC6.1"],
        "iso27001": ["A.10.1.1"],
        "nist": ["SC-13"],
        "description": "Insufficient Randomness — Use CSPRNG for security operations",
    },
    "CWE-601": {  # Open Redirect
        "soc2": ["CC6.1", "CC6.6"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SI-10"],
        "description": "Open Redirect — URL validation and whitelisting",
    },
    "CWE-352": {  # CSRF
        "soc2": ["CC6.1", "CC6.6"],
        "iso27001": ["A.14.2.5", "A.14.1.2"],
        "nist": ["SI-10", "SC-23"],
        "description": "Cross-Site Request Forgery — Anti-CSRF tokens",
    },
    "CWE-362": {  # Race Condition
        "soc2": ["CC7.1"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SI-16"],
        "description": "Race Condition — Synchronization and concurrency controls",
    },
    "CWE-120": {  # Buffer Overflow
        "soc2": ["CC7.1", "CC7.2"],
        "iso27001": ["A.14.2.5", "A.12.6.1"],
        "nist": ["SI-16", "SA-11"],
        "description": "Buffer Overflow — Memory-safe coding practices",
    },
    "CWE-190": {  # Integer Overflow
        "soc2": ["CC7.1"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SI-16"],
        "description": "Integer Overflow — Bounds checking and safe integer operations",
    },
    "CWE-862": {  # Missing Authorization
        "soc2": ["CC6.1", "CC6.3"],
        "iso27001": ["A.9.4.1", "A.14.2.5"],
        "nist": ["AC-3", "AC-6"],
        "description": "Missing Authorization — Enforce access control checks",
    },
    "CWE-639": {  # IDOR
        "soc2": ["CC6.1", "CC6.3"],
        "iso27001": ["A.9.4.1"],
        "nist": ["AC-3", "AC-4"],
        "description": "Insecure Direct Object Reference — Object-level authorization",
    },
    "CWE-117": {  # Log Injection
        "soc2": ["CC7.1", "CC7.3"],
        "iso27001": ["A.12.4.1", "A.14.2.5"],
        "nist": ["AU-3", "SI-10"],
        "description": "Log Injection — Log sanitization and integrity",
    },
    "CWE-200": {  # Information Disclosure
        "soc2": ["CC6.1", "CC6.5"],
        "iso27001": ["A.18.1.4", "A.14.2.5"],
        "nist": ["AC-4", "SC-8"],
        "description": "Information Disclosure — Data classification and access control",
    },
    "CWE-90": {  # LDAP Injection
        "soc2": ["CC6.1", "CC6.6"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SI-10", "SA-11"],
        "description": "LDAP Injection — Input validation for LDAP queries",
    },
    "CWE-91": {  # XML Injection
        "soc2": ["CC6.1"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SI-10"],
        "description": "XML Injection — Secure XML processing",
    },
    "CWE-94": {  # Code Injection
        "soc2": ["CC6.1", "CC6.6", "CC7.1"],
        "iso27001": ["A.14.2.5", "A.12.5.1"],
        "nist": ["SI-10", "SI-3", "SA-11"],
        "description": "Code Injection — Avoid dynamic code execution with user input",
    },
    "CWE-95": {  # Eval Injection
        "soc2": ["CC6.1", "CC6.6"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SI-10", "SA-11"],
        "description": "Eval Injection — Eliminate eval() with user-controlled data",
    },
    "CWE-1321": {  # Prototype Pollution
        "soc2": ["CC6.1"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SI-10", "SI-16"],
        "description": "Prototype Pollution — Object freezing and input validation",
    },
    "CWE-915": {  # Mass Assignment
        "soc2": ["CC6.1", "CC6.3"],
        "iso27001": ["A.14.2.5", "A.9.4.1"],
        "nist": ["AC-3", "SI-10"],
        "description": "Mass Assignment — Allowlist acceptable fields",
    },
    "CWE-434": {  # Unrestricted Upload
        "soc2": ["CC6.1", "CC6.6", "CC7.1"],
        "iso27001": ["A.14.2.5", "A.12.2.1"],
        "nist": ["SI-3", "SI-10", "SC-18"],
        "description": "Unrestricted File Upload — File type validation and sandboxing",
    },
    "CWE-400": {  # Resource Exhaustion
        "soc2": ["CC7.1", "CC7.2"],
        "iso27001": ["A.12.1.3", "A.14.2.5"],
        "nist": ["SC-5", "SI-10"],
        "description": "Resource Exhaustion — Rate limiting and input size bounds",
    },
    "CWE-1333": {  # ReDoS
        "soc2": ["CC7.1"],
        "iso27001": ["A.14.2.5"],
        "nist": ["SC-5", "SI-10"],
        "description": "ReDoS — Use safe regex patterns and input length limits",
    },
}

# SOC2 Trust Services Criteria descriptions
SOC2_CONTROLS: dict[str, str] = {
    "CC6.1": "Logical and Physical Access Controls — The entity implements logical access security",
    "CC6.2": "User Authentication — Prior to issuing system credentials and granting access",
    "CC6.3": "Authorization — The entity authorizes, modifies, or removes access",
    "CC6.5": "Data Transmission — The entity protects data transmitted",
    "CC6.6": "Security Controls — The entity implements controls to prevent threats",
    "CC6.7": "Data Disposal — The entity restricts transmission of confidential data",
    "CC7.1": "Monitoring — The entity detects and monitors anomalies",
    "CC7.2": "Incident Response — The entity monitors system components for anomalies",
    "CC7.3": "Recovery — The entity evaluates security events to determine their impact",
}

# ISO 27001:2022 control descriptions
ISO27001_CONTROLS: dict[str, str] = {
    "A.9.2.4": "Management of secret authentication information of users",
    "A.9.4.1": "Information access restriction",
    "A.9.4.2": "Secure log-on procedures",
    "A.9.4.3": "Password management system",
    "A.10.1.1": "Policy on the use of cryptographic controls",
    "A.10.1.2": "Key management",
    "A.12.1.3": "Capacity management",
    "A.12.2.1": "Controls against malware",
    "A.12.4.1": "Event logging",
    "A.12.5.1": "Installation of software on operational systems",
    "A.12.6.1": "Management of technical vulnerabilities",
    "A.13.1.1": "Network controls",
    "A.14.1.2": "Securing application services on public networks",
    "A.14.2.5": "Secure system engineering principles",
    "A.18.1.4": "Privacy and protection of personally identifiable information",
}

# NIST 800-53 control descriptions
NIST_CONTROLS: dict[str, str] = {
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-6": "Least Privilege",
    "AU-3": "Content of Audit Records",
    "IA-2": "Identification and Authentication",
    "IA-5": "Authenticator Management",
    "SA-11": "Developer Testing and Evaluation",
    "SC-5": "Denial-of-Service Protection",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-18": "Mobile Code",
    "SC-23": "Session Authenticity",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection",
    "SI-10": "Information Input Validation",
    "SI-16": "Memory Protection",
}


def map_finding_to_compliance(finding: dict) -> dict:
    """Map a security finding to compliance framework controls.

    Takes a finding dict (with at least 'cwe' and optionally 'severity',
    'description') and returns a dict with compliance control mappings.

    Returns a dict with keys: cwe, soc2, iso27001, nist, description,
    and the original finding fields.
    """
    cwe = finding.get("cwe", "")
    controls = COMPLIANCE_CONTROLS.get(cwe, {})

    return {
        **finding,
        "compliance": {
            "cwe": cwe,
            "soc2": controls.get("soc2", []),
            "iso27001": controls.get("iso27001", []),
            "nist": controls.get("nist", []),
            "control_description": controls.get("description", ""),
        },
    }


def map_findings_to_compliance(findings: list[dict]) -> list[dict]:
    """Map all findings to compliance controls.

    Returns a new list with compliance mappings added to each finding.
    """
    return [map_finding_to_compliance(f) for f in findings]


def generate_compliance_report(
    findings: list[dict],
    frameworks: list[str] | None = None,
) -> dict:
    """Generate a compliance-oriented report from security findings.

    Aggregates findings by compliance framework and control, producing
    a structured report showing which controls are impacted by which
    findings.

    Args:
        findings: list of finding dicts (should already have 'cwe' enrichment)
        frameworks: list of frameworks to include (default: all three)

    Returns:
        A dict with per-framework control impact summaries and overall
        compliance posture assessment.
    """
    if frameworks is None:
        frameworks = ["soc2", "iso27001", "nist"]

    mapped = map_findings_to_compliance(findings)

    # Aggregate by framework and control
    framework_data: dict[str, dict] = {}

    control_descriptions = {
        "soc2": SOC2_CONTROLS,
        "iso27001": ISO27001_CONTROLS,
        "nist": NIST_CONTROLS,
    }

    for fw in frameworks:
        controls_impacted: dict[str, list[dict]] = {}
        for m in mapped:
            comp = m.get("compliance", {})
            for ctrl in comp.get(fw, []):
                if ctrl not in controls_impacted:
                    controls_impacted[ctrl] = []
                controls_impacted[ctrl].append({
                    "cwe": comp.get("cwe", ""),
                    "severity": m.get("severity", "info"),
                    "description": m.get("description", ""),
                    "file_path": m.get("file_path", "unknown"),
                })

        desc_map = control_descriptions.get(fw, {})
        framework_data[fw] = {
            "controls_impacted": len(controls_impacted),
            "total_controls": len(desc_map),
            "details": {
                ctrl: {
                    "description": desc_map.get(ctrl, ctrl),
                    "findings": ctrl_findings,
                    "finding_count": len(ctrl_findings),
                    "max_severity": _max_severity([f["severity"] for f in ctrl_findings]),
                }
                for ctrl, ctrl_findings in sorted(controls_impacted.items())
            },
        }

    # Overall posture
    severity_order = ["info", "low", "medium", "high", "critical"]
    all_severities = [f.get("severity", "info") for f in findings]
    max_sev = _max_severity(all_severities) if all_severities else "none"

    posture_map = {
        "critical": "NON_COMPLIANT",
        "high": "AT_RISK",
        "medium": "NEEDS_REVIEW",
        "low": "ACCEPTABLE",
        "info": "COMPLIANT",
        "none": "COMPLIANT",
    }

    return {
        "report_type": "compliance",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "frameworks": framework_data,
        "overall_posture": posture_map.get(max_sev, "COMPLIANT"),
        "total_findings": len(findings),
        "findings_with_compliance_mapping": sum(
            1 for m in mapped if m.get("compliance", {}).get("cwe") in COMPLIANCE_CONTROLS
        ),
    }


def _max_severity(severities: list[str]) -> str:
    """Return the highest severity from a list."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if not severities:
        return "none"
    return max(severities, key=lambda s: order.get(s.lower(), -1))


def format_compliance_markdown(report: dict) -> str:
    """Format a compliance report dict as a Markdown section for the MR report.

    Produces a human-readable compliance section with tables per framework.
    """
    lines = [
        "### Compliance Impact Assessment",
        "",
        f"**Overall Posture:** {report.get('overall_posture', 'UNKNOWN')}",
        f"**Findings with Compliance Mapping:** "
        f"{report.get('findings_with_compliance_mapping', 0)}"
        f"/{report.get('total_findings', 0)}",
        "",
    ]

    framework_labels = {
        "soc2": "SOC 2 Type II",
        "iso27001": "ISO 27001:2022",
        "nist": "NIST 800-53",
    }

    for fw, fw_data in report.get("frameworks", {}).items():
        label = framework_labels.get(fw, fw.upper())
        impacted = fw_data.get("controls_impacted", 0)
        total = fw_data.get("total_controls", 0)
        lines.append(f"#### {label}")
        lines.append(f"**Controls Impacted:** {impacted}/{total}")
        lines.append("")

        details = fw_data.get("details", {})
        if details:
            lines.append("| Control | Description | Findings | Max Severity |")
            lines.append("|---------|-------------|----------|--------------|")
            for ctrl, ctrl_data in details.items():
                desc = ctrl_data.get("description", "")
                if len(desc) > 50:
                    desc = desc[:47] + "..."
                count = ctrl_data.get("finding_count", 0)
                max_sev = ctrl_data.get("max_severity", "info").upper()
                lines.append(f"| {ctrl} | {desc} | {count} | {max_sev} |")
            lines.append("")
        else:
            lines.append("No controls impacted.")
            lines.append("")

    return "\n".join(lines)


# ── Fix Suggestions (Auto-Remediation) ────────────────────────

FIX_SUGGESTION_PROMPT = """You are a senior security engineer generating fix suggestions.
For each security finding, provide a concise, actionable code fix.

Rules:
- Output ONLY the fixed code snippet (no explanations unless essential).
- If the fix requires multiple steps, number them.
- Use the SAME programming language as the original code.
- Prefer the most secure standard-library approach.
- If a finding is informational or cannot be auto-fixed, say "Manual review recommended."
- Keep suggestions under 20 lines each.

Format each fix as:
### Fix for: <finding description>
**File:** `<path>` (line <N>)
```<language>
<fixed code>
```
"""


def generate_fix_suggestions(
    findings: list[dict],
    diff_text: str,
    model: str = "claude-sonnet-4-5",
) -> str:
    """Generate AI-powered fix suggestions for security findings.

    Sends parsed findings along with the relevant diff context to Claude,
    which returns concrete remediation code snippets for each issue.

    Args:
        findings: list of finding dicts from ``_parse_findings``
        diff_text: the formatted MR diff (for context)
        model: Claude model to use

    Returns:
        Markdown-formatted fix suggestions string.
    """
    if not findings:
        return "_No findings require fix suggestions._"

    # Build a concise summary of findings for the AI
    finding_lines = []
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").upper()
        desc = f.get("description", "Unknown")
        path = f.get("file_path", "unknown")
        line = f.get("line_num", 1)
        cwe = f.get("cwe", "")
        cwe_str = f" ({cwe})" if cwe else ""
        finding_lines.append(
            f"{i}. [{sev}]{cwe_str} {desc} — `{path}` line {line}"
        )

    findings_summary = "\n".join(finding_lines)

    # Truncate diff to keep token usage reasonable
    max_context = 50_000
    context = diff_text[:max_context]
    if len(diff_text) > max_context:
        context += "\n\n> (diff truncated for token limit)"

    user_message = (
        f"Generate fix suggestions for these {len(findings)} security finding(s):\n\n"
        f"{findings_summary}\n\n"
        f"Here is the relevant code diff for context:\n\n{context}"
    )

    try:
        return call_ai_gateway(FIX_SUGGESTION_PROMPT, user_message, model=model)
    except Exception as e:
        return f"_Fix suggestion generation failed: {e}_"


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


# ── GitLab MR Interaction ────────────────────────────────────


def post_mr_note(project_id: str, mr_iid: str, body: str) -> bool:
    """Post a summary comment on the merge request."""
    if not GITLAB_TOKEN:
        print("       Skipping MR note: no GitLab token available")
        return False
    url = (f"{GITLAB_API_URL}/projects/{quote_plus(project_id)}"
           f"/merge_requests/{mr_iid}/notes")
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    try:
        resp = _session.post(url, headers=headers, json={"body": body}, timeout=30)
        resp.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        print(f"       WARNING: Failed to post MR note: {exc}")
        return False


def post_inline_discussions(
    project_id: str, mr_iid: str, findings: list[dict],
    mr_changes: dict,
) -> int:
    """Post findings as inline diff discussions on the MR.

    Each finding with a file_path and line_num is posted as a discussion
    thread anchored to the new-file side of the diff.

    Returns the number of discussions successfully created.
    """
    if not GITLAB_TOKEN:
        print("       Skipping inline comments: no GitLab token available")
        return 0

    # Build set of valid (file, line) pairs from the diff to avoid posting
    # on lines that don't exist in this MR.
    valid_paths = set()
    for change in mr_changes.get("changes", []):
        new_path = change.get("new_path", "")
        if new_path:
            valid_paths.add(new_path)

    url = (f"{GITLAB_API_URL}/projects/{quote_plus(project_id)}"
           f"/merge_requests/{mr_iid}/discussions")
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}

    head_sha = mr_changes.get("diff_refs", {}).get("head_sha", "")
    base_sha = mr_changes.get("diff_refs", {}).get("base_sha", "")
    start_sha = mr_changes.get("diff_refs", {}).get("start_sha", "")

    posted = 0
    for f in findings:
        fp = f.get("file_path", "")
        line = f.get("line_num")
        if not fp or not line:
            continue
        # Normalize path (strip leading /)
        fp = fp.lstrip("/")
        if fp not in valid_paths:
            continue

        severity = f.get("severity", "MEDIUM").upper()
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
            severity, "⚪")
        cwe = f.get("cwe_id", "")
        cwe_tag = f" ({cwe})" if cwe else ""
        body = (f"{emoji} **[{severity}]{cwe_tag}** {f.get('description', 'Security finding')}\n\n"
                f"_Category: {f.get('category', 'unknown')}_")

        position = {
            "position_type": "text",
            "new_path": fp,
            "new_line": int(line),
            "old_path": fp,
        }
        if head_sha:
            position["head_sha"] = head_sha
        if base_sha:
            position["base_sha"] = base_sha
        if start_sha:
            position["start_sha"] = start_sha

        payload = {"body": body, "position": position}
        try:
            resp = _session.post(url, headers=headers, json=payload, timeout=15)
            if resp.status_code in (200, 201):
                posted += 1
            # 400/422 usually means the line doesn't exist in the diff — skip
        except requests.exceptions.RequestException:
            pass

    return posted


def set_mr_labels(project_id: str, mr_iid: str, severity: str) -> bool:
    """Add a security label to the merge request based on overall severity."""
    if not GITLAB_TOKEN:
        return False
    label_map = {
        "CRITICAL": "security::critical",
        "HIGH": "security::high",
        "MEDIUM": "security::medium",
        "LOW": "security::low",
        "NONE": "security::clean",
    }
    label = label_map.get(severity, "security::reviewed")
    url = (f"{GITLAB_API_URL}/projects/{quote_plus(project_id)}"
           f"/merge_requests/{mr_iid}")
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    try:
        # Get current labels
        resp = _session.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        current_labels = resp.json().get("labels", [])
        # Remove existing security labels, add new one
        new_labels = [l for l in current_labels if not l.startswith("security::")]
        new_labels.append(label)
        resp = _session.put(url, headers=headers,
                            json={"labels": ",".join(new_labels)}, timeout=15)
        resp.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        print(f"       WARNING: Failed to set MR labels: {exc}")
        return False


def approve_or_reject_mr(
    project_id: str, mr_iid: str, severity: str, cfg: dict,
) -> str | None:
    """Approve or leave unapproved based on severity vs approve_threshold.

    Returns "approved", "unapproved", or None if approval is disabled.
    """
    if not cfg.get("approve", False):
        return None
    if not GITLAB_TOKEN:
        print("       Skipping auto-approval: no GitLab token available")
        return None

    threshold = cfg.get("approve_threshold", "HIGH")
    severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    sev_idx = severity_order.index(severity) if severity in severity_order else 0
    thr_idx = severity_order.index(threshold) if threshold in severity_order else 3

    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    base = (f"{GITLAB_API_URL}/projects/{quote_plus(project_id)}"
            f"/merge_requests/{mr_iid}")

    if sev_idx < thr_idx:
        # Severity below threshold — approve
        try:
            resp = _session.post(f"{base}/approve", headers=headers, timeout=15)
            if resp.status_code in (200, 201):
                return "approved"
        except requests.exceptions.RequestException as exc:
            print(f"       WARNING: Failed to approve MR: {exc}")
        return None
    else:
        # Severity meets/exceeds threshold — leave unapproved
        return "unapproved"


def create_issues_for_findings(
    project_id: str, findings: list[dict], mr_iid: str,
    max_issues: int = 5,
) -> int:
    """Create GitLab issues for critical and high severity findings.

    Returns the number of issues created.
    """
    if not GITLAB_TOKEN:
        return 0

    high_findings = [f for f in findings
                     if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]
    if not high_findings:
        return 0

    url = f"{GITLAB_API_URL}/projects/{quote_plus(project_id)}/issues"
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    created = 0

    for f in high_findings[:max_issues]:
        severity = f.get("severity", "HIGH").upper()
        cwe = f.get("cwe_id", "")
        desc = f.get("description", "Security finding")
        fp = f.get("file_path", "unknown")
        line = f.get("line_num", "")

        title = f"[DuoGuard] [{severity}] {desc[:80]}"
        cwe_link = f"\n\n**CWE:** [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html)" if cwe else ""
        body = (
            f"## Security Finding from MR !{mr_iid}\n\n"
            f"**Severity:** {severity}\n"
            f"**File:** `{fp}`{f' (line {line})' if line else ''}\n"
            f"**Category:** {f.get('category', 'unknown')}\n"
            f"{cwe_link}\n\n"
            f"### Description\n{desc}\n\n"
            f"_Auto-created by DuoGuard security review._"
        )
        labels = f"security::{severity.lower()},DuoGuard"

        try:
            resp = _session.post(url, headers=headers, json={
                "title": title, "description": body, "labels": labels,
            }, timeout=15)
            if resp.status_code in (200, 201):
                created += 1
        except requests.exceptions.RequestException:
            pass

    return created


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
    print("\n[1/7] Fetching merge request data...")
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
    print("\n[2/7] Running security agents in parallel...")
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

    # Generate fix suggestions for findings
    fix_suggestions = None
    if cfg.get("fix_suggestions", True):
        all_parsed = (
            _parse_findings(code_findings, "code-security")
            + _parse_findings(dep_findings, "dependency-audit")
            + _parse_findings(secret_findings, "secret-scan")
        )
        if all_parsed:
            print("\n[2.5/7] Generating fix suggestions...")
            model = cfg.get("model", "claude-sonnet-4-5")
            fix_suggestions = generate_fix_suggestions(all_parsed, diff_text, model=model)
            print(f"         Generated suggestions for {len(all_parsed)} finding(s)")

    # Generate reports
    scan_duration = time.monotonic() - scan_start
    print("\n[3/7] Generating reports...")
    report = generate_report(mr_info, code_findings, dep_findings, secret_findings,
                             scan_duration=scan_duration, files_scanned=len(changes),
                             complexity=complexity, fix_suggestions=fix_suggestions)
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

    sast_path = "gl-sast-report.json"
    generate_sast_report(code_findings,
                         dep_findings=dep_findings,
                         secret_findings=secret_findings,
                         output_path=sast_path)
    print(f"       SAST report: {sast_path}")

    # Generate dependency scanning report if dependency changes exist
    if dep_changes:
        dep_scan_path = "gl-dependency-scanning-report.json"
        sbom = generate_sbom(dep_changes,
                             project_name=mr_info.get("title", "unknown"))
        generate_dependency_scanning_report(sbom,
                                            dep_findings=dep_findings,
                                            output_path=dep_scan_path)
        print(f"       Dependency Scanning report: {dep_scan_path}")

    # Export findings JSON for inline comments
    print("\n[4/7] Exporting findings...")
    findings_path = "duoguard-findings.json"
    all_findings = export_findings_json(
        code_findings, dep_findings, secret_findings, findings_path)
    print(f"       {len(all_findings)} finding(s) exported to {findings_path}")

    print("\n[5/7] Evaluating risk...")
    severity = determine_severity(code_findings, dep_findings, secret_findings)
    print(f"       Overall Risk Level: {severity}")

    # Write severity to file for downstream jobs
    Path("duoguard-severity.txt").write_text(severity)

    # Post results back to GitLab MR
    print("\n[6/7] Posting results to GitLab MR...")

    # Post summary comment
    if post_mr_note(project_id, mr_iid, report):
        print("       Summary comment posted")

    # Post inline diff discussions
    if cfg.get("inline_comments", True) and all_findings:
        posted = post_inline_discussions(
            project_id, mr_iid, all_findings, mr_changes)
        print(f"       {posted} inline discussion(s) posted")

    # Set security label
    if set_mr_labels(project_id, mr_iid, severity):
        print(f"       Label set: security::{severity.lower()}")

    # Auto-approve/reject
    approval = approve_or_reject_mr(project_id, mr_iid, severity, cfg)
    if approval:
        print(f"       MR {approval}")

    # Create issues for critical/high findings
    print("\n[7/7] Creating issues for critical findings...")
    issues_created = create_issues_for_findings(
        project_id, all_findings, mr_iid)
    if issues_created:
        print(f"       {issues_created} issue(s) created")
    else:
        print("       No critical/high findings requiring issues")

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
        if not AI_FLOW_PROJECT_PATH:
            print("  HINT: AI_FLOW_PROJECT_PATH is not set. "
                  "Ensure the agent is configured in GitLab Duo.")
        if not GITLAB_TOKEN:
            print("  HINT: No GitLab token found. Set AI_FLOW_GITLAB_TOKEN or GITLAB_TOKEN.")
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
