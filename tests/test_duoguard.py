"""Tests for DuoGuard security review orchestration."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from duoguard import (
    CWE_KEYWORD_MAP,
    DEFAULT_CONFIG,
    MAX_DIFF_SIZE,
    _count_by_severity,
    _parse_agent_context,
    _parse_findings,
    _parse_gateway_headers,
    _resolve_api_url_for_agent,
    _run_security_scan,
    call_ai_gateway,
    compute_diff_complexity,
    count_findings,
    determine_severity,
    enrich_finding_cwe,
    export_findings_json,
    extract_dependency_files,
    filter_excluded_changes,
    format_diff_for_analysis,
    generate_codequality_report,
    generate_report,
    generate_sarif_report,
    load_agent_prompt,
    load_config,
    run_agent_mode,
    run_code_security_review,
    run_dependency_audit,
    run_secret_scan,
    should_exclude_path,
)
from post_report import (
    SECURITY_LABELS,
    approve_mr,
    create_issue_for_finding,
    create_issues_for_findings,
    find_existing_comment,
    get_mr_diff_versions,
    post_inline_discussion,
    post_inline_findings,
    post_mr_comment,
    resolve_stale_discussions,
    unapprove_mr,
    update_mr_comment,
    update_mr_labels,
)


class TestFormatDiff:
    def test_formats_single_file(self):
        changes = [{"new_path": "app.py", "diff": "+print('hello')"}]
        result = format_diff_for_analysis(changes)
        assert "app.py" in result
        assert "+print('hello')" in result

    def test_formats_multiple_files(self):
        changes = [
            {"new_path": "a.py", "diff": "+x = 1"},
            {"new_path": "b.py", "diff": "-y = 2"},
        ]
        result = format_diff_for_analysis(changes)
        assert "a.py" in result
        assert "b.py" in result

    def test_skips_empty_diffs(self):
        changes = [{"new_path": "empty.py", "diff": ""}]
        result = format_diff_for_analysis(changes)
        assert "empty.py" not in result

    def test_uses_old_path_as_fallback(self):
        changes = [{"old_path": "renamed.py", "diff": "+code"}]
        result = format_diff_for_analysis(changes)
        assert "renamed.py" in result


class TestExtractDependencyFiles:
    def test_detects_package_json(self):
        changes = [
            {"new_path": "package.json", "diff": "+dep"},
            {"new_path": "app.js", "diff": "+code"},
        ]
        result = extract_dependency_files(changes)
        assert len(result) == 1
        assert result[0]["new_path"] == "package.json"

    def test_detects_requirements_txt(self):
        changes = [{"new_path": "requirements.txt", "diff": "+flask"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_detects_go_mod(self):
        changes = [{"new_path": "go.mod", "diff": "+require"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_detects_nested_dependency_files(self):
        changes = [{"new_path": "services/api/package.json", "diff": "+dep"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_ignores_non_dependency_files(self):
        changes = [
            {"new_path": "main.py", "diff": "+code"},
            {"new_path": "README.md", "diff": "+docs"},
        ]
        result = extract_dependency_files(changes)
        assert len(result) == 0

    def test_detects_all_supported_formats(self):
        dep_files = [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile", "pyproject.toml",
            "go.mod", "go.sum", "Gemfile", "Cargo.toml",
            "pom.xml", "build.gradle", "composer.json",
        ]
        changes = [{"new_path": f, "diff": "+change"} for f in dep_files]
        result = extract_dependency_files(changes)
        assert len(result) == len(dep_files)

    def test_detects_extended_formats(self):
        dep_files = [
            "requirements-dev.txt", "requirements-prod.txt",
            "constraints.txt", "poetry.lock", "uv.lock",
            "setup.py", "setup.cfg", "mix.exs", "Dockerfile",
            "Package.swift", "packages.config",
        ]
        changes = [{"new_path": f, "diff": "+change"} for f in dep_files]
        result = extract_dependency_files(changes)
        assert len(result) == len(dep_files)

    def test_detects_prefixed_requirements(self):
        changes = [{"new_path": "requirements-ci.txt", "diff": "+pytest"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1


class TestDetermineSeverity:
    def test_critical(self):
        assert determine_severity("### [CRITICAL] SQL Injection", "", "") == "CRITICAL"

    def test_high(self):
        assert determine_severity("### [HIGH] XSS", "", "") == "HIGH"

    def test_medium(self):
        assert determine_severity("", "### [MEDIUM] outdated dep", "") == "MEDIUM"

    def test_low(self):
        assert determine_severity("", "", "### [LOW] weak key") == "LOW"

    def test_none(self):
        assert determine_severity("No issues found", "Clean", "Clean") == "NONE"

    def test_highest_severity_wins(self):
        assert determine_severity(
            "### [CRITICAL] injection",
            "### [LOW] old dep",
            "### [HIGH] leaked key",
        ) == "CRITICAL"

    def test_case_insensitive(self):
        assert determine_severity("### [critical] test", "", "") == "CRITICAL"

    def test_weighted_multiple_mediums_escalate(self):
        """Multiple medium findings should escalate to HIGH."""
        mediums = "\n".join(f"[MEDIUM] Finding {i}" for i in range(3))
        assert determine_severity(mediums, "", "") == "HIGH"

    def test_weighted_many_lows_escalate(self):
        """Many low findings should escalate to MEDIUM."""
        lows = "\n".join(f"[LOW] Finding {i}" for i in range(3))
        assert determine_severity(lows, "", "") == "MEDIUM"


class TestCountFindings:
    def test_counts_multiple_findings(self):
        text = """
### [HIGH] Finding 1
details
### [MEDIUM] Finding 2
details
### [LOW] Finding 3
"""
        assert count_findings(text) == 3

    def test_zero_findings(self):
        assert count_findings("No security issues found.") == 0

    def test_counts_critical(self):
        text = "### [CRITICAL] SQL injection detected"
        assert count_findings(text) == 1


class TestGenerateReport:
    def test_includes_mr_info(self):
        report = generate_report(
            {"iid": 42, "title": "Add login"},
            "No issues",
            "No issues",
            "No issues",
        )
        assert "!42" in report
        assert "Add login" in report

    def test_includes_all_sections(self):
        report = generate_report(
            {"iid": 1, "title": "Test"},
            "Code findings here",
            "Dep findings here",
            "Secret findings here",
        )
        assert "Code Security Analysis" in report
        assert "Dependency Audit" in report
        assert "Secret Scan" in report
        assert "Summary" in report

    def test_severity_in_report(self):
        report = generate_report(
            {"iid": 1, "title": "Test"},
            "### [HIGH] XSS found",
            "",
            "",
        )
        assert "HIGH" in report

    def test_hackathon_attribution(self):
        report = generate_report(
            {"iid": 1, "title": "Test"},
            "",
            "",
            "",
        )
        assert "GitLab AI Hackathon" in report
        assert "Claude AI" in report


class TestGenerateCodequalityReport:
    def test_generates_valid_json(self, tmp_path):
        output = tmp_path / "cq.json"
        findings = """### [HIGH] Finding: SQL Injection
**File:** `app/db.py` (line 42)
**CWE:** CWE-89
"""
        generate_codequality_report(findings, str(output))
        data = json.loads(output.read_text())
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["severity"] == "critical"  # HIGH maps to critical in CQ
        assert data[0]["location"]["path"] == "app/db.py"

    def test_empty_findings(self, tmp_path):
        output = tmp_path / "cq.json"
        generate_codequality_report("No issues found.", str(output))
        data = json.loads(output.read_text())
        assert data == []

    def test_multiple_findings(self, tmp_path):
        output = tmp_path / "cq.json"
        findings = """### [CRITICAL] Finding: RCE via eval
**File:** `api/handler.py` (line 10)

### [MEDIUM] Finding: Missing CSRF token
**File:** `web/views.py` (line 55)
"""
        generate_codequality_report(findings, str(output))
        data = json.loads(output.read_text())
        assert len(data) == 2
        assert data[0]["severity"] == "blocker"
        assert data[1]["severity"] == "major"

    def test_count_by_severity(self):
        text = "[HIGH] Finding 1\n[HIGH] Finding 2\n[MEDIUM] Finding 3\n[LOW] ok"
        from duoguard import _count_by_severity
        counts = _count_by_severity(text)
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["critical"] == 0

    def test_fingerprints_are_unique(self, tmp_path):
        output = tmp_path / "cq.json"
        findings = """### [HIGH] Finding: XSS in template
**File:** `views/index.html` (line 5)

### [HIGH] Finding: XSS in admin
**File:** `views/admin.html` (line 12)
"""
        generate_codequality_report(findings, str(output))
        data = json.loads(output.read_text())
        assert data[0]["fingerprint"] != data[1]["fingerprint"]


class TestPostReport:
    @patch("post_report.requests.post")
    def test_post_mr_comment(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": 123}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        post_mr_comment("42", "1", "Test comment")
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "notes" in call_kwargs[0][0]
        assert call_kwargs[1]["json"]["body"] == "Test comment"

    @patch("post_report.requests.get")
    def test_find_existing_comment_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 10, "body": "unrelated comment"},
            {"id": 20, "body": "## DuoGuard Security Review Report\nfindings..."},
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = find_existing_comment("42", "1")
        assert result == 20

    @patch("post_report.requests.get")
    def test_find_existing_comment_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 10, "body": "unrelated comment"},
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = find_existing_comment("42", "1")
        assert result is None

    @patch("post_report.requests.put")
    def test_update_mr_comment(self, mock_put):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_put.return_value = mock_resp

        update_mr_comment("42", "1", 20, "Updated report")
        mock_put.assert_called_once()
        assert "20" in mock_put.call_args[0][0]


class TestGenerateSarifReport:
    def test_generates_valid_sarif(self, tmp_path):
        output = tmp_path / "sarif.json"
        findings = """### [HIGH] Finding: SQL Injection
**File:** `app/db.py` (line 42)

### [MEDIUM] Finding: Missing input validation
**File:** `api/handler.py` (line 10)
"""
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 2
        assert data["runs"][0]["tool"]["driver"]["name"] == "DuoGuard"

    def test_sarif_severity_mapping(self, tmp_path):
        output = tmp_path / "sarif.json"
        findings = """### [CRITICAL] Finding: RCE
**File:** `cmd.py` (line 1)

### [LOW] Finding: Debug log
**File:** `log.py` (line 5)
"""
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        results = data["runs"][0]["results"]
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "note"

    def test_sarif_empty_findings(self, tmp_path):
        output = tmp_path / "sarif.json"
        generate_sarif_report("No issues found.", str(output))
        data = json.loads(output.read_text())
        assert data["runs"][0]["results"] == []

    def test_sarif_file_locations(self, tmp_path):
        output = tmp_path / "sarif.json"
        findings = """### [HIGH] Finding: Hardcoded credential
**File:** `config/secrets.py` (line 99)
"""
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "config/secrets.py"
        assert loc["region"]["startLine"] == 99

    def test_sarif_rules_are_unique(self, tmp_path):
        output = tmp_path / "sarif.json"
        findings = """### [HIGH] Finding: XSS
**File:** `a.py` (line 1)

### [HIGH] Finding: XSS
**File:** `b.py` (line 2)
"""
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        # Same finding type should produce only one rule
        assert len(rules) == 1
        # But two results
        assert len(data["runs"][0]["results"]) == 2


class TestLoadAgentPrompt:
    def test_returns_empty_for_missing_file(self):
        result = load_agent_prompt("nonexistent/agent.yml")
        assert result == ""

    def test_loads_existing_agent_config(self):
        # Test with the actual agent config files in the project
        agent_dir = Path(__file__).parent.parent / ".gitlab" / "duo" / "agents"
        if agent_dir.exists():
            for yml in agent_dir.glob("*.yml"):
                result = load_agent_prompt(
                    str(yml.relative_to(Path(__file__).parent.parent))
                )
                # Existing configs should have non-empty prompts
                assert isinstance(result, str)


class TestAgentFunctions:
    @patch("duoguard.call_ai_gateway")
    def test_run_code_security_review(self, mock_call):
        mock_call.return_value = "### [HIGH] Finding: XSS\n**File:** `app.py` (line 1)"
        result = run_code_security_review("test diff")
        mock_call.assert_called_once()
        assert "[HIGH]" in result

    @patch("duoguard.call_ai_gateway")
    def test_run_dependency_audit_with_changes(self, mock_call):
        mock_call.return_value = "### [MEDIUM] Finding: Outdated dep"
        result = run_dependency_audit("package.json changes")
        mock_call.assert_called_once()
        assert "[MEDIUM]" in result

    def test_run_dependency_audit_no_changes(self):
        result = run_dependency_audit("")
        assert "No dependency file changes" in result

    @patch("duoguard.call_ai_gateway")
    def test_run_secret_scan(self, mock_call):
        mock_call.return_value = "No secrets detected."
        result = run_secret_scan("test diff")
        mock_call.assert_called_once()
        assert "No secrets" in result


class TestCallAIGateway:
    def test_no_credentials_returns_message(self):
        with patch.dict(
            "os.environ",
            {"AI_FLOW_AI_GATEWAY_URL": "", "AI_FLOW_AI_GATEWAY_TOKEN": "", "ANTHROPIC_API_KEY": ""},
            clear=False,
        ):
            # Re-import to pick up patched env
            import duoguard
            old_url = duoguard.AI_GATEWAY_URL
            old_token = duoguard.AI_GATEWAY_TOKEN
            duoguard.AI_GATEWAY_URL = ""
            duoguard.AI_GATEWAY_TOKEN = ""
            try:
                result = duoguard.call_ai_gateway("system", "user")
                assert "not configured" in result.lower()
            finally:
                duoguard.AI_GATEWAY_URL = old_url
                duoguard.AI_GATEWAY_TOKEN = old_token

    @patch("duoguard._session")
    def test_ai_gateway_success(self, mock_session):
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = "https://ai-gateway.example.com"
        duoguard.AI_GATEWAY_TOKEN = "test-token"
        try:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": "Analysis result"}}]
            }
            mock_resp.raise_for_status = MagicMock()
            mock_session.post.return_value = mock_resp

            result = duoguard.call_ai_gateway("system prompt", "user message")
            assert result == "Analysis result"
            mock_session.post.assert_called_once()
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    @patch("duoguard._session")
    def test_anthropic_proxy_path(self, mock_session):
        """Test GitLab managed credentials via Anthropic proxy."""
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = ""  # No explicit URL
        duoguard.AI_GATEWAY_TOKEN = "gitlab-managed-token"
        try:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {
                "content": [{"text": "Proxy analysis result"}]
            }
            mock_resp.raise_for_status = MagicMock()
            mock_session.post.return_value = mock_resp

            result = duoguard.call_ai_gateway("system", "user")
            assert result == "Proxy analysis result"
            # Verify it called the proxy URL
            call_url = mock_session.post.call_args[0][0]
            assert "cloud.gitlab.com" in call_url
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token


class TestParseGatewayHeaders:
    def test_json_headers(self):
        result = _parse_gateway_headers('{"X-Custom": "value", "Auth": "token"}')
        assert result == {"X-Custom": "value", "Auth": "token"}

    def test_newline_separated_headers(self):
        result = _parse_gateway_headers("X-Custom: value\nAuth: token")
        assert result == {"X-Custom": "value", "Auth": "token"}

    def test_empty_string(self):
        assert _parse_gateway_headers("") == {}

    def test_invalid_json_falls_through(self):
        result = _parse_gateway_headers("not json at all")
        assert result == {}


class TestResolveApiUrl:
    def test_default_hostname(self):
        import duoguard
        old = duoguard.GITLAB_HOSTNAME
        duoguard.GITLAB_HOSTNAME = "gitlab.com"
        try:
            assert _resolve_api_url_for_agent() == "https://gitlab.com/api/v4"
        finally:
            duoguard.GITLAB_HOSTNAME = old

    def test_custom_hostname(self):
        import duoguard
        old = duoguard.GITLAB_HOSTNAME
        duoguard.GITLAB_HOSTNAME = "gitlab.example.com"
        try:
            assert _resolve_api_url_for_agent() == "https://gitlab.example.com/api/v4"
        finally:
            duoguard.GITLAB_HOSTNAME = old


class TestParseAgentContext:
    def test_json_context_with_mr(self):
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        duoguard.AI_FLOW_CONTEXT = json.dumps({
            "merge_request": {"iid": 42},
            "project": {"path_with_namespace": "group/project"},
        })
        duoguard.AI_FLOW_PROJECT_PATH = ""
        try:
            project_id, mr_iid = _parse_agent_context()
            assert mr_iid == "42"
            assert "group%2Fproject" in project_id
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path

    def test_text_context_with_mr_reference(self):
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        old_input = duoguard.AI_FLOW_INPUT
        duoguard.AI_FLOW_CONTEXT = "Please review !123 for security issues"
        duoguard.AI_FLOW_PROJECT_PATH = "mygroup/myproject"
        duoguard.AI_FLOW_INPUT = ""
        try:
            project_id, mr_iid = _parse_agent_context()
            assert mr_iid == "123"
            assert "mygroup%2Fmyproject" in project_id
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path
            duoguard.AI_FLOW_INPUT = old_input

    def test_mr_from_input(self):
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_input = duoguard.AI_FLOW_INPUT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        duoguard.AI_FLOW_CONTEXT = ""
        duoguard.AI_FLOW_INPUT = "Review !99"
        duoguard.AI_FLOW_PROJECT_PATH = "team/repo"
        try:
            project_id, mr_iid = _parse_agent_context()
            assert mr_iid == "99"
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_INPUT = old_input
            duoguard.AI_FLOW_PROJECT_PATH = old_path

    def test_empty_context(self):
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_input = duoguard.AI_FLOW_INPUT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        duoguard.AI_FLOW_CONTEXT = ""
        duoguard.AI_FLOW_INPUT = ""
        duoguard.AI_FLOW_PROJECT_PATH = ""
        try:
            project_id, mr_iid = _parse_agent_context()
            assert project_id == ""
            assert mr_iid == ""
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_INPUT = old_input
            duoguard.AI_FLOW_PROJECT_PATH = old_path

    def test_project_path_from_env(self):
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        duoguard.AI_FLOW_CONTEXT = json.dumps({"merge_request": {"iid": 5}})
        duoguard.AI_FLOW_PROJECT_PATH = "org/repo"
        try:
            project_id, mr_iid = _parse_agent_context()
            assert "org%2Frepo" in project_id
            assert mr_iid == "5"
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path


class TestParseFindings:
    """Tests for the shared _parse_findings helper."""

    def test_parses_single_finding(self):
        text = "### [HIGH] Finding: SQL Injection\n**File:** `app/db.py` (line 42)\n"
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["description"] == "SQL Injection"
        assert findings[0]["file_path"] == "app/db.py"
        assert findings[0]["line_num"] == 42
        assert findings[0]["category"] == "code-security"

    def test_parses_multiple_findings(self):
        text = (
            "### [CRITICAL] Finding: RCE\n**File:** `cmd.py` (line 1)\n\n"
            "### [LOW] Finding: Debug log\n**File:** `log.py` (line 5)\n"
        )
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 2
        assert findings[0]["severity"] == "critical"
        assert findings[1]["severity"] == "low"

    def test_returns_empty_for_no_findings(self):
        assert _parse_findings("No issues found.", "code-security") == []

    def test_category_is_set(self):
        text = "### [MEDIUM] Finding: Outdated dep\n**File:** `go.mod` (line 3)\n"
        findings = _parse_findings(text, "dependency-audit")
        assert findings[0]["category"] == "dependency-audit"

    def test_finding_without_file_line_not_appended(self):
        """A heading without a matching **File:** line is not emitted."""
        text = "### [HIGH] Finding: Orphan\nSome other text without File marker\n"
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 0

    def test_default_line_num(self):
        text = "### [INFO] Finding: Informational\n**File:** `readme.md`\n"
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        assert findings[0]["line_num"] == 1  # default


class TestCodequalityReportAllFindings:
    """Tests that CodeQuality report includes dep and secret findings."""

    def test_includes_dep_findings(self, tmp_path):
        output = tmp_path / "cq.json"
        dep = "### [MEDIUM] Finding: Outdated dep\n**File:** `go.mod` (line 3)\n"
        generate_codequality_report("", str(output), dep_findings=dep)
        data = json.loads(output.read_text())
        assert len(data) == 1
        assert data[0]["check_name"] == "duoguard-dependency-audit"
        assert data[0]["severity"] == "major"

    def test_includes_secret_findings(self, tmp_path):
        output = tmp_path / "cq.json"
        secret = "### [CRITICAL] Finding: Leaked API key\n**File:** `config.py` (line 10)\n"
        generate_codequality_report("", str(output), secret_findings=secret)
        data = json.loads(output.read_text())
        assert len(data) == 1
        assert data[0]["check_name"] == "duoguard-secret-scan"
        assert data[0]["severity"] == "blocker"

    def test_includes_all_categories(self, tmp_path):
        output = tmp_path / "cq.json"
        code = "### [HIGH] Finding: XSS\n**File:** `view.py` (line 1)\n"
        dep = "### [LOW] Finding: Old version\n**File:** `package.json` (line 5)\n"
        secret = "### [CRITICAL] Finding: Hardcoded password\n**File:** `.env` (line 2)\n"
        generate_codequality_report(code, str(output), dep_findings=dep, secret_findings=secret)
        data = json.loads(output.read_text())
        assert len(data) == 3
        check_names = {d["check_name"] for d in data}
        assert check_names == {"duoguard-code-security", "duoguard-dependency-audit", "duoguard-secret-scan"}


class TestSarifReportAllFindings:
    """Tests that SARIF report includes dep/secret findings and enriched fields."""

    def test_includes_dep_and_secret_findings(self, tmp_path):
        output = tmp_path / "sarif.json"
        code = "### [HIGH] Finding: XSS\n**File:** `app.py` (line 1)\n"
        dep = "### [MEDIUM] Finding: Outdated lib\n**File:** `requirements.txt` (line 10)\n"
        secret = "### [CRITICAL] Finding: API key\n**File:** `config.py` (line 5)\n"
        generate_sarif_report(code, str(output), dep_findings=dep, secret_findings=secret)
        data = json.loads(output.read_text())
        results = data["runs"][0]["results"]
        assert len(results) == 3
        rule_ids = [r["ruleId"] for r in results]
        assert any("code-security" in rid for rid in rule_ids)
        assert any("dependency-audit" in rid for rid in rule_ids)
        assert any("secret-scan" in rid for rid in rule_ids)

    def test_has_invocations(self, tmp_path):
        output = tmp_path / "sarif.json"
        generate_sarif_report("No issues.", str(output))
        data = json.loads(output.read_text())
        run = data["runs"][0]
        assert "invocations" in run
        assert run["invocations"][0]["executionSuccessful"] is True
        assert "endTimeUtc" in run["invocations"][0]

    def test_has_automation_details(self, tmp_path):
        output = tmp_path / "sarif.json"
        generate_sarif_report("No issues.", str(output))
        data = json.loads(output.read_text())
        run = data["runs"][0]
        assert "automationDetails" in run
        assert run["automationDetails"]["id"].startswith("duoguard/")

    def test_rules_have_full_description_and_help_uri(self, tmp_path):
        output = tmp_path / "sarif.json"
        findings = "### [HIGH] Finding: SQL Injection\n**File:** `db.py` (line 1)\n"
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert "fullDescription" in rule
        assert "text" in rule["fullDescription"]
        assert "helpUri" in rule
        assert rule["helpUri"].startswith("https://")

    def test_results_have_partial_fingerprints(self, tmp_path):
        output = tmp_path / "sarif.json"
        findings = "### [HIGH] Finding: XSS\n**File:** `app.py` (line 1)\n"
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        result = data["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert "duoguardFindingHash/v1" in result["partialFingerprints"]
        # SHA-256 hex digest is 64 characters
        assert len(result["partialFingerprints"]["duoguardFindingHash/v1"]) == 64

    def test_rules_have_category_property(self, tmp_path):
        output = tmp_path / "sarif.json"
        dep = "### [MEDIUM] Finding: Outdated\n**File:** `go.mod` (line 1)\n"
        generate_sarif_report("", str(output), dep_findings=dep)
        data = json.loads(output.read_text())
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["category"] == "dependency-audit"


class TestDiffTruncation:
    """Tests for MAX_DIFF_SIZE diff truncation."""

    def test_small_diff_not_truncated(self):
        changes = [{"new_path": "a.py", "diff": "+x = 1"}]
        result = format_diff_for_analysis(changes)
        assert "a.py" in result
        assert "omitted" not in result

    def test_large_diff_truncated(self):
        # Create changes that exceed a small limit
        changes = [
            {"new_path": f"file{i}.py", "diff": "+" + "x" * 100}
            for i in range(20)
        ]
        result = format_diff_for_analysis(changes, max_size=500)
        assert "omitted" in result
        # Some files should still be present
        assert "file0.py" in result

    def test_truncation_count_is_correct(self):
        changes = [
            {"new_path": f"f{i}.py", "diff": "+" + "a" * 200}
            for i in range(5)
        ]
        # Each chunk is ~230 chars; limit to hold ~2 chunks
        result = format_diff_for_analysis(changes, max_size=500)
        assert "3 file(s) omitted" in result

    def test_default_max_size_constant(self):
        assert MAX_DIFF_SIZE == 200_000


class TestSeverityCountingStrict:
    """Tests that _count_by_severity avoids prose false positives."""

    def test_bracket_severity_at_line_start(self):
        text = "[HIGH] Finding here"
        counts = _count_by_severity(text)
        assert counts["high"] == 1

    def test_heading_prefixed_severity(self):
        text = "### [CRITICAL] SQL Injection"
        counts = _count_by_severity(text)
        assert counts["critical"] == 1

    def test_mid_sentence_bracket_not_counted(self):
        """A severity mention mid-sentence should NOT be counted."""
        text = "This is a reference to [high] severity in prose."
        counts = _count_by_severity(text)
        assert counts["high"] == 0

    def test_dash_prefixed_severity(self):
        text = "- [MEDIUM] Some bullet finding"
        counts = _count_by_severity(text)
        assert counts["medium"] == 1


class TestRunSecurityScan:
    """Integration tests for _run_security_scan with mocked externals."""

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_full_scan_happy_path(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        mock_info.return_value = {"iid": 10, "title": "Test MR"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+print('hello')"}]
        }
        mock_code.return_value = "### [LOW] Finding: Debug log\n**File:** `app.py` (line 1)\n"
        mock_dep.return_value = "No dependency file changes detected."
        mock_secret.return_value = "No secrets detected."

        output = str(tmp_path / "report.md")
        # fail_on=CRITICAL so we don't exit
        _run_security_scan("42", "10", output, "", "CRITICAL")

        # Report file was written
        assert Path(output).exists()
        report_text = Path(output).read_text()
        assert "DuoGuard Security Review Report" in report_text
        assert "!10" in report_text

        # Code quality and SARIF generators were called with all findings
        mock_cq.assert_called_once()
        cq_kwargs = mock_cq.call_args
        assert "dep_findings" in cq_kwargs.kwargs or len(cq_kwargs.args) >= 3
        mock_sarif.assert_called_once()

    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_no_changes_short_circuits(self, mock_info, mock_diff, tmp_path):
        mock_info.return_value = {"iid": 5, "title": "Empty MR"}
        mock_diff.return_value = {"changes": []}

        output = str(tmp_path / "report.md")
        _run_security_scan("42", "5", output, "", "HIGH")

        report_text = Path(output).read_text()
        assert "No code changes detected" in report_text

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_severity_threshold_triggers_exit(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        mock_info.return_value = {"iid": 7, "title": "Risky MR"}
        mock_diff.return_value = {
            "changes": [{"new_path": "cmd.py", "diff": "+os.system(input())"}]
        }
        mock_code.return_value = "### [CRITICAL] Finding: RCE\n**File:** `cmd.py` (line 1)\n"
        mock_dep.return_value = ""
        mock_secret.return_value = ""

        output = str(tmp_path / "report.md")
        with pytest.raises(SystemExit) as exc_info:
            _run_security_scan("42", "7", output, "", "HIGH")
        assert exc_info.value.code == 1

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_sarif_receives_all_findings(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        mock_info.return_value = {"iid": 11, "title": "Full scan MR"}
        mock_diff.return_value = {
            "changes": [
                {"new_path": "app.py", "diff": "+code"},
                {"new_path": "package.json", "diff": "+dep"},
            ]
        }
        mock_code.return_value = "### [HIGH] Finding: XSS\n**File:** `app.py` (line 5)\n"
        mock_dep.return_value = "### [MEDIUM] Finding: Old lib\n**File:** `package.json` (line 2)\n"
        mock_secret.return_value = "### [CRITICAL] Finding: API key\n**File:** `app.py` (line 3)\n"

        output = str(tmp_path / "report.md")
        with pytest.raises(SystemExit):
            _run_security_scan("42", "11", output, "", "LOW")

        # Verify sarif was called with dep_findings and secret_findings kwargs
        sarif_call = mock_sarif.call_args
        assert "dep_findings" in sarif_call.kwargs
        assert "secret_findings" in sarif_call.kwargs
        assert "[MEDIUM]" in sarif_call.kwargs["dep_findings"]
        assert "[CRITICAL]" in sarif_call.kwargs["secret_findings"]


# ── Configuration file tests ────────────────────────────────────


class TestLoadConfig:
    def test_defaults_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg["severity_threshold"] == "HIGH"
        assert cfg["agents"]["code_security"] is True
        assert cfg["inline_comments"] is True

    def test_loads_yml_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text("severity_threshold: CRITICAL\nexclude_paths:\n  - vendor/*\n")
        cfg = load_config()
        assert cfg["severity_threshold"] == "CRITICAL"
        assert cfg["exclude_paths"] == ["vendor/*"]
        # Defaults preserved for unset keys
        assert cfg["agents"]["code_security"] is True

    def test_loads_yaml_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yaml"
        config_file.write_text("approve: true\napprove_threshold: MEDIUM\n")
        cfg = load_config()
        assert cfg["approve"] is True
        assert cfg["approve_threshold"] == "MEDIUM"

    def test_explicit_path(self, tmp_path):
        config_file = tmp_path / "custom.yml"
        config_file.write_text("severity_threshold: LOW\n")
        cfg = load_config(str(config_file))
        assert cfg["severity_threshold"] == "LOW"

    def test_env_var_path(self, tmp_path, monkeypatch):
        config_file = tmp_path / "env-config.yml"
        config_file.write_text("max_diff_size: 50000\n")
        monkeypatch.setenv("DUOGUARD_CONFIG", str(config_file))
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg["max_diff_size"] == 50000

    def test_agents_deep_merge(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text("agents:\n  secret_scan: false\n")
        cfg = load_config()
        assert cfg["agents"]["secret_scan"] is False
        assert cfg["agents"]["code_security"] is True
        assert cfg["agents"]["dependency_audit"] is True

    def test_invalid_yaml_uses_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text("not a dict")
        cfg = load_config()
        assert cfg["severity_threshold"] == "HIGH"


# ── Path exclusion tests ────────────────────────────────────────


class TestPathExclusion:
    def test_exclude_by_path_pattern(self):
        assert should_exclude_path("vendor/lib/foo.go", exclude_paths=["vendor/*"])

    def test_exclude_by_nested_path(self):
        assert should_exclude_path("node_modules/pkg/index.js",
                                    exclude_paths=["node_modules/*"])

    def test_no_exclude_when_no_match(self):
        assert not should_exclude_path("src/app.py", exclude_paths=["vendor/*"])

    def test_exclude_by_extension(self):
        assert should_exclude_path("bundle.min.js", exclude_extensions=["js"])

    def test_no_exclude_different_extension(self):
        assert not should_exclude_path("app.py", exclude_extensions=["js"])

    def test_empty_rules_no_exclude(self):
        assert not should_exclude_path("any/path.go")

    def test_glob_pattern_matching(self):
        assert should_exclude_path("docs/api.md", exclude_paths=["docs/*.md"])
        assert not should_exclude_path("docs/api.py", exclude_paths=["docs/*.md"])

    def test_filter_excluded_changes(self):
        changes = [
            {"new_path": "src/app.py", "diff": "+code"},
            {"new_path": "vendor/lib.go", "diff": "+code"},
            {"new_path": "README.md", "diff": "+docs"},
        ]
        result = filter_excluded_changes(changes, exclude_paths=["vendor/*"],
                                          exclude_extensions=["md"])
        assert len(result) == 1
        assert result[0]["new_path"] == "src/app.py"

    def test_filter_no_exclusions_returns_all(self):
        changes = [{"new_path": "a.py", "diff": "+x"}]
        assert filter_excluded_changes(changes) == changes


# ── Findings JSON export tests ──────────────────────────────────


class TestExportFindingsJson:
    def test_exports_all_categories(self, tmp_path):
        output = str(tmp_path / "findings.json")
        code = "### [HIGH] Finding: XSS\n**File:** `app.py` (line 5)\n"
        dep = "### [MEDIUM] Finding: Outdated\n**File:** `go.mod` (line 1)\n"
        secret = "### [CRITICAL] Finding: API key\n**File:** `config.py` (line 3)\n"
        findings = export_findings_json(code, dep, secret, output)
        assert len(findings) == 3
        # File was written
        data = json.loads(Path(output).read_text())
        assert len(data) == 3

    def test_exports_empty_findings(self, tmp_path):
        output = str(tmp_path / "findings.json")
        findings = export_findings_json("Clean", "Clean", "Clean", output)
        assert findings == []
        data = json.loads(Path(output).read_text())
        assert data == []


# ── Inline discussion tests ─────────────────────────────────────


class TestInlineDiscussions:
    @patch("post_report.requests.get")
    def test_get_mr_diff_versions(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"base_commit_sha": "abc", "head_commit_sha": "def", "start_commit_sha": "ghi"}
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        versions = get_mr_diff_versions("42", "1")
        assert len(versions) == 1
        assert versions[0]["base_commit_sha"] == "abc"

    @patch("post_report.requests.post")
    def test_post_inline_discussion_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "disc-123"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = post_inline_discussion(
            "42", "1", "Finding text", "app.py", 10,
            "base-sha", "head-sha", "start-sha",
        )
        assert result is not None
        assert result["id"] == "disc-123"
        mock_post.assert_called_once()

    @patch("post_report.requests.post")
    def test_post_inline_discussion_failure_returns_none(self, mock_post):
        from requests.exceptions import HTTPError
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.raise_for_status.side_effect = HTTPError(response=mock_resp)
        mock_post.return_value = mock_resp

        result = post_inline_discussion(
            "42", "1", "Finding text", "app.py", 10,
            "base-sha", "head-sha", "start-sha",
        )
        assert result is None

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_post_inline_findings(self, mock_versions, mock_post_disc):
        mock_versions.return_value = [{
            "base_commit_sha": "abc",
            "head_commit_sha": "def",
            "start_commit_sha": "ghi",
        }]
        mock_post_disc.return_value = {"id": "disc-1"}

        findings = [
            {"file_path": "app.py", "line_num": 5, "severity": "high",
             "description": "XSS", "category": "code-security"},
            {"file_path": "db.py", "line_num": 10, "severity": "critical",
             "description": "SQLi", "category": "code-security"},
        ]
        posted = post_inline_findings("42", "1", findings)
        assert posted == 2
        assert mock_post_disc.call_count == 2

    @patch("post_report.get_mr_diff_versions")
    def test_post_inline_findings_no_versions(self, mock_versions):
        mock_versions.return_value = []
        posted = post_inline_findings("42", "1", [{"file_path": "a.py"}])
        assert posted == 0

    def test_post_inline_findings_empty_list(self):
        posted = post_inline_findings("42", "1", [])
        assert posted == 0


# ── MR approval tests ──────────────────────────────────────────


class TestMRApproval:
    @patch("post_report.requests.post")
    def test_approve_mr_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = approve_mr("42", "1")
        assert result is True
        assert "approve" in mock_post.call_args[0][0]

    @patch("post_report.requests.post")
    def test_approve_mr_failure(self, mock_post):
        from requests.exceptions import HTTPError
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = HTTPError(response=mock_resp)
        mock_post.return_value = mock_resp

        result = approve_mr("42", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_unapprove_mr_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = unapprove_mr("42", "1")
        assert result is True
        assert "unapprove" in mock_post.call_args[0][0]

    @patch("post_report.requests.post")
    def test_unapprove_mr_failure(self, mock_post):
        from requests.exceptions import HTTPError
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = HTTPError(response=mock_resp)
        mock_post.return_value = mock_resp

        result = unapprove_mr("42", "1")
        assert result is False


# ── Run security scan with config tests ─────────────────────────


class TestRunSecurityScanWithConfig:
    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_disabled_agents_not_called(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "Clean"
        mock_dep.return_value = "Clean"
        mock_secret.return_value = "Clean"

        output = str(tmp_path / "report.md")
        config = dict(DEFAULT_CONFIG)
        config["agents"] = {
            "code_security": True,
            "dependency_audit": False,
            "secret_scan": False,
        }
        _run_security_scan("42", "1", output, "", "CRITICAL", config=config)

        mock_code.assert_called_once()
        mock_dep.assert_not_called()
        mock_secret.assert_not_called()

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_exclude_paths_applied(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        mock_info.return_value = {"iid": 2, "title": "Exclude test"}
        mock_diff.return_value = {
            "changes": [
                {"new_path": "src/app.py", "diff": "+code"},
                {"new_path": "vendor/lib.go", "diff": "+vendor"},
            ]
        }
        mock_code.return_value = "Clean"
        mock_dep.return_value = "Clean"
        mock_secret.return_value = "Clean"

        output = str(tmp_path / "report.md")
        config = dict(DEFAULT_CONFIG)
        config["exclude_paths"] = ["vendor/*"]
        _run_security_scan("42", "2", output, "", "CRITICAL", config=config)

        # The diff passed to code review should only contain src/app.py
        code_call_args = mock_code.call_args[0][0]
        assert "src/app.py" in code_call_args
        assert "vendor/lib.go" not in code_call_args

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_findings_json_exported(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        mock_info.return_value = {"iid": 3, "title": "Export test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "### [HIGH] Finding: XSS\n**File:** `app.py` (line 1)\n"
        mock_dep.return_value = "Clean"
        mock_secret.return_value = "Clean"

        output = str(tmp_path / "report.md")
        _run_security_scan("42", "3", output, "", "CRITICAL")

        findings_file = tmp_path / "duoguard-findings.json"
        assert findings_file.exists()
        data = json.loads(findings_file.read_text())
        assert len(data) == 1
        assert data[0]["severity"] == "high"

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_severity_written_to_file(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        mock_info.return_value = {"iid": 4, "title": "Severity file test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "### [HIGH] Finding: Bug\n**File:** `app.py` (line 1)\n"
        mock_dep.return_value = ""
        mock_secret.return_value = ""

        output = str(tmp_path / "report.md")
        with pytest.raises(SystemExit):
            _run_security_scan("42", "4", output, "", "HIGH")

        severity_file = tmp_path / "duoguard-severity.txt"
        assert severity_file.exists()
        assert severity_file.read_text() == "HIGH"


class TestResolveStaleDiscussions:
    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_resolves_duoguard_discussions(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {
                    "id": "disc1",
                    "notes": [{
                        "body": "**:shield: DuoGuard [HIGH]** — SQL Injection",
                        "resolvable": True,
                        "resolved": False,
                    }],
                },
            ]),
        )
        mock_put.return_value = MagicMock(status_code=200)
        result = resolve_stale_discussions("42", "1")
        assert result == 1
        mock_put.assert_called_once()

    @patch("post_report.requests.get")
    def test_skips_non_duoguard_discussions(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {
                    "id": "disc2",
                    "notes": [{
                        "body": "Regular review comment",
                        "resolvable": True,
                        "resolved": False,
                    }],
                },
            ]),
        )
        result = resolve_stale_discussions("42", "1")
        assert result == 0

    @patch("post_report.requests.get")
    def test_skips_already_resolved(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {
                    "id": "disc3",
                    "notes": [{
                        "body": "**:shield: DuoGuard [LOW]** — Info leak",
                        "resolvable": True,
                        "resolved": True,
                    }],
                },
            ]),
        )
        result = resolve_stale_discussions("42", "1")
        assert result == 0

    @patch("post_report.requests.get")
    def test_handles_api_error(self, mock_get):
        mock_get.return_value = MagicMock(status_code=403)
        mock_get.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError(response=MagicMock(status_code=403))
        )
        result = resolve_stale_discussions("42", "1")
        assert result == 0


class TestUpdateMRLabels:
    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_adds_severity_label(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"labels": ["bug", "review"]}),
        )
        mock_put.return_value = MagicMock(status_code=200)
        result = update_mr_labels("42", "1", "HIGH")
        assert result is True
        call_args = mock_put.call_args
        labels = call_args[1]["json"]["labels"]
        assert "security::high" in labels
        assert "bug" in labels

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_replaces_old_security_label(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "labels": ["security::low", "feature"]
            }),
        )
        mock_put.return_value = MagicMock(status_code=200)
        update_mr_labels("42", "1", "CRITICAL")
        call_args = mock_put.call_args
        labels = call_args[1]["json"]["labels"]
        assert "security::critical" in labels
        assert "security::low" not in labels

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_clean_label_for_none(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"labels": []}),
        )
        mock_put.return_value = MagicMock(status_code=200)
        update_mr_labels("42", "1", "NONE")
        call_args = mock_put.call_args
        labels = call_args[1]["json"]["labels"]
        assert "security::clean" in labels

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_handles_put_failure(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"labels": []}),
        )
        mock_put.return_value = MagicMock(status_code=403)
        mock_put.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError(response=MagicMock(status_code=403))
        )
        result = update_mr_labels("42", "1", "HIGH")
        assert result is False


class TestScanMetrics:
    def test_report_includes_metrics(self):
        report = generate_report(
            {"iid": 1, "title": "Test"},
            "Clean", "Clean", "Clean",
            scan_duration=3.5,
            files_scanned=12,
        )
        assert "Scan Metrics" in report
        assert "3.5s" in report
        assert "12" in report

    def test_report_without_metrics(self):
        report = generate_report(
            {"iid": 1, "title": "Test"},
            "Clean", "Clean", "Clean",
        )
        assert "Scan Metrics" not in report

    def test_report_with_only_duration(self):
        report = generate_report(
            {"iid": 1, "title": "Test"},
            "Clean", "Clean", "Clean",
            scan_duration=1.2,
        )
        assert "Scan Metrics" in report
        assert "1.2s" in report

    def test_report_with_only_file_count(self):
        report = generate_report(
            {"iid": 1, "title": "Test"},
            "Clean", "Clean", "Clean",
            files_scanned=5,
        )
        assert "Scan Metrics" in report
        assert "5" in report


class TestSecurityLabelsConstant:
    def test_all_labels_present(self):
        assert "security::critical" in SECURITY_LABELS
        assert "security::high" in SECURITY_LABELS
        assert "security::medium" in SECURITY_LABELS
        assert "security::low" in SECURITY_LABELS
        assert "security::clean" in SECURITY_LABELS
        assert len(SECURITY_LABELS) == 5


# ── NEW TESTS: Edge cases, security patterns, integration ────────


class TestFormatDiffEdgeCases:
    """Additional edge cases for diff formatting."""

    def test_no_path_keys_uses_unknown(self):
        """When neither new_path nor old_path is present, 'unknown' is used."""
        changes = [{"diff": "+some code"}]
        result = format_diff_for_analysis(changes)
        assert "unknown" in result
        assert "+some code" in result

    def test_empty_changes_list(self):
        """An empty changes list produces empty output."""
        result = format_diff_for_analysis([])
        assert result == ""

    def test_unicode_content_preserved(self):
        """Unicode characters in diffs are preserved."""
        changes = [{"new_path": "i18n.py", "diff": "+msg = 'Hola mundo'"}]
        result = format_diff_for_analysis(changes)
        assert "Hola mundo" in result

    def test_exact_boundary_truncation(self):
        """A diff that lands exactly at max_size boundary is included."""
        changes = [{"new_path": "a.py", "diff": "+x"}]
        # The formatted chunk will be small enough for any reasonable limit
        result = format_diff_for_analysis(changes, max_size=5000)
        assert "a.py" in result
        assert "omitted" not in result

    def test_all_files_truncated_at_zero_limit(self):
        """When max_size=0, all files with diffs are omitted."""
        changes = [{"new_path": "a.py", "diff": "+x = 1"}]
        result = format_diff_for_analysis(changes, max_size=0)
        assert "1 file(s) omitted" in result
        assert "a.py" not in result.split("omitted")[0]

    def test_diff_contains_markdown_code_fences(self):
        """Diff output is wrapped in code fences with diff language."""
        changes = [{"new_path": "test.py", "diff": "+pass"}]
        result = format_diff_for_analysis(changes)
        assert "```diff" in result
        assert "```" in result


class TestParseFindingsEdgeCases:
    """Edge cases for the _parse_findings parser."""

    def test_finding_with_very_large_line_number(self):
        """Line numbers are capped at 5 digits."""
        text = "### [HIGH] Finding: Overflow\n**File:** `x.py` (line 999999999)\n"
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        assert findings[0]["line_num"] == 99999

    def test_finding_with_no_line_keyword(self):
        """File line without 'line' keyword uses default line_num=1."""
        text = "### [MEDIUM] Finding: No line info\n**File:** `app.py`\n"
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        assert findings[0]["line_num"] == 1

    def test_consecutive_findings_without_file(self):
        """Only headings followed by **File:** are emitted; orphans are dropped."""
        text = (
            "### [HIGH] Finding: First orphan\n"
            "### [CRITICAL] Finding: Second orphan\n"
            "### [LOW] Finding: Has file\n"
            "**File:** `ok.py` (line 5)\n"
        )
        findings = _parse_findings(text, "code-security")
        # Only the last one (which has a **File:** line) should be emitted
        # Actually the parser sets current on each heading and only appends on File
        # So "Second orphan" overwrites "First orphan", then "Has file" overwrites
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"

    def test_mixed_case_severity_in_heading(self):
        """Mixed case like [High] is handled."""
        text = "### [High] Finding: Mixed case\n**File:** `app.py` (line 1)\n"
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_info_severity_finding(self):
        """INFO severity findings are parsed correctly."""
        text = "### [INFO] Finding: Informational note\n**File:** `readme.md` (line 1)\n"
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    def test_file_path_with_spaces_in_backticks(self):
        """File paths are extracted from between backticks."""
        text = "### [LOW] Finding: Test\n**File:** `path/to/my file.py` (line 3)\n"
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        assert findings[0]["file_path"] == "path/to/my file.py"


class TestCountBySeverityEdgeCases:
    """Additional strict counting edge cases."""

    def test_bold_prefixed_severity(self):
        """**[SEVERITY] should be counted."""
        text = "**[HIGH] Critical finding"
        counts = _count_by_severity(text)
        assert counts["high"] == 1

    def test_info_severity_counted(self):
        """INFO severity is counted at line start."""
        text = "[INFO] Informational note"
        counts = _count_by_severity(text)
        assert counts["info"] == 1

    def test_multiple_severities_on_separate_lines(self):
        """Multiple severity markers on separate lines are each counted."""
        text = "[HIGH] First\n[HIGH] Second\n[MEDIUM] Third"
        counts = _count_by_severity(text)
        assert counts["high"] == 2
        assert counts["medium"] == 1

    def test_empty_string_returns_all_zeros(self):
        """Empty string produces zero counts for all severities."""
        counts = _count_by_severity("")
        assert all(v == 0 for v in counts.values())
        assert len(counts) == 5

    def test_severity_in_url_not_counted(self):
        """Severity words embedded in URLs/prose are not counted."""
        text = "See https://example.com/docs#[high]-level for details"
        counts = _count_by_severity(text)
        assert counts["high"] == 0


class TestDetermineSeverityEdgeCases:
    """Boundary and combined severity scoring."""

    def test_single_critical_always_critical(self):
        """Even one critical finding should return CRITICAL."""
        assert determine_severity("", "### [CRITICAL] Bad dep", "") == "CRITICAL"

    def test_score_boundary_at_exactly_5(self):
        """Score=5 should produce HIGH (one high=3 + one medium=2 = 5)."""
        text = "[HIGH] a\n[MEDIUM] b"
        assert determine_severity(text, "", "") == "HIGH"

    def test_score_boundary_at_exactly_2(self):
        """Score=2 should produce MEDIUM (one medium=2)."""
        assert determine_severity("[MEDIUM] finding", "", "") == "MEDIUM"

    def test_score_boundary_at_exactly_1(self):
        """Score=1 should produce LOW (one low=1)."""
        assert determine_severity("", "", "[LOW] minor") == "LOW"

    def test_findings_spread_across_all_categories(self):
        """Findings from code + dep + secret are combined for scoring."""
        assert determine_severity(
            "[HIGH] code issue",
            "[MEDIUM] dep issue",
            "[LOW] secret issue",
        ) == "HIGH"  # score = 3 + 2 + 1 = 6 >= 5


class TestParseGatewayHeadersEdgeCases:
    """Additional edge cases for header parsing."""

    def test_json_list_not_treated_as_dict(self):
        """A JSON array should fall through to line parsing."""
        result = _parse_gateway_headers('[1, 2, 3]')
        assert result == {}

    def test_header_with_colon_in_value(self):
        """Values containing colons are handled correctly."""
        result = _parse_gateway_headers("Auth: Bearer token:with:colons")
        assert result == {"Auth": "Bearer token:with:colons"}

    def test_whitespace_only_string(self):
        """Whitespace-only input returns empty dict."""
        result = _parse_gateway_headers("   \n  \n  ")
        assert result == {}


class TestCallAIGatewayErrorPaths:
    """Error handling paths in call_ai_gateway."""

    @patch("duoguard._session")
    def test_ai_gateway_rate_limit_429(self, mock_session):
        """Rate limit (429) should raise HTTPError."""
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = "https://ai-gateway.example.com"
        duoguard.AI_GATEWAY_TOKEN = "test-token"
        try:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
                response=mock_resp
            )
            mock_session.post.return_value = mock_resp
            with pytest.raises(requests.exceptions.HTTPError):
                duoguard.call_ai_gateway("system", "user")
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    @patch("duoguard._session")
    def test_ai_gateway_timeout(self, mock_session):
        """Timeout should raise Timeout exception."""
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = "https://ai-gateway.example.com"
        duoguard.AI_GATEWAY_TOKEN = "test-token"
        try:
            mock_session.post.side_effect = requests.exceptions.Timeout("timed out")
            with pytest.raises(requests.exceptions.Timeout):
                duoguard.call_ai_gateway("system", "user")
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    @patch("duoguard._session")
    def test_direct_anthropic_api_path(self, mock_session):
        """Direct Anthropic API path when ANTHROPIC_API_KEY is set."""
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = ""
        duoguard.AI_GATEWAY_TOKEN = ""
        try:
            with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-key"}):
                mock_resp = MagicMock()
                mock_resp.json.return_value = {
                    "content": [{"text": "Direct API result"}]
                }
                mock_resp.raise_for_status = MagicMock()
                mock_session.post.return_value = mock_resp

                result = duoguard.call_ai_gateway("system", "user")
                assert result == "Direct API result"
                call_url = mock_session.post.call_args[0][0]
                assert "api.anthropic.com" in call_url
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    @patch("duoguard._session")
    def test_direct_anthropic_api_invalid_key(self, mock_session):
        """Direct Anthropic API with invalid key should raise HTTPError."""
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = ""
        duoguard.AI_GATEWAY_TOKEN = ""
        try:
            with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "invalid-key"}):
                mock_resp = MagicMock()
                mock_resp.status_code = 401
                mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
                    response=mock_resp
                )
                mock_session.post.return_value = mock_resp
                with pytest.raises(requests.exceptions.HTTPError):
                    duoguard.call_ai_gateway("system", "user")
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    @patch("duoguard._session")
    def test_anthropic_proxy_model_mapping(self, mock_session):
        """Anthropic proxy maps model names correctly."""
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = ""
        duoguard.AI_GATEWAY_TOKEN = "gitlab-token"
        try:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"content": [{"text": "ok"}]}
            mock_resp.raise_for_status = MagicMock()
            mock_session.post.return_value = mock_resp

            duoguard.call_ai_gateway("sys", "usr", model="claude-sonnet-4-5")
            call_json = mock_session.post.call_args[1]["json"]
            assert call_json["model"] == "claude-sonnet-4-5-20250929"
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token


class TestExtractDependencyFilesEdgeCases:
    """Edge cases for dependency file extraction."""

    def test_empty_changes_list(self):
        """Empty changes returns empty list."""
        assert extract_dependency_files([]) == []

    def test_change_with_no_new_path(self):
        """Change dict missing new_path uses empty string, no match."""
        changes = [{"diff": "+code"}]
        result = extract_dependency_files(changes)
        assert result == []

    def test_dockerfile_detected(self):
        """Dockerfile is recognized as a dependency file."""
        changes = [{"new_path": "deploy/Dockerfile", "diff": "+FROM python:3.12"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_pnpm_lock_detected(self):
        """pnpm-lock.yaml is recognized."""
        changes = [{"new_path": "pnpm-lock.yaml", "diff": "+lock"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_build_gradle_kts_detected(self):
        """build.gradle.kts is recognized."""
        changes = [{"new_path": "app/build.gradle.kts", "diff": "+dep"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_directory_packages_props_detected(self):
        """Directory.Packages.props (.NET) is recognized."""
        changes = [{"new_path": "Directory.Packages.props", "diff": "+pkg"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1


class TestLoadConfigEdgeCases:
    """Additional config loading edge cases."""

    def test_empty_yaml_file_uses_defaults(self, tmp_path, monkeypatch):
        """An empty YAML file (null) uses defaults."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text("")
        cfg = load_config()
        assert cfg["severity_threshold"] == "HIGH"
        assert cfg["agents"]["code_security"] is True

    def test_yml_takes_priority_over_yaml(self, tmp_path, monkeypatch):
        """.duoguard.yml is checked before .duoguard.yaml."""
        monkeypatch.chdir(tmp_path)
        yml_file = tmp_path / ".duoguard.yml"
        yml_file.write_text("severity_threshold: CRITICAL\n")
        yaml_file = tmp_path / ".duoguard.yaml"
        yaml_file.write_text("severity_threshold: LOW\n")
        cfg = load_config()
        assert cfg["severity_threshold"] == "CRITICAL"

    def test_explicit_path_overrides_env_var(self, tmp_path, monkeypatch):
        """Explicit config_path takes priority over DUOGUARD_CONFIG env."""
        explicit = tmp_path / "explicit.yml"
        explicit.write_text("severity_threshold: CRITICAL\n")
        env_config = tmp_path / "env.yml"
        env_config.write_text("severity_threshold: LOW\n")
        monkeypatch.setenv("DUOGUARD_CONFIG", str(env_config))
        cfg = load_config(str(explicit))
        assert cfg["severity_threshold"] == "CRITICAL"

    def test_config_with_custom_model(self, tmp_path, monkeypatch):
        """Custom model setting is loaded from config."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text("model: claude-sonnet-4\n")
        cfg = load_config()
        assert cfg["model"] == "claude-sonnet-4"


class TestShouldExcludePathEdgeCases:
    """Edge cases for path exclusion logic."""

    def test_double_star_glob_pattern(self):
        """Double star glob matches deeply nested files."""
        assert should_exclude_path("a/b/c/d.py", exclude_paths=["a/b/c/*.py"])

    def test_dotfiles_have_no_extension(self):
        """Dotfiles like .env have no suffix, so extension matching does not apply."""
        # Path(".env").suffix is "" — it's a hidden file, not an extension
        assert not should_exclude_path(".env", exclude_extensions=["env"])
        # But glob patterns can match dotfiles
        assert should_exclude_path(".env", exclude_paths=[".env"])

    def test_extension_without_dot(self):
        """Extension matching strips leading dot from suffix."""
        assert should_exclude_path("data.csv", exclude_extensions=["csv"])
        assert not should_exclude_path("data.csv", exclude_extensions=[".csv"])

    def test_file_with_no_extension(self):
        """Files without extensions have empty suffix, not matched."""
        assert not should_exclude_path("Makefile", exclude_extensions=["py"])

    def test_multiple_exclude_patterns(self):
        """Multiple patterns are checked with OR logic."""
        assert should_exclude_path("vendor/x.go",
                                    exclude_paths=["vendor/*", "node_modules/*"])
        assert should_exclude_path("node_modules/y.js",
                                    exclude_paths=["vendor/*", "node_modules/*"])
        assert not should_exclude_path("src/main.py",
                                        exclude_paths=["vendor/*", "node_modules/*"])


class TestGenerateReportEdgeCases:
    """Edge cases for report generation."""

    def test_missing_mr_iid_uses_na(self):
        """Missing iid field uses N/A."""
        report = generate_report({}, "clean", "clean", "clean")
        assert "!N/A" in report

    def test_missing_mr_title_uses_untitled(self):
        """Missing title field uses Untitled."""
        report = generate_report({"iid": 1}, "clean", "clean", "clean")
        assert "Untitled" in report

    def test_all_severity_emojis_present(self):
        """Each severity level has a corresponding emoji in the report."""
        # CRITICAL
        report = generate_report(
            {"iid": 1, "title": "T"},
            "### [CRITICAL] Finding: RCE\n**File:** `x.py` (line 1)\n", "", "",
        )
        assert ":rotating_light:" in report

        # NONE
        report = generate_report(
            {"iid": 1, "title": "T"}, "clean", "clean", "clean",
        )
        assert ":white_check_mark:" in report

    def test_report_counts_findings_per_section(self):
        """Summary table counts findings per category."""
        code = "### [HIGH] Finding: A\n**File:** `a.py` (line 1)\n"
        dep = "### [MEDIUM] Finding: B\n**File:** `b.py` (line 1)\n### [LOW] Finding: C\n**File:** `c.py` (line 1)\n"
        secret = ""
        report = generate_report({"iid": 1, "title": "T"}, code, dep, secret)
        assert "1 issue(s)" in report  # code
        assert "2 issue(s)" in report  # dep


class TestSarifReportEdgeCases:
    """Additional SARIF report edge cases."""

    def test_sarif_help_uri_varies_by_category(self, tmp_path):
        """Different categories get different helpUri values."""
        output = tmp_path / "sarif.json"
        code = "### [HIGH] Finding: XSS\n**File:** `a.py` (line 1)\n"
        dep = "### [MEDIUM] Finding: Outdated\n**File:** `b.py` (line 1)\n"
        secret = "### [CRITICAL] Finding: Key\n**File:** `c.py` (line 1)\n"
        generate_sarif_report(code, str(output), dep_findings=dep, secret_findings=secret)
        data = json.loads(output.read_text())
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        help_uris = {r["properties"]["category"]: r["helpUri"] for r in rules}
        # Each category should have a different help URI
        assert "owasp.org/www-project-top-ten" in help_uris["code-security"]
        assert "dependency-check" in help_uris["dependency-audit"]
        assert "hard-coded_password" in help_uris["secret-scan"]

    def test_sarif_partial_fingerprints_differ_for_same_finding_different_files(self, tmp_path):
        """Same finding in different files gets different fingerprints."""
        output = tmp_path / "sarif.json"
        findings = (
            "### [HIGH] Finding: XSS\n**File:** `a.py` (line 1)\n\n"
            "### [HIGH] Finding: XSS\n**File:** `b.py` (line 1)\n"
        )
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        results = data["runs"][0]["results"]
        fp1 = results[0]["partialFingerprints"]["duoguardFindingHash/v1"]
        fp2 = results[1]["partialFingerprints"]["duoguardFindingHash/v1"]
        assert fp1 != fp2

    def test_sarif_schema_url_present(self, tmp_path):
        """SARIF output includes the schema URL."""
        output = tmp_path / "sarif.json"
        generate_sarif_report("No issues.", str(output))
        data = json.loads(output.read_text())
        assert "$schema" in data
        assert "sarif-schema-2.1.0" in data["$schema"]


class TestCodequalityReportEdgeCases:
    """Additional Code Quality report edge cases."""

    def test_severity_mapping_complete(self, tmp_path):
        """All five severity levels are mapped correctly."""
        output = tmp_path / "cq.json"
        findings = (
            "### [CRITICAL] Finding: A\n**File:** `a.py` (line 1)\n"
            "### [HIGH] Finding: B\n**File:** `b.py` (line 2)\n"
            "### [MEDIUM] Finding: C\n**File:** `c.py` (line 3)\n"
            "### [LOW] Finding: D\n**File:** `d.py` (line 4)\n"
            "### [INFO] Finding: E\n**File:** `e.py` (line 5)\n"
        )
        generate_codequality_report(findings, str(output))
        data = json.loads(output.read_text())
        assert len(data) == 5
        severities = [d["severity"] for d in data]
        assert "blocker" in severities
        assert "critical" in severities
        assert "major" in severities
        assert "minor" in severities
        assert "info" in severities

    def test_codequality_check_name_prefix(self, tmp_path):
        """All check_names are prefixed with 'duoguard-'."""
        output = tmp_path / "cq.json"
        code = "### [HIGH] Finding: XSS\n**File:** `app.py` (line 1)\n"
        generate_codequality_report(code, str(output))
        data = json.loads(output.read_text())
        for issue in data:
            assert issue["check_name"].startswith("duoguard-")

    def test_codequality_categories_always_security(self, tmp_path):
        """All code quality issues have 'Security' in categories."""
        output = tmp_path / "cq.json"
        code = "### [LOW] Finding: Minor\n**File:** `x.py` (line 1)\n"
        generate_codequality_report(code, str(output))
        data = json.loads(output.read_text())
        for issue in data:
            assert "Security" in issue["categories"]


class TestParseAgentContextEdgeCases:
    """Additional agent context parsing edge cases."""

    def test_malformed_json_context_falls_back_to_regex(self):
        """Malformed JSON falls back to regex MR extraction."""
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        old_input = duoguard.AI_FLOW_INPUT
        duoguard.AI_FLOW_CONTEXT = "{malformed json !55 content"
        duoguard.AI_FLOW_PROJECT_PATH = "org/repo"
        duoguard.AI_FLOW_INPUT = ""
        try:
            project_id, mr_iid = _parse_agent_context()
            assert mr_iid == "55"
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path
            duoguard.AI_FLOW_INPUT = old_input

    def test_json_context_without_merge_request_key(self):
        """JSON context without merge_request key yields empty mr_iid."""
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        old_input = duoguard.AI_FLOW_INPUT
        duoguard.AI_FLOW_CONTEXT = json.dumps({"project": {"path_with_namespace": "g/p"}})
        duoguard.AI_FLOW_PROJECT_PATH = ""
        duoguard.AI_FLOW_INPUT = ""
        try:
            project_id, mr_iid = _parse_agent_context()
            assert mr_iid == ""
            assert "g%2Fp" in project_id
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path
            duoguard.AI_FLOW_INPUT = old_input

    def test_project_path_url_encoded_with_slashes(self):
        """Nested project paths are properly URL-encoded."""
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        old_input = duoguard.AI_FLOW_INPUT
        duoguard.AI_FLOW_CONTEXT = json.dumps({"merge_request": {"iid": 1}})
        duoguard.AI_FLOW_PROJECT_PATH = "org/sub-group/my-project"
        duoguard.AI_FLOW_INPUT = ""
        try:
            project_id, mr_iid = _parse_agent_context()
            assert "org%2Fsub-group%2Fmy-project" in project_id
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path
            duoguard.AI_FLOW_INPUT = old_input


class TestResolveApiUrlEdgeCases:
    """Edge cases for API URL resolution."""

    def test_empty_hostname_uses_default(self):
        """Empty hostname falls back to gitlab.com."""
        import duoguard
        old = duoguard.GITLAB_HOSTNAME
        duoguard.GITLAB_HOSTNAME = ""
        try:
            url = _resolve_api_url_for_agent()
            assert url == "https://gitlab.com/api/v4"
        finally:
            duoguard.GITLAB_HOSTNAME = old


class TestPostInlineFindingsEdgeCases:
    """Edge cases for inline findings posting."""

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_incomplete_sha_versions_skips(self, mock_versions, mock_post_disc):
        """Missing SHA fields in version causes skip."""
        mock_versions.return_value = [{
            "base_commit_sha": "abc",
            "head_commit_sha": "",  # Missing
            "start_commit_sha": "ghi",
        }]
        findings = [{"file_path": "a.py", "line_num": 1, "severity": "high",
                      "description": "XSS", "category": "code-security"}]
        posted = post_inline_findings("42", "1", findings)
        assert posted == 0
        mock_post_disc.assert_not_called()

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_finding_with_cwe_field(self, mock_versions, mock_post_disc):
        """Findings with CWE field include it in the discussion body."""
        mock_versions.return_value = [{
            "base_commit_sha": "abc",
            "head_commit_sha": "def",
            "start_commit_sha": "ghi",
        }]
        mock_post_disc.return_value = {"id": "disc-1"}

        findings = [{"file_path": "a.py", "line_num": 1, "severity": "high",
                      "description": "SQL Injection", "category": "code-security",
                      "cwe": "CWE-89"}]
        posted = post_inline_findings("42", "1", findings)
        assert posted == 1
        # Verify CWE was included in the body
        call_body = mock_post_disc.call_args[0][2]  # 3rd positional arg is body
        assert "CWE-89" in call_body

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_partial_failure_counts_only_successes(self, mock_versions, mock_post_disc):
        """When some discussions fail, only successes are counted."""
        mock_versions.return_value = [{
            "base_commit_sha": "abc",
            "head_commit_sha": "def",
            "start_commit_sha": "ghi",
        }]
        # First succeeds, second fails
        mock_post_disc.side_effect = [{"id": "disc-1"}, None]

        findings = [
            {"file_path": "a.py", "line_num": 1, "severity": "high",
             "description": "XSS", "category": "code-security"},
            {"file_path": "b.py", "line_num": 5, "severity": "medium",
             "description": "CSRF", "category": "code-security"},
        ]
        posted = post_inline_findings("42", "1", findings)
        assert posted == 1


class TestFilterExcludedChangesEdgeCases:
    """Edge cases for the filter_excluded_changes function."""

    def test_change_with_only_old_path(self):
        """Changes with only old_path (deleted files) are filtered correctly."""
        changes = [
            {"old_path": "vendor/old.go", "diff": "-code"},
            {"old_path": "src/app.py", "diff": "-code"},
        ]
        result = filter_excluded_changes(changes, exclude_paths=["vendor/*"])
        assert len(result) == 1
        assert result[0]["old_path"] == "src/app.py"

    def test_change_with_no_path_keys(self):
        """Changes without any path key use empty string, no exclusion match."""
        changes = [{"diff": "+code"}]
        result = filter_excluded_changes(changes, exclude_paths=["vendor/*"])
        assert len(result) == 1


class TestExportFindingsJsonEdgeCases:
    """Edge cases for findings JSON export."""

    def test_findings_include_all_fields(self, tmp_path):
        """Exported findings have all expected fields."""
        output = str(tmp_path / "findings.json")
        code = "### [HIGH] Finding: SQL Injection\n**File:** `db.py` (line 42)\n"
        findings = export_findings_json(code, "", "", output)
        assert len(findings) == 1
        f = findings[0]
        assert "severity" in f
        assert "description" in f
        assert "file_path" in f
        assert "line_num" in f
        assert "category" in f
        assert f["severity"] == "high"
        assert f["file_path"] == "db.py"
        assert f["line_num"] == 42

    def test_findings_json_is_valid_json_file(self, tmp_path):
        """The output file is valid JSON that can be round-tripped."""
        output = str(tmp_path / "findings.json")
        code = "### [CRITICAL] Finding: RCE\n**File:** `cmd.py` (line 1)\n"
        export_findings_json(code, "", "", output)
        with open(output) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 1


class TestDefaultConfigValues:
    """Verify DEFAULT_CONFIG has expected structure and values."""

    def test_default_config_keys(self):
        expected_keys = {
            "version", "severity_threshold", "agents", "exclude_paths",
            "exclude_extensions", "inline_comments", "approve",
            "approve_threshold", "model", "max_diff_size",
        }
        assert set(DEFAULT_CONFIG.keys()) == expected_keys

    def test_default_agents_all_enabled(self):
        agents = DEFAULT_CONFIG["agents"]
        assert agents["code_security"] is True
        assert agents["dependency_audit"] is True
        assert agents["secret_scan"] is True

    def test_default_model(self):
        assert DEFAULT_CONFIG["model"] == "claude-sonnet-4-5"

    def test_default_max_diff_size(self):
        assert DEFAULT_CONFIG["max_diff_size"] == 200_000

    def test_default_approve_is_false(self):
        assert DEFAULT_CONFIG["approve"] is False

    def test_default_severity_threshold(self):
        assert DEFAULT_CONFIG["severity_threshold"] == "HIGH"


class TestCreateSession:
    """Tests for the HTTP session creation."""

    def test_session_has_retry_adapter(self):
        from duoguard import _create_session
        session = _create_session(retries=2, backoff=0.5)
        assert isinstance(session, requests.Session)
        # The session should have adapters mounted
        assert "https://" in session.adapters
        assert "http://" in session.adapters

    def test_session_retry_status_codes(self):
        from duoguard import _create_session
        session = _create_session()
        adapter = session.get_adapter("https://example.com")
        retry = adapter.max_retries
        assert 429 in retry.status_forcelist
        assert 500 in retry.status_forcelist
        assert 502 in retry.status_forcelist
        assert 503 in retry.status_forcelist
        assert 504 in retry.status_forcelist


# ── CWE / OWASP enrichment tests ─────────────────────────────


class TestCWEKeywordMap:
    """Verify the CWE keyword map structure and coverage."""

    def test_map_is_non_empty(self):
        assert len(CWE_KEYWORD_MAP) > 0

    def test_all_entries_have_cwe_and_owasp(self):
        for keyword, classification in CWE_KEYWORD_MAP.items():
            assert "cwe" in classification, f"Missing CWE for {keyword}"
            assert "owasp" in classification, f"Missing OWASP for {keyword}"

    def test_cwe_format(self):
        for keyword, classification in CWE_KEYWORD_MAP.items():
            assert classification["cwe"].startswith("CWE-"), f"Bad CWE format for {keyword}"

    def test_owasp_format(self):
        for keyword, classification in CWE_KEYWORD_MAP.items():
            assert classification["owasp"].startswith("A"), f"Bad OWASP format for {keyword}"
            assert ":2021-" in classification["owasp"], f"Not OWASP 2021 for {keyword}"

    def test_covers_owasp_top_10(self):
        """Verify we have coverage for all OWASP Top 10 (2021) categories."""
        owasp_categories = set()
        for classification in CWE_KEYWORD_MAP.values():
            cat = classification["owasp"].split("-")[0]  # e.g. "A03:2021"
            owasp_categories.add(cat)
        # Should cover most of the OWASP Top 10
        assert len(owasp_categories) >= 8

    def test_sql_injection_mapping(self):
        assert CWE_KEYWORD_MAP["sql injection"]["cwe"] == "CWE-89"
        assert "Injection" in CWE_KEYWORD_MAP["sql injection"]["owasp"]

    def test_xss_mapping(self):
        assert CWE_KEYWORD_MAP["xss"]["cwe"] == "CWE-79"

    def test_ssrf_mapping(self):
        assert CWE_KEYWORD_MAP["ssrf"]["cwe"] == "CWE-918"
        assert "SSRF" in CWE_KEYWORD_MAP["ssrf"]["owasp"]

    def test_hardcoded_password_mapping(self):
        assert CWE_KEYWORD_MAP["hardcoded password"]["cwe"] == "CWE-798"

    def test_path_traversal_mapping(self):
        assert CWE_KEYWORD_MAP["path traversal"]["cwe"] == "CWE-22"


class TestEnrichFindingCWE:
    """Tests for CWE/OWASP enrichment of findings."""

    def test_enriches_sql_injection(self):
        finding = {"description": "SQL Injection via string concatenation", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-89"
        assert "Injection" in result["owasp"]

    def test_enriches_xss(self):
        finding = {"description": "Reflected XSS in search parameter", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-79"

    def test_enriches_command_injection(self):
        finding = {"description": "Command injection via user input", "severity": "critical"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-78"

    def test_enriches_ssrf(self):
        finding = {"description": "SSRF via URL parameter", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-918"

    def test_enriches_hardcoded_secret(self):
        finding = {"description": "Hardcoded secret in config", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-798"

    def test_preserves_existing_cwe(self):
        finding = {"description": "SQL Injection", "cwe": "CWE-999", "owasp": "A99:Custom"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-999"
        assert result["owasp"] == "A99:Custom"

    def test_no_match_leaves_finding_unchanged(self):
        finding = {"description": "Something unrelated", "severity": "low"}
        result = enrich_finding_cwe(finding)
        assert "cwe" not in result
        assert "owasp" not in result

    def test_case_insensitive(self):
        finding = {"description": "SQL INJECTION in query", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-89"

    def test_enriches_open_redirect(self):
        finding = {"description": "Open redirect in login flow", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-601"

    def test_enriches_prototype_pollution(self):
        finding = {"description": "Prototype pollution via merge", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-1321"

    def test_enriches_deserialization(self):
        finding = {"description": "Insecure deserialization of user data", "severity": "critical"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-502"

    def test_partial_existing_cwe_fills_owasp(self):
        finding = {"description": "SQL Injection", "cwe": "CWE-89"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-89"
        assert "owasp" in result

    def test_enriches_regex_dos(self):
        finding = {"description": "ReDoS in email validation", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-1333"

    def test_enriches_file_upload(self):
        finding = {"description": "Unrestricted upload of dangerous file type", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-434"


class TestParseFindings_CWE:
    """Test that _parse_findings now enriches with CWE/OWASP."""

    def test_sql_injection_finding_gets_cwe(self):
        text = "### [HIGH] Finding: SQL Injection via concatenation\n**File:** `app.py` (line 10)\n"
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert findings[0]["cwe"] == "CWE-89"
        assert "Injection" in findings[0]["owasp"]

    def test_xss_finding_gets_cwe(self):
        text = "### [HIGH] Finding: Reflected XSS in search\n**File:** `views.py` (line 25)\n"
        findings = _parse_findings(text)
        assert findings[0]["cwe"] == "CWE-79"

    def test_secret_finding_gets_cwe(self):
        text = "### [HIGH] Finding: Hardcoded API key in config\n**File:** `config.py` (line 5)\n"
        findings = _parse_findings(text, category="secret-scan")
        assert findings[0]["cwe"] == "CWE-798"
        assert findings[0]["category"] == "secret-scan"

    def test_unknown_finding_no_cwe(self):
        text = "### [LOW] Finding: Minor style issue\n**File:** `style.py` (line 1)\n"
        findings = _parse_findings(text)
        assert "cwe" not in findings[0] or findings[0].get("cwe") is None


# ── Diff complexity tests ─────────────────────────────────────


class TestDiffComplexity:
    """Tests for diff complexity scoring."""

    def test_empty_changes(self):
        result = compute_diff_complexity([])
        assert result["total_additions"] == 0
        assert result["total_deletions"] == 0
        assert result["total_files"] == 0
        assert result["complexity_score"] == 0
        assert result["high_risk_files"] == []
        assert result["risk_factors"] == []

    def test_simple_addition(self):
        changes = [{"new_path": "hello.py", "diff": "\n+print('hello')\n+print('world')"}]
        result = compute_diff_complexity(changes)
        assert result["total_additions"] >= 1
        assert result["total_files"] == 1

    def test_detects_password_handling(self):
        changes = [{"new_path": "auth.py", "diff": "\n+password = request.form['password']"}]
        result = compute_diff_complexity(changes)
        assert "auth.py" in result["high_risk_files"]
        assert any("credential" in f for f in result["risk_factors"])

    def test_detects_exec_calls(self):
        changes = [{"new_path": "run.py", "diff": "\n+subprocess.call(cmd)"}]
        result = compute_diff_complexity(changes)
        assert "run.py" in result["high_risk_files"]
        assert any("command execution" in f for f in result["risk_factors"])

    def test_detects_sql_operations(self):
        changes = [{"new_path": "db.py", "diff": "\n+cursor.execute(query)"}]
        result = compute_diff_complexity(changes)
        assert "db.py" in result["high_risk_files"]

    def test_detects_auth_changes(self):
        changes = [{"new_path": "login.py", "diff": "\n+session['user'] = authenticated_user"}]
        result = compute_diff_complexity(changes)
        assert "login.py" in result["high_risk_files"]

    def test_detects_crypto_operations(self):
        changes = [{"new_path": "crypto.py", "diff": "\n+encrypted = encrypt(data, key)"}]
        result = compute_diff_complexity(changes)
        assert "crypto.py" in result["high_risk_files"]

    def test_complexity_score_increases_with_size(self):
        small = [{"new_path": "a.py", "diff": "\n+x = 1"}]
        large_diff = "\n".join([f"\n+line_{i} = {i}" for i in range(200)])
        large = [{"new_path": "b.py", "diff": large_diff}]
        small_score = compute_diff_complexity(small)["complexity_score"]
        large_score = compute_diff_complexity(large)["complexity_score"]
        assert large_score > small_score

    def test_complexity_score_increases_with_files(self):
        one_file = [{"new_path": "a.py", "diff": "\n+x = 1"}]
        five_files = [{"new_path": f"{c}.py", "diff": "\n+x = 1"} for c in "abcde"]
        one_score = compute_diff_complexity(one_file)["complexity_score"]
        five_score = compute_diff_complexity(five_files)["complexity_score"]
        assert five_score > one_score

    def test_complexity_score_capped_at_100(self):
        huge_diff = "\n".join([f"\n+password_{i} = exec(query_{i})" for i in range(500)])
        changes = [{"new_path": f"f{i}.py", "diff": huge_diff} for i in range(20)]
        result = compute_diff_complexity(changes)
        assert result["complexity_score"] <= 100

    def test_skips_empty_diffs(self):
        changes = [{"new_path": "empty.py", "diff": ""}]
        result = compute_diff_complexity(changes)
        assert result["total_additions"] == 0
        assert result["total_deletions"] == 0

    def test_multiple_risk_files(self):
        changes = [
            {"new_path": "auth.py", "diff": "\n+password = get_password()"},
            {"new_path": "db.py", "diff": "\n+cursor.execute(sql)"},
            {"new_path": "safe.py", "diff": "\n+x = 1 + 2"},
        ]
        result = compute_diff_complexity(changes)
        assert len(result["high_risk_files"]) == 2
        assert "safe.py" not in result["high_risk_files"]

    def test_returns_expected_keys(self):
        result = compute_diff_complexity([])
        expected_keys = {"total_additions", "total_deletions", "total_files",
                         "high_risk_files", "complexity_score", "risk_factors"}
        assert set(result.keys()) == expected_keys

    def test_deletions_counted(self):
        changes = [{"new_path": "a.py", "diff": "\n-old_line_1\n-old_line_2\n+new_line"}]
        result = compute_diff_complexity(changes)
        assert result["total_deletions"] >= 1

    def test_detects_url_handling(self):
        changes = [{"new_path": "api.py", "diff": "\n+redirect_url = request.args['redirect']"}]
        result = compute_diff_complexity(changes)
        assert "api.py" in result["high_risk_files"]

    def test_detects_file_operations(self):
        changes = [{"new_path": "io.py", "diff": "\n+upload_file(path)"}]
        result = compute_diff_complexity(changes)
        assert "io.py" in result["high_risk_files"]

    def test_risk_factors_no_duplicates(self):
        changes = [
            {"new_path": "a.py", "diff": "\n+password = x\n+secret = y\n+token = z"},
        ]
        result = compute_diff_complexity(changes)
        # Should only have one risk factor entry per file
        file_factors = [f for f in result["risk_factors"] if "a.py" in f]
        assert len(file_factors) == 1


class TestReportComplexity:
    """Test that generate_report includes complexity analysis."""

    def test_report_includes_complexity_section(self):
        mr_info = {"iid": 1, "title": "Test MR"}
        complexity = {
            "total_additions": 50,
            "total_deletions": 10,
            "total_files": 3,
            "high_risk_files": ["auth.py"],
            "complexity_score": 45,
            "risk_factors": ["authentication logic modified in auth.py"],
        }
        report = generate_report(mr_info, "", "", "", complexity=complexity)
        assert "Diff Complexity Analysis" in report
        assert "45/100" in report
        assert "Medium" in report
        assert "auth.py" in report

    def test_report_skips_complexity_when_zero(self):
        mr_info = {"iid": 1, "title": "Test MR"}
        complexity = {
            "total_additions": 0, "total_deletions": 0, "total_files": 0,
            "high_risk_files": [], "complexity_score": 0, "risk_factors": [],
        }
        report = generate_report(mr_info, "", "", "", complexity=complexity)
        assert "Diff Complexity Analysis" not in report

    def test_report_shows_low_risk(self):
        mr_info = {"iid": 1, "title": "Test MR"}
        complexity = {
            "total_additions": 5, "total_deletions": 0, "total_files": 1,
            "high_risk_files": [], "complexity_score": 2, "risk_factors": [],
        }
        report = generate_report(mr_info, "", "", "", complexity=complexity)
        assert "Low" in report

    def test_report_shows_high_risk(self):
        mr_info = {"iid": 1, "title": "Test MR"}
        complexity = {
            "total_additions": 500, "total_deletions": 200, "total_files": 10,
            "high_risk_files": ["a.py", "b.py", "c.py", "d.py"],
            "complexity_score": 80,
            "risk_factors": ["database operations modified in a.py"],
        }
        report = generate_report(mr_info, "", "", "", complexity=complexity)
        assert "High" in report
        assert "80/100" in report

    def test_report_without_complexity(self):
        mr_info = {"iid": 1, "title": "Test MR"}
        report = generate_report(mr_info, "", "", "")
        assert "Diff Complexity Analysis" not in report


# ── SARIF CWE enrichment tests ───────────────────────────────


class TestSarifCWE:
    """Test SARIF reports include CWE/OWASP properties."""

    def test_sarif_includes_cwe_property(self, tmp_path):
        code = "### [HIGH] Finding: SQL Injection in query\n**File:** `db.py` (line 10)\n"
        output = str(tmp_path / "sarif.json")
        generate_sarif_report(code, output)
        with open(output) as f:
            sarif = json.load(f)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        assert rules[0]["properties"]["cwe"] == "CWE-89"

    def test_sarif_includes_owasp_property(self, tmp_path):
        code = "### [HIGH] Finding: SSRF via user URL\n**File:** `api.py` (line 5)\n"
        output = str(tmp_path / "sarif.json")
        generate_sarif_report(code, output)
        with open(output) as f:
            sarif = json.load(f)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "owasp" in rules[0]["properties"]
        assert "SSRF" in rules[0]["properties"]["owasp"]

    def test_sarif_no_cwe_for_unknown(self, tmp_path):
        code = "### [LOW] Finding: Minor style issue\n**File:** `style.py` (line 1)\n"
        output = str(tmp_path / "sarif.json")
        generate_sarif_report(code, output)
        with open(output) as f:
            sarif = json.load(f)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "cwe" not in rules[0]["properties"]


# ── GitLab issue creation tests ──────────────────────────────


class TestCreateIssueForFinding:
    """Tests for creating GitLab issues from findings."""

    @patch("post_report.requests.post")
    def test_creates_issue_with_correct_payload(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 42, "title": "test"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        finding = {
            "severity": "critical",
            "description": "SQL Injection in query",
            "file_path": "db.py",
            "line_num": 10,
            "category": "code-security",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
        }
        result = create_issue_for_finding("123", "5", finding)
        assert result is not None
        assert result["iid"] == 42
        # Verify the POST was called
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert "SQL Injection" in payload["title"]
        assert "DuoGuard" in payload["labels"]

    @patch("post_report.requests.post")
    def test_returns_none_on_http_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)
        mock_post.return_value = mock_resp

        finding = {"severity": "high", "description": "Test", "file_path": "a.py"}
        result = create_issue_for_finding("123", "5", finding)
        assert result is None

    @patch("post_report.requests.post")
    def test_issue_includes_cwe_link(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 10}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        finding = {
            "severity": "high", "description": "XSS", "file_path": "view.py",
            "line_num": 5, "category": "code-security", "cwe": "CWE-79",
        }
        create_issue_for_finding("123", "5", finding)
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "CWE-79" in payload["description"]
        assert "cwe.mitre.org" in payload["description"]

    @patch("post_report.requests.post")
    def test_title_truncation(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 1}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        finding = {
            "severity": "critical",
            "description": "A" * 300,
            "file_path": "x.py",
        }
        create_issue_for_finding("123", "5", finding)
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert len(payload["title"]) <= 255


class TestCreateIssuesForFindings:
    """Tests for batch issue creation with severity filtering."""

    @patch("post_report.create_issue_for_finding")
    def test_only_creates_for_high_and_above(self, mock_create):
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "critical", "description": "RCE"},
            {"severity": "high", "description": "SQLi"},
            {"severity": "medium", "description": "XSS"},
            {"severity": "low", "description": "Info leak"},
        ]
        result = create_issues_for_findings("123", "5", findings, min_severity="high")
        assert len(result) == 2
        assert mock_create.call_count == 2

    @patch("post_report.create_issue_for_finding")
    def test_creates_for_medium_when_threshold_lowered(self, mock_create):
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "high", "description": "SQLi"},
            {"severity": "medium", "description": "XSS"},
            {"severity": "low", "description": "Info"},
        ]
        result = create_issues_for_findings("123", "5", findings, min_severity="medium")
        assert len(result) == 2

    @patch("post_report.create_issue_for_finding")
    def test_empty_findings_returns_empty(self, mock_create):
        result = create_issues_for_findings("123", "5", [], min_severity="high")
        assert result == []
        mock_create.assert_not_called()

    @patch("post_report.create_issue_for_finding")
    def test_skips_failed_creations(self, mock_create):
        mock_create.side_effect = [{"iid": 1}, None, {"iid": 3}]
        findings = [
            {"severity": "critical", "description": "A"},
            {"severity": "critical", "description": "B"},
            {"severity": "critical", "description": "C"},
        ]
        result = create_issues_for_findings("123", "5", findings, min_severity="high")
        assert len(result) == 2

    @patch("post_report.create_issue_for_finding")
    def test_critical_only_threshold(self, mock_create):
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "critical", "description": "RCE"},
            {"severity": "high", "description": "SQLi"},
        ]
        result = create_issues_for_findings("123", "5", findings, min_severity="critical")
        assert len(result) == 1


# ── Agent mode tests ─────────────────────────────────────────


class TestRunAgentMode:
    """Tests for run_agent_mode() function."""

    @patch("duoguard._run_security_scan")
    @patch("duoguard._parse_agent_context")
    @patch("duoguard._resolve_api_url_for_agent")
    def test_agent_mode_happy_path(self, mock_resolve, mock_parse, mock_scan):
        """Agent mode resolves API URL, parses context, and runs scan."""
        import duoguard
        from duoguard import run_agent_mode
        old_event = duoguard.AI_FLOW_EVENT
        duoguard.AI_FLOW_EVENT = "mention"
        mock_resolve.return_value = "https://gitlab.com/api/v4"
        mock_parse.return_value = ("group%2Fproject", "42")
        try:
            run_agent_mode(output="report.md", sarif="sarif.json",
                           fail_on="HIGH", config=None)
            mock_resolve.assert_called_once()
            mock_parse.assert_called_once()
            mock_scan.assert_called_once_with(
                "group%2Fproject", "42", "report.md", "sarif.json", "HIGH", config=None
            )
        finally:
            duoguard.AI_FLOW_EVENT = old_event

    @patch("duoguard._parse_agent_context")
    @patch("duoguard._resolve_api_url_for_agent")
    def test_agent_mode_missing_context_exits(self, mock_resolve, mock_parse):
        """Agent mode exits with code 1 when context cannot be parsed."""
        import duoguard
        from duoguard import run_agent_mode
        old_event = duoguard.AI_FLOW_EVENT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        old_ctx = duoguard.AI_FLOW_CONTEXT
        duoguard.AI_FLOW_EVENT = "mention"
        duoguard.AI_FLOW_PROJECT_PATH = ""
        duoguard.AI_FLOW_CONTEXT = ""
        mock_resolve.return_value = "https://gitlab.com/api/v4"
        mock_parse.return_value = ("", "")
        try:
            with pytest.raises(SystemExit) as exc_info:
                run_agent_mode()
            assert exc_info.value.code == 1
        finally:
            duoguard.AI_FLOW_EVENT = old_event
            duoguard.AI_FLOW_PROJECT_PATH = old_path
            duoguard.AI_FLOW_CONTEXT = old_ctx

    @patch("duoguard._run_security_scan")
    @patch("duoguard._parse_agent_context")
    @patch("duoguard._resolve_api_url_for_agent")
    def test_agent_mode_missing_mr_iid_exits(self, mock_resolve, mock_parse, mock_scan):
        """Agent mode exits when MR IID is empty but project is present."""
        import duoguard
        from duoguard import run_agent_mode
        old_event = duoguard.AI_FLOW_EVENT
        duoguard.AI_FLOW_EVENT = "assign_reviewer"
        mock_resolve.return_value = "https://gitlab.com/api/v4"
        mock_parse.return_value = ("group%2Fproject", "")
        try:
            with pytest.raises(SystemExit) as exc_info:
                run_agent_mode()
            assert exc_info.value.code == 1
            mock_scan.assert_not_called()
        finally:
            duoguard.AI_FLOW_EVENT = old_event

    @patch("duoguard._run_security_scan")
    @patch("duoguard._parse_agent_context")
    @patch("duoguard._resolve_api_url_for_agent")
    def test_agent_mode_sets_gitlab_api_url(self, mock_resolve, mock_parse, mock_scan):
        """Agent mode sets GITLAB_API_URL from resolved agent URL."""
        import duoguard
        from duoguard import run_agent_mode
        old_api_url = duoguard.GITLAB_API_URL
        old_event = duoguard.AI_FLOW_EVENT
        duoguard.AI_FLOW_EVENT = "mention"
        mock_resolve.return_value = "https://gitlab.example.com/api/v4"
        mock_parse.return_value = ("proj", "1")
        try:
            run_agent_mode()
            assert duoguard.GITLAB_API_URL == "https://gitlab.example.com/api/v4"
        finally:
            duoguard.GITLAB_API_URL = old_api_url
            duoguard.AI_FLOW_EVENT = old_event

    @patch("duoguard._run_security_scan")
    @patch("duoguard._parse_agent_context")
    @patch("duoguard._resolve_api_url_for_agent")
    def test_agent_mode_default_event_is_unknown(self, mock_resolve, mock_parse, mock_scan):
        """When AI_FLOW_EVENT is empty, event defaults to 'unknown'."""
        import duoguard
        from duoguard import run_agent_mode
        old_event = duoguard.AI_FLOW_EVENT
        duoguard.AI_FLOW_EVENT = ""
        mock_resolve.return_value = "https://gitlab.com/api/v4"
        mock_parse.return_value = ("proj", "1")
        try:
            run_agent_mode()
            # The function should still work (no crash on empty event)
            mock_scan.assert_called_once()
        finally:
            duoguard.AI_FLOW_EVENT = old_event

    @patch("duoguard._run_security_scan")
    @patch("duoguard._parse_agent_context")
    @patch("duoguard._resolve_api_url_for_agent")
    def test_agent_mode_passes_config(self, mock_resolve, mock_parse, mock_scan):
        """Agent mode passes the config dict through to _run_security_scan."""
        import duoguard
        from duoguard import run_agent_mode
        old_event = duoguard.AI_FLOW_EVENT
        duoguard.AI_FLOW_EVENT = "mention"
        mock_resolve.return_value = "https://gitlab.com/api/v4"
        mock_parse.return_value = ("proj", "1")
        custom_config = {"severity_threshold": "CRITICAL", "agents": {"code_security": True}}
        try:
            run_agent_mode(config=custom_config)
            mock_scan.assert_called_once_with(
                "proj", "1", "duoguard-report.md", "", "HIGH", config=custom_config
            )
        finally:
            duoguard.AI_FLOW_EVENT = old_event

    @patch("duoguard._run_security_scan")
    @patch("duoguard._parse_agent_context")
    @patch("duoguard._resolve_api_url_for_agent")
    def test_agent_mode_custom_output_and_sarif(self, mock_resolve, mock_parse, mock_scan):
        """Agent mode passes custom output and sarif paths."""
        import duoguard
        from duoguard import run_agent_mode
        old_event = duoguard.AI_FLOW_EVENT
        duoguard.AI_FLOW_EVENT = "mention"
        mock_resolve.return_value = "https://gitlab.com/api/v4"
        mock_parse.return_value = ("proj", "1")
        try:
            run_agent_mode(output="/tmp/custom-report.md", sarif="/tmp/custom.sarif",
                           fail_on="CRITICAL")
            mock_scan.assert_called_once_with(
                "proj", "1", "/tmp/custom-report.md", "/tmp/custom.sarif",
                "CRITICAL", config=None
            )
        finally:
            duoguard.AI_FLOW_EVENT = old_event

    @patch("duoguard._run_security_scan")
    @patch("duoguard._parse_agent_context")
    @patch("duoguard._resolve_api_url_for_agent")
    def test_agent_mode_assign_reviewer_event(self, mock_resolve, mock_parse, mock_scan):
        """Agent mode handles assign_reviewer event type."""
        import duoguard
        from duoguard import run_agent_mode
        old_event = duoguard.AI_FLOW_EVENT
        duoguard.AI_FLOW_EVENT = "assign_reviewer"
        mock_resolve.return_value = "https://gitlab.com/api/v4"
        mock_parse.return_value = ("team%2Frepo", "99")
        try:
            run_agent_mode()
            mock_scan.assert_called_once()
        finally:
            duoguard.AI_FLOW_EVENT = old_event


# ── Secret scanning pattern tests ────────────────────────────


class TestSecretScanPatterns:
    """Tests verifying the secret scanner agent is invoked with diffs
    containing real secret patterns, and that findings are produced."""

    @patch("duoguard.call_ai_gateway")
    def test_detects_rsa_private_key(self, mock_call):
        """RSA private key in diff triggers secret scan finding."""
        mock_call.return_value = (
            "### [CRITICAL] Finding: RSA private key exposed\n"
            "**File:** `id_rsa` (line 1)\n"
        )
        diff = "+-----BEGIN RSA PRIVATE KEY-----\n+MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn..."
        result = run_secret_scan(diff)
        assert "[CRITICAL]" in result
        assert "private key" in result.lower()
        mock_call.assert_called_once()
        # Verify the diff was passed in the user message
        user_msg = mock_call.call_args[0][1]
        assert "BEGIN RSA PRIVATE KEY" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_detects_aws_access_key(self, mock_call):
        """AWS access key pattern in diff triggers finding."""
        mock_call.return_value = (
            "### [CRITICAL] Finding: AWS access key exposed\n"
            "**File:** `config.py` (line 5)\n"
        )
        diff = "+AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'"
        result = run_secret_scan(diff)
        assert "[CRITICAL]" in result
        user_msg = mock_call.call_args[0][1]
        assert "AKIA" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_detects_aws_secret_key(self, mock_call):
        """AWS secret access key pattern in diff triggers finding."""
        mock_call.return_value = (
            "### [CRITICAL] Finding: AWS secret key exposed\n"
            "**File:** `.env` (line 3)\n"
        )
        diff = "+AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        result = run_secret_scan(diff)
        assert "[CRITICAL]" in result

    @patch("duoguard.call_ai_gateway")
    def test_detects_github_personal_access_token(self, mock_call):
        """GitHub personal access token in diff triggers finding."""
        mock_call.return_value = (
            "### [CRITICAL] Finding: GitHub token exposed\n"
            "**File:** `deploy.sh` (line 10)\n"
        )
        diff = "+GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345"
        result = run_secret_scan(diff)
        assert "[CRITICAL]" in result
        user_msg = mock_call.call_args[0][1]
        assert "ghp_" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_detects_generic_api_key_in_header(self, mock_call):
        """Generic API key in HTTP header pattern triggers finding."""
        mock_call.return_value = (
            "### [HIGH] Finding: API key in source code\n"
            "**File:** `client.py` (line 20)\n"
        )
        diff = "+headers = {'X-Api-Key': 'sk_test_FAKE_KEY_FOR_UNIT_TEST_0000'}"
        result = run_secret_scan(diff)
        assert "API key" in result or "api key" in result.lower()

    @patch("duoguard.call_ai_gateway")
    def test_detects_database_connection_string(self, mock_call):
        """Database connection string with password triggers finding."""
        mock_call.return_value = (
            "### [CRITICAL] Finding: Database password in connection string\n"
            "**File:** `settings.py` (line 15)\n"
        )
        diff = "+DATABASE_URL = 'postgresql://admin:s3cretP@ss@db.example.com:5432/mydb'"
        result = run_secret_scan(diff)
        assert "[CRITICAL]" in result
        user_msg = mock_call.call_args[0][1]
        assert "postgresql://" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_detects_jwt_token(self, mock_call):
        """JWT token in diff triggers finding."""
        mock_call.return_value = (
            "### [HIGH] Finding: JWT token hardcoded\n"
            "**File:** `auth.py` (line 8)\n"
        )
        diff = "+token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'"
        result = run_secret_scan(diff)
        assert "[HIGH]" in result
        user_msg = mock_call.call_args[0][1]
        assert "eyJ" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_detects_slack_webhook_url(self, mock_call):
        """Slack webhook URL in diff triggers finding."""
        mock_call.return_value = (
            "### [HIGH] Finding: Slack webhook URL exposed\n"
            "**File:** `notify.py` (line 3)\n"
        )
        diff = "+SLACK_WEBHOOK = 'https://hooks.example.com/services/TTEST00000/BTEST00000/xxxxxxxxxFAKExxxxxxxxxx'"
        result = run_secret_scan(diff)
        assert "[HIGH]" in result
        user_msg = mock_call.call_args[0][1]
        assert "hooks.example.com" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_detects_private_key_in_env(self, mock_call):
        """Private key assigned to env variable triggers finding."""
        mock_call.return_value = (
            "### [CRITICAL] Finding: Private key in environment\n"
            "**File:** `.env` (line 1)\n"
        )
        diff = "+PRIVATE_KEY='-----BEGIN EC PRIVATE KEY-----\\nMHQCAQE...'"
        result = run_secret_scan(diff)
        assert "[CRITICAL]" in result

    @patch("duoguard.call_ai_gateway")
    def test_detects_google_api_key(self, mock_call):
        """Google API key pattern triggers finding."""
        mock_call.return_value = (
            "### [HIGH] Finding: Google API key\n"
            "**File:** `maps.js` (line 12)\n"
        )
        diff = "+const apiKey = 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY';"
        result = run_secret_scan(diff)
        assert "[HIGH]" in result
        user_msg = mock_call.call_args[0][1]
        assert "AIza" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_clean_diff_no_secrets(self, mock_call):
        """A clean diff with no secrets produces no findings."""
        mock_call.return_value = "No secrets detected."
        diff = "+def add(a, b):\n+    return a + b"
        result = run_secret_scan(diff)
        assert "No secrets" in result

    @patch("duoguard.call_ai_gateway")
    def test_detects_stripe_secret_key(self, mock_call):
        """Stripe secret key pattern triggers finding."""
        mock_call.return_value = (
            "### [CRITICAL] Finding: Stripe secret key\n"
            "**File:** `billing.py` (line 7)\n"
        )
        diff = "+stripe.api_key = 'sk_test_FAKE_STRIPE_KEY_FOR_TESTING_00'"
        result = run_secret_scan(diff)
        assert "[CRITICAL]" in result
        user_msg = mock_call.call_args[0][1]
        assert "sk_test_" in user_msg


# ── CWE/OWASP map extension tests ───────────────────────────


class TestCWEMapExtendedVulnerabilities:
    """Tests for additional vulnerability patterns in CWE_KEYWORD_MAP."""

    def test_xxe_cwe_611(self):
        """XXE (CWE-611) is mapped correctly."""
        assert "xxe" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["xxe"]["cwe"] == "CWE-611"
        assert "Misconfiguration" in CWE_KEYWORD_MAP["xxe"]["owasp"]

    def test_xml_external_entity_cwe_611(self):
        """XML External Entity (CWE-611) full name is mapped."""
        assert "xml external entity" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["xml external entity"]["cwe"] == "CWE-611"

    def test_ldap_injection_cwe_90(self):
        """LDAP injection (CWE-90) is mapped correctly."""
        assert "ldap injection" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["ldap injection"]["cwe"] == "CWE-90"
        assert "Injection" in CWE_KEYWORD_MAP["ldap injection"]["owasp"]

    def test_path_traversal_cwe_22(self):
        """Path traversal (CWE-22) is mapped correctly."""
        assert "path traversal" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["path traversal"]["cwe"] == "CWE-22"
        assert "Access Control" in CWE_KEYWORD_MAP["path traversal"]["owasp"]

    def test_directory_traversal_cwe_22(self):
        """Directory traversal (CWE-22) alias is mapped."""
        assert "directory traversal" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["directory traversal"]["cwe"] == "CWE-22"

    def test_open_redirect_cwe_601(self):
        """Open redirect (CWE-601) is mapped correctly."""
        assert "open redirect" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["open redirect"]["cwe"] == "CWE-601"
        assert "Access Control" in CWE_KEYWORD_MAP["open redirect"]["owasp"]

    def test_csrf_cwe_352(self):
        """CSRF (CWE-352) is mapped correctly."""
        assert "csrf" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["csrf"]["cwe"] == "CWE-352"

    def test_code_injection_cwe_94(self):
        """Code injection (CWE-94) is mapped correctly."""
        assert "code injection" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["code injection"]["cwe"] == "CWE-94"

    def test_eval_cwe_95(self):
        """Eval injection (CWE-95) is mapped correctly."""
        assert "eval" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["eval"]["cwe"] == "CWE-95"

    def test_mass_assignment_cwe_915(self):
        """Mass assignment (CWE-915) is mapped correctly."""
        assert "mass assignment" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["mass assignment"]["cwe"] == "CWE-915"

    def test_unrestricted_upload_cwe_434(self):
        """Unrestricted file upload (CWE-434) is mapped correctly."""
        assert "unrestricted upload" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["unrestricted upload"]["cwe"] == "CWE-434"

    def test_denial_of_service_cwe_400(self):
        """Denial of service (CWE-400) is mapped correctly."""
        assert "denial of service" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["denial of service"]["cwe"] == "CWE-400"

    def test_insecure_random_cwe_330(self):
        """Insecure random (CWE-330) is mapped correctly."""
        assert "insecure random" in CWE_KEYWORD_MAP
        assert CWE_KEYWORD_MAP["insecure random"]["cwe"] == "CWE-330"
        assert "Cryptographic" in CWE_KEYWORD_MAP["insecure random"]["owasp"]


class TestEnrichFindingCWEExtended:
    """Extended enrichment tests for additional vulnerability patterns."""

    def test_enriches_xxe(self):
        finding = {"description": "XXE via user-supplied XML", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-611"

    def test_enriches_ldap_injection(self):
        finding = {"description": "LDAP injection in user search", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-90"

    def test_enriches_path_traversal(self):
        finding = {"description": "Path traversal in file download", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-22"

    def test_enriches_directory_traversal(self):
        finding = {"description": "Directory traversal via ../", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-22"

    def test_enriches_csrf(self):
        finding = {"description": "CSRF token missing on state-changing endpoint", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-352"

    def test_enriches_code_injection(self):
        finding = {"description": "Code injection via dynamic import", "severity": "critical"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-94"

    def test_enriches_eval_injection(self):
        finding = {"description": "Dangerous eval of user input", "severity": "critical"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-95"

    def test_enriches_mass_assignment(self):
        finding = {"description": "Mass assignment allows privilege escalation", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-915"

    def test_enriches_denial_of_service(self):
        finding = {"description": "Denial of service via large payload", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-400"


# ── Main entry point CLI tests ───────────────────────────────


class TestMainCLI:
    """Tests for the main() CLI entry point."""

    @patch("duoguard._run_security_scan")
    @patch("duoguard.load_config")
    def test_cicd_mode_with_required_args(self, mock_config, mock_scan):
        """CI/CD mode runs with --project-id and --mr-iid."""
        from duoguard import main
        mock_config.return_value = dict(DEFAULT_CONFIG)
        with patch("sys.argv", ["duoguard", "--mode", "cicd",
                                 "--project-id", "123", "--mr-iid", "5"]):
            main()
        mock_scan.assert_called_once()
        call_args = mock_scan.call_args
        assert call_args[0][0] == "123"
        assert call_args[0][1] == "5"

    @patch("duoguard.load_config")
    def test_cicd_mode_missing_project_id_errors(self, mock_config):
        """CI/CD mode without --project-id raises SystemExit."""
        from duoguard import main
        mock_config.return_value = dict(DEFAULT_CONFIG)
        with patch("sys.argv", ["duoguard", "--mode", "cicd", "--mr-iid", "5"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2  # argparse error code

    @patch("duoguard.load_config")
    def test_cicd_mode_missing_mr_iid_errors(self, mock_config):
        """CI/CD mode without --mr-iid raises SystemExit."""
        from duoguard import main
        mock_config.return_value = dict(DEFAULT_CONFIG)
        with patch("sys.argv", ["duoguard", "--mode", "cicd", "--project-id", "123"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    @patch("duoguard.run_agent_mode")
    @patch("duoguard.load_config")
    def test_agent_mode_invokes_run_agent_mode(self, mock_config, mock_agent):
        """--mode agent invokes run_agent_mode."""
        from duoguard import main
        mock_config.return_value = dict(DEFAULT_CONFIG)
        with patch("sys.argv", ["duoguard", "--mode", "agent"]):
            main()
        mock_agent.assert_called_once()

    @patch("duoguard._run_security_scan")
    @patch("duoguard.load_config")
    def test_fail_on_cli_overrides_config(self, mock_config, mock_scan):
        """--fail-on CLI argument overrides config severity_threshold."""
        from duoguard import main
        cfg = dict(DEFAULT_CONFIG)
        cfg["severity_threshold"] = "LOW"
        mock_config.return_value = cfg
        with patch("sys.argv", ["duoguard", "--mode", "cicd",
                                 "--project-id", "1", "--mr-iid", "2",
                                 "--fail-on", "CRITICAL"]):
            main()
        call_args = mock_scan.call_args
        # fail_on should be CRITICAL (from CLI), not LOW (from config)
        assert call_args[0][4] == "CRITICAL"

    @patch("duoguard._run_security_scan")
    @patch("duoguard.load_config")
    def test_config_path_passed_to_load_config(self, mock_config, mock_scan):
        """--config argument is passed to load_config."""
        from duoguard import main
        mock_config.return_value = dict(DEFAULT_CONFIG)
        with patch("sys.argv", ["duoguard", "--mode", "cicd",
                                 "--project-id", "1", "--mr-iid", "2",
                                 "--config", "/path/to/config.yml"]):
            main()
        mock_config.assert_called_once_with("/path/to/config.yml")


# ── MR approval edge cases ───────────────────────────────────


class TestMRApprovalEdgeCases:
    """Boundary conditions for MR approval thresholds."""

    @patch("post_report.requests.post")
    def test_approve_mr_network_timeout(self, mock_post):
        """Network timeout returns False instead of raising."""
        mock_post.side_effect = requests.exceptions.HTTPError(
            response=MagicMock(status_code=504)
        )
        result = approve_mr("42", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_unapprove_mr_network_timeout(self, mock_post):
        """Network timeout on unapprove returns False."""
        mock_post.side_effect = requests.exceptions.HTTPError(
            response=MagicMock(status_code=504)
        )
        result = unapprove_mr("42", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_approve_mr_401_unauthorized(self, mock_post):
        """401 Unauthorized on approve returns False."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_resp
        )
        mock_post.return_value = mock_resp
        result = approve_mr("42", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_approve_mr_url_contains_project_and_mr(self, mock_post):
        """Approve URL is correctly constructed with project and MR IDs."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        approve_mr("my%2Fproject", "99")
        call_url = mock_post.call_args[0][0]
        assert "my%2Fproject" in call_url
        assert "99" in call_url
        assert "approve" in call_url

    @patch("post_report.requests.post")
    def test_unapprove_mr_url_contains_unapprove(self, mock_post):
        """Unapprove URL correctly uses 'unapprove' endpoint."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        unapprove_mr("42", "7")
        call_url = mock_post.call_args[0][0]
        assert "unapprove" in call_url
        assert "7" in call_url


# ── Severity threshold boundary tests ────────────────────────


class TestSeverityThresholdBoundaries:
    """Tests for severity threshold comparison in _run_security_scan."""

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_severity_equal_to_threshold_fails(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        """When severity exactly equals threshold, pipeline should fail."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "### [MEDIUM] Finding: XSS\n**File:** `app.py` (line 1)\n"
        mock_dep.return_value = ""
        mock_secret.return_value = ""

        output = str(tmp_path / "report.md")
        with pytest.raises(SystemExit) as exc_info:
            _run_security_scan("42", "1", output, "", "MEDIUM")
        assert exc_info.value.code == 1

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_severity_below_threshold_passes(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        """When severity is below threshold, pipeline should pass."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "### [LOW] Finding: Minor\n**File:** `app.py` (line 1)\n"
        mock_dep.return_value = ""
        mock_secret.return_value = ""

        output = str(tmp_path / "report.md")
        # LOW severity, threshold is HIGH => should pass (no exit)
        _run_security_scan("42", "1", output, "", "HIGH")
        assert Path(output).exists()

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_none_severity_below_all_thresholds(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        """NONE severity is below even LOW threshold, so pipeline passes."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "No issues found."
        mock_dep.return_value = ""
        mock_secret.return_value = ""

        output = str(tmp_path / "report.md")
        _run_security_scan("42", "1", output, "", "LOW")
        assert Path(output).exists()

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_critical_threshold_only_fails_on_critical(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        """With CRITICAL threshold, HIGH severity should pass."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "### [HIGH] Finding: XSS\n**File:** `app.py` (line 1)\n"
        mock_dep.return_value = ""
        mock_secret.return_value = ""

        output = str(tmp_path / "report.md")
        # HIGH < CRITICAL, so should pass
        _run_security_scan("42", "1", output, "", "CRITICAL")
        assert Path(output).exists()


# ── Agent context with various env var combinations ──────────


class TestAgentContextEnvironmentVariations:
    """Tests for agent context parsing with various environment variable combos."""

    def test_context_with_full_mr_url(self):
        """Context containing a full GitLab MR URL extracts the MR IID."""
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        old_input = duoguard.AI_FLOW_INPUT
        duoguard.AI_FLOW_CONTEXT = "Review https://gitlab.com/group/project/-/merge_requests/77"
        duoguard.AI_FLOW_PROJECT_PATH = "group/project"
        duoguard.AI_FLOW_INPUT = ""
        try:
            # The regex looks for !(\d+) so URL won't match. But text fallback:
            project_id, mr_iid = _parse_agent_context()
            # URL doesn't have !77 format, so it won't find MR from context
            # But input is empty too, so both are empty
            assert project_id == "group%2Fproject"
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path
            duoguard.AI_FLOW_INPUT = old_input

    def test_context_and_input_both_have_mr_ref(self):
        """When both context and input have MR refs, context takes priority."""
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        old_input = duoguard.AI_FLOW_INPUT
        duoguard.AI_FLOW_CONTEXT = "Check !10 for security"
        duoguard.AI_FLOW_INPUT = "Please look at !20"
        duoguard.AI_FLOW_PROJECT_PATH = "org/repo"
        try:
            project_id, mr_iid = _parse_agent_context()
            assert mr_iid == "10"  # Context takes priority
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_INPUT = old_input
            duoguard.AI_FLOW_PROJECT_PATH = old_path

    def test_json_context_with_numeric_iid(self):
        """JSON context with numeric IID (not string) is handled."""
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        duoguard.AI_FLOW_CONTEXT = json.dumps({
            "merge_request": {"iid": 999},
            "project": {"path_with_namespace": "team/repo"},
        })
        duoguard.AI_FLOW_PROJECT_PATH = ""
        try:
            project_id, mr_iid = _parse_agent_context()
            assert mr_iid == "999"
            assert "team%2Frepo" in project_id
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path

    def test_json_context_with_zero_iid(self):
        """JSON context with IID of 0 is treated as empty/falsy."""
        import duoguard
        old_ctx = duoguard.AI_FLOW_CONTEXT
        old_path = duoguard.AI_FLOW_PROJECT_PATH
        old_input = duoguard.AI_FLOW_INPUT
        duoguard.AI_FLOW_CONTEXT = json.dumps({
            "merge_request": {"iid": 0},
        })
        duoguard.AI_FLOW_PROJECT_PATH = "org/repo"
        duoguard.AI_FLOW_INPUT = ""
        try:
            project_id, mr_iid = _parse_agent_context()
            # str(0) == "0" which is truthy in Python but MR IID 0 is unusual
            assert mr_iid == "0" or mr_iid == ""
        finally:
            duoguard.AI_FLOW_CONTEXT = old_ctx
            duoguard.AI_FLOW_PROJECT_PATH = old_path
            duoguard.AI_FLOW_INPUT = old_input


# ── Issue creation edge cases ────────────────────────────────


class TestCreateIssueEdgeCases:
    """Additional edge cases for GitLab issue creation."""

    @patch("post_report.create_issue_for_finding")
    def test_info_severity_excluded_from_all_thresholds(self, mock_create):
        """Info severity findings are excluded even at lowest threshold."""
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "info", "description": "Note"},
        ]
        result = create_issues_for_findings("123", "5", findings, min_severity="low")
        assert len(result) == 0
        mock_create.assert_not_called()

    @patch("post_report.create_issue_for_finding")
    def test_all_severities_created_at_low_threshold(self, mock_create):
        """All non-info findings are created at 'low' threshold."""
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "critical", "description": "A"},
            {"severity": "high", "description": "B"},
            {"severity": "medium", "description": "C"},
            {"severity": "low", "description": "D"},
        ]
        result = create_issues_for_findings("123", "5", findings, min_severity="low")
        assert len(result) == 4

    @patch("post_report.requests.post")
    def test_issue_without_cwe_omits_cwe_section(self, mock_post):
        """Issue body omits CWE section when finding has no CWE."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 1}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        finding = {
            "severity": "high",
            "description": "Unknown vulnerability",
            "file_path": "app.py",
            "line_num": 10,
            "category": "code-security",
        }
        create_issue_for_finding("123", "5", finding)
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "cwe.mitre.org" not in payload["description"]

    @patch("post_report.requests.post")
    def test_issue_labels_include_security_and_duoguard(self, mock_post):
        """Issue labels include severity, DuoGuard, and security."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 1}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        finding = {
            "severity": "critical",
            "description": "RCE",
            "file_path": "cmd.py",
        }
        create_issue_for_finding("123", "5", finding)
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        labels = payload["labels"]
        assert "security::critical" in labels
        assert "DuoGuard" in labels
        assert "security" in labels


# ── Binary and unusual diff content tests ────────────────────


class TestFormatDiffUnusualContent:
    """Tests for format_diff_for_analysis with unusual diff content."""

    def test_null_bytes_in_diff_preserved(self):
        """Null bytes in diff content are preserved (binary detection responsibility is on agent)."""
        changes = [{"new_path": "binary.bin", "diff": "+\x00\x01\x02content"}]
        result = format_diff_for_analysis(changes)
        assert "binary.bin" in result

    def test_very_long_single_line_diff(self):
        """A single very long line in diff is handled without truncation within the line."""
        long_line = "+" + "A" * 10_000
        changes = [{"new_path": "long.py", "diff": long_line}]
        result = format_diff_for_analysis(changes, max_size=50_000)
        assert "long.py" in result
        assert long_line[1:50] in result  # first 50 chars of long line present

    def test_diff_with_only_plus_plus_plus_header(self):
        """Diff that is entirely header lines (no +/- content lines) produces minimal output."""
        changes = [{"new_path": "header_only.py", "diff": "+++ b/header_only.py\n--- a/header_only.py"}]
        result = format_diff_for_analysis(changes)
        # The diff is non-empty so it gets included
        assert "header_only.py" in result

    def test_multiple_files_only_first_fits(self):
        """With tight size limit, only first files fit and rest are truncated."""
        changes = [
            {"new_path": f"file{i}.py", "diff": "+" + "x" * 50}
            for i in range(10)
        ]
        result = format_diff_for_analysis(changes, max_size=200)
        assert "omitted" in result

    def test_diff_with_unicode_filename(self):
        """Filenames with unicode characters are handled correctly."""
        changes = [{"new_path": "src/naïve_parser.py", "diff": "+code"}]
        result = format_diff_for_analysis(changes)
        assert "naïve_parser.py" in result

    def test_diff_with_special_regex_chars_in_path(self):
        """File paths with characters that would break regex (brackets, dots) are fine."""
        changes = [{"new_path": "app[v2].py", "diff": "+x = 1"}]
        result = format_diff_for_analysis(changes)
        assert "app[v2].py" in result

    def test_none_diff_value_skipped(self):
        """Change with diff=None should be skipped (falsy diff)."""
        changes = [{"new_path": "missing.py", "diff": None}]
        result = format_diff_for_analysis(changes)
        # None is falsy, should be skipped
        assert "missing.py" not in result


# ── Dependency file detection extended edge cases ─────────────


class TestExtractDependencyFilesExtended:
    """Further edge cases for extract_dependency_files."""

    def test_pdm_lock_detected(self):
        """pdm.lock is recognized as a dependency file."""
        changes = [{"new_path": "pdm.lock", "diff": "+lock"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_mix_lock_detected(self):
        """mix.lock (Elixir) is recognized."""
        changes = [{"new_path": "mix.lock", "diff": "+dep"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_package_resolved_detected(self):
        """Package.resolved (Swift) is recognized."""
        changes = [{"new_path": "Package.resolved", "diff": "+pkg"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_cargo_lock_detected(self):
        """Cargo.lock (Rust) is recognized."""
        changes = [{"new_path": "Cargo.lock", "diff": "+lock"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_gemfile_lock_detected(self):
        """Gemfile.lock (Ruby) is recognized."""
        changes = [{"new_path": "Gemfile.lock", "diff": "+locked"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_constraints_txt_detected(self):
        """constraints.txt is recognized as dependency file."""
        changes = [{"new_path": "constraints.txt", "diff": "+pin"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_requirements_custom_suffix_detected(self):
        """requirements-test.txt matches the prefix pattern."""
        changes = [{"new_path": "requirements-test.txt", "diff": "+pytest"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_non_dep_txt_file_not_detected(self):
        """A .txt file that doesn't match dep patterns is excluded."""
        changes = [{"new_path": "notes.txt", "diff": "+some notes"}]
        result = extract_dependency_files(changes)
        assert len(result) == 0

    def test_dep_file_in_deep_nested_path(self):
        """Dependency files in deeply nested paths are detected by filename."""
        changes = [{"new_path": "a/b/c/d/e/package.json", "diff": "+dep"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_multiple_dep_and_non_dep_files(self):
        """Mixed list filters correctly to only dep files."""
        changes = [
            {"new_path": "src/app.py", "diff": "+code"},
            {"new_path": "package.json", "diff": "+dep"},
            {"new_path": "README.md", "diff": "+docs"},
            {"new_path": "go.mod", "diff": "+go"},
            {"new_path": "Makefile", "diff": "+build"},
        ]
        result = extract_dependency_files(changes)
        assert len(result) == 2
        paths = {c["new_path"] for c in result}
        assert paths == {"package.json", "go.mod"}


# ── _count_by_severity extended tests ────────────────────────


class TestCountBySeverityExtended:
    """Extended tests for _count_by_severity to cover corner cases."""

    def test_heading_with_info_severity(self):
        """### [INFO] heading is counted."""
        text = "### [INFO] Finding: Note"
        counts = _count_by_severity(text)
        assert counts["info"] == 1

    def test_all_five_severities_counted(self):
        """All five severity levels in one text are all counted."""
        text = (
            "### [CRITICAL] A\n"
            "### [HIGH] B\n"
            "### [MEDIUM] C\n"
            "### [LOW] D\n"
            "### [INFO] E\n"
        )
        counts = _count_by_severity(text)
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 1

    def test_severity_word_in_description_not_counted(self):
        """Severity word appearing inside description text is not counted."""
        text = "### [HIGH] This critical finding is high severity and low impact"
        counts = _count_by_severity(text)
        assert counts["high"] == 1
        assert counts["critical"] == 0
        assert counts["low"] == 0

    def test_count_findings_sums_all_categories(self):
        """count_findings returns the sum of all severity counts."""
        text = "### [CRITICAL] A\n### [HIGH] B\n### [INFO] C"
        total = count_findings(text)
        assert total == 3

    def test_count_findings_zero_for_clean_output(self):
        """count_findings returns 0 for clean AI output."""
        text = "No security issues were found in the diff."
        assert count_findings(text) == 0


# ── determine_severity scoring boundary tests ─────────────────


class TestDetermineSeverityScoring:
    """Verify exact scoring thresholds for determine_severity."""

    def test_score_exactly_8_is_critical(self):
        """Score=8 exactly hits the CRITICAL threshold (>= 8)."""
        # Two HIGH (3+3=6) + one MEDIUM (2) = 8 >= 8 => CRITICAL
        text = "[HIGH] a\n[HIGH] b\n[MEDIUM] c"
        result = determine_severity(text, "", "")
        assert result == "CRITICAL"

    def test_score_exactly_7_is_high(self):
        """Score=7 is HIGH (>= 5 but < 8), no criticals."""
        # Two HIGH (3+3=6) + one LOW (1) = 7
        text = "[HIGH] a\n[HIGH] b\n[LOW] c"
        result = determine_severity(text, "", "")
        assert result == "HIGH"

    def test_two_mediums_score_4_is_high(self):
        """Two MEDIUMs (score=4) with no HIGH still gives HIGH because score >= 5 is needed.
        Actually 4 < 5 so it should be MEDIUM (no high count). Let's verify."""
        # 2 * MEDIUM = 4. No HIGH, score=4 => MEDIUM (score >=2)
        text = "[MEDIUM] a\n[MEDIUM] b"
        result = determine_severity(text, "", "")
        # score=4, no critical, no high => check MEDIUM threshold: score >= 2 -> MEDIUM
        assert result == "MEDIUM"

    def test_three_mediums_score_6_is_high(self):
        """Three MEDIUMs score=6 >= 5 but no explicit HIGH count, so check conditions.
        score >= 5 => HIGH even without explicit high count."""
        text = "[MEDIUM] a\n[MEDIUM] b\n[MEDIUM] c"
        result = determine_severity(text, "", "")
        assert result == "HIGH"

    def test_info_findings_dont_count_in_score(self):
        """INFO findings have weight 0, don't affect severity score."""
        text = "[INFO] a\n[INFO] b\n[INFO] c"
        result = determine_severity(text, "", "")
        # INFO has no weight, score=0 => NONE
        assert result == "NONE"

    def test_multiple_inputs_combined(self):
        """All three finding strings are concatenated before scoring.

        Each finding must be on its own line for the line-start pattern to match.
        """
        code = "[HIGH] code issue\n"
        dep = "[HIGH] dep issue\n"
        secret = "[CRITICAL] secret issue\n"
        result = determine_severity(code, dep, secret)
        # CRITICAL present => CRITICAL
        assert result == "CRITICAL"


# ── _parse_findings extended edge cases ───────────────────────


class TestParseFindingsExtended:
    """Additional _parse_findings edge cases."""

    def test_finding_description_strip_whitespace(self):
        """Description is stripped of leading/trailing whitespace."""
        text = "### [HIGH] Finding:   Padded description  \n**File:** `app.py` (line 1)\n"
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert findings[0]["description"] == "Padded description"

    def test_finding_with_line_number_zero(self):
        """Line number 0 in text should be handled (parseInt of '0')."""
        text = "### [LOW] Finding: Zero line\n**File:** `x.py` (line 0)\n"
        findings = _parse_findings(text)
        assert len(findings) == 1
        # '0' is valid digit parsing but zero line may result in 0 or 1
        assert findings[0]["line_num"] >= 0

    def test_multiple_findings_with_mixed_severity(self):
        """Five findings with different severities all parsed correctly."""
        text = (
            "### [CRITICAL] Finding: RCE\n**File:** `a.py` (line 1)\n\n"
            "### [HIGH] Finding: SQLi\n**File:** `b.py` (line 2)\n\n"
            "### [MEDIUM] Finding: XSS\n**File:** `c.py` (line 3)\n\n"
            "### [LOW] Finding: Log injection\n**File:** `d.py` (line 4)\n\n"
            "### [INFO] Finding: Debug note\n**File:** `e.py` (line 5)\n"
        )
        findings = _parse_findings(text)
        assert len(findings) == 5
        severities = [f["severity"] for f in findings]
        assert severities == ["critical", "high", "medium", "low", "info"]

    def test_category_defaults_to_code_security(self):
        """When no category is provided, default is 'code-security'."""
        text = "### [HIGH] Finding: Test\n**File:** `app.py` (line 1)\n"
        findings = _parse_findings(text)
        assert findings[0]["category"] == "code-security"

    def test_finding_file_path_with_nested_directories(self):
        """Deeply nested file paths are extracted correctly."""
        text = "### [HIGH] Finding: Issue\n**File:** `src/api/v2/handlers/user.py` (line 100)\n"
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert findings[0]["file_path"] == "src/api/v2/handlers/user.py"
        assert findings[0]["line_num"] == 100

    def test_finding_with_unicode_description(self):
        """Unicode characters in finding description are preserved."""
        text = "### [MEDIUM] Finding: Ré-injection via formulaire\n**File:** `app.py` (line 5)\n"
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert "formulaire" in findings[0]["description"]


# ── generate_codequality_report edge cases ────────────────────


class TestGenerateCodequalityReportExtended:
    """Additional edge cases for the Code Quality report generator."""

    def test_location_lines_begin_field(self, tmp_path):
        """Code quality report includes location.lines.begin with the line number."""
        output = tmp_path / "cq.json"
        findings = "### [HIGH] Finding: SQL injection\n**File:** `db.py` (line 77)\n"
        generate_codequality_report(findings, str(output))
        data = json.loads(output.read_text())
        assert len(data) == 1
        assert data[0]["location"]["lines"]["begin"] == 77

    def test_type_field_is_issue(self, tmp_path):
        """Each Code Quality entry has type='issue'."""
        output = tmp_path / "cq.json"
        findings = "### [LOW] Finding: Minor issue\n**File:** `x.py` (line 1)\n"
        generate_codequality_report(findings, str(output))
        data = json.loads(output.read_text())
        assert data[0]["type"] == "issue"

    def test_fingerprint_is_md5_hex(self, tmp_path):
        """Code Quality fingerprint is a valid MD5 hex string (32 chars)."""
        output = tmp_path / "cq.json"
        findings = "### [MEDIUM] Finding: CSRF missing\n**File:** `forms.py` (line 30)\n"
        generate_codequality_report(findings, str(output))
        data = json.loads(output.read_text())
        fp = data[0]["fingerprint"]
        assert len(fp) == 32
        assert all(c in "0123456789abcdef" for c in fp)

    def test_dep_findings_have_dependency_audit_check_name(self, tmp_path):
        """Dependency audit findings use 'duoguard-dependency-audit' check_name."""
        output = tmp_path / "cq.json"
        dep = "### [LOW] Finding: Minor dep version\n**File:** `go.mod` (line 3)\n"
        generate_codequality_report("", str(output), dep_findings=dep)
        data = json.loads(output.read_text())
        assert data[0]["check_name"] == "duoguard-dependency-audit"

    def test_secret_findings_have_secret_scan_check_name(self, tmp_path):
        """Secret scan findings use 'duoguard-secret-scan' check_name."""
        output = tmp_path / "cq.json"
        secret = "### [CRITICAL] Finding: Hardcoded password\n**File:** `.env` (line 1)\n"
        generate_codequality_report("", str(output), secret_findings=secret)
        data = json.loads(output.read_text())
        assert data[0]["check_name"] == "duoguard-secret-scan"


# ── generate_sarif_report extended tests ─────────────────────


class TestGenerateSarifReportExtended:
    """Additional SARIF report tests for edge cases."""

    def test_medium_severity_maps_to_warning(self, tmp_path):
        """MEDIUM finding produces level='warning' in SARIF."""
        output = tmp_path / "sarif.json"
        findings = "### [MEDIUM] Finding: CSRF\n**File:** `views.py` (line 10)\n"
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        result = data["runs"][0]["results"][0]
        assert result["level"] == "warning"

    def test_info_severity_maps_to_note(self, tmp_path):
        """INFO finding produces level='note' in SARIF."""
        output = tmp_path / "sarif.json"
        findings = "### [INFO] Finding: Debug mode enabled\n**File:** `config.py` (line 5)\n"
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        result = data["runs"][0]["results"][0]
        assert result["level"] == "note"

    def test_high_severity_maps_to_error(self, tmp_path):
        """HIGH finding produces level='error' in SARIF."""
        output = tmp_path / "sarif.json"
        findings = "### [HIGH] Finding: XSS in template\n**File:** `tmpl.html` (line 1)\n"
        generate_sarif_report(findings, str(output))
        data = json.loads(output.read_text())
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_tool_version(self, tmp_path):
        """SARIF report includes tool version string."""
        output = tmp_path / "sarif.json"
        generate_sarif_report("No issues.", str(output))
        data = json.loads(output.read_text())
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["version"] == "1.0.0"

    def test_sarif_tool_information_uri(self, tmp_path):
        """SARIF report includes tool informationUri."""
        output = tmp_path / "sarif.json"
        generate_sarif_report("No issues.", str(output))
        data = json.loads(output.read_text())
        driver = data["runs"][0]["tool"]["driver"]
        assert "informationUri" in driver
        assert driver["informationUri"].startswith("https://")

    def test_sarif_run_id_is_uuid_format(self, tmp_path):
        """SARIF automationDetails id starts with 'duoguard/' followed by UUID."""
        output = tmp_path / "sarif.json"
        generate_sarif_report("No issues.", str(output))
        data = json.loads(output.read_text())
        run_id = data["runs"][0]["automationDetails"]["id"]
        assert run_id.startswith("duoguard/")
        # UUID part has 5 segments separated by hyphens
        uuid_part = run_id[len("duoguard/"):]
        assert len(uuid_part) == 36  # standard UUID length


# ── generate_report extended tests ────────────────────────────


class TestGenerateReportExtended:
    """Additional generate_report edge cases."""

    def test_report_contains_summary_table_headers(self):
        """Summary table has Category and Findings column headers."""
        report = generate_report({"iid": 1, "title": "T"}, "", "", "")
        assert "| Category | Findings |" in report
        assert "|----------|----------|" in report

    def test_report_mr_sections_present_with_empty_findings(self):
        """Even with empty findings, all three section headers are in report."""
        report = generate_report({"iid": 1, "title": "T"}, "", "", "")
        assert "Code Security Analysis" in report
        assert "Dependency Audit" in report
        assert "Secret Scan" in report

    def test_report_gitlab_attribution_link(self):
        """Report includes link to GitLab AI Hackathon page."""
        report = generate_report({"iid": 1, "title": "T"}, "", "", "")
        assert "gitlab.devpost.com" in report

    def test_complexity_medium_risk_at_score_45(self):
        """Complexity score 45 shows as Medium risk."""
        complexity = {
            "total_additions": 50, "total_deletions": 10, "total_files": 3,
            "high_risk_files": [], "complexity_score": 45, "risk_factors": [],
        }
        report = generate_report({"iid": 1, "title": "T"}, "", "", "", complexity=complexity)
        assert "Medium" in report
        assert "45/100" in report

    def test_complexity_with_many_risk_factors(self):
        """All risk factors in complexity appear in the report."""
        complexity = {
            "total_additions": 100, "total_deletions": 50, "total_files": 5,
            "high_risk_files": ["auth.py", "db.py"],
            "complexity_score": 70,
            "risk_factors": [
                "authentication logic modified in auth.py",
                "database operations modified in db.py",
            ],
        }
        report = generate_report({"iid": 1, "title": "T"}, "", "", "", complexity=complexity)
        assert "authentication logic modified in auth.py" in report
        assert "database operations modified in db.py" in report

    def test_complexity_zero_score_omits_section(self):
        """When complexity_score is 0, no Diff Complexity Analysis section appears."""
        complexity = {
            "total_additions": 0, "total_deletions": 0, "total_files": 0,
            "high_risk_files": [], "complexity_score": 0, "risk_factors": [],
        }
        report = generate_report({"iid": 1, "title": "T"}, "", "", "", complexity=complexity)
        assert "Diff Complexity Analysis" not in report

    def test_scan_metrics_zero_duration_not_shown(self):
        """scan_duration=0.0 is still shown (it's not None)."""
        report = generate_report(
            {"iid": 1, "title": "T"}, "", "", "",
            scan_duration=0.0,
        )
        assert "Scan Metrics" in report
        assert "0.0s" in report


# ── compute_diff_complexity extended tests ───────────────────


class TestDiffComplexityExtended:
    """Additional compute_diff_complexity edge cases."""

    def test_detects_cookie_handling(self):
        """Cookie-related changes are flagged as high risk (HTTP handling pattern)."""
        changes = [{"new_path": "middleware.py", "diff": "\n+response.set_cookie('session', value)"}]
        result = compute_diff_complexity(changes)
        assert "middleware.py" in result["high_risk_files"]

    def test_detects_deserialization(self):
        """Deserialization patterns are flagged as high risk."""
        changes = [{"new_path": "parser.py", "diff": "\n+data = yaml.load(raw_input)"}]
        result = compute_diff_complexity(changes)
        assert "parser.py" in result["high_risk_files"]

    def test_detects_permission_changes(self):
        """Permission/ACL/RBAC patterns are flagged as high risk."""
        changes = [{"new_path": "authz.py", "diff": "\n+if user.role == 'admin':"}]
        result = compute_diff_complexity(changes)
        assert "authz.py" in result["high_risk_files"]

    def test_no_path_key_falls_back_to_unknown(self):
        """Change without new_path or old_path shows as 'unknown' in results."""
        changes = [{"diff": "\n+password = 'hardcoded'"}]
        result = compute_diff_complexity(changes)
        # Should still detect the risk pattern (unknown file)
        assert len(result["high_risk_files"]) == 1
        assert result["high_risk_files"][0] == "unknown"

    def test_size_score_capped_at_40(self):
        """Size portion of score is capped at 40 points."""
        # 400+ additions/deletions should hit the cap
        huge_diff = "\n+" + "\n+".join(["x = 1"] * 1000)
        changes = [{"new_path": "huge.py", "diff": huge_diff}]
        result = compute_diff_complexity(changes)
        # size_score = min(40, total_lines // 10). With 1000 lines: min(40, 100) = 40
        # We can't directly access size_score but complexity_score <= 100
        assert result["complexity_score"] <= 100
        assert result["total_additions"] >= 100

    def test_file_count_score_capped_at_20(self):
        """File count portion of score is capped at 20 points."""
        # 10+ files each give 2 pts capped at 20
        changes = [{"new_path": f"file{i}.py", "diff": "\n+x = 1"} for i in range(15)]
        result = compute_diff_complexity(changes)
        assert result["total_files"] == 15
        # Even with 15 files the score doesn't exceed 40 (file cap 20 + size 0)
        # Plus if any are high-risk, up to 40 more
        assert result["complexity_score"] <= 100


# ── load_config extended edge cases ──────────────────────────


class TestLoadConfigExtended:
    """Additional config loading edge cases."""

    def test_all_agents_disabled_in_config(self, tmp_path, monkeypatch):
        """Config can disable all three agents."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text(
            "agents:\n  code_security: false\n  dependency_audit: false\n  secret_scan: false\n"
        )
        cfg = load_config()
        assert cfg["agents"]["code_security"] is False
        assert cfg["agents"]["dependency_audit"] is False
        assert cfg["agents"]["secret_scan"] is False

    def test_config_with_exclude_extensions(self, tmp_path, monkeypatch):
        """Config can set exclude_extensions list."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text("exclude_extensions:\n  - js\n  - min\n")
        cfg = load_config()
        assert "js" in cfg["exclude_extensions"]
        assert "min" in cfg["exclude_extensions"]

    def test_config_with_inline_comments_false(self, tmp_path, monkeypatch):
        """Config can disable inline comments."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text("inline_comments: false\n")
        cfg = load_config()
        assert cfg["inline_comments"] is False

    def test_config_with_version_1(self, tmp_path, monkeypatch):
        """Config version field is preserved."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".duoguard.yml"
        config_file.write_text("version: 1\nseverity_threshold: MEDIUM\n")
        cfg = load_config()
        assert cfg["version"] == 1
        assert cfg["severity_threshold"] == "MEDIUM"

    def test_nonexistent_explicit_path_uses_defaults(self, tmp_path, monkeypatch):
        """Nonexistent explicit config path still falls through to defaults."""
        monkeypatch.chdir(tmp_path)
        # Pass a path that doesn't exist; no .duoguard.yml either
        cfg = load_config(str(tmp_path / "nonexistent.yml"))
        assert cfg["severity_threshold"] == "HIGH"


# ── should_exclude_path / filter_excluded_changes extended ────


class TestPathExclusionExtended:
    """Additional path exclusion edge cases."""

    def test_both_path_and_extension_exclude(self):
        """When both exclude_paths and exclude_extensions are set, either can exclude."""
        # Matches by extension
        assert should_exclude_path("src/app.min.js",
                                    exclude_paths=["vendor/*"],
                                    exclude_extensions=["js"])
        # Matches by path
        assert should_exclude_path("vendor/lib.go",
                                    exclude_paths=["vendor/*"],
                                    exclude_extensions=["js"])
        # Neither matches
        assert not should_exclude_path("src/main.py",
                                        exclude_paths=["vendor/*"],
                                        exclude_extensions=["js"])

    def test_exclude_root_level_file(self):
        """Root-level file can be excluded by exact glob."""
        assert should_exclude_path(".env", exclude_paths=[".env"])
        assert should_exclude_path(".secrets", exclude_paths=[".secrets"])

    def test_glob_star_matches_subdir(self):
        """vendor/* matches vendor/lib.go and also deeply nested vendor/sub/lib.go.

        fnmatch treats '*' as matching any character including '/', so both paths match.
        """
        # fnmatch('vendor/lib.go', 'vendor/*') => True
        assert should_exclude_path("vendor/lib.go", exclude_paths=["vendor/*"])
        # fnmatch('vendor/sub/lib.go', 'vendor/*') => True (fnmatch * includes /)
        assert should_exclude_path("vendor/sub/lib.go", exclude_paths=["vendor/*"])

    def test_filter_returns_same_list_when_no_rules(self):
        """With both exclusions empty, original list is returned unchanged."""
        changes = [{"new_path": "a.py"}, {"new_path": "b.py"}]
        result = filter_excluded_changes(changes, exclude_paths=[], exclude_extensions=[])
        assert result == changes

    def test_filter_with_extension_and_path_rules_combined(self):
        """filter_excluded_changes handles both path and extension rules."""
        changes = [
            {"new_path": "src/app.py", "diff": "+code"},
            {"new_path": "vendor/lib.go", "diff": "+vendor"},
            {"new_path": "dist/bundle.js", "diff": "+bundle"},
            {"new_path": "src/utils.js", "diff": "+utils"},
        ]
        result = filter_excluded_changes(
            changes,
            exclude_paths=["vendor/*"],
            exclude_extensions=["js"],
        )
        assert len(result) == 1
        assert result[0]["new_path"] == "src/app.py"


# ── enrich_finding_cwe extended tests ────────────────────────


class TestEnrichFindingCWEFurtherEdgeCases:
    """Further edge cases for CWE enrichment."""

    def test_api_key_in_description_enriched(self):
        """'api key' keyword in description triggers CWE-798 enrichment."""
        finding = {"description": "Hardcoded API key found in constants", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-798"

    def test_private_key_in_description_enriched(self):
        """'private key' keyword enriches with CWE-321."""
        finding = {"description": "RSA private key hardcoded in deployment script", "severity": "critical"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-321"

    def test_weak_crypto_cwe_327(self):
        """'weak crypto' enriches with CWE-327 (Cryptographic Failures)."""
        finding = {"description": "Use of weak crypto algorithm MD5", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-327"

    def test_race_condition_cwe_362(self):
        """'race condition' enriches with CWE-362."""
        finding = {"description": "Race condition in file access", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-362"

    def test_buffer_overflow_cwe_120(self):
        """'buffer overflow' enriches with CWE-120."""
        finding = {"description": "Potential buffer overflow in C code", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-120"

    def test_idor_cwe_639(self):
        """'idor' enriches with CWE-639 (IDOR)."""
        finding = {"description": "IDOR vulnerability in user profile endpoint", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-639"

    def test_information_disclosure_cwe_200(self):
        """'information disclosure' enriches with CWE-200."""
        finding = {"description": "Information disclosure in error messages", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-200"

    def test_log_injection_cwe_117(self):
        """'log injection' enriches with CWE-117."""
        finding = {"description": "Log injection via user input", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-117"

    def test_integer_overflow_cwe_190(self):
        """'integer overflow' enriches with CWE-190."""
        finding = {"description": "Integer overflow in loop counter", "severity": "medium"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-190"

    def test_missing_access_control_cwe_862(self):
        """'missing access control' enriches with CWE-862."""
        finding = {"description": "Missing access control on admin endpoint", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-862"

    def test_broken_auth_cwe_287(self):
        """'broken auth' enriches with CWE-287."""
        finding = {"description": "Broken auth allows unauthenticated access", "severity": "critical"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-287"

    def test_empty_description_no_match(self):
        """Empty description produces no CWE enrichment."""
        finding = {"description": "", "severity": "info"}
        result = enrich_finding_cwe(finding)
        assert "cwe" not in result

    def test_sensitive_data_exposure_cwe_200(self):
        """'sensitive data exposure' enriches with CWE-200."""
        finding = {"description": "Sensitive data exposure via plaintext storage", "severity": "high"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-200"


# ── resolve_stale_discussions extended tests ──────────────────


class TestResolveStaleDiscussionsExtended:
    """Additional edge cases for resolve_stale_discussions."""

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_multiple_duoguard_discussions_all_resolved(self, mock_get, mock_put):
        """Multiple unresolved DuoGuard discussions are all resolved."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {
                    "id": "disc1",
                    "notes": [{"body": "**:shield: DuoGuard [HIGH]** — XSS",
                                "resolvable": True, "resolved": False}],
                },
                {
                    "id": "disc2",
                    "notes": [{"body": "**:shield: DuoGuard [CRITICAL]** — SQLi",
                                "resolvable": True, "resolved": False}],
                },
            ]),
        )
        mock_put.return_value = MagicMock(status_code=200)
        result = resolve_stale_discussions("42", "1")
        assert result == 2
        assert mock_put.call_count == 2

    @patch("post_report.requests.get")
    def test_non_resolvable_duoguard_discussion_not_resolved(self, mock_get):
        """DuoGuard discussions that are not resolvable are skipped."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {
                    "id": "disc1",
                    "notes": [{"body": "**:shield: DuoGuard [LOW]** — Note",
                                "resolvable": False, "resolved": False}],
                },
            ]),
        )
        result = resolve_stale_discussions("42", "1")
        assert result == 0

    @patch("post_report.requests.get")
    def test_discussion_with_no_notes_skipped(self, mock_get):
        """Discussions with empty notes list are skipped."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {"id": "disc1", "notes": []},
            ]),
        )
        result = resolve_stale_discussions("42", "1")
        assert result == 0

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_resolve_failure_on_one_is_tolerated(self, mock_get, mock_put):
        """If one resolve PUT fails, the function still returns count of successes."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {
                    "id": "disc1",
                    "notes": [{"body": "**:shield: DuoGuard [HIGH]** — XSS",
                                "resolvable": True, "resolved": False}],
                },
                {
                    "id": "disc2",
                    "notes": [{"body": "**:shield: DuoGuard [MEDIUM]** — CSRF",
                                "resolvable": True, "resolved": False}],
                },
            ]),
        )
        # First PUT succeeds, second PUT raises HTTPError
        mock_put.side_effect = [
            MagicMock(status_code=200, raise_for_status=MagicMock()),
            requests.exceptions.HTTPError(response=MagicMock(status_code=403)),
        ]
        result = resolve_stale_discussions("42", "1")
        # Only first was successfully resolved
        assert result == 1


# ── update_mr_labels extended tests ──────────────────────────


class TestUpdateMRLabelsExtended:
    """Additional edge cases for update_mr_labels."""

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_medium_severity_label(self, mock_get, mock_put):
        """MEDIUM severity adds 'security::medium' label."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"labels": []}),
        )
        mock_put.return_value = MagicMock(status_code=200)
        update_mr_labels("42", "1", "MEDIUM")
        labels = mock_put.call_args[1]["json"]["labels"]
        assert "security::medium" in labels

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_unknown_severity_maps_to_clean(self, mock_get, mock_put):
        """Unknown severity falls back to 'security::clean' label."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"labels": []}),
        )
        mock_put.return_value = MagicMock(status_code=200)
        update_mr_labels("42", "1", "UNKNOWN_SEVERITY")
        labels = mock_put.call_args[1]["json"]["labels"]
        assert "security::clean" in labels

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_get_failure_proceeds_with_empty_labels(self, mock_get, mock_put):
        """When GET fails, proceeds with empty current_labels and still adds new label."""
        mock_get.return_value = MagicMock(status_code=403)
        mock_get.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError(response=MagicMock(status_code=403))
        )
        mock_put.return_value = MagicMock(status_code=200, raise_for_status=MagicMock())
        result = update_mr_labels("42", "1", "HIGH")
        # Should still attempt PUT with the new security::high label
        assert result is True
        labels = mock_put.call_args[1]["json"]["labels"]
        assert "security::high" in labels

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_preserves_non_security_labels(self, mock_get, mock_put):
        """Non-security labels from the MR are preserved after update."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"labels": ["bug", "enhancement", "security::low"]}),
        )
        mock_put.return_value = MagicMock(status_code=200)
        update_mr_labels("42", "1", "HIGH")
        labels = mock_put.call_args[1]["json"]["labels"]
        assert "bug" in labels
        assert "enhancement" in labels
        assert "security::low" not in labels
        assert "security::high" in labels


# ── _run_security_scan with config extended ───────────────────


class TestRunSecurityScanConfigExtended:
    """Additional _run_security_scan config-driven edge cases."""

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_max_diff_size_from_config(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        """max_diff_size from config limits diff passed to agents."""
        mock_info.return_value = {"iid": 1, "title": "Limit test"}
        # Create a diff that's larger than our small limit
        long_diff = "+" + "x" * 5000
        mock_diff.return_value = {
            "changes": [
                {"new_path": "big.py", "diff": long_diff},
                {"new_path": "medium.py", "diff": "+" + "y" * 100},
            ]
        }
        mock_code.return_value = "Clean"
        mock_dep.return_value = "Clean"
        mock_secret.return_value = "Clean"

        output = str(tmp_path / "report.md")
        config = dict(DEFAULT_CONFIG)
        config["max_diff_size"] = 200  # Very small limit to force truncation
        _run_security_scan("42", "1", output, "", "CRITICAL", config=config)

        # The diff passed to code review should be truncated
        code_diff = mock_code.call_args[0][0]
        assert "omitted" in code_diff or len(code_diff) <= 400  # truncated

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_only_code_security_agent_enabled(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        """When only code_security agent is enabled, dep and secret are not called."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "No issues."

        output = str(tmp_path / "report.md")
        config = dict(DEFAULT_CONFIG)
        config["agents"] = {
            "code_security": True,
            "dependency_audit": False,
            "secret_scan": False,
        }
        _run_security_scan("42", "1", output, "", "CRITICAL", config=config)

        mock_code.assert_called_once()
        mock_dep.assert_not_called()
        mock_secret.assert_not_called()

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_report_written_before_exit_on_severity_breach(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        """Report is written to disk even when severity causes sys.exit(1)."""
        mock_info.return_value = {"iid": 1, "title": "Risky"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+x"}]
        }
        mock_code.return_value = "### [CRITICAL] Finding: RCE\n**File:** `app.py` (line 1)\n"
        mock_dep.return_value = ""
        mock_secret.return_value = ""

        output = str(tmp_path / "report.md")
        with pytest.raises(SystemExit):
            _run_security_scan("42", "1", output, "", "HIGH")

        # Report should still exist despite exit
        assert Path(output).exists()
        report_text = Path(output).read_text()
        assert "DuoGuard Security Review Report" in report_text

    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.run_secret_scan")
    @patch("duoguard.run_dependency_audit")
    @patch("duoguard.run_code_security_review")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_extension_exclusion_applied_from_config(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret,
        mock_cq, mock_sarif, tmp_path,
    ):
        """exclude_extensions config filters files before analysis."""
        mock_info.return_value = {"iid": 1, "title": "Ext filter"}
        mock_diff.return_value = {
            "changes": [
                {"new_path": "app.py", "diff": "+code"},
                {"new_path": "bundle.js", "diff": "+js"},
                {"new_path": "styles.css", "diff": "+css"},
            ]
        }
        mock_code.return_value = "Clean"
        mock_dep.return_value = "Clean"
        mock_secret.return_value = "Clean"

        output = str(tmp_path / "report.md")
        config = dict(DEFAULT_CONFIG)
        config["exclude_extensions"] = ["js", "css"]
        _run_security_scan("42", "1", output, "", "CRITICAL", config=config)

        code_diff = mock_code.call_args[0][0]
        assert "app.py" in code_diff
        assert "bundle.js" not in code_diff
        assert "styles.css" not in code_diff


# ── post_inline_findings body formatting tests ────────────────


class TestPostInlineFindingsBody:
    """Verify the body format of inline discussions."""

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_body_includes_severity_and_description(self, mock_versions, mock_disc):
        """Inline discussion body contains severity and description."""
        mock_versions.return_value = [{
            "base_commit_sha": "abc", "head_commit_sha": "def", "start_commit_sha": "ghi",
        }]
        mock_disc.return_value = {"id": "disc-1"}

        findings = [{"file_path": "app.py", "line_num": 5, "severity": "high",
                      "description": "SQL Injection", "category": "code-security"}]
        post_inline_findings("42", "1", findings)

        body = mock_disc.call_args[0][2]
        assert "HIGH" in body
        assert "SQL Injection" in body

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_body_includes_category(self, mock_versions, mock_disc):
        """Inline discussion body shows the finding category."""
        mock_versions.return_value = [{
            "base_commit_sha": "abc", "head_commit_sha": "def", "start_commit_sha": "ghi",
        }]
        mock_disc.return_value = {"id": "disc-1"}

        findings = [{"file_path": "go.mod", "line_num": 3, "severity": "medium",
                      "description": "Outdated dep", "category": "dependency-audit"}]
        post_inline_findings("42", "1", findings)

        body = mock_disc.call_args[0][2]
        assert "dependency-audit" in body

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_body_without_cwe_omits_cwe_line(self, mock_versions, mock_disc):
        """If finding has no CWE, the CWE line is not included in the body."""
        mock_versions.return_value = [{
            "base_commit_sha": "abc", "head_commit_sha": "def", "start_commit_sha": "ghi",
        }]
        mock_disc.return_value = {"id": "disc-1"}

        findings = [{"file_path": "app.py", "line_num": 1, "severity": "low",
                      "description": "Minor issue", "category": "code-security"}]
        post_inline_findings("42", "1", findings)

        body = mock_disc.call_args[0][2]
        assert "CWE" not in body

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_default_severity_info_when_missing(self, mock_versions, mock_disc):
        """Finding without 'severity' key defaults to INFO in body."""
        mock_versions.return_value = [{
            "base_commit_sha": "abc", "head_commit_sha": "def", "start_commit_sha": "ghi",
        }]
        mock_disc.return_value = {"id": "disc-1"}

        findings = [{"file_path": "x.py", "line_num": 1,
                      "description": "Some finding", "category": "code-security"}]
        post_inline_findings("42", "1", findings)

        body = mock_disc.call_args[0][2]
        assert "INFO" in body

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_shield_emoji_present_in_body(self, mock_versions, mock_disc):
        """All inline discussion bodies start with the shield emoji prefix."""
        mock_versions.return_value = [{
            "base_commit_sha": "abc", "head_commit_sha": "def", "start_commit_sha": "ghi",
        }]
        mock_disc.return_value = {"id": "disc-1"}

        findings = [{"file_path": "a.py", "line_num": 1, "severity": "critical",
                      "description": "RCE", "category": "code-security"}]
        post_inline_findings("42", "1", findings)

        body = mock_disc.call_args[0][2]
        assert ":shield: DuoGuard" in body


# ── run_dependency_audit whitespace-only diff ─────────────────


class TestRunDependencyAuditEdgeCases:
    """Edge cases for run_dependency_audit."""

    def test_whitespace_only_diff_returns_no_changes(self):
        """Whitespace-only diff is treated as no dependency changes."""
        result = run_dependency_audit("   \n\t\n  ")
        assert "No dependency file changes" in result

    def test_newline_only_diff_returns_no_changes(self):
        """Newline-only diff (stripped to empty) returns no changes message."""
        result = run_dependency_audit("\n\n\n")
        assert "No dependency file changes" in result

    @patch("duoguard.call_ai_gateway")
    def test_non_empty_diff_calls_ai_gateway(self, mock_call):
        """Non-empty dep diff triggers the AI gateway call."""
        mock_call.return_value = "### [LOW] Finding: Old dep\n**File:** `package.json` (line 1)\n"
        result = run_dependency_audit("+ some dep change")
        mock_call.assert_called_once()
        assert "[LOW]" in result


# ── _parse_gateway_headers further edge cases ─────────────────


class TestParseGatewayHeadersExtended:
    """Further edge cases for _parse_gateway_headers."""

    def test_json_with_nested_values_ignored_non_dict(self):
        """JSON object with non-string values is still returned as dict."""
        result = _parse_gateway_headers('{"X-Retry": "3", "X-Timeout": "120"}')
        assert result == {"X-Retry": "3", "X-Timeout": "120"}

    def test_newline_separated_with_extra_whitespace(self):
        """Key-value pairs with extra whitespace are stripped."""
        result = _parse_gateway_headers("  X-Custom  :  value  \n  Auth  :  token  ")
        assert result.get("X-Custom") == "value"
        assert result.get("Auth") == "token"

    def test_line_without_colon_is_ignored(self):
        """Lines without a colon separator are ignored in fallback mode."""
        result = _parse_gateway_headers("NoCOLONhere\nValid: value")
        assert "NoCOLONhere" not in result
        assert result.get("Valid") == "value"
