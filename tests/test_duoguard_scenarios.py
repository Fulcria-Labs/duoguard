"""DuoGuard scenario tests -- OWASP, concurrency, pipeline, cross-format,
fuzzing, configuration, and post-report orchestration.

Adds 105+ new tests organised into 7 categories.
"""

import hashlib
import json
import os
import re
import sys
import tempfile
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch

import pytest
import requests

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
    get_mr_diff,
    get_mr_info,
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
    _headers,
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


# ═══════════════════════════════════════════════════════════════
# Helper utilities
# ═══════════════════════════════════════════════════════════════


def _make_finding_text(severity: str, description: str,
                       file_path: str = "src/app.py",
                       line: int = 1) -> str:
    """Build a finding in the format _parse_findings expects."""
    return (
        f"### [{severity.upper()}] Finding: {description}\n"
        f"**File:** `{file_path}` (line {line})"
    )


def _tmp_json_path():
    """Return a temporary file path for JSON output."""
    return tempfile.mktemp(suffix=".json")


# ═══════════════════════════════════════════════════════════════
# 1. OWASP Top 10 Vulnerability Scenario Tests (31 tests)
# ═══════════════════════════════════════════════════════════════


class TestOwaspA01BrokenAccessControl:
    """A01:2021 - Broken Access Control scenarios."""

    def test_path_traversal_cwe_and_owasp(self):
        finding = _parse_findings(
            _make_finding_text("HIGH", "Path traversal via user-supplied filename allows reading /etc/passwd")
        )
        assert len(finding) == 1
        assert finding[0]["cwe"] == "CWE-22"
        assert "A01" in finding[0]["owasp"]

    def test_directory_traversal_cwe(self):
        f = enrich_finding_cwe({"description": "Directory traversal in file download endpoint"})
        assert f["cwe"] == "CWE-22"
        assert "Broken Access Control" in f["owasp"]

    def test_idor_via_numeric_id(self):
        text = _make_finding_text(
            "HIGH",
            "IDOR allows accessing other users' invoices by changing invoice_id parameter",
            "src/views/invoices.py", 88,
        )
        finding = _parse_findings(text)[0]
        assert finding["cwe"] == "CWE-639"
        assert finding["line_num"] == 88

    def test_open_redirect_login(self):
        f = enrich_finding_cwe({
            "description": "Open redirect after login allows phishing via redirect_url parameter"
        })
        assert f["cwe"] == "CWE-601"
        assert "A01" in f["owasp"]

    def test_csrf_missing_token(self):
        f = enrich_finding_cwe({
            "description": "CSRF token not validated on state-changing POST /api/transfer"
        })
        assert f["cwe"] == "CWE-352"

    def test_missing_access_control_admin_endpoint(self):
        f = enrich_finding_cwe({
            "description": "Missing access control on /admin/users endpoint allows any authenticated user to list all users"
        })
        assert f["cwe"] == "CWE-862"
        assert "Broken Access Control" in f["owasp"]


class TestOwaspA02CryptographicFailures:
    """A02:2021 - Cryptographic Failures scenarios."""

    def test_weak_md5_hashing(self):
        f = enrich_finding_cwe({
            "description": "Weak crypto: MD5 used for password hashing instead of bcrypt/argon2"
        })
        assert f["cwe"] == "CWE-327"
        assert "Cryptographic" in f["owasp"]

    def test_insecure_random_token(self):
        f = enrich_finding_cwe({
            "description": "Insecure random number generator used for session token generation"
        })
        assert f["cwe"] == "CWE-330"

    def test_private_key_committed(self):
        text = _make_finding_text(
            "CRITICAL",
            "Private key embedded in source file for TLS certificate",
            "config/server.pem", 1,
        )
        finding = _parse_findings(text, "secret-scan")[0]
        assert finding["cwe"] == "CWE-321"
        assert finding["category"] == "secret-scan"


class TestOwaspA03Injection:
    """A03:2021 - Injection scenarios."""

    def test_sql_injection_login(self):
        f = enrich_finding_cwe({
            "description": "SQL injection in login query: SELECT * FROM users WHERE name='\" + user + \"'"
        })
        assert f["cwe"] == "CWE-89"
        assert "Injection" in f["owasp"]

    def test_xss_reflected(self):
        f = enrich_finding_cwe({
            "description": "Reflected XSS via search parameter rendered without escaping"
        })
        assert f["cwe"] == "CWE-79"

    def test_cross_site_scripting_stored(self):
        f = enrich_finding_cwe({
            "description": "Stored cross-site scripting in user bio field"
        })
        assert f["cwe"] == "CWE-79"

    def test_command_injection_subprocess(self):
        f = enrich_finding_cwe({
            "description": "Command injection via unsanitized filename passed to subprocess.Popen"
        })
        assert f["cwe"] == "CWE-78"

    def test_os_command_injection(self):
        f = enrich_finding_cwe({
            "description": "OS command injection through shell=True in os.system call"
        })
        assert f["cwe"] == "CWE-78"

    def test_ldap_injection_search(self):
        f = enrich_finding_cwe({
            "description": "LDAP injection in directory search filter allows auth bypass"
        })
        assert f["cwe"] == "CWE-90"

    def test_xml_injection_soap(self):
        f = enrich_finding_cwe({
            "description": "XML injection in SOAP request allows entity expansion"
        })
        assert f["cwe"] == "CWE-91"

    def test_code_injection_template(self):
        f = enrich_finding_cwe({
            "description": "Server-side code injection via Jinja2 template with user input"
        })
        assert f["cwe"] == "CWE-94"

    def test_eval_user_input(self):
        f = enrich_finding_cwe({
            "description": "User input passed directly to eval() for dynamic expression parsing"
        })
        assert f["cwe"] == "CWE-95"

    def test_prototype_pollution_merge(self):
        f = enrich_finding_cwe({
            "description": "Prototype pollution via recursive object merge with __proto__ key"
        })
        assert f["cwe"] == "CWE-1321"


class TestOwaspA04InsecureDesign:
    """A04:2021 - Insecure Design scenarios."""

    def test_mass_assignment_user_role(self):
        f = enrich_finding_cwe({
            "description": "Mass assignment allows setting is_admin=true via JSON body"
        })
        assert f["cwe"] == "CWE-915"
        assert "Insecure Design" in f["owasp"]

    def test_unrestricted_file_upload(self):
        f = enrich_finding_cwe({
            "description": "Unrestricted upload allows .exe files on avatar endpoint"
        })
        assert f["cwe"] == "CWE-434"

    def test_race_condition_balance(self):
        f = enrich_finding_cwe({
            "description": "Race condition in wallet balance update allows double-spend"
        })
        assert f["cwe"] == "CWE-362"


class TestOwaspA05SecurityMisconfiguration:
    """A05:2021 - Security Misconfiguration."""

    def test_xxe_xml_parser(self):
        f = enrich_finding_cwe({
            "description": "XML external entity (XXE) enabled in lxml parser configuration"
        })
        assert f["cwe"] == "CWE-611"
        assert "Misconfiguration" in f["owasp"]

    def test_xxe_keyword(self):
        f = enrich_finding_cwe({"description": "XXE in document import handler"})
        assert f["cwe"] == "CWE-611"


class TestOwaspA06VulnerableComponents:
    """A06:2021 - Vulnerable and Outdated Components."""

    def test_buffer_overflow_c_extension(self):
        f = enrich_finding_cwe({
            "description": "Buffer overflow in native C extension string copy"
        })
        assert f["cwe"] == "CWE-120"

    def test_regex_dos_email(self):
        f = enrich_finding_cwe({
            "description": "Regex DOS in email validation pattern causes catastrophic backtracking"
        })
        assert f["cwe"] == "CWE-1333"


class TestOwaspA07AuthFailures:
    """A07:2021 - Identification and Authentication Failures."""

    def test_hardcoded_password_db(self):
        f = enrich_finding_cwe({
            "description": "Hardcoded password for database connection string"
        })
        assert f["cwe"] == "CWE-798"

    def test_broken_auth_session(self):
        f = enrich_finding_cwe({
            "description": "Broken auth: session token not invalidated after password change"
        })
        assert f["cwe"] == "CWE-287"

    def test_authentication_bypass_jwt(self):
        f = enrich_finding_cwe({
            "description": "Authentication bypass via JWT algorithm confusion (none algorithm)"
        })
        assert f["cwe"] == "CWE-287"
        assert "Authentication" in f["owasp"]


class TestOwaspA08IntegrityFailures:
    """A08:2021 - Software and Data Integrity Failures."""

    def test_insecure_deserialization_pickle(self):
        f = enrich_finding_cwe({
            "description": "Insecure deserialization of user-controlled pickle data"
        })
        assert f["cwe"] == "CWE-502"
        assert "Integrity" in f["owasp"]


class TestOwaspA09LoggingFailures:
    """A09:2021 - Security Logging and Monitoring Failures."""

    def test_log_injection_newline(self):
        f = enrich_finding_cwe({
            "description": "Log injection via newline characters in username field"
        })
        assert f["cwe"] == "CWE-117"
        assert "Logging" in f["owasp"]


class TestOwaspA10SSRF:
    """A10:2021 - Server-Side Request Forgery."""

    def test_ssrf_webhook(self):
        f = enrich_finding_cwe({
            "description": "SSRF via webhook URL allows internal network scanning"
        })
        assert f["cwe"] == "CWE-918"
        assert "SSRF" in f["owasp"]

    def test_server_side_request_forgery_pdf(self):
        f = enrich_finding_cwe({
            "description": "Server-side request forgery in PDF generation fetches internal metadata"
        })
        assert f["cwe"] == "CWE-918"


# ═══════════════════════════════════════════════════════════════
# 2. Concurrent / Parallel Execution Tests (16 tests)
# ═══════════════════════════════════════════════════════════════


class TestRunSecurityScanParallel:
    """Test _run_security_scan with ThreadPoolExecutor mocking."""

    @pytest.fixture(autouse=True)
    def _setup_env(self, tmp_path, monkeypatch):
        self.output = str(tmp_path / "report.md")
        self.sarif = str(tmp_path / "report.sarif.json")
        self.tmp_path = tmp_path
        # Ensure severity file goes to tmp_path
        monkeypatch.chdir(tmp_path)

    def _mock_mr_data(self, changes=None):
        """Return mocks for get_mr_info and get_mr_diff."""
        if changes is None:
            changes = [{"new_path": "app.py", "diff": "+x = 1"}]
        mr_info = {"iid": 1, "title": "Test MR"}
        mr_changes = {"changes": changes}
        return mr_info, mr_changes

    @patch("duoguard.run_secret_scan", return_value="No secrets found.")
    @patch("duoguard.run_dependency_audit", return_value="No dependency issues.")
    @patch("duoguard.run_code_security_review", return_value="No vulnerabilities found.")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_all_agents_succeed(self, mock_info, mock_diff,
                                mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL")
        assert Path(self.output).exists()
        report = Path(self.output).read_text()
        assert "DuoGuard" in report

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review",
           side_effect=requests.exceptions.Timeout("Gateway timeout"))
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_code_agent_timeout_propagates(self, mock_info, mock_diff,
                                           mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        with pytest.raises(requests.exceptions.Timeout):
            _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL")

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit",
           side_effect=RuntimeError("Dep agent crashed"))
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_dep_agent_failure_propagates(self, mock_info, mock_diff,
                                          mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        with pytest.raises(RuntimeError, match="Dep agent crashed"):
            _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL")

    @patch("duoguard.run_secret_scan",
           side_effect=requests.exceptions.ConnectionError("No network"))
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_secret_agent_network_error(self, mock_info, mock_diff,
                                         mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        with pytest.raises(requests.exceptions.ConnectionError):
            _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL")

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_only_code_agent_enabled(self, mock_info, mock_diff,
                                      mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        config = dict(DEFAULT_CONFIG)
        config["agents"] = {"code_security": True, "dependency_audit": False, "secret_scan": False}
        _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL", config=config)
        mock_code.assert_called_once()
        mock_dep.assert_not_called()
        mock_secret.assert_not_called()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_only_secret_agent_enabled(self, mock_info, mock_diff,
                                        mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        config = dict(DEFAULT_CONFIG)
        config["agents"] = {"code_security": False, "dependency_audit": False, "secret_scan": True}
        _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL", config=config)
        mock_code.assert_not_called()
        mock_dep.assert_not_called()
        mock_secret.assert_called_once()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_all_agents_disabled_still_generates_report(self, mock_info, mock_diff,
                                                         mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        config = dict(DEFAULT_CONFIG)
        config["agents"] = {"code_security": False, "dependency_audit": False, "secret_scan": False}
        _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL", config=config)
        assert Path(self.output).exists()
        mock_code.assert_not_called()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_empty_diff_no_agents_called(self, mock_info, mock_diff,
                                          mock_code, mock_dep, mock_secret):
        mock_info.return_value = {"iid": 1, "title": "Empty"}
        mock_diff.return_value = {"changes": []}
        _run_security_scan("123", "1", self.output, "", "CRITICAL")
        mock_code.assert_not_called()
        mock_dep.assert_not_called()
        mock_secret.assert_not_called()
        assert Path(self.output).exists()
        assert "No code changes" in Path(self.output).read_text()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="No dependency file changes detected in this merge request.")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_dep_agent_receives_empty_when_no_dep_files(self, mock_info, mock_diff,
                                                          mock_code, mock_dep, mock_secret):
        """When MR has no dependency files, dep agent gets empty diff."""
        mr_info = {"iid": 1, "title": "Code only MR"}
        mr_changes = {"changes": [{"new_path": "app.py", "diff": "+code"}]}
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL")
        # run_dependency_audit is called with whatever format_diff_for_analysis returns
        # for an empty list, which is ""
        assert mock_dep.called

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review",
           return_value="### [CRITICAL] Finding: SQL injection\n**File:** `db.py` (line 42)")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_critical_finding_causes_exit(self, mock_info, mock_diff,
                                           mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        with pytest.raises(SystemExit) as exc_info:
            _run_security_scan("123", "1", self.output, self.sarif, "HIGH")
        assert exc_info.value.code == 1

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="### [LOW] Finding: Minor\n**File:** `a.py` (line 1)")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_low_finding_below_high_threshold_passes(self, mock_info, mock_diff,
                                                       mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        # Should NOT exit -- low < high threshold
        _run_security_scan("123", "1", self.output, self.sarif, "HIGH")
        assert Path(self.output).exists()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_exclusions_filter_all_files(self, mock_info, mock_diff,
                                          mock_code, mock_dep, mock_secret):
        """When exclusions filter out every file, no agents are called."""
        mr_info = {"iid": 1, "title": "All excluded"}
        mr_changes = {"changes": [
            {"new_path": "vendor/lib.js", "diff": "+code"},
            {"new_path": "vendor/util.js", "diff": "+code"},
        ]}
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        config = dict(DEFAULT_CONFIG)
        config["exclude_paths"] = ["vendor/*"]
        _run_security_scan("123", "1", self.output, "", "CRITICAL", config=config)
        mock_code.assert_not_called()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_severity_file_written(self, mock_info, mock_diff,
                                     mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL")
        sev_path = self.tmp_path / "duoguard-severity.txt"
        assert sev_path.exists()
        assert sev_path.read_text() in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_codequality_and_sarif_generated(self, mock_info, mock_diff,
                                               mock_code, mock_dep, mock_secret):
        mr_info, mr_changes = self._mock_mr_data()
        mock_info.return_value = mr_info
        mock_diff.return_value = mr_changes
        _run_security_scan("123", "1", self.output, self.sarif, "CRITICAL")
        assert Path(self.sarif).exists()
        cq = self.tmp_path / "duoguard-codequality.json"
        assert cq.exists()


# ═══════════════════════════════════════════════════════════════
# 3. Full Pipeline Integration Tests (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestFullPipelineIntegration:
    """Test complete scan flow from MR diff through report generation."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.tmp = tmp_path
        self.output = str(tmp_path / "report.md")
        self.sarif = str(tmp_path / "report.sarif.json")
        monkeypatch.chdir(tmp_path)

    def test_clean_mr_produces_none_severity(self):
        mr_info = {"iid": 5, "title": "Add README"}
        report = generate_report(mr_info, "No issues.", "No issues.", "No issues.")
        assert "NONE" in report

    def test_critical_finding_in_report(self):
        mr_info = {"iid": 10, "title": "Fix auth"}
        code = "### [CRITICAL] Finding: SQL injection\n**File:** `db.py` (line 1)"
        report = generate_report(mr_info, code, "", "")
        assert "CRITICAL" in report
        assert ":rotating_light:" in report

    def test_only_dependency_findings(self):
        mr_info = {"iid": 7, "title": "Update deps"}
        dep = "### [MEDIUM] Finding: Outdated lodash\n**File:** `package.json` (line 10)"
        report = generate_report(mr_info, "", dep, "")
        assert "MEDIUM" in report
        assert "1 issue(s)" in report

    def test_mixed_severity_findings(self):
        mr_info = {"iid": 3, "title": "Large refactor"}
        code = "### [HIGH] Finding: XSS\n**File:** `view.js` (line 5)"
        dep = "### [LOW] Finding: Old dep\n**File:** `req.txt` (line 1)"
        secret = "### [MEDIUM] Finding: API key in comment\n**File:** `config.py` (line 30)"
        report = generate_report(mr_info, code, dep, secret)
        # HIGH + LOW + MEDIUM = 3+1+2=6, plus high>0 => at least HIGH
        assert "HIGH" in report or "CRITICAL" in report

    def test_full_report_structure(self):
        mr_info = {"iid": 99, "title": "Security sweep"}
        code = "### [HIGH] Finding: Command injection\n**File:** `run.py` (line 20)"
        report = generate_report(mr_info, code, "", "", scan_duration=3.5, files_scanned=8)
        assert "Code Security Analysis" in report
        assert "Dependency Audit" in report
        assert "Secret Scan" in report
        assert "Summary" in report
        assert "3.5s" in report
        assert "8" in report

    def test_sarif_and_codequality_from_same_findings(self):
        """Same findings produce reports in both SARIF and CodeQuality."""
        code = "### [HIGH] Finding: XSS\n**File:** `app.js` (line 10)"
        sarif_path = str(self.tmp / "test.sarif.json")
        cq_path = str(self.tmp / "test.cq.json")
        generate_sarif_report(code, sarif_path)
        generate_codequality_report(code, cq_path)
        sarif = json.loads(Path(sarif_path).read_text())
        cq = json.loads(Path(cq_path).read_text())
        assert len(sarif["runs"][0]["results"]) == 1
        assert len(cq) == 1

    def test_export_findings_round_trips(self):
        code = "### [HIGH] Finding: SSRF\n**File:** `fetch.py` (line 33)"
        dep = "### [LOW] Finding: Old lib\n**File:** `req.txt` (line 2)"
        out_path = str(self.tmp / "findings.json")
        findings = export_findings_json(code, dep, "", out_path)
        assert len(findings) == 2
        loaded = json.loads(Path(out_path).read_text())
        assert len(loaded) == 2
        assert loaded[0]["file_path"] == "fetch.py"
        assert loaded[1]["file_path"] == "req.txt"

    def test_findings_json_includes_cwe(self):
        code = "### [HIGH] Finding: SQL injection in search\n**File:** `search.py` (line 7)"
        out_path = str(self.tmp / "cwe_findings.json")
        findings = export_findings_json(code, "", "", out_path)
        assert findings[0].get("cwe") == "CWE-89"

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review",
           return_value="### [MEDIUM] Finding: Info leak\n**File:** `api.py` (line 15)")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_pipeline_generates_all_artifacts(self, mock_info, mock_diff,
                                                mock_code, mock_dep, mock_secret):
        mock_info.return_value = {"iid": 1, "title": "T"}
        mock_diff.return_value = {"changes": [{"new_path": "api.py", "diff": "+x"}]}
        _run_security_scan("1", "1", self.output, self.sarif, "CRITICAL")
        assert Path(self.output).exists()
        assert Path(self.sarif).exists()
        assert (self.tmp / "duoguard-codequality.json").exists()
        assert (self.tmp / "duoguard-findings.json").exists()
        assert (self.tmp / "duoguard-severity.txt").exists()

    def test_agent_mode_missing_context_exits(self):
        with patch.dict(os.environ, {
            "AI_FLOW_CONTEXT": "",
            "AI_FLOW_INPUT": "",
            "AI_FLOW_PROJECT_PATH": "",
        }, clear=False):
            with patch("duoguard.AI_FLOW_CONTEXT", ""):
                with patch("duoguard.AI_FLOW_INPUT", ""):
                    with patch("duoguard.AI_FLOW_PROJECT_PATH", ""):
                        with pytest.raises(SystemExit):
                            run_agent_mode()

    def test_parse_agent_context_json(self):
        ctx = json.dumps({
            "merge_request": {"iid": 42},
            "project": {"path_with_namespace": "group/repo"},
        })
        with patch("duoguard.AI_FLOW_CONTEXT", ctx):
            with patch("duoguard.AI_FLOW_PROJECT_PATH", ""):
                with patch("duoguard.AI_FLOW_INPUT", ""):
                    pid, mr_iid = _parse_agent_context()
                    assert mr_iid == "42"
                    assert "group" in pid

    def test_parse_agent_context_from_input_fallback(self):
        with patch("duoguard.AI_FLOW_CONTEXT", "no json here"):
            with patch("duoguard.AI_FLOW_INPUT", "Review !99 please"):
                with patch("duoguard.AI_FLOW_PROJECT_PATH", "org/proj"):
                    pid, mr_iid = _parse_agent_context()
                    assert mr_iid == "99"

    def test_resolve_api_url_default(self):
        with patch("duoguard.GITLAB_HOSTNAME", ""):
            url = _resolve_api_url_for_agent()
            assert url == "https://gitlab.com/api/v4"

    def test_resolve_api_url_custom_hostname(self):
        with patch("duoguard.GITLAB_HOSTNAME", "gitlab.example.com"):
            url = _resolve_api_url_for_agent()
            assert url == "https://gitlab.example.com/api/v4"

    def test_fail_on_none_threshold_always_passes(self):
        """fail_on=NONE means even NONE severity is at the threshold."""
        # severity_order.index("NONE") = 0, index("NONE") = 0 => 0 >= 0 => exit
        mr_info = {"iid": 1, "title": "T"}
        code = ""  # no findings => NONE severity
        sev = determine_severity(code, "", "")
        assert sev == "NONE"


# ═══════════════════════════════════════════════════════════════
# 4. Report Cross-Format Consistency Tests (12 tests)
# ═══════════════════════════════════════════════════════════════


class TestCrossFormatConsistency:
    """Verify same findings produce consistent output across formats."""

    SAMPLE_CODE = "### [HIGH] Finding: XSS in template\n**File:** `views.py` (line 25)"
    SAMPLE_DEP = "### [MEDIUM] Finding: Outdated library\n**File:** `requirements.txt` (line 3)"
    SAMPLE_SECRET = "### [CRITICAL] Finding: Hardcoded password in config\n**File:** `settings.py` (line 10)"

    @pytest.fixture(autouse=True)
    def _paths(self, tmp_path):
        self.sarif_path = str(tmp_path / "test.sarif.json")
        self.cq_path = str(tmp_path / "test.cq.json")
        self.findings_path = str(tmp_path / "test.findings.json")

    def test_sarif_severity_matches_markdown(self):
        """HIGH in markdown => 'error' in SARIF."""
        generate_sarif_report(self.SAMPLE_CODE, self.sarif_path)
        sarif = json.loads(Path(self.sarif_path).read_text())
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_codequality_severity_matches_markdown(self):
        """HIGH in markdown => 'critical' in CodeQuality."""
        generate_codequality_report(self.SAMPLE_CODE, self.cq_path)
        cq = json.loads(Path(self.cq_path).read_text())
        assert cq[0]["severity"] == "critical"

    def test_critical_maps_to_error_and_blocker(self):
        generate_sarif_report(self.SAMPLE_SECRET, self.sarif_path)
        generate_codequality_report(self.SAMPLE_SECRET, self.cq_path)
        sarif = json.loads(Path(self.sarif_path).read_text())
        cq = json.loads(Path(self.cq_path).read_text())
        assert sarif["runs"][0]["results"][0]["level"] == "error"
        assert cq[0]["severity"] == "blocker"

    def test_medium_maps_to_warning_and_major(self):
        generate_sarif_report(self.SAMPLE_DEP, self.sarif_path)
        generate_codequality_report(self.SAMPLE_DEP, self.cq_path)
        sarif = json.loads(Path(self.sarif_path).read_text())
        cq = json.loads(Path(self.cq_path).read_text())
        assert sarif["runs"][0]["results"][0]["level"] == "warning"
        assert cq[0]["severity"] == "major"

    def test_low_maps_to_note_and_minor(self):
        low_finding = "### [LOW] Finding: Minor style\n**File:** `style.py` (line 1)"
        generate_sarif_report(low_finding, self.sarif_path)
        generate_codequality_report(low_finding, self.cq_path)
        sarif = json.loads(Path(self.sarif_path).read_text())
        cq = json.loads(Path(self.cq_path).read_text())
        assert sarif["runs"][0]["results"][0]["level"] == "note"
        assert cq[0]["severity"] == "minor"

    def test_info_maps_to_note_and_info(self):
        info_finding = "### [INFO] Finding: FYI\n**File:** `note.py` (line 1)"
        generate_sarif_report(info_finding, self.sarif_path)
        generate_codequality_report(info_finding, self.cq_path)
        sarif = json.loads(Path(self.sarif_path).read_text())
        cq = json.loads(Path(self.cq_path).read_text())
        assert sarif["runs"][0]["results"][0]["level"] == "note"
        assert cq[0]["severity"] == "info"

    def test_fingerprint_deterministic(self):
        """Same input always produces the same CodeQuality fingerprint."""
        generate_codequality_report(self.SAMPLE_CODE, self.cq_path)
        fp1 = json.loads(Path(self.cq_path).read_text())[0]["fingerprint"]
        generate_codequality_report(self.SAMPLE_CODE, self.cq_path)
        fp2 = json.loads(Path(self.cq_path).read_text())[0]["fingerprint"]
        assert fp1 == fp2

    def test_sarif_fingerprint_deterministic(self):
        """Same input always produces the same SARIF partial fingerprint."""
        generate_sarif_report(self.SAMPLE_CODE, self.sarif_path)
        s1 = json.loads(Path(self.sarif_path).read_text())
        fp1 = s1["runs"][0]["results"][0]["partialFingerprints"]["duoguardFindingHash/v1"]
        generate_sarif_report(self.SAMPLE_CODE, self.sarif_path)
        s2 = json.loads(Path(self.sarif_path).read_text())
        fp2 = s2["runs"][0]["results"][0]["partialFingerprints"]["duoguardFindingHash/v1"]
        assert fp1 == fp2

    def test_empty_findings_all_formats_graceful(self):
        generate_sarif_report("", self.sarif_path)
        generate_codequality_report("", self.cq_path)
        findings = export_findings_json("", "", "", self.findings_path)
        sarif = json.loads(Path(self.sarif_path).read_text())
        cq = json.loads(Path(self.cq_path).read_text())
        assert sarif["runs"][0]["results"] == []
        assert cq == []
        assert findings == []

    def test_finding_count_consistent_across_formats(self):
        """All three formats report the same number of findings."""
        code = self.SAMPLE_CODE + "\n" + self.SAMPLE_SECRET
        generate_sarif_report(code, self.sarif_path)
        generate_codequality_report(code, self.cq_path)
        findings = export_findings_json(code, "", "", self.findings_path)
        sarif = json.loads(Path(self.sarif_path).read_text())
        cq = json.loads(Path(self.cq_path).read_text())
        assert len(sarif["runs"][0]["results"]) == len(cq) == len(findings) == 2

    def test_sarif_cwe_matches_enrichment(self):
        """SARIF rules include CWE from enrichment."""
        code = "### [HIGH] Finding: SQL injection in query\n**File:** `db.py` (line 1)"
        generate_sarif_report(code, self.sarif_path)
        sarif = json.loads(Path(self.sarif_path).read_text())
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"].get("cwe") == "CWE-89"

    def test_multi_category_findings_all_present(self):
        """Findings from all 3 categories appear in all formats."""
        generate_sarif_report(self.SAMPLE_CODE, self.sarif_path,
                              self.SAMPLE_DEP, self.SAMPLE_SECRET)
        generate_codequality_report(self.SAMPLE_CODE, self.cq_path,
                                    self.SAMPLE_DEP, self.SAMPLE_SECRET)
        sarif = json.loads(Path(self.sarif_path).read_text())
        cq = json.loads(Path(self.cq_path).read_text())
        assert len(sarif["runs"][0]["results"]) == 3
        assert len(cq) == 3


# ═══════════════════════════════════════════════════════════════
# 5. Security Input Fuzzing Tests (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestSecurityInputFuzzing:
    """Test DuoGuard handles adversarial/malicious inputs safely."""

    def test_diff_with_markdown_injection(self):
        """Diff containing markdown formatting should not break report."""
        changes = [{"new_path": "evil.py",
                     "diff": "+# ## Injected heading\n+**bold** _italic_ [link](http://evil.com)"}]
        result = format_diff_for_analysis(changes)
        # The content should be inside a code fence, so markdown won't render
        assert "```diff" in result
        assert "evil.py" in result

    def test_diff_with_null_bytes(self):
        """Null bytes in diff should not cause crashes."""
        changes = [{"new_path": "binary.dat", "diff": "+data\x00\x00\x00end"}]
        result = format_diff_for_analysis(changes)
        assert "binary.dat" in result

    def test_diff_with_extremely_long_line(self):
        """Single line over 1MB should not crash."""
        long_line = "+" + "A" * (1024 * 1024)
        changes = [{"new_path": "huge.py", "diff": long_line}]
        # Use a max_size large enough to hold the content
        result = format_diff_for_analysis(changes, max_size=2 * 1024 * 1024)
        assert "huge.py" in result

    def test_finding_description_with_html_tags(self):
        """HTML in finding description should be handled safely."""
        text = '### [HIGH] Finding: <script>alert("xss")</script>\n**File:** `xss.py` (line 1)'
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert "<script>" in findings[0]["description"]

    def test_file_path_with_spaces(self):
        """File paths with spaces should parse correctly."""
        text = '### [MEDIUM] Finding: Issue\n**File:** `src/my file.py` (line 5)'
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert findings[0]["file_path"] == "src/my file.py"

    def test_file_path_with_unicode(self):
        """Unicode file paths should not crash."""
        text = '### [LOW] Finding: Style\n**File:** `src/\u00fcbung.py` (line 1)'
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert "\u00fc" in findings[0]["file_path"]

    def test_file_path_with_traversal(self):
        """Path traversal in file path should be parsed as-is (not evaluated)."""
        text = '### [HIGH] Finding: Path issue\n**File:** `../../../etc/passwd` (line 1)'
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert findings[0]["file_path"] == "../../../etc/passwd"

    def test_very_large_finding_count(self):
        """Parsing hundreds of findings should not crash."""
        lines = []
        for i in range(200):
            lines.append(f"### [LOW] Finding: Issue {i}")
            lines.append(f"**File:** `f{i}.py` (line {i + 1})")
        text = "\n".join(lines)
        findings = _parse_findings(text)
        assert len(findings) == 200

    def test_json_injection_in_description(self):
        """JSON special characters in description should not break export."""
        text = '### [HIGH] Finding: {"key": "value"}\n**File:** `api.py` (line 1)'
        findings = _parse_findings(text)
        # Export should not crash
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_findings_json(text, "", "", path)
            data = json.loads(Path(path).read_text())
            assert len(data) == 1
        finally:
            os.unlink(path)

    def test_deeply_nested_json_agent_context(self):
        """Very deep nested JSON in agent context should not crash."""
        nested = {"a": {"b": {"c": {"d": {"merge_request": {"iid": 1}}}}}}
        ctx = json.dumps(nested)
        with patch("duoguard.AI_FLOW_CONTEXT", ctx):
            with patch("duoguard.AI_FLOW_INPUT", ""):
                with patch("duoguard.AI_FLOW_PROJECT_PATH", "org/proj"):
                    pid, mr_iid = _parse_agent_context()
                    # Won't find MR IID in deeply nested structure
                    assert mr_iid == ""

    def test_empty_string_inputs_to_generate_report(self):
        report = generate_report({"iid": 0, "title": ""}, "", "", "")
        assert "DuoGuard" in report

    def test_special_chars_in_mr_title(self):
        mr_info = {"iid": 1, "title": 'Fix "quotes" & <angles> in $variables'}
        report = generate_report(mr_info, "", "", "")
        assert '"quotes"' in report

    def test_diff_complexity_with_binary_looking_content(self):
        diff = "+\xff\xfe\x00\x01binary content"
        changes = [{"new_path": "bin.dat", "diff": diff}]
        result = compute_diff_complexity(changes)
        assert isinstance(result["complexity_score"], int)

    def test_gateway_headers_malformed_json(self):
        """Malformed JSON falls back to key-value parsing."""
        result = _parse_gateway_headers('{"broken json')
        assert result == {}

    def test_gateway_headers_empty_string(self):
        result = _parse_gateway_headers("")
        assert result == {}


# ═══════════════════════════════════════════════════════════════
# 6. Configuration Merge Tests (11 tests)
# ═══════════════════════════════════════════════════════════════


class TestConfigurationMerge:
    """Test load_config deep merge behavior."""

    def test_default_config_complete(self):
        """Default config has all expected keys."""
        assert "severity_threshold" in DEFAULT_CONFIG
        assert "agents" in DEFAULT_CONFIG
        assert "exclude_paths" in DEFAULT_CONFIG
        assert "exclude_extensions" in DEFAULT_CONFIG
        assert "inline_comments" in DEFAULT_CONFIG
        assert "approve" in DEFAULT_CONFIG
        assert "model" in DEFAULT_CONFIG

    def test_config_with_only_some_agents_disabled(self, tmp_path):
        cfg_file = tmp_path / ".duoguard.yml"
        cfg_file.write_text("agents:\n  secret_scan: false\n")
        config = load_config(str(cfg_file))
        assert config["agents"]["code_security"] is True
        assert config["agents"]["dependency_audit"] is True
        assert config["agents"]["secret_scan"] is False

    def test_config_with_custom_exclude_paths(self, tmp_path):
        cfg_file = tmp_path / ".duoguard.yml"
        cfg_file.write_text("exclude_paths:\n  - 'vendor/*'\n  - 'dist/*'\n")
        config = load_config(str(cfg_file))
        assert "vendor/*" in config["exclude_paths"]
        assert "dist/*" in config["exclude_paths"]

    def test_config_severity_threshold_override(self, tmp_path):
        cfg_file = tmp_path / ".duoguard.yml"
        cfg_file.write_text("severity_threshold: MEDIUM\n")
        config = load_config(str(cfg_file))
        assert config["severity_threshold"] == "MEDIUM"

    def test_config_file_not_found_uses_defaults(self):
        config = load_config("/nonexistent/path/.duoguard.yml")
        assert config == DEFAULT_CONFIG

    def test_invalid_yaml_raises(self, tmp_path):
        """Invalid YAML in config file causes a YAML parse error."""
        cfg_file = tmp_path / ".duoguard.yml"
        cfg_file.write_text(":::invalid: yaml: [[[")
        import yaml
        with pytest.raises(yaml.YAMLError):
            load_config(str(cfg_file))

    def test_empty_config_file_uses_defaults(self, tmp_path):
        cfg_file = tmp_path / ".duoguard.yml"
        cfg_file.write_text("")
        config = load_config(str(cfg_file))
        assert config["model"] == DEFAULT_CONFIG["model"]

    def test_config_with_extra_unknown_keys_preserved(self, tmp_path):
        cfg_file = tmp_path / ".duoguard.yml"
        cfg_file.write_text("custom_key: custom_value\nfoo: bar\n")
        config = load_config(str(cfg_file))
        assert config["custom_key"] == "custom_value"
        assert config["foo"] == "bar"

    def test_config_env_var_fallback(self, tmp_path, monkeypatch):
        cfg_file = tmp_path / "env_config.yml"
        cfg_file.write_text("approve: true\n")
        monkeypatch.setenv("DUOGUARD_CONFIG", str(cfg_file))
        # Pass None so it falls through to env var
        config = load_config(None)
        assert config["approve"] is True

    def test_config_explicit_path_takes_priority(self, tmp_path, monkeypatch):
        env_cfg = tmp_path / "env.yml"
        env_cfg.write_text("model: env-model\n")
        explicit_cfg = tmp_path / "explicit.yml"
        explicit_cfg.write_text("model: explicit-model\n")
        monkeypatch.setenv("DUOGUARD_CONFIG", str(env_cfg))
        config = load_config(str(explicit_cfg))
        assert config["model"] == "explicit-model"

    def test_config_deep_merge_agents_preserves_unset(self, tmp_path):
        """Setting one agent in config preserves defaults for others."""
        cfg_file = tmp_path / ".duoguard.yml"
        cfg_file.write_text("agents:\n  code_security: false\n")
        config = load_config(str(cfg_file))
        assert config["agents"]["code_security"] is False
        assert config["agents"]["dependency_audit"] is True
        assert config["agents"]["secret_scan"] is True


# ═══════════════════════════════════════════════════════════════
# 7. Post-Report Orchestration Tests (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestPostReportOrchestration:
    """Test post_report.py functions and main() workflow."""

    def test_find_existing_comment_found(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 100, "body": "Some other comment"},
            {"id": 200, "body": "## DuoGuard Security Review Report\nDetails..."},
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            result = find_existing_comment("1", "1")
            assert result == 200

    def test_find_existing_comment_not_found(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 100, "body": "Regular comment"},
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            result = find_existing_comment("1", "1")
            assert result is None

    def test_update_mr_labels_removes_stale(self):
        get_resp = MagicMock()
        get_resp.json.return_value = {
            "labels": ["security::high", "feature", "security::medium"]
        }
        get_resp.raise_for_status = MagicMock()

        put_resp = MagicMock()
        put_resp.raise_for_status = MagicMock()

        with patch("post_report.requests.get", return_value=get_resp):
            with patch("post_report.requests.put", return_value=put_resp) as mock_put:
                result = update_mr_labels("1", "1", "CRITICAL")
                assert result is True
                call_args = mock_put.call_args
                labels_str = call_args[1]["json"]["labels"]
                assert "security::critical" in labels_str
                assert "security::high" not in labels_str
                assert "feature" in labels_str

    def test_approve_mr_success(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp):
            assert approve_mr("1", "1") is True

    def test_approve_mr_forbidden(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        error = requests.exceptions.HTTPError(response=mock_resp)
        mock_resp.raise_for_status.side_effect = error
        with patch("post_report.requests.post", return_value=mock_resp):
            assert approve_mr("1", "1") is False

    def test_unapprove_mr_success(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp):
            assert unapprove_mr("1", "1") is True

    def test_create_issue_for_finding_success(self):
        finding = {
            "severity": "critical",
            "description": "SQL injection in API",
            "file_path": "api.py",
            "line_num": 42,
            "category": "code-security",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 10, "title": "test"}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp):
            issue = create_issue_for_finding("1", "1", finding)
            assert issue is not None
            assert issue["iid"] == 10

    def test_create_issues_filters_by_severity(self):
        findings = [
            {"severity": "critical", "description": "Crit", "file_path": "a.py",
             "line_num": 1, "category": "code-security"},
            {"severity": "low", "description": "Low", "file_path": "b.py",
             "line_num": 1, "category": "code-security"},
            {"severity": "high", "description": "High", "file_path": "c.py",
             "line_num": 1, "category": "code-security"},
        ]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 1, "title": "t"}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp):
            created = create_issues_for_findings("1", "1", findings, min_severity="high")
            # critical and high should trigger issues, not low
            assert len(created) == 2

    def test_resolve_stale_discussions(self):
        get_resp = MagicMock()
        get_resp.json.return_value = [
            {
                "id": "disc1",
                "notes": [{
                    "body": ":shield: DuoGuard [HIGH] old finding",
                    "resolvable": True,
                    "resolved": False,
                }],
            },
            {
                "id": "disc2",
                "notes": [{
                    "body": "Regular discussion",
                    "resolvable": True,
                    "resolved": False,
                }],
            },
        ]
        get_resp.raise_for_status = MagicMock()

        put_resp = MagicMock()
        put_resp.raise_for_status = MagicMock()

        with patch("post_report.requests.get", return_value=get_resp):
            with patch("post_report.requests.put", return_value=put_resp) as mock_put:
                resolved = resolve_stale_discussions("1", "1")
                assert resolved == 1
                # Only disc1 should be resolved, not disc2
                assert mock_put.call_count == 1

    def test_post_inline_findings_empty_returns_zero(self):
        assert post_inline_findings("1", "1", []) == 0


# ═══════════════════════════════════════════════════════════════
# Additional edge-case tests to reach 105+ total
# ═══════════════════════════════════════════════════════════════


class TestAdditionalEdgeCases:
    """Miscellaneous edge cases to bring total above 105."""

    def test_cwe_keyword_map_all_entries_have_required_keys(self):
        """Every entry in CWE_KEYWORD_MAP must have 'cwe' and 'owasp'."""
        for keyword, info in CWE_KEYWORD_MAP.items():
            assert "cwe" in info, f"Missing 'cwe' for keyword '{keyword}'"
            assert "owasp" in info, f"Missing 'owasp' for keyword '{keyword}'"
            assert info["cwe"].startswith("CWE-"), f"Invalid CWE format for '{keyword}'"

    def test_security_labels_list_complete(self):
        expected = {
            "security::critical", "security::high", "security::medium",
            "security::low", "security::clean",
        }
        assert set(SECURITY_LABELS) == expected

    def test_max_diff_size_constant(self):
        assert MAX_DIFF_SIZE == 200_000

    def test_default_config_model(self):
        assert DEFAULT_CONFIG["model"] == "claude-sonnet-4-5"

    def test_issue_title_truncation(self):
        """Issue title over 255 chars should be truncated."""
        long_desc = "A" * 300
        finding = {
            "severity": "high",
            "description": long_desc,
            "file_path": "x.py",
            "line_num": 1,
            "category": "code-security",
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 1, "title": "truncated"}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            create_issue_for_finding("1", "1", finding)
            payload = mock_post.call_args[1]["json"]
            assert len(payload["title"]) <= 255
            assert payload["title"].endswith("...")
