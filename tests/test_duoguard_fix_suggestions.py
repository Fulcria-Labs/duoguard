"""Tests for DuoGuard fix suggestions (auto-remediation) feature."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from duoguard import (
    FIX_SUGGESTION_PROMPT,
    generate_fix_suggestions,
    generate_report,
    _parse_findings,
    _run_security_scan,
    DEFAULT_CONFIG,
)


# ── Sample data ──────────────────────────────────────────────────

SAMPLE_FINDINGS = [
    {
        "severity": "critical",
        "description": "SQL Injection in user query",
        "file_path": "app/db.py",
        "line_num": 42,
        "category": "code-security",
        "cwe": "CWE-89",
    },
    {
        "severity": "high",
        "description": "Hardcoded API key",
        "file_path": "config.py",
        "line_num": 10,
        "category": "secret-scan",
        "cwe": "CWE-798",
    },
    {
        "severity": "medium",
        "description": "Missing CSRF token",
        "file_path": "views/form.py",
        "line_num": 55,
        "category": "code-security",
        "cwe": "CWE-352",
    },
]

SAMPLE_DIFF = """### File: `app/db.py`
```diff
+    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### File: `config.py`
```diff
+API_KEY = "sk-live-abc123def456"
```

### File: `views/form.py`
```diff
+@app.route('/submit', methods=['POST'])
+def submit():
+    data = request.form
```
"""

MOCK_FIX_RESPONSE = """### Fix for: SQL Injection in user query
**File:** `app/db.py` (line 42)
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Fix for: Hardcoded API key
**File:** `config.py` (line 10)
```python
import os
API_KEY = os.environ.get("API_KEY")
```

### Fix for: Missing CSRF token
**File:** `views/form.py` (line 55)
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```
"""


# ── Tests: generate_fix_suggestions ──────────────────────────────


class TestGenerateFixSuggestions:
    """Tests for the generate_fix_suggestions function."""

    def test_returns_message_for_empty_findings(self):
        result = generate_fix_suggestions([], "some diff")
        assert "No findings" in result

    def test_returns_message_for_none_findings(self):
        result = generate_fix_suggestions([], "")
        assert "No findings" in result

    @patch("duoguard.call_ai_gateway")
    def test_calls_ai_gateway_with_correct_prompt(self, mock_gateway):
        mock_gateway.return_value = MOCK_FIX_RESPONSE
        generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)

        mock_gateway.assert_called_once()
        args = mock_gateway.call_args
        system_prompt = args[0][0]
        assert "fix suggestions" in system_prompt.lower()
        assert "security engineer" in system_prompt.lower()

    @patch("duoguard.call_ai_gateway")
    def test_includes_all_findings_in_message(self, mock_gateway):
        mock_gateway.return_value = MOCK_FIX_RESPONSE
        generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)

        user_msg = mock_gateway.call_args[0][1]
        assert "SQL Injection" in user_msg
        assert "Hardcoded API key" in user_msg
        assert "Missing CSRF token" in user_msg
        assert "3 security finding(s)" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_includes_severity_in_message(self, mock_gateway):
        mock_gateway.return_value = MOCK_FIX_RESPONSE
        generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)

        user_msg = mock_gateway.call_args[0][1]
        assert "[CRITICAL]" in user_msg
        assert "[HIGH]" in user_msg
        assert "[MEDIUM]" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_includes_cwe_in_message(self, mock_gateway):
        mock_gateway.return_value = MOCK_FIX_RESPONSE
        generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)

        user_msg = mock_gateway.call_args[0][1]
        assert "CWE-89" in user_msg
        assert "CWE-798" in user_msg
        assert "CWE-352" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_includes_file_paths_in_message(self, mock_gateway):
        mock_gateway.return_value = MOCK_FIX_RESPONSE
        generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)

        user_msg = mock_gateway.call_args[0][1]
        assert "app/db.py" in user_msg
        assert "config.py" in user_msg
        assert "views/form.py" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_includes_diff_context(self, mock_gateway):
        mock_gateway.return_value = MOCK_FIX_RESPONSE
        generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)

        user_msg = mock_gateway.call_args[0][1]
        assert "cursor.execute" in user_msg
        assert "sk-live-abc123def456" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_truncates_large_diffs(self, mock_gateway):
        mock_gateway.return_value = "Fix: use parameterized queries"
        large_diff = "x" * 100_000
        generate_fix_suggestions(SAMPLE_FINDINGS[:1], large_diff)

        user_msg = mock_gateway.call_args[0][1]
        assert "truncated" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_respects_model_parameter(self, mock_gateway):
        mock_gateway.return_value = "fix"
        generate_fix_suggestions(SAMPLE_FINDINGS[:1], "diff", model="claude-opus-4")

        args = mock_gateway.call_args
        assert args[1]["model"] == "claude-opus-4" or args[0][2] == "claude-opus-4"

    @patch("duoguard.call_ai_gateway")
    def test_returns_ai_response(self, mock_gateway):
        mock_gateway.return_value = MOCK_FIX_RESPONSE
        result = generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)
        assert result == MOCK_FIX_RESPONSE

    @patch("duoguard.call_ai_gateway")
    def test_handles_gateway_exception(self, mock_gateway):
        mock_gateway.side_effect = Exception("API error")
        result = generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)
        assert "failed" in result.lower()
        assert "API error" in result

    @patch("duoguard.call_ai_gateway")
    def test_handles_timeout_exception(self, mock_gateway):
        import requests
        mock_gateway.side_effect = requests.exceptions.Timeout("Timed out")
        result = generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)
        assert "failed" in result.lower()

    @patch("duoguard.call_ai_gateway")
    def test_handles_http_error(self, mock_gateway):
        import requests
        resp = MagicMock()
        resp.status_code = 429
        mock_gateway.side_effect = requests.exceptions.HTTPError(response=resp)
        result = generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)
        assert "failed" in result.lower()

    @patch("duoguard.call_ai_gateway")
    def test_single_finding(self, mock_gateway):
        mock_gateway.return_value = "Use parameterized queries"
        result = generate_fix_suggestions([SAMPLE_FINDINGS[0]], SAMPLE_DIFF)

        user_msg = mock_gateway.call_args[0][1]
        assert "1 security finding(s)" in user_msg
        assert "SQL Injection" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_finding_without_cwe(self, mock_gateway):
        mock_gateway.return_value = "Fix suggestion"
        findings = [{"severity": "low", "description": "Info disclosure",
                      "file_path": "app.py", "line_num": 1, "category": "code-security"}]
        generate_fix_suggestions(findings, "diff")

        user_msg = mock_gateway.call_args[0][1]
        assert "[LOW]" in user_msg
        assert "Info disclosure" in user_msg
        # No CWE should not crash
        assert "()" not in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_finding_with_default_line_num(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        findings = [{"severity": "medium", "description": "Issue",
                      "file_path": "test.py", "category": "code-security"}]
        generate_fix_suggestions(findings, "diff")

        user_msg = mock_gateway.call_args[0][1]
        assert "line 1" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_numbered_findings_in_message(self, mock_gateway):
        mock_gateway.return_value = "Fixes"
        generate_fix_suggestions(SAMPLE_FINDINGS, SAMPLE_DIFF)

        user_msg = mock_gateway.call_args[0][1]
        assert "1. [CRITICAL]" in user_msg
        assert "2. [HIGH]" in user_msg
        assert "3. [MEDIUM]" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_empty_diff_still_works(self, mock_gateway):
        mock_gateway.return_value = "Manual review recommended."
        result = generate_fix_suggestions(SAMPLE_FINDINGS[:1], "")
        assert result == "Manual review recommended."


class TestFixSuggestionPrompt:
    """Tests for the FIX_SUGGESTION_PROMPT constant."""

    def test_prompt_mentions_security_engineer(self):
        assert "security engineer" in FIX_SUGGESTION_PROMPT.lower()

    def test_prompt_mentions_fix(self):
        assert "fix" in FIX_SUGGESTION_PROMPT.lower()

    def test_prompt_mentions_code_snippet(self):
        assert "code" in FIX_SUGGESTION_PROMPT.lower()

    def test_prompt_mentions_manual_review(self):
        assert "Manual review recommended" in FIX_SUGGESTION_PROMPT

    def test_prompt_mentions_same_language(self):
        assert "SAME programming language" in FIX_SUGGESTION_PROMPT

    def test_prompt_has_format_instructions(self):
        assert "### Fix for:" in FIX_SUGGESTION_PROMPT

    def test_prompt_limits_length(self):
        assert "20 lines" in FIX_SUGGESTION_PROMPT

    def test_prompt_prefers_stdlib(self):
        assert "standard-library" in FIX_SUGGESTION_PROMPT


# ── Tests: Report integration ────────────────────────────────────


class TestReportWithFixSuggestions:
    """Tests for fix suggestions integration in generate_report."""

    def test_report_includes_fix_suggestions_section(self):
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            fix_suggestions="Use parameterized queries for SQL",
        )
        assert "Fix Suggestions" in report
        assert "parameterized queries" in report

    def test_report_without_fix_suggestions(self):
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
        )
        assert "Fix Suggestions" not in report

    def test_report_with_none_fix_suggestions(self):
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            fix_suggestions=None,
        )
        assert "Fix Suggestions" not in report

    def test_report_with_empty_fix_suggestions(self):
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            fix_suggestions="",
        )
        assert "Fix Suggestions" not in report

    def test_report_with_whitespace_fix_suggestions(self):
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            fix_suggestions="   \n  ",
        )
        assert "Fix Suggestions" not in report

    def test_fix_suggestions_section_has_wrench_emoji(self):
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            fix_suggestions="Fix: use env vars",
        )
        assert ":wrench:" in report

    def test_fix_suggestions_appears_before_scan_metrics(self):
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            scan_duration=5.0, files_scanned=3,
            fix_suggestions="Use prepared statements",
        )
        fix_idx = report.index("Fix Suggestions")
        metrics_idx = report.index("Scan Metrics")
        assert fix_idx < metrics_idx

    def test_fix_suggestions_appears_before_complexity(self):
        complexity = {
            "total_additions": 10, "total_deletions": 5,
            "total_files": 2, "high_risk_files": ["auth.py"],
            "complexity_score": 50, "risk_factors": ["auth logic"],
        }
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            complexity=complexity,
            fix_suggestions="Sanitize input",
        )
        fix_idx = report.index("Fix Suggestions")
        complexity_idx = report.index("Diff Complexity")
        assert fix_idx < complexity_idx

    def test_report_with_multiline_fix_suggestions(self):
        fixes = """### Fix for: SQL Injection
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Fix for: XSS
```python
from markupsafe import escape
output = escape(user_input)
```"""
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            fix_suggestions=fixes,
        )
        assert "SQL Injection" in report
        assert "XSS" in report
        assert "markupsafe" in report

    def test_report_preserves_code_blocks_in_fixes(self):
        fixes = "```python\nprint('safe')\n```"
        report = generate_report(
            {"iid": 1, "title": "Test MR"},
            "No issues", "No issues", "No issues",
            fix_suggestions=fixes,
        )
        assert "```python" in report
        assert "print('safe')" in report


# ── Tests: Config integration ────────────────────────────────────


class TestConfigFixSuggestions:
    """Tests for fix_suggestions config option."""

    def test_default_config_enables_fix_suggestions(self):
        assert DEFAULT_CONFIG["fix_suggestions"] is True

    def test_config_key_exists(self):
        assert "fix_suggestions" in DEFAULT_CONFIG


# ── Tests: Pipeline integration ──────────────────────────────────


class TestPipelineFixSuggestions:
    """Tests for fix suggestions in the _run_security_scan pipeline."""

    @patch("duoguard.generate_fix_suggestions")
    @patch("duoguard.call_ai_gateway")
    @patch("duoguard.get_mr_info")
    @patch("duoguard.get_mr_diff")
    def test_pipeline_generates_fix_suggestions(
        self, mock_diff, mock_info, mock_gateway, mock_fix
    ):
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+eval(input())"}]
        }
        mock_gateway.return_value = (
            "### [CRITICAL] Finding: Code injection\n"
            "**File:** `app.py` (line 1)"
        )
        mock_fix.return_value = "Use ast.literal_eval instead"

        with patch("pathlib.Path.write_text"):
            with patch("duoguard.generate_codequality_report"):
                with patch("duoguard.generate_sarif_report"):
                    with patch("duoguard.export_findings_json", return_value=[]):
                        try:
                            _run_security_scan(
                                "123", "1", "/tmp/out.md", "", "CRITICAL",
                                config=DEFAULT_CONFIG,
                            )
                        except SystemExit:
                            pass

        mock_fix.assert_called_once()
        args = mock_fix.call_args[0]
        assert len(args[0]) > 0  # findings list
        assert isinstance(args[1], str)  # diff_text

    @patch("duoguard.generate_fix_suggestions")
    @patch("duoguard.call_ai_gateway")
    @patch("duoguard.get_mr_info")
    @patch("duoguard.get_mr_diff")
    def test_pipeline_skips_fix_suggestions_when_disabled(
        self, mock_diff, mock_info, mock_gateway, mock_fix
    ):
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "app.py", "diff": "+eval(input())"}]
        }
        mock_gateway.return_value = (
            "### [HIGH] Finding: Eval usage\n"
            "**File:** `app.py` (line 1)"
        )

        config = dict(DEFAULT_CONFIG)
        config["fix_suggestions"] = False

        with patch("pathlib.Path.write_text"):
            with patch("duoguard.generate_codequality_report"):
                with patch("duoguard.generate_sarif_report"):
                    with patch("duoguard.export_findings_json", return_value=[]):
                        try:
                            _run_security_scan(
                                "123", "1", "/tmp/out.md", "", "CRITICAL",
                                config=config,
                            )
                        except SystemExit:
                            pass

        mock_fix.assert_not_called()

    @patch("duoguard.generate_fix_suggestions")
    @patch("duoguard.call_ai_gateway")
    @patch("duoguard.get_mr_info")
    @patch("duoguard.get_mr_diff")
    def test_pipeline_skips_fix_suggestions_when_no_findings(
        self, mock_diff, mock_info, mock_gateway, mock_fix
    ):
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {
            "changes": [{"new_path": "readme.md", "diff": "+# Hello"}]
        }
        mock_gateway.return_value = "No security issues found."

        with patch("pathlib.Path.write_text"):
            with patch("duoguard.generate_codequality_report"):
                with patch("duoguard.generate_sarif_report"):
                    with patch("duoguard.export_findings_json", return_value=[]):
                        _run_security_scan(
                            "123", "1", "/tmp/out.md", "", "CRITICAL",
                            config=DEFAULT_CONFIG,
                        )

        mock_fix.assert_not_called()


# ── Tests: Edge cases ────────────────────────────────────────────


class TestFixSuggestionsEdgeCases:
    """Edge case tests for fix suggestions."""

    @patch("duoguard.call_ai_gateway")
    def test_finding_with_very_long_description(self, mock_gateway):
        mock_gateway.return_value = "Fix suggestion"
        findings = [{
            "severity": "high",
            "description": "A" * 500,
            "file_path": "long.py",
            "line_num": 1,
            "category": "code-security",
            "cwe": "CWE-79",
        }]
        result = generate_fix_suggestions(findings, "diff")
        assert result == "Fix suggestion"
        user_msg = mock_gateway.call_args[0][1]
        assert "A" * 500 in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_finding_with_special_characters_in_path(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        findings = [{
            "severity": "medium",
            "description": "Issue",
            "file_path": "src/app (copy)/utils.py",
            "line_num": 5,
            "category": "code-security",
        }]
        generate_fix_suggestions(findings, "diff")
        user_msg = mock_gateway.call_args[0][1]
        assert "src/app (copy)/utils.py" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_finding_with_unicode_description(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        findings = [{
            "severity": "low",
            "description": "Exposição de dados sensíveis",
            "file_path": "api.py",
            "line_num": 20,
            "category": "code-security",
        }]
        generate_fix_suggestions(findings, "diff")
        user_msg = mock_gateway.call_args[0][1]
        assert "Exposição" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_many_findings(self, mock_gateway):
        mock_gateway.return_value = "Multiple fixes"
        findings = [
            {
                "severity": "medium",
                "description": f"Finding {i}",
                "file_path": f"file{i}.py",
                "line_num": i,
                "category": "code-security",
            }
            for i in range(20)
        ]
        generate_fix_suggestions(findings, "diff")
        user_msg = mock_gateway.call_args[0][1]
        assert "20 security finding(s)" in user_msg
        assert "Finding 0" in user_msg
        assert "Finding 19" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_diff_exactly_at_limit(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        diff = "x" * 50_000  # Exactly at limit
        generate_fix_suggestions(SAMPLE_FINDINGS[:1], diff)
        user_msg = mock_gateway.call_args[0][1]
        assert "truncated" not in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_diff_one_over_limit(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        diff = "x" * 50_001  # One over limit
        generate_fix_suggestions(SAMPLE_FINDINGS[:1], diff)
        user_msg = mock_gateway.call_args[0][1]
        assert "truncated" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_all_severity_levels(self, mock_gateway):
        mock_gateway.return_value = "Fixes for all"
        findings = [
            {"severity": sev, "description": f"{sev} issue",
             "file_path": "f.py", "line_num": 1, "category": "code-security"}
            for sev in ["critical", "high", "medium", "low", "info"]
        ]
        generate_fix_suggestions(findings, "diff")
        user_msg = mock_gateway.call_args[0][1]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert f"[{sev}]" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_mixed_categories(self, mock_gateway):
        mock_gateway.return_value = "Mixed fixes"
        findings = [
            {"severity": "high", "description": "Code issue",
             "file_path": "a.py", "line_num": 1, "category": "code-security"},
            {"severity": "medium", "description": "Dep issue",
             "file_path": "package.json", "line_num": 5, "category": "dependency-audit"},
            {"severity": "critical", "description": "Secret found",
             "file_path": "env.py", "line_num": 3, "category": "secret-scan"},
        ]
        generate_fix_suggestions(findings, "diff")
        user_msg = mock_gateway.call_args[0][1]
        assert "Code issue" in user_msg
        assert "Dep issue" in user_msg
        assert "Secret found" in user_msg

    @patch("duoguard.call_ai_gateway")
    def test_gateway_returns_empty_string(self, mock_gateway):
        mock_gateway.return_value = ""
        result = generate_fix_suggestions(SAMPLE_FINDINGS[:1], "diff")
        assert result == ""

    @patch("duoguard.call_ai_gateway")
    def test_finding_missing_all_optional_fields(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        findings = [{"severity": "info", "description": "Minimal finding",
                      "file_path": "unknown", "line_num": 1, "category": "code-security"}]
        # Should not raise
        result = generate_fix_suggestions(findings, "")
        assert result == "Fix"

    @patch("duoguard.call_ai_gateway")
    def test_uses_fix_suggestion_prompt_constant(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        generate_fix_suggestions(SAMPLE_FINDINGS[:1], "diff")
        system_prompt = mock_gateway.call_args[0][0]
        assert system_prompt == FIX_SUGGESTION_PROMPT


# ── Tests: Integration with _parse_findings ──────────────────────


class TestFixSuggestionsWithParsedFindings:
    """Tests that fix suggestions work with findings from _parse_findings."""

    @patch("duoguard.call_ai_gateway")
    def test_works_with_parsed_code_findings(self, mock_gateway):
        mock_gateway.return_value = "Use parameterized queries"
        raw_findings = (
            "### [CRITICAL] Finding: SQL Injection via string concatenation\n"
            "**File:** `app/models.py` (line 42)\n"
        )
        parsed = _parse_findings(raw_findings, "code-security")
        assert len(parsed) == 1

        result = generate_fix_suggestions(parsed, "some diff")
        assert result == "Use parameterized queries"

    @patch("duoguard.call_ai_gateway")
    def test_works_with_parsed_secret_findings(self, mock_gateway):
        mock_gateway.return_value = "Use environment variables"
        raw_findings = (
            "### [HIGH] Finding: Hardcoded AWS access key\n"
            "**File:** `config/settings.py` (line 15)\n"
        )
        parsed = _parse_findings(raw_findings, "secret-scan")
        assert len(parsed) == 1

        result = generate_fix_suggestions(parsed, "diff text")
        assert result == "Use environment variables"

    @patch("duoguard.call_ai_gateway")
    def test_works_with_multiple_parsed_categories(self, mock_gateway):
        mock_gateway.return_value = "Combined fixes"
        code_raw = "### [HIGH] Finding: XSS vulnerability\n**File:** `views.py` (line 10)\n"
        dep_raw = "### [MEDIUM] Finding: Outdated library\n**File:** `package.json` (line 5)\n"
        secret_raw = "### [CRITICAL] Finding: Private key exposed\n**File:** `keys/id_rsa` (line 1)\n"

        all_findings = (
            _parse_findings(code_raw, "code-security")
            + _parse_findings(dep_raw, "dependency-audit")
            + _parse_findings(secret_raw, "secret-scan")
        )
        assert len(all_findings) == 3

        result = generate_fix_suggestions(all_findings, "diff")
        user_msg = mock_gateway.call_args[0][1]
        assert "XSS" in user_msg
        assert "Outdated library" in user_msg
        assert "Private key" in user_msg


# ── Tests: Regression guards ─────────────────────────────────────


class TestFixSuggestionsRegression:
    """Regression tests for fix suggestions."""

    def test_generate_report_signature_accepts_fix_suggestions(self):
        """Ensure generate_report accepts the fix_suggestions kwarg."""
        # Should not raise TypeError
        report = generate_report(
            {"iid": 99, "title": "Regression MR"},
            "", "", "",
            fix_suggestions="test",
        )
        assert isinstance(report, str)

    def test_generate_report_default_fix_suggestions_is_none(self):
        """Ensure fix_suggestions defaults to None (no section rendered)."""
        report = generate_report(
            {"iid": 99, "title": "Regression MR"},
            "", "", "",
        )
        assert "Fix Suggestions" not in report

    @patch("duoguard.call_ai_gateway")
    def test_fix_suggestions_does_not_modify_findings_list(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        findings = [dict(SAMPLE_FINDINGS[0])]
        original = dict(findings[0])
        generate_fix_suggestions(findings, "diff")
        assert findings[0] == original

    @patch("duoguard.call_ai_gateway")
    def test_fix_suggestions_uses_default_model(self, mock_gateway):
        mock_gateway.return_value = "Fix"
        generate_fix_suggestions(SAMPLE_FINDINGS[:1], "diff")
        # Default model should be passed as positional or keyword arg
        args, kwargs = mock_gateway.call_args
        model_val = args[2] if len(args) > 2 else kwargs.get("model", "")
        assert model_val == "claude-sonnet-4-5"
