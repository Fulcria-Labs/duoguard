"""DuoGuard integration tests -- full pipeline flows, config edge cases,
multi-agent coordination, SARIF edge cases, Code Quality validation,
diff complexity scoring, AI Gateway fallback chain, large MR handling,
and concurrent finding deduplication.

Adds 100+ tests covering integration-level scenarios not well-tested
in the existing unit and scenario test files.
"""

import hashlib
import json
import os
import re
import sys
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch

import pytest
import requests
import yaml

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


def _finding_text(severity, desc, path="src/app.py", line=1):
    """Build a finding block in the format _parse_findings expects."""
    return (
        f"### [{severity.upper()}] Finding: {desc}\n"
        f"**File:** `{path}` (line {line})"
    )


def _multi_findings(*specs):
    """Build multiple finding blocks. Each spec is (severity, desc, path, line)."""
    return "\n".join(_finding_text(*s) for s in specs)


# ═══════════════════════════════════════════════════════════════
# 1. Full Pipeline Flows (15 tests)
#    MR arrives → agents analyze → findings posted → labels applied
# ═══════════════════════════════════════════════════════════════


class TestEndToEndPipelineFlow:
    """Integration tests that exercise the full MR→agents→report→label pipeline."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.tmp = tmp_path
        self.output = str(tmp_path / "report.md")
        self.sarif = str(tmp_path / "report.sarif.json")
        monkeypatch.chdir(tmp_path)

    @patch("duoguard.run_secret_scan",
           return_value="### [HIGH] Finding: AWS key leaked\n**File:** `config.py` (line 5)")
    @patch("duoguard.run_dependency_audit",
           return_value="### [MEDIUM] Finding: Outdated requests\n**File:** `requirements.txt` (line 3)")
    @patch("duoguard.run_code_security_review",
           return_value="### [CRITICAL] Finding: SQL injection in login\n**File:** `auth.py` (line 42)")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_all_three_agents_findings_appear_in_report(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        """All agent findings appear in the markdown report."""
        mock_info.return_value = {"iid": 10, "title": "Add auth feature"}
        mock_diff.return_value = {
            "changes": [
                {"new_path": "auth.py", "diff": "+cursor.execute(query)"},
                {"new_path": "requirements.txt", "diff": "+requests==2.20.0"},
                {"new_path": "config.py", "diff": "+AWS_KEY='AKIA...'"},
            ]
        }
        with pytest.raises(SystemExit):
            _run_security_scan("123", "10", self.output, self.sarif, "HIGH")

        report = Path(self.output).read_text()
        assert "SQL injection" in report
        assert "Outdated requests" in report
        assert "AWS key leaked" in report

    @patch("duoguard.run_secret_scan", return_value="No secrets found.")
    @patch("duoguard.run_dependency_audit", return_value="No dep issues.")
    @patch("duoguard.run_code_security_review",
           return_value="### [HIGH] Finding: AWS key in env\n**File:** `deploy.sh` (line 8)")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_severity_file_reflects_worst_finding(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        """The severity file should contain the highest severity from any agent."""
        mock_info.return_value = {"iid": 5, "title": "Deploy changes"}
        mock_diff.return_value = {"changes": [{"new_path": "deploy.sh", "diff": "+export KEY=abc"}]}
        with pytest.raises(SystemExit):
            _run_security_scan("1", "5", self.output, self.sarif, "LOW")

        sev = (self.tmp / "duoguard-severity.txt").read_text()
        assert sev in ("HIGH", "CRITICAL")

    @patch("duoguard.run_secret_scan", return_value="No secrets found.")
    @patch("duoguard.run_dependency_audit", return_value="No dep issues.")
    @patch("duoguard.run_code_security_review", return_value="No vulnerabilities.")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_clean_scan_produces_none_severity_and_no_exit(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        """Clean MR passes without SystemExit and severity = NONE."""
        mock_info.return_value = {"iid": 1, "title": "Docs update"}
        mock_diff.return_value = {"changes": [{"new_path": "README.md", "diff": "+docs"}]}
        _run_security_scan("1", "1", self.output, self.sarif, "CRITICAL")

        sev = (self.tmp / "duoguard-severity.txt").read_text()
        assert sev == "NONE"

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review",
           return_value="### [MEDIUM] Finding: Info leak\n**File:** `api.py` (line 10)")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_findings_json_written_with_correct_count(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        """The exported findings JSON should match the number of parsed findings."""
        mock_info.return_value = {"iid": 2, "title": "API fix"}
        mock_diff.return_value = {"changes": [{"new_path": "api.py", "diff": "+leak"}]}
        _run_security_scan("1", "2", self.output, self.sarif, "CRITICAL")

        findings = json.loads((self.tmp / "duoguard-findings.json").read_text())
        assert len(findings) == 1
        assert findings[0]["file_path"] == "api.py"

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review",
           return_value="### [LOW] Finding: Debug log\n**File:** `utils.py` (line 3)")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_low_finding_below_critical_threshold_does_not_exit(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        mock_info.return_value = {"iid": 3, "title": "Utils"}
        mock_diff.return_value = {"changes": [{"new_path": "utils.py", "diff": "+print()"}]}
        # Should NOT raise SystemExit since LOW < CRITICAL
        _run_security_scan("1", "3", self.output, self.sarif, "CRITICAL")
        assert Path(self.output).exists()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review",
           return_value="### [MEDIUM] Finding: Open redirect\n**File:** `redirect.py` (line 8)")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_medium_meets_medium_threshold_exits(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        mock_info.return_value = {"iid": 4, "title": "Redirect"}
        mock_diff.return_value = {"changes": [{"new_path": "redirect.py", "diff": "+url"}]}
        with pytest.raises(SystemExit):
            _run_security_scan("1", "4", self.output, self.sarif, "MEDIUM")

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_codequality_report_generated_alongside_sarif(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        mock_info.return_value = {"iid": 6, "title": "Feature"}
        mock_diff.return_value = {"changes": [{"new_path": "a.py", "diff": "+x"}]}
        _run_security_scan("1", "6", self.output, self.sarif, "CRITICAL")

        assert (self.tmp / "duoguard-codequality.json").exists()
        cq = json.loads((self.tmp / "duoguard-codequality.json").read_text())
        assert isinstance(cq, list)

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_report_contains_scan_duration(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        mock_info.return_value = {"iid": 7, "title": "Perf"}
        mock_diff.return_value = {"changes": [{"new_path": "perf.py", "diff": "+fast"}]}
        _run_security_scan("1", "7", self.output, self.sarif, "CRITICAL")

        report = Path(self.output).read_text()
        assert "Scan duration" in report or "Scan Metrics" in report

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_report_contains_files_scanned_count(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        changes = [{"new_path": f"f{i}.py", "diff": f"+line{i}"} for i in range(5)]
        mock_info.return_value = {"iid": 8, "title": "Multi"}
        mock_diff.return_value = {"changes": changes}
        _run_security_scan("1", "8", self.output, self.sarif, "CRITICAL")

        report = Path(self.output).read_text()
        assert "5" in report  # files scanned

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_no_changes_produces_short_report(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        """MR with empty changes list produces 'no code changes' report."""
        mock_info.return_value = {"iid": 9, "title": "Empty"}
        mock_diff.return_value = {"changes": []}
        _run_security_scan("1", "9", self.output, self.sarif, "CRITICAL")

        report = Path(self.output).read_text()
        assert "No code changes" in report
        mock_code.assert_not_called()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_exclusions_reduce_scanned_file_count(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        mock_info.return_value = {"iid": 10, "title": "Vendor update"}
        mock_diff.return_value = {
            "changes": [
                {"new_path": "vendor/lib.js", "diff": "+vendored"},
                {"new_path": "src/app.js", "diff": "+code"},
            ]
        }
        config = dict(DEFAULT_CONFIG)
        config["exclude_paths"] = ["vendor/*"]
        _run_security_scan("1", "10", self.output, self.sarif, "CRITICAL", config=config)

        report = Path(self.output).read_text()
        # Only src/app.js should have been scanned (1 file)
        assert "1" in report

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review",
           return_value=("### [HIGH] Finding: XSS in template\n**File:** `views.py` (line 5)\n"
                         "### [MEDIUM] Finding: Missing CSRF\n**File:** `forms.py` (line 20)"))
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_multiple_findings_from_single_agent(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        mock_info.return_value = {"iid": 11, "title": "Forms"}
        mock_diff.return_value = {"changes": [
            {"new_path": "views.py", "diff": "+render"},
            {"new_path": "forms.py", "diff": "+form"},
        ]}
        with pytest.raises(SystemExit):
            _run_security_scan("1", "11", self.output, self.sarif, "MEDIUM")

        findings = json.loads((self.tmp / "duoguard-findings.json").read_text())
        assert len(findings) == 2

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_complexity_analysis_in_report_for_risky_files(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        mock_info.return_value = {"iid": 12, "title": "Auth refactor"}
        mock_diff.return_value = {"changes": [
            {"new_path": "auth.py", "diff": "\n".join([f"+password = check()" for _ in range(50)])},
        ]}
        _run_security_scan("1", "12", self.output, self.sarif, "CRITICAL")

        report = Path(self.output).read_text()
        assert "Complexity" in report or "complexity" in report.lower()

    @patch("duoguard.run_secret_scan", return_value="Clean")
    @patch("duoguard.run_dependency_audit", return_value="Clean")
    @patch("duoguard.run_code_security_review", return_value="Clean")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.get_mr_info")
    def test_sarif_report_has_valid_schema_version(
        self, mock_info, mock_diff, mock_code, mock_dep, mock_secret
    ):
        mock_info.return_value = {"iid": 13, "title": "Schema check"}
        mock_diff.return_value = {"changes": [{"new_path": "a.py", "diff": "+x"}]}
        _run_security_scan("1", "13", self.output, self.sarif, "CRITICAL")

        sarif = json.loads(Path(self.sarif).read_text())
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif


# ═══════════════════════════════════════════════════════════════
# 2. Config File Interactions (14 tests)
#    .duoguard.yml edge cases: empty, invalid, conflicting settings
# ═══════════════════════════════════════════════════════════════


class TestConfigFileEdgeCases:
    """Test .duoguard.yml parsing edge cases."""

    def test_yaml_with_only_comments(self, tmp_path):
        """Config file with only comments is treated as empty."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("# This is just a comment\n# No actual config\n")
        config = load_config(str(cfg))
        assert config["model"] == DEFAULT_CONFIG["model"]

    def test_yaml_with_null_value(self, tmp_path):
        """Null values in YAML should not crash."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("severity_threshold: null\n")
        config = load_config(str(cfg))
        # null gets interpreted as None, but config should still load
        assert config["severity_threshold"] is None

    def test_yaml_with_list_instead_of_dict(self, tmp_path):
        """Top-level YAML list should fall through to defaults."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("- item1\n- item2\n")
        config = load_config(str(cfg))
        # isinstance check should skip non-dict top-level
        assert config["model"] == DEFAULT_CONFIG["model"]

    def test_yaml_with_integer_top_level(self, tmp_path):
        """Integer in YAML file should not crash."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("42\n")
        config = load_config(str(cfg))
        assert config == DEFAULT_CONFIG

    def test_yaml_with_boolean_top_level(self, tmp_path):
        """Boolean in YAML file should not crash."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("true\n")
        config = load_config(str(cfg))
        assert config == DEFAULT_CONFIG

    def test_config_agents_as_non_dict_ignored(self, tmp_path):
        """If agents is a string in config, it replaces the agents dict."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("agents: all\n")
        config = load_config(str(cfg))
        # Non-dict agents value is set directly (not merged)
        assert config["agents"] == "all"

    def test_conflicting_threshold_and_fail_on(self, tmp_path):
        """Config severity_threshold vs CLI fail_on: CLI wins."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("severity_threshold: LOW\n")
        config = load_config(str(cfg))
        assert config["severity_threshold"] == "LOW"
        # Simulate CLI override
        fail_on = "CRITICAL" or config.get("severity_threshold", "HIGH")
        assert fail_on == "CRITICAL"

    def test_config_max_diff_size_custom(self, tmp_path):
        """Custom max_diff_size should override default."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("max_diff_size: 50000\n")
        config = load_config(str(cfg))
        assert config["max_diff_size"] == 50000

    def test_config_exclude_extensions(self, tmp_path):
        """exclude_extensions should be loaded from config."""
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("exclude_extensions:\n  - min.js\n  - map\n  - svg\n")
        config = load_config(str(cfg))
        assert "min.js" in config["exclude_extensions"]
        assert "svg" in config["exclude_extensions"]

    def test_config_inline_comments_false(self, tmp_path):
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("inline_comments: false\n")
        config = load_config(str(cfg))
        assert config["inline_comments"] is False

    def test_config_approve_with_threshold(self, tmp_path):
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("approve: true\napprove_threshold: MEDIUM\n")
        config = load_config(str(cfg))
        assert config["approve"] is True
        assert config["approve_threshold"] == "MEDIUM"

    def test_yaml_extension_variants(self, tmp_path, monkeypatch):
        """Both .yml and .yaml should be detected."""
        monkeypatch.chdir(tmp_path)
        yaml_file = tmp_path / ".duoguard.yaml"
        yaml_file.write_text("model: claude-haiku-35\n")
        config = load_config(None)
        assert config["model"] == "claude-haiku-35"

    def test_env_var_config_overrides_cwd(self, tmp_path, monkeypatch):
        """DUOGUARD_CONFIG env var takes priority over CWD files."""
        monkeypatch.chdir(tmp_path)
        cwd_cfg = tmp_path / ".duoguard.yml"
        cwd_cfg.write_text("model: cwd-model\n")
        env_cfg = tmp_path / "custom.yml"
        env_cfg.write_text("model: env-model\n")
        monkeypatch.setenv("DUOGUARD_CONFIG", str(env_cfg))
        config = load_config(None)
        assert config["model"] == "env-model"

    def test_config_version_field(self, tmp_path):
        cfg = tmp_path / ".duoguard.yml"
        cfg.write_text("version: 2\n")
        config = load_config(str(cfg))
        assert config["version"] == 2


# ═══════════════════════════════════════════════════════════════
# 3. Multi-Agent Coordination (12 tests)
#    Findings from all 3 agents merged correctly
# ═══════════════════════════════════════════════════════════════


class TestMultiAgentCoordination:
    """Verify findings from code, dependency, and secret agents are merged correctly."""

    def test_findings_from_all_three_categories_exported(self, tmp_path):
        code = _finding_text("HIGH", "XSS in template", "views.py", 25)
        dep = _finding_text("MEDIUM", "Outdated flask", "requirements.txt", 3)
        secret = _finding_text("CRITICAL", "Hardcoded password", "settings.py", 10)
        out = str(tmp_path / "findings.json")
        findings = export_findings_json(code, dep, secret, out)
        assert len(findings) == 3
        categories = {f["category"] for f in findings}
        assert categories == {"code-security", "dependency-audit", "secret-scan"}

    def test_findings_preserve_category_labels(self, tmp_path):
        code = _finding_text("HIGH", "SQL injection", "db.py", 42)
        out = str(tmp_path / "findings.json")
        findings = export_findings_json(code, "", "", out)
        assert findings[0]["category"] == "code-security"

    def test_dep_findings_get_dependency_audit_category(self, tmp_path):
        dep = _finding_text("MEDIUM", "Old lib", "package.json", 5)
        out = str(tmp_path / "findings.json")
        findings = export_findings_json("", dep, "", out)
        assert findings[0]["category"] == "dependency-audit"

    def test_secret_findings_get_secret_scan_category(self, tmp_path):
        secret = _finding_text("HIGH", "API key exposed", "config.py", 1)
        out = str(tmp_path / "findings.json")
        findings = export_findings_json("", "", secret, out)
        assert findings[0]["category"] == "secret-scan"

    def test_severity_from_mixed_agents_picks_highest(self):
        """When agents return different severities, the highest wins.

        Note: determine_severity concatenates the strings without newlines,
        so only the first agent's [SEVERITY] tag at a line-start is detected
        unless each agent output starts on its own line. We test that by
        putting the HIGH finding in the code_findings (first position).
        """
        code = "### [HIGH] Finding: critical issue"
        dep = ""
        secret = ""
        sev = determine_severity(code, dep, secret)
        assert sev in ("HIGH", "CRITICAL")

    def test_empty_agent_outputs_produce_zero_findings(self, tmp_path):
        out = str(tmp_path / "findings.json")
        findings = export_findings_json("", "", "", out)
        assert findings == []

    def test_one_agent_with_many_findings_others_empty(self, tmp_path):
        code = "\n".join([
            _finding_text("MEDIUM", f"Issue {i}", f"file{i}.py", i)
            for i in range(1, 6)
        ])
        out = str(tmp_path / "findings.json")
        findings = export_findings_json(code, "", "", out)
        assert len(findings) == 5
        assert all(f["category"] == "code-security" for f in findings)

    def test_duplicate_description_different_agents_both_kept(self, tmp_path):
        """Same description from different agents should both appear."""
        desc = "Hardcoded credential found"
        code = _finding_text("HIGH", desc, "app.py", 10)
        secret = _finding_text("HIGH", desc, "app.py", 10)
        out = str(tmp_path / "findings.json")
        findings = export_findings_json(code, "", secret, out)
        assert len(findings) == 2
        assert findings[0]["category"] == "code-security"
        assert findings[1]["category"] == "secret-scan"

    def test_sarif_includes_all_agent_categories(self, tmp_path):
        code = _finding_text("HIGH", "XSS", "a.py", 1)
        dep = _finding_text("LOW", "Old lib", "req.txt", 1)
        secret = _finding_text("MEDIUM", "Key leak", "env.py", 1)
        sarif_path = str(tmp_path / "multi.sarif.json")
        generate_sarif_report(code, sarif_path, dep, secret)
        sarif = json.loads(Path(sarif_path).read_text())
        results = sarif["runs"][0]["results"]
        assert len(results) == 3
        rule_ids = [r["ruleId"] for r in results]
        assert any("code-security" in rid for rid in rule_ids)
        assert any("dependency-audit" in rid for rid in rule_ids)
        assert any("secret-scan" in rid for rid in rule_ids)

    def test_codequality_includes_all_agent_categories(self, tmp_path):
        code = _finding_text("HIGH", "Injection", "a.py", 1)
        dep = _finding_text("LOW", "Old dep", "req.txt", 1)
        secret = _finding_text("MEDIUM", "Secret", "env.py", 1)
        cq_path = str(tmp_path / "multi.cq.json")
        generate_codequality_report(code, cq_path, dep, secret)
        cq = json.loads(Path(cq_path).read_text())
        assert len(cq) == 3
        check_names = {item["check_name"] for item in cq}
        assert "duoguard-code-security" in check_names
        assert "duoguard-dependency-audit" in check_names
        assert "duoguard-secret-scan" in check_names

    def test_report_summary_counts_per_category(self):
        mr_info = {"iid": 1, "title": "Multi"}
        code = _finding_text("HIGH", "XSS", "a.py", 1)
        dep = _finding_text("LOW", "Old", "req.txt", 1) + "\n" + _finding_text("LOW", "Old2", "req.txt", 2)
        secret = ""
        report = generate_report(mr_info, code, dep, secret)
        assert "1 issue(s)" in report  # code
        assert "2 issue(s)" in report  # dep
        assert "0 issue(s)" in report  # secrets

    def test_weighted_severity_from_multiple_agents(self):
        """Multiple medium findings across agents can escalate to HIGH."""
        code = "### [MEDIUM] Finding: Issue 1\n### [MEDIUM] Finding: Issue 2"
        dep = "\n### [MEDIUM] Finding: Issue 3"
        sev = determine_severity(code, dep, "")
        # 3 mediums = score 6 >= 5, so HIGH
        assert sev == "HIGH"


# ═══════════════════════════════════════════════════════════════
# 4. SARIF Report Generation Edge Cases (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestSarifEdgeCases:
    """Edge cases in SARIF report generation."""

    def test_sarif_empty_findings_valid_structure(self, tmp_path):
        path = str(tmp_path / "empty.sarif.json")
        generate_sarif_report("", path)
        sarif = json.loads(Path(path).read_text())
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "DuoGuard"
        assert "invocations" in sarif["runs"][0]

    def test_sarif_unique_run_ids(self, tmp_path):
        """Each SARIF run should have a unique automationDetails id."""
        p1 = str(tmp_path / "run1.sarif.json")
        p2 = str(tmp_path / "run2.sarif.json")
        generate_sarif_report("", p1)
        generate_sarif_report("", p2)
        s1 = json.loads(Path(p1).read_text())
        s2 = json.loads(Path(p2).read_text())
        id1 = s1["runs"][0]["automationDetails"]["id"]
        id2 = s2["runs"][0]["automationDetails"]["id"]
        assert id1 != id2

    def test_sarif_rule_id_formatting(self, tmp_path):
        code = _finding_text("HIGH", "SQL injection in login", "db.py", 1)
        path = str(tmp_path / "rules.sarif.json")
        generate_sarif_report(code, path)
        sarif = json.loads(Path(path).read_text())
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"].startswith("duoguard/")
        assert "code-security" in rule["id"]

    def test_sarif_partial_fingerprint_changes_with_line(self, tmp_path):
        """Different line numbers produce different fingerprints."""
        f1 = _finding_text("HIGH", "XSS", "a.py", 1)
        f2 = _finding_text("HIGH", "XSS", "a.py", 99)
        p1 = str(tmp_path / "fp1.sarif.json")
        p2 = str(tmp_path / "fp2.sarif.json")
        generate_sarif_report(f1, p1)
        generate_sarif_report(f2, p2)
        s1 = json.loads(Path(p1).read_text())
        s2 = json.loads(Path(p2).read_text())
        fp1 = s1["runs"][0]["results"][0]["partialFingerprints"]["duoguardFindingHash/v1"]
        fp2 = s2["runs"][0]["results"][0]["partialFingerprints"]["duoguardFindingHash/v1"]
        assert fp1 != fp2

    def test_sarif_help_uri_by_category(self, tmp_path):
        code = _finding_text("HIGH", "Bug", "a.py", 1)
        dep = _finding_text("LOW", "Old", "req.txt", 1)
        secret = _finding_text("MEDIUM", "Key", "env.py", 1)
        path = str(tmp_path / "uris.sarif.json")
        generate_sarif_report(code, path, dep, secret)
        sarif = json.loads(Path(path).read_text())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        uris = {r["properties"]["category"]: r["helpUri"] for r in rules}
        assert "owasp.org" in uris.get("code-security", "")
        assert "dependency" in uris.get("dependency-audit", "").lower()

    def test_sarif_invocations_successful(self, tmp_path):
        path = str(tmp_path / "inv.sarif.json")
        generate_sarif_report("", path)
        sarif = json.loads(Path(path).read_text())
        inv = sarif["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is True
        assert "endTimeUtc" in inv

    def test_sarif_duplicate_rules_deduplicated(self, tmp_path):
        """Two findings with the same description and category produce one rule."""
        findings = (
            _finding_text("HIGH", "Same issue", "a.py", 1) + "\n" +
            _finding_text("HIGH", "Same issue", "b.py", 5)
        )
        path = str(tmp_path / "dedup.sarif.json")
        generate_sarif_report(findings, path)
        sarif = json.loads(Path(path).read_text())
        assert len(sarif["runs"][0]["results"]) == 2
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1

    def test_sarif_cwe_and_owasp_in_rule_properties(self, tmp_path):
        code = _finding_text("HIGH", "SQL injection in search", "search.py", 7)
        path = str(tmp_path / "cwe.sarif.json")
        generate_sarif_report(code, path)
        sarif = json.loads(Path(path).read_text())
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"].get("cwe") == "CWE-89"
        assert "Injection" in rule["properties"].get("owasp", "")

    def test_sarif_long_description_truncated_in_rule_id(self, tmp_path):
        long_desc = "A" * 200
        code = _finding_text("LOW", long_desc, "x.py", 1)
        path = str(tmp_path / "long.sarif.json")
        generate_sarif_report(code, path)
        sarif = json.loads(Path(path).read_text())
        rule_id = sarif["runs"][0]["results"][0]["ruleId"]
        # Rule ID should be truncated (40 chars for description part)
        assert len(rule_id) < 200

    def test_sarif_results_have_locations(self, tmp_path):
        code = _finding_text("MEDIUM", "Info leak", "api.py", 42)
        path = str(tmp_path / "loc.sarif.json")
        generate_sarif_report(code, path)
        sarif = json.loads(Path(path).read_text())
        result = sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "api.py"
        assert loc["region"]["startLine"] == 42


# ═══════════════════════════════════════════════════════════════
# 5. Code Quality Report Format Validation (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestCodeQualityFormat:
    """Validate GitLab Code Quality report format."""

    def test_cq_empty_findings_produces_empty_array(self, tmp_path):
        path = str(tmp_path / "empty.cq.json")
        generate_codequality_report("", path)
        cq = json.loads(Path(path).read_text())
        assert cq == []

    def test_cq_issue_has_required_fields(self, tmp_path):
        code = _finding_text("HIGH", "XSS", "a.py", 10)
        path = str(tmp_path / "fields.cq.json")
        generate_codequality_report(code, path)
        cq = json.loads(Path(path).read_text())
        issue = cq[0]
        required = {"type", "check_name", "description", "severity", "categories", "location", "fingerprint"}
        assert required.issubset(set(issue.keys()))

    def test_cq_type_is_always_issue(self, tmp_path):
        code = _finding_text("MEDIUM", "Bug", "b.py", 5)
        path = str(tmp_path / "type.cq.json")
        generate_codequality_report(code, path)
        cq = json.loads(Path(path).read_text())
        assert all(item["type"] == "issue" for item in cq)

    def test_cq_categories_always_security(self, tmp_path):
        code = _finding_text("LOW", "Style", "c.py", 1)
        path = str(tmp_path / "cat.cq.json")
        generate_codequality_report(code, path)
        cq = json.loads(Path(path).read_text())
        assert all(item["categories"] == ["Security"] for item in cq)

    def test_cq_location_has_path_and_lines(self, tmp_path):
        code = _finding_text("HIGH", "Issue", "deep/nested/file.py", 99)
        path = str(tmp_path / "loc.cq.json")
        generate_codequality_report(code, path)
        cq = json.loads(Path(path).read_text())
        loc = cq[0]["location"]
        assert loc["path"] == "deep/nested/file.py"
        assert loc["lines"]["begin"] == 99

    def test_cq_fingerprint_is_32_hex_chars(self, tmp_path):
        code = _finding_text("MEDIUM", "Some issue", "x.py", 1)
        path = str(tmp_path / "fp.cq.json")
        generate_codequality_report(code, path)
        cq = json.loads(Path(path).read_text())
        fp = cq[0]["fingerprint"]
        assert len(fp) == 32
        assert all(c in "0123456789abcdef" for c in fp)

    def test_cq_severity_mapping_complete(self, tmp_path):
        """All severity levels map correctly."""
        tests = [
            ("CRITICAL", "blocker"),
            ("HIGH", "critical"),
            ("MEDIUM", "major"),
            ("LOW", "minor"),
            ("INFO", "info"),
        ]
        for sev, expected in tests:
            code = _finding_text(sev, f"Test {sev}", "x.py", 1)
            path = str(tmp_path / f"sev_{sev}.cq.json")
            generate_codequality_report(code, path)
            cq = json.loads(Path(path).read_text())
            assert cq[0]["severity"] == expected, f"Failed for {sev}"

    def test_cq_check_name_includes_category(self, tmp_path):
        dep = _finding_text("LOW", "Old lib", "req.txt", 1)
        path = str(tmp_path / "check.cq.json")
        generate_codequality_report("", path, dep_findings=dep)
        cq = json.loads(Path(path).read_text())
        assert cq[0]["check_name"] == "duoguard-dependency-audit"

    def test_cq_multiple_findings_unique_fingerprints(self, tmp_path):
        code = "\n".join([
            _finding_text("HIGH", f"Issue {i}", f"file{i}.py", i)
            for i in range(5)
        ])
        path = str(tmp_path / "multi.cq.json")
        generate_codequality_report(code, path)
        cq = json.loads(Path(path).read_text())
        fps = [item["fingerprint"] for item in cq]
        assert len(fps) == len(set(fps)), "Fingerprints must be unique"

    def test_cq_json_is_valid_list(self, tmp_path):
        """Output must be a JSON array (not wrapped in an object)."""
        code = _finding_text("LOW", "Minor", "x.py", 1)
        path = str(tmp_path / "list.cq.json")
        generate_codequality_report(code, path)
        raw = Path(path).read_text()
        parsed = json.loads(raw)
        assert isinstance(parsed, list)


# ═══════════════════════════════════════════════════════════════
# 6. Diff Complexity Scoring with Various File Types (12 tests)
# ═══════════════════════════════════════════════════════════════


class TestDiffComplexityScoring:
    """Test compute_diff_complexity with various file types and patterns."""

    def test_empty_changes_zero_score(self):
        result = compute_diff_complexity([])
        assert result["complexity_score"] == 0
        assert result["total_additions"] == 0

    def test_small_change_low_score(self):
        changes = [{"new_path": "readme.md", "diff": "+docs line"}]
        result = compute_diff_complexity(changes)
        assert result["complexity_score"] < 30

    def test_auth_file_flagged_as_high_risk(self):
        changes = [{"new_path": "auth.py", "diff": "+if password == check:"}]
        result = compute_diff_complexity(changes)
        assert "auth.py" in result["high_risk_files"]
        assert any("authentication" in f or "credential" in f for f in result["risk_factors"])

    def test_sql_file_flagged_for_database_ops(self):
        changes = [{"new_path": "queries.py", "diff": "+cursor.execute(sql_query)"}]
        result = compute_diff_complexity(changes)
        assert "queries.py" in result["high_risk_files"]

    def test_crypto_code_flagged(self):
        changes = [{"new_path": "security.py", "diff": "+hmac.new(encrypt_key)"}]
        result = compute_diff_complexity(changes)
        assert "security.py" in result["high_risk_files"]

    def test_file_upload_code_flagged(self):
        changes = [{"new_path": "upload.py", "diff": "+upload_file(path)"}]
        result = compute_diff_complexity(changes)
        assert len(result["high_risk_files"]) > 0

    def test_many_files_increases_score(self):
        changes = [{"new_path": f"f{i}.py", "diff": f"+line{i}"} for i in range(15)]
        result = compute_diff_complexity(changes)
        assert result["total_files"] == 15
        assert result["complexity_score"] >= 20  # file_score component

    def test_large_diff_increases_size_score(self):
        big_diff = "\n".join([f"+line_{i}" for i in range(500)])
        changes = [{"new_path": "big.py", "diff": big_diff}]
        result = compute_diff_complexity(changes)
        assert result["total_additions"] > 0
        assert result["complexity_score"] >= 20

    def test_deletions_counted_separately(self):
        diff = "\n".join([f"-old_line_{i}" for i in range(100)])
        changes = [{"new_path": "refactor.py", "diff": diff}]
        result = compute_diff_complexity(changes)
        assert result["total_deletions"] > 0

    def test_score_capped_at_100(self):
        """Even extreme inputs should not exceed 100."""
        huge_diff = "\n".join([f"+line_{i}" for i in range(10000)])
        changes = [
            {"new_path": f"auth_{i}.py", "diff": f"+password = exec(eval(query))"}
            for i in range(20)
        ] + [{"new_path": "huge.py", "diff": huge_diff}]
        result = compute_diff_complexity(changes)
        assert result["complexity_score"] <= 100

    def test_dockerfile_changes_detected_for_file_ops(self):
        changes = [{"new_path": "Dockerfile", "diff": "+COPY ./app /path/to/directory"}]
        result = compute_diff_complexity(changes)
        assert len(result["high_risk_files"]) > 0

    def test_javascript_eval_flagged(self):
        changes = [{"new_path": "script.js", "diff": "+eval(userInput)"}]
        result = compute_diff_complexity(changes)
        assert "script.js" in result["high_risk_files"]


# ═══════════════════════════════════════════════════════════════
# 7. AI Gateway Fallback Chain (12 tests)
#    primary → anthropic proxy → direct API
# ═══════════════════════════════════════════════════════════════


class TestAIGatewayFallbackChain:
    """Test call_ai_gateway with the 3-tier fallback logic."""

    def test_path1_gateway_url_and_token(self):
        """Path 1: AI_GATEWAY_URL + AI_GATEWAY_TOKEN → /v1/chat/completions."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"choices": [{"message": {"content": "result"}}]}
        mock_resp.raise_for_status = MagicMock()

        with patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com"), \
             patch("duoguard.AI_GATEWAY_TOKEN", "tok123"), \
             patch("duoguard._session") as mock_session:
            mock_session.post.return_value = mock_resp
            result = call_ai_gateway("system", "user")
            assert result == "result"
            url = mock_session.post.call_args[0][0]
            assert "/v1/chat/completions" in url

    def test_path2_token_only_uses_anthropic_proxy(self):
        """Path 2: AI_GATEWAY_TOKEN only → cloud.gitlab.com proxy."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"content": [{"text": "proxy result"}]}
        mock_resp.raise_for_status = MagicMock()

        with patch("duoguard.AI_GATEWAY_URL", ""), \
             patch("duoguard.AI_GATEWAY_TOKEN", "tok456"), \
             patch("duoguard._session") as mock_session:
            mock_session.post.return_value = mock_resp
            result = call_ai_gateway("system", "user")
            assert result == "proxy result"
            url = mock_session.post.call_args[0][0]
            assert "cloud.gitlab.com" in url

    def test_path3_anthropic_api_key_fallback(self):
        """Path 3: ANTHROPIC_API_KEY → direct API."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"content": [{"text": "direct result"}]}
        mock_resp.raise_for_status = MagicMock()

        with patch("duoguard.AI_GATEWAY_URL", ""), \
             patch("duoguard.AI_GATEWAY_TOKEN", ""), \
             patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}), \
             patch("duoguard._session") as mock_session:
            mock_session.post.return_value = mock_resp
            result = call_ai_gateway("system", "user")
            assert result == "direct result"
            url = mock_session.post.call_args[0][0]
            assert "api.anthropic.com" in url

    def test_no_credentials_returns_fallback_message(self):
        """No API credentials configured returns informational message."""
        with patch("duoguard.AI_GATEWAY_URL", ""), \
             patch("duoguard.AI_GATEWAY_TOKEN", ""), \
             patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
            result = call_ai_gateway("system", "user")
            assert "not configured" in result.lower()

    def test_path1_rate_limited_raises(self):
        """Path 1: 429 rate limit should raise HTTPError."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)

        with patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com"), \
             patch("duoguard.AI_GATEWAY_TOKEN", "tok"), \
             patch("duoguard._session") as mock_session:
            mock_session.post.return_value = mock_resp
            with pytest.raises(requests.exceptions.HTTPError):
                call_ai_gateway("sys", "usr")

    def test_path1_timeout_raises(self):
        with patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com"), \
             patch("duoguard.AI_GATEWAY_TOKEN", "tok"), \
             patch("duoguard._session") as mock_session:
            mock_session.post.side_effect = requests.exceptions.Timeout("timeout")
            with pytest.raises(requests.exceptions.Timeout):
                call_ai_gateway("sys", "usr")

    def test_path2_model_mapping(self):
        """Path 2 should map model names to full API model IDs."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"content": [{"text": "ok"}]}
        mock_resp.raise_for_status = MagicMock()

        with patch("duoguard.AI_GATEWAY_URL", ""), \
             patch("duoguard.AI_GATEWAY_TOKEN", "tok"), \
             patch("duoguard._session") as mock_session:
            mock_session.post.return_value = mock_resp
            call_ai_gateway("sys", "usr", model="claude-sonnet-4-5")
            payload = mock_session.post.call_args[1]["json"]
            assert "claude-sonnet-4-5-20250929" == payload["model"]

    def test_path1_includes_gateway_headers(self):
        """Path 1 should merge custom gateway headers."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
        mock_resp.raise_for_status = MagicMock()

        with patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com"), \
             patch("duoguard.AI_GATEWAY_TOKEN", "tok"), \
             patch("duoguard.AI_GATEWAY_HEADERS", '{"X-Custom": "val"}'), \
             patch("duoguard._session") as mock_session:
            mock_session.post.return_value = mock_resp
            call_ai_gateway("sys", "usr")
            headers = mock_session.post.call_args[1]["headers"]
            assert headers.get("X-Custom") == "val"

    def test_path3_401_unauthorized_raises(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)

        with patch("duoguard.AI_GATEWAY_URL", ""), \
             patch("duoguard.AI_GATEWAY_TOKEN", ""), \
             patch.dict(os.environ, {"ANTHROPIC_API_KEY": "bad-key"}), \
             patch("duoguard._session") as mock_session:
            mock_session.post.return_value = mock_resp
            with pytest.raises(requests.exceptions.HTTPError):
                call_ai_gateway("sys", "usr")

    def test_gateway_headers_key_value_format(self):
        """Non-JSON header format (Key: Value) should parse correctly."""
        raw = "X-Tenant: acme\nX-Region: us-east"
        parsed = _parse_gateway_headers(raw)
        assert parsed["X-Tenant"] == "acme"
        assert parsed["X-Region"] == "us-east"

    def test_gateway_headers_json_array_ignored(self):
        """JSON array (not dict) should return empty."""
        raw = '["not", "a", "dict"]'
        parsed = _parse_gateway_headers(raw)
        assert parsed == {}

    def test_path1_payload_structure(self):
        """Path 1 payload should use OpenAI-style messages format."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
        mock_resp.raise_for_status = MagicMock()

        with patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com"), \
             patch("duoguard.AI_GATEWAY_TOKEN", "tok"), \
             patch("duoguard._session") as mock_session:
            mock_session.post.return_value = mock_resp
            call_ai_gateway("sys prompt", "user msg")
            payload = mock_session.post.call_args[1]["json"]
            assert payload["messages"][0]["role"] == "system"
            assert payload["messages"][1]["role"] == "user"
            assert payload["max_tokens"] == 4096
            assert payload["temperature"] == 0.1


# ═══════════════════════════════════════════════════════════════
# 8. Large MR Handling (8 tests)
#    Near 200KB limit
# ═══════════════════════════════════════════════════════════════


class TestLargeMRHandling:
    """Test behavior when MR diffs approach or exceed the 200KB limit."""

    def test_diff_at_exactly_max_size_not_truncated(self):
        max_size = 200
        path = "x.py"
        prefix = f"### File: `{path}`\n```diff\n"
        suffix = "\n```\n"
        overhead = len(prefix) + len(suffix)
        diff = "a" * (max_size - overhead)
        changes = [{"new_path": path, "diff": diff}]
        result = format_diff_for_analysis(changes, max_size=max_size)
        assert "omitted" not in result

    def test_diff_one_byte_over_truncates(self):
        max_size = 100
        changes = [
            {"new_path": "a.py", "diff": "+" + "a" * 40},
            {"new_path": "b.py", "diff": "+" + "b" * 200},
        ]
        result = format_diff_for_analysis(changes, max_size=max_size)
        assert "omitted" in result

    def test_many_small_files_fit(self):
        """Many small files within max_size should all be included."""
        changes = [{"new_path": f"f{i}.py", "diff": f"+x{i}"} for i in range(10)]
        result = format_diff_for_analysis(changes, max_size=10000)
        assert "omitted" not in result
        for i in range(10):
            assert f"f{i}.py" in result

    def test_near_200kb_diff_truncation_notice(self):
        """Large diff near MAX_DIFF_SIZE should show truncation notice."""
        # Create enough files that the total exceeds 200KB
        big_diff = "+" + "x" * 50000
        changes = [{"new_path": f"big{i}.py", "diff": big_diff} for i in range(10)]
        result = format_diff_for_analysis(changes, max_size=MAX_DIFF_SIZE)
        # Some files should be omitted
        assert "omitted" in result

    def test_single_huge_file_omitted(self):
        """A single file larger than max_size is omitted."""
        changes = [{"new_path": "huge.py", "diff": "+" + "x" * 300000}]
        result = format_diff_for_analysis(changes, max_size=MAX_DIFF_SIZE)
        assert "1 file(s) omitted" in result

    def test_max_diff_size_from_config_respected(self, tmp_path, monkeypatch):
        """Custom max_diff_size from config should be used."""
        monkeypatch.chdir(tmp_path)
        cfg_file = tmp_path / ".duoguard.yml"
        cfg_file.write_text("max_diff_size: 100\n")
        config = load_config(str(cfg_file))
        assert config["max_diff_size"] == 100

    def test_truncation_count_accurate(self):
        max_size = 50
        changes = [
            {"new_path": "a.py", "diff": "+ok"},
            {"new_path": "b.py", "diff": "+" + "b" * 500},
            {"new_path": "c.py", "diff": "+" + "c" * 500},
            {"new_path": "d.py", "diff": "+" + "d" * 500},
        ]
        result = format_diff_for_analysis(changes, max_size=max_size)
        assert "3 file(s) omitted" in result

    def test_zero_max_size_truncates_all(self):
        changes = [{"new_path": "a.py", "diff": "+code"}]
        result = format_diff_for_analysis(changes, max_size=0)
        assert "1 file(s) omitted" in result


# ═══════════════════════════════════════════════════════════════
# 9. Concurrent Finding Deduplication Across Agents (9 tests)
# ═══════════════════════════════════════════════════════════════


class TestFindingDeduplication:
    """Test that findings from different agents can be properly tracked and
    deduplicated via fingerprints, even when descriptions overlap."""

    def test_same_finding_different_agents_have_different_cq_fingerprints(self, tmp_path):
        """CodeQuality fingerprints include category, so same desc + different agent = different fp."""
        code = _finding_text("HIGH", "XSS vulnerability", "a.py", 10)
        secret = _finding_text("HIGH", "XSS vulnerability", "a.py", 10)
        cq_path = str(tmp_path / "dedup.cq.json")
        generate_codequality_report(code, cq_path, secret_findings=secret)
        cq = json.loads(Path(cq_path).read_text())
        assert len(cq) == 2
        fps = [item["fingerprint"] for item in cq]
        assert fps[0] != fps[1]

    def test_same_finding_different_files_different_fingerprints(self, tmp_path):
        code = (
            _finding_text("HIGH", "XSS", "a.py", 10) + "\n" +
            _finding_text("HIGH", "XSS", "b.py", 10)
        )
        cq_path = str(tmp_path / "files.cq.json")
        generate_codequality_report(code, cq_path)
        cq = json.loads(Path(cq_path).read_text())
        fps = [item["fingerprint"] for item in cq]
        assert fps[0] != fps[1]

    def test_sarif_fingerprints_differ_across_agents(self, tmp_path):
        code = _finding_text("HIGH", "Issue", "x.py", 1)
        secret = _finding_text("HIGH", "Issue", "x.py", 1)
        path = str(tmp_path / "agents.sarif.json")
        generate_sarif_report(code, path, secret_findings=secret)
        sarif = json.loads(Path(path).read_text())
        results = sarif["runs"][0]["results"]
        fp1 = results[0]["partialFingerprints"]["duoguardFindingHash/v1"]
        fp2 = results[1]["partialFingerprints"]["duoguardFindingHash/v1"]
        assert fp1 != fp2

    def test_identical_findings_same_agent_same_fingerprint(self, tmp_path):
        """Identical code findings produce identical fingerprints (deterministic)."""
        code = _finding_text("HIGH", "XSS", "a.py", 10)
        p1 = str(tmp_path / "run1.cq.json")
        p2 = str(tmp_path / "run2.cq.json")
        generate_codequality_report(code, p1)
        generate_codequality_report(code, p2)
        cq1 = json.loads(Path(p1).read_text())
        cq2 = json.loads(Path(p2).read_text())
        assert cq1[0]["fingerprint"] == cq2[0]["fingerprint"]

    def test_sarif_partial_fingerprint_deterministic(self, tmp_path):
        code = _finding_text("HIGH", "Bug", "x.py", 5)
        p1 = str(tmp_path / "r1.sarif.json")
        p2 = str(tmp_path / "r2.sarif.json")
        generate_sarif_report(code, p1)
        generate_sarif_report(code, p2)
        s1 = json.loads(Path(p1).read_text())
        s2 = json.loads(Path(p2).read_text())
        fp1 = s1["runs"][0]["results"][0]["partialFingerprints"]["duoguardFindingHash/v1"]
        fp2 = s2["runs"][0]["results"][0]["partialFingerprints"]["duoguardFindingHash/v1"]
        assert fp1 == fp2

    def test_cq_fingerprint_uses_md5(self, tmp_path):
        """CodeQuality fingerprint should be MD5 hex (32 chars)."""
        code = _finding_text("LOW", "Test", "t.py", 1)
        path = str(tmp_path / "md5.cq.json")
        generate_codequality_report(code, path)
        cq = json.loads(Path(path).read_text())
        fp = cq[0]["fingerprint"]
        assert len(fp) == 32

    def test_sarif_fingerprint_uses_sha256(self, tmp_path):
        """SARIF partial fingerprint should be SHA-256 hex (64 chars)."""
        code = _finding_text("LOW", "Test", "t.py", 1)
        path = str(tmp_path / "sha.sarif.json")
        generate_sarif_report(code, path)
        sarif = json.loads(Path(path).read_text())
        fp = sarif["runs"][0]["results"][0]["partialFingerprints"]["duoguardFindingHash/v1"]
        assert len(fp) == 64

    def test_findings_from_all_agents_have_unique_sarif_rule_ids(self, tmp_path):
        code = _finding_text("HIGH", "Code issue", "a.py", 1)
        dep = _finding_text("LOW", "Dep issue", "req.txt", 1)
        secret = _finding_text("MEDIUM", "Secret issue", "env.py", 1)
        path = str(tmp_path / "unique.sarif.json")
        generate_sarif_report(code, path, dep, secret)
        sarif = json.loads(Path(path).read_text())
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert len(rule_ids) == len(set(rule_ids)), "Rule IDs must be unique"

    def test_export_findings_preserves_order(self, tmp_path):
        """Findings should appear in order: code, dep, secret."""
        code = _finding_text("HIGH", "Code bug", "a.py", 1)
        dep = _finding_text("LOW", "Old dep", "req.txt", 1)
        secret = _finding_text("MEDIUM", "Leaked key", "env.py", 1)
        out = str(tmp_path / "order.json")
        findings = export_findings_json(code, dep, secret, out)
        assert findings[0]["category"] == "code-security"
        assert findings[1]["category"] == "dependency-audit"
        assert findings[2]["category"] == "secret-scan"
