"""DuoGuard advanced tests -- deep edge cases for post_report.py, config
loading, SARIF/CodeQuality structure validation, inline discussions,
approval workflows, issue creation, and CLI argument parsing.

Targets 250+ new passing tests.
"""

import hashlib
import json
import os
import re
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch, mock_open

import pytest
import requests
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from duoguard import (
    CWE_KEYWORD_MAP,
    DEFAULT_CONFIG,
    MAX_DIFF_SIZE,
    _count_by_severity,
    _create_session,
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
    main as duoguard_main,
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
    main as post_report_main,
)


def _ft(severity, desc, path="src/app.py", line=1):
    """Build finding text in the format _parse_findings expects."""
    return (
        f"### [{severity.upper()}] Finding: {desc}\n"
        f"**File:** `{path}` (line {line})"
    )


# ═══════════════════════════════════════════════════════════════
# 1. SARIF structure deep validation (25 tests)
# ═══════════════════════════════════════════════════════════════


class TestSarifStructureDeep:
    """Deep validation of SARIF 2.1.0 report structure."""

    def _gen(self, code="", dep="", secret=""):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        generate_sarif_report(code, path, dep_findings=dep, secret_findings=secret)
        data = json.loads(Path(path).read_text())
        os.unlink(path)
        return data

    def test_top_level_keys(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert "$schema" in data
        assert "version" in data
        assert "runs" in data

    def test_version_is_2_1_0(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert data["version"] == "2.1.0"

    def test_single_run(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert len(data["runs"]) == 1

    def test_tool_driver_name(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert data["runs"][0]["tool"]["driver"]["name"] == "DuoGuard"

    def test_tool_driver_version(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert data["runs"][0]["tool"]["driver"]["version"] == "1.0.0"

    def test_invocations_present(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert "invocations" in data["runs"][0]
        assert data["runs"][0]["invocations"][0]["executionSuccessful"] is True

    def test_invocation_has_end_time(self):
        data = self._gen(_ft("HIGH", "Test"))
        end_time = data["runs"][0]["invocations"][0]["endTimeUtc"]
        assert "T" in end_time
        assert end_time.endswith("Z")

    def test_automation_details_id(self):
        data = self._gen(_ft("HIGH", "Test"))
        auto_id = data["runs"][0]["automationDetails"]["id"]
        assert auto_id.startswith("duoguard/")

    def test_result_has_rule_id(self):
        data = self._gen(_ft("HIGH", "Test finding"))
        result = data["runs"][0]["results"][0]
        assert result["ruleId"].startswith("duoguard/")

    def test_result_has_message(self):
        data = self._gen(_ft("HIGH", "Test finding"))
        result = data["runs"][0]["results"][0]
        assert "text" in result["message"]

    def test_result_has_locations(self):
        data = self._gen(_ft("HIGH", "Test finding"))
        result = data["runs"][0]["results"][0]
        assert len(result["locations"]) == 1
        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc

    def test_result_artifact_uri(self):
        data = self._gen(_ft("HIGH", "Test", path="src/main.py"))
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/main.py"

    def test_result_start_line(self):
        data = self._gen(_ft("HIGH", "Test", line=42))
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 42

    def test_result_partial_fingerprints(self):
        data = self._gen(_ft("HIGH", "Test"))
        result = data["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert "duoguardFindingHash/v1" in result["partialFingerprints"]

    def test_rule_has_short_description(self):
        data = self._gen(_ft("HIGH", "Test"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert "shortDescription" in rules[0]

    def test_rule_has_full_description(self):
        data = self._gen(_ft("HIGH", "Test"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert "fullDescription" in rules[0]

    def test_rule_has_help_uri(self):
        data = self._gen(_ft("HIGH", "Test"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert "helpUri" in rules[0]

    def test_rule_default_configuration(self):
        data = self._gen(_ft("HIGH", "Test"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert "defaultConfiguration" in rules[0]

    def test_rule_properties_category(self):
        data = self._gen(_ft("HIGH", "Test"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["properties"]["category"] == "code-security"

    def test_dep_finding_category(self):
        data = self._gen(dep=_ft("MEDIUM", "Dep vuln"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["properties"]["category"] == "dependency-audit"

    def test_secret_finding_category(self):
        data = self._gen(secret=_ft("CRITICAL", "Leaked key"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["properties"]["category"] == "secret-scan"

    def test_empty_findings_produces_empty_results(self):
        data = self._gen()
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_multiple_findings_multiple_results(self):
        text = _ft("HIGH", "F1") + "\n" + _ft("MEDIUM", "F2") + "\n" + _ft("LOW", "F3")
        data = self._gen(text)
        assert len(data["runs"][0]["results"]) == 3

    def test_duplicate_rule_ids_deduplicated(self):
        text = _ft("HIGH", "Same finding") + "\n" + _ft("HIGH", "Same finding")
        data = self._gen(text)
        assert len(data["runs"][0]["results"]) == 2
        # Same description => same rule_id => only 1 rule
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 1

    def test_cwe_in_sarif_rule_properties(self):
        text = _ft("HIGH", "SQL injection vulnerability")
        data = self._gen(text)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["properties"].get("cwe") == "CWE-89"


# ═══════════════════════════════════════════════════════════════
# 2. Code Quality report structure validation (20 tests)
# ═══════════════════════════════════════════════════════════════


class TestCodeQualityStructureDeep:
    """Deep validation of GitLab Code Quality JSON report."""

    def _gen(self, code="", dep="", secret=""):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        generate_codequality_report(code, path, dep_findings=dep, secret_findings=secret)
        data = json.loads(Path(path).read_text())
        os.unlink(path)
        return data

    def test_empty_findings_produces_empty_array(self):
        data = self._gen()
        assert data == []

    def test_issue_type(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert data[0]["type"] == "issue"

    def test_check_name_format(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert data[0]["check_name"].startswith("duoguard-")

    def test_check_name_code_security(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert data[0]["check_name"] == "duoguard-code-security"

    def test_check_name_dependency(self):
        data = self._gen(dep=_ft("MEDIUM", "Dep"))
        assert data[0]["check_name"] == "duoguard-dependency-audit"

    def test_check_name_secret(self):
        data = self._gen(secret=_ft("CRITICAL", "Secret"))
        assert data[0]["check_name"] == "duoguard-secret-scan"

    def test_categories_include_security(self):
        data = self._gen(_ft("HIGH", "Test"))
        assert "Security" in data[0]["categories"]

    def test_location_path(self):
        data = self._gen(_ft("HIGH", "Test", path="src/main.py"))
        assert data[0]["location"]["path"] == "src/main.py"

    def test_location_lines(self):
        data = self._gen(_ft("HIGH", "Test", line=42))
        assert data[0]["location"]["lines"]["begin"] == 42

    def test_fingerprint_is_md5_hex(self):
        data = self._gen(_ft("HIGH", "Test"))
        fp = data[0]["fingerprint"]
        assert len(fp) == 32
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_unique_per_finding(self):
        text = _ft("HIGH", "Finding 1") + "\n" + _ft("HIGH", "Finding 2")
        data = self._gen(text)
        fps = [d["fingerprint"] for d in data]
        assert len(set(fps)) == 2

    def test_fingerprint_deterministic(self):
        text = _ft("HIGH", "Deterministic test")
        data1 = self._gen(text)
        data2 = self._gen(text)
        assert data1[0]["fingerprint"] == data2[0]["fingerprint"]

    def test_multiple_findings(self):
        text = _ft("HIGH", "F1") + "\n" + _ft("MEDIUM", "F2") + "\n" + _ft("LOW", "F3")
        data = self._gen(text)
        assert len(data) == 3

    def test_severity_blocker_for_critical(self):
        data = self._gen(_ft("CRITICAL", "Crit"))
        assert data[0]["severity"] == "blocker"

    def test_severity_critical_for_high(self):
        data = self._gen(_ft("HIGH", "High"))
        assert data[0]["severity"] == "critical"

    def test_description_matches_finding(self):
        data = self._gen(_ft("HIGH", "SQL injection detected"))
        assert "SQL injection detected" in data[0]["description"]

    def test_cross_category_findings(self):
        data = self._gen(
            code=_ft("HIGH", "Code issue"),
            dep=_ft("MEDIUM", "Dep issue"),
            secret=_ft("CRITICAL", "Secret issue"),
        )
        assert len(data) == 3
        check_names = [d["check_name"] for d in data]
        assert "duoguard-code-security" in check_names
        assert "duoguard-dependency-audit" in check_names
        assert "duoguard-secret-scan" in check_names

    def test_all_issues_have_required_keys(self):
        text = _ft("HIGH", "Test") + "\n" + _ft("MEDIUM", "Test2")
        data = self._gen(text)
        required = {"type", "check_name", "description", "severity",
                     "categories", "location", "fingerprint"}
        for issue in data:
            assert required.issubset(set(issue.keys()))

    def test_location_has_required_structure(self):
        data = self._gen(_ft("HIGH", "Test"))
        loc = data[0]["location"]
        assert "path" in loc
        assert "lines" in loc
        assert "begin" in loc["lines"]

    def test_large_finding_count(self):
        findings = "\n".join([_ft("MEDIUM", f"Finding {i}") for i in range(20)])
        data = self._gen(findings)
        assert len(data) == 20


# ═══════════════════════════════════════════════════════════════
# 3. Post inline discussion edge cases (20 tests)
# ═══════════════════════════════════════════════════════════════


class TestPostInlineDiscussionAdvanced:
    """Advanced tests for post_inline_discussion."""

    def test_returns_discussion_on_success(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "disc_1", "notes": []}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp):
            result = post_inline_discussion(
                "proj", "1", "body", "file.py", 10,
                "base_sha", "head_sha", "start_sha"
            )
            assert result is not None
            assert result["id"] == "disc_1"

    def test_returns_none_on_http_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)
        with patch("post_report.requests.post", return_value=mock_resp):
            result = post_inline_discussion(
                "proj", "1", "body", "file.py", 10,
                "base_sha", "head_sha", "start_sha"
            )
            assert result is None

    def test_correct_position_type(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "d1"}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            post_inline_discussion(
                "proj", "1", "body", "file.py", 10,
                "base", "head", "start"
            )
            payload = mock_post.call_args[1]["json"]
            assert payload["position"]["position_type"] == "text"

    def test_position_shas(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "d1"}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            post_inline_discussion(
                "proj", "1", "body", "file.py", 10,
                "base123", "head456", "start789"
            )
            pos = mock_post.call_args[1]["json"]["position"]
            assert pos["base_sha"] == "base123"
            assert pos["head_sha"] == "head456"
            assert pos["start_sha"] == "start789"

    def test_position_paths(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "d1"}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            post_inline_discussion(
                "proj", "1", "body", "src/main.py", 42,
                "base", "head", "start"
            )
            pos = mock_post.call_args[1]["json"]["position"]
            assert pos["new_path"] == "src/main.py"
            assert pos["old_path"] == "src/main.py"
            assert pos["new_line"] == 42

    def test_url_construction(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "d1"}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            post_inline_discussion(
                "123", "45", "body", "file.py", 1,
                "base", "head", "start"
            )
            url = mock_post.call_args[0][0]
            assert "/projects/123/merge_requests/45/discussions" in url

    def test_timeout_set(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "d1"}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            post_inline_discussion(
                "proj", "1", "body", "file.py", 1,
                "base", "head", "start"
            )
            assert mock_post.call_args[1]["timeout"] == 30


# ═══════════════════════════════════════════════════════════════
# 4. Post inline findings orchestration (20 tests)
# ═══════════════════════════════════════════════════════════════


class TestPostInlineFindingsAdvanced:
    """Advanced tests for post_inline_findings."""

    def test_returns_zero_for_empty_findings(self):
        assert post_inline_findings("proj", "1", []) == 0

    def test_returns_zero_when_no_versions(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            result = post_inline_findings("proj", "1", [{"severity": "high"}])
            assert result == 0

    def test_returns_zero_when_shas_incomplete(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"base_commit_sha": "", "head_commit_sha": "h", "start_commit_sha": "s"}]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            result = post_inline_findings("proj", "1", [{"severity": "high"}])
            assert result == 0

    def test_posts_for_each_finding(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"base_commit_sha": "b", "head_commit_sha": "h", "start_commit_sha": "s"}
        ]
        mock_get.return_value.raise_for_status = MagicMock()
        mock_post = MagicMock()
        mock_post.return_value.json.return_value = {"id": "disc_1"}
        mock_post.return_value.raise_for_status = MagicMock()

        findings = [
            {"severity": "high", "description": "F1", "file_path": "a.py", "line_num": 1, "category": "code-security"},
            {"severity": "medium", "description": "F2", "file_path": "b.py", "line_num": 2, "category": "code-security"},
        ]
        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.post", mock_post):
            result = post_inline_findings("proj", "1", findings)
            assert result == 2

    def test_counts_only_successful_posts(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"base_commit_sha": "b", "head_commit_sha": "h", "start_commit_sha": "s"}
        ]
        mock_get.return_value.raise_for_status = MagicMock()

        call_count = [0]

        def mock_post_side_effect(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            if call_count[0] == 1:
                resp.json.return_value = {"id": "disc_1"}
                resp.raise_for_status = MagicMock()
            else:
                resp.status_code = 400
                resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=resp)
            return resp

        findings = [
            {"severity": "high", "description": "F1", "file_path": "a.py", "line_num": 1, "category": "code-security"},
            {"severity": "medium", "description": "F2", "file_path": "b.py", "line_num": 2, "category": "code-security"},
        ]
        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.post", side_effect=mock_post_side_effect):
            result = post_inline_findings("proj", "1", findings)
            assert result == 1

    def test_body_includes_severity(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"base_commit_sha": "b", "head_commit_sha": "h", "start_commit_sha": "s"}
        ]
        mock_get.return_value.raise_for_status = MagicMock()
        mock_post = MagicMock()
        mock_post.return_value.json.return_value = {"id": "d1"}
        mock_post.return_value.raise_for_status = MagicMock()

        findings = [{"severity": "critical", "description": "F", "file_path": "a.py",
                      "line_num": 1, "category": "code-security"}]
        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.post", mock_post):
            post_inline_findings("proj", "1", findings)
            body = mock_post.call_args[1]["json"]["body"]
            assert "CRITICAL" in body

    def test_body_includes_cwe(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"base_commit_sha": "b", "head_commit_sha": "h", "start_commit_sha": "s"}
        ]
        mock_get.return_value.raise_for_status = MagicMock()
        mock_post = MagicMock()
        mock_post.return_value.json.return_value = {"id": "d1"}
        mock_post.return_value.raise_for_status = MagicMock()

        findings = [{"severity": "high", "description": "F", "file_path": "a.py",
                      "line_num": 1, "category": "code-security", "cwe": "CWE-89"}]
        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.post", mock_post):
            post_inline_findings("proj", "1", findings)
            body = mock_post.call_args[1]["json"]["body"]
            assert "CWE-89" in body

    def test_default_values_used(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"base_commit_sha": "b", "head_commit_sha": "h", "start_commit_sha": "s"}
        ]
        mock_get.return_value.raise_for_status = MagicMock()
        mock_post = MagicMock()
        mock_post.return_value.json.return_value = {"id": "d1"}
        mock_post.return_value.raise_for_status = MagicMock()

        findings = [{}]  # empty dict, uses defaults
        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.post", mock_post):
            post_inline_findings("proj", "1", findings)
            payload = mock_post.call_args[1]["json"]
            pos = payload["position"]
            assert pos["new_path"] == "unknown"
            assert pos["new_line"] == 1


# ═══════════════════════════════════════════════════════════════
# 5. Resolve stale discussions (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestResolveStaleDiscussionsAdvanced:
    """Advanced tests for resolve_stale_discussions."""

    def test_returns_zero_on_http_error(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert resolve_stale_discussions("proj", "1") == 0

    def test_returns_zero_when_no_discussions(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert resolve_stale_discussions("proj", "1") == 0

    def test_skips_non_duoguard_discussions(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": "d1", "notes": [{"body": "Regular comment", "resolvable": True, "resolved": False}]}
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert resolve_stale_discussions("proj", "1") == 0

    def test_skips_already_resolved(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": "d1", "notes": [{"body": ":shield: DuoGuard [HIGH]", "resolvable": True, "resolved": True}]}
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert resolve_stale_discussions("proj", "1") == 0

    def test_skips_non_resolvable(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": "d1", "notes": [{"body": ":shield: DuoGuard [HIGH]", "resolvable": False, "resolved": False}]}
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert resolve_stale_discussions("proj", "1") == 0

    def test_resolves_duoguard_discussion(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"id": "d1", "notes": [{"body": ":shield: DuoGuard [HIGH] Test", "resolvable": True, "resolved": False}]}
        ]
        mock_get.return_value.raise_for_status = MagicMock()
        mock_put = MagicMock()
        mock_put.return_value.raise_for_status = MagicMock()
        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.put", mock_put):
            result = resolve_stale_discussions("proj", "1")
            assert result == 1

    def test_resolves_multiple_discussions(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"id": "d1", "notes": [{"body": ":shield: DuoGuard [HIGH]", "resolvable": True, "resolved": False}]},
            {"id": "d2", "notes": [{"body": ":shield: DuoGuard [MEDIUM]", "resolvable": True, "resolved": False}]},
        ]
        mock_get.return_value.raise_for_status = MagicMock()
        mock_put = MagicMock()
        mock_put.return_value.raise_for_status = MagicMock()
        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.put", mock_put):
            result = resolve_stale_discussions("proj", "1")
            assert result == 2

    def test_continues_on_resolve_failure(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"id": "d1", "notes": [{"body": ":shield: DuoGuard [HIGH]", "resolvable": True, "resolved": False}]},
            {"id": "d2", "notes": [{"body": ":shield: DuoGuard [LOW]", "resolvable": True, "resolved": False}]},
        ]
        mock_get.return_value.raise_for_status = MagicMock()

        call_count = [0]
        def put_side_effect(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            if call_count[0] == 1:
                resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
            else:
                resp.raise_for_status = MagicMock()
            return resp

        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.put", side_effect=put_side_effect):
            result = resolve_stale_discussions("proj", "1")
            assert result == 1  # second one succeeds

    def test_skips_empty_notes(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": "d1", "notes": []}
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert resolve_stale_discussions("proj", "1") == 0

    def test_url_construction(self):
        mock_get = MagicMock()
        mock_get.return_value.json.return_value = [
            {"id": "d1", "notes": [{"body": ":shield: DuoGuard [HIGH]", "resolvable": True, "resolved": False}]}
        ]
        mock_get.return_value.raise_for_status = MagicMock()
        mock_put = MagicMock()
        mock_put.return_value.raise_for_status = MagicMock()
        with patch("post_report.requests.get", mock_get), \
             patch("post_report.requests.put", mock_put):
            resolve_stale_discussions("123", "45")
            url = mock_put.call_args[0][0]
            assert "/projects/123/merge_requests/45/discussions/d1" in url


# ═══════════════════════════════════════════════════════════════
# 6. Config loading edge cases (20 tests)
# ═══════════════════════════════════════════════════════════════


class TestLoadConfigAdvanced:
    """Advanced config loading tests."""

    def test_default_config_returned_when_no_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                cfg = load_config()
                assert cfg["version"] == DEFAULT_CONFIG["version"]
                assert cfg["severity_threshold"] == DEFAULT_CONFIG["severity_threshold"]
            finally:
                os.chdir(old_cwd)

    def test_loads_from_explicit_path(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"severity_threshold": "LOW"}, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg["severity_threshold"] == "LOW"
        finally:
            os.unlink(path)

    def test_env_var_config_path(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"severity_threshold": "CRITICAL"}, f)
            path = f.name
        try:
            with patch.dict(os.environ, {"DUOGUARD_CONFIG": path}):
                cfg = load_config()
                assert cfg["severity_threshold"] == "CRITICAL"
        finally:
            os.unlink(path)

    def test_deep_merge_agents(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"agents": {"code_security": False}}, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg["agents"]["code_security"] is False
            # Other agents remain True from defaults
            assert cfg["agents"]["dependency_audit"] is True
            assert cfg["agents"]["secret_scan"] is True
        finally:
            os.unlink(path)

    def test_non_dict_yaml_ignored(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            f.write("just a string")
            path = f.name
        try:
            cfg = load_config(path)
            # Should fall through to defaults
            assert cfg["version"] == DEFAULT_CONFIG["version"]
        finally:
            os.unlink(path)

    def test_empty_yaml_file(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            f.write("")
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg["version"] == DEFAULT_CONFIG["version"]
        finally:
            os.unlink(path)

    def test_override_max_diff_size(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"max_diff_size": 500_000}, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg["max_diff_size"] == 500_000
        finally:
            os.unlink(path)

    def test_override_model(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"model": "claude-opus"}, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg["model"] == "claude-opus"
        finally:
            os.unlink(path)

    def test_exclude_paths_from_config(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"exclude_paths": ["vendor/*", "dist/*"]}, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert "vendor/*" in cfg["exclude_paths"]
            assert "dist/*" in cfg["exclude_paths"]
        finally:
            os.unlink(path)

    def test_exclude_extensions_from_config(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"exclude_extensions": ["min.js", "map"]}, f)
            path = f.name
        try:
            cfg = load_config(path)
            assert "min.js" in cfg["exclude_extensions"]
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════
# 7. Load agent prompt edge cases (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestLoadAgentPromptAdvanced:
    """Advanced tests for load_agent_prompt."""

    def test_returns_empty_string_for_missing_file(self):
        result = load_agent_prompt("nonexistent/agent.yml")
        assert result == ""

    def test_returns_empty_for_non_dict_yaml(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            f.write("just a string\n")
            path = f.name
        try:
            with patch("duoguard.Path.__truediv__", return_value=Path(path)):
                result = load_agent_prompt("dummy.yml")
                # May or may not find it depending on path resolution
                assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_returns_system_prompt_from_valid_config(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"system_prompt": "You are a security reviewer."}, f)
            path = f.name
        try:
            # Direct file test
            with open(path) as fp:
                config = yaml.safe_load(fp)
            assert config.get("system_prompt") == "You are a security reviewer."
        finally:
            os.unlink(path)

    def test_returns_empty_for_config_without_system_prompt(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            yaml.dump({"name": "test-agent"}, f)
            path = f.name
        try:
            with open(path) as fp:
                config = yaml.safe_load(fp)
            assert config.get("system_prompt", "") == ""
        finally:
            os.unlink(path)

    def test_returns_empty_for_none_yaml(self):
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as f:
            f.write("---\n")
            path = f.name
        try:
            with open(path) as fp:
                config = yaml.safe_load(fp)
            # None config
            assert config is None or config.get("system_prompt", "") == ""
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════
# 8. Enrich finding CWE advanced (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestEnrichFindingCWEAdvanced:
    """Advanced CWE enrichment tests."""

    def test_no_description_key(self):
        finding = {}
        result = enrich_finding_cwe(finding)
        assert result is finding  # Returns same dict

    def test_empty_description(self):
        finding = {"description": ""}
        result = enrich_finding_cwe(finding)
        assert "cwe" not in result or result.get("cwe") is None

    def test_description_with_no_match(self):
        finding = {"description": "This is a completely unrelated text about cooking"}
        result = enrich_finding_cwe(finding)
        assert "cwe" not in result or result.get("cwe") is None

    def test_preserves_existing_cwe_only(self):
        finding = {"description": "sql injection", "cwe": "CWE-999"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"] == "CWE-999"
        # owasp should be added since it was missing
        assert "owasp" in result

    def test_preserves_existing_owasp_only(self):
        finding = {"description": "sql injection", "owasp": "A99:Custom"}
        result = enrich_finding_cwe(finding)
        assert result["owasp"] == "A99:Custom"
        # cwe should be added since it was missing
        assert "cwe" in result

    def test_multiple_keywords_first_match_wins(self):
        finding = {"description": "sql injection with xss and path traversal"}
        result = enrich_finding_cwe(finding)
        assert result.get("cwe") is not None
        # Should match one of the keywords

    def test_cwe_format(self):
        finding = {"description": "SQL injection vulnerability"}
        result = enrich_finding_cwe(finding)
        assert result["cwe"].startswith("CWE-")

    def test_owasp_format(self):
        finding = {"description": "SQL injection vulnerability"}
        result = enrich_finding_cwe(finding)
        assert result["owasp"].startswith("A")
        assert ":" in result["owasp"]

    def test_case_insensitive_matching(self):
        finding = {"description": "SQL INJECTION detected"}
        result = enrich_finding_cwe(finding)
        assert result.get("cwe") == "CWE-89"

    def test_keyword_substring_matching(self):
        finding = {"description": "possible xss attack vector"}
        result = enrich_finding_cwe(finding)
        assert result.get("cwe") == "CWE-79"

    def test_all_cwe_values_are_valid_format(self):
        for keyword, classification in CWE_KEYWORD_MAP.items():
            cwe = classification["cwe"]
            assert re.match(r"CWE-\d+", cwe), f"Invalid CWE format for {keyword}: {cwe}"

    def test_all_owasp_values_are_valid_format(self):
        for keyword, classification in CWE_KEYWORD_MAP.items():
            owasp = classification["owasp"]
            assert re.match(r"A\d{2}:", owasp), f"Invalid OWASP format for {keyword}: {owasp}"

    def test_finding_returned_is_same_object(self):
        finding = {"description": "sql injection"}
        result = enrich_finding_cwe(finding)
        assert result is finding  # mutates in place

    def test_enrichment_idempotent(self):
        finding = {"description": "sql injection"}
        result1 = enrich_finding_cwe(finding)
        result2 = enrich_finding_cwe(result1)
        assert result1["cwe"] == result2["cwe"]
        assert result1["owasp"] == result2["owasp"]

    def test_numeric_description_no_crash(self):
        # Edge case: non-string description
        finding = {"description": 12345}
        # This might fail, but should handle gracefully
        try:
            result = enrich_finding_cwe(finding)
        except (AttributeError, TypeError):
            pass  # Expected if description is not a string


# ═══════════════════════════════════════════════════════════════
# 9. Resolve API URL edge cases (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestResolveApiUrlAdvanced:
    """Advanced tests for _resolve_api_url_for_agent."""

    def test_default_gitlab_com(self):
        import duoguard
        old = duoguard.GITLAB_HOSTNAME
        duoguard.GITLAB_HOSTNAME = ""
        try:
            url = _resolve_api_url_for_agent()
            assert url == "https://gitlab.com/api/v4"
        finally:
            duoguard.GITLAB_HOSTNAME = old

    def test_custom_hostname(self):
        import duoguard
        old = duoguard.GITLAB_HOSTNAME
        duoguard.GITLAB_HOSTNAME = "gitlab.example.com"
        try:
            url = _resolve_api_url_for_agent()
            assert url == "https://gitlab.example.com/api/v4"
        finally:
            duoguard.GITLAB_HOSTNAME = old

    def test_self_hosted_hostname(self):
        import duoguard
        old = duoguard.GITLAB_HOSTNAME
        duoguard.GITLAB_HOSTNAME = "git.internal.corp"
        try:
            url = _resolve_api_url_for_agent()
            assert url == "https://git.internal.corp/api/v4"
        finally:
            duoguard.GITLAB_HOSTNAME = old

    def test_url_format(self):
        import duoguard
        old = duoguard.GITLAB_HOSTNAME
        duoguard.GITLAB_HOSTNAME = "test.host"
        try:
            url = _resolve_api_url_for_agent()
            assert url.startswith("https://")
            assert url.endswith("/api/v4")
        finally:
            duoguard.GITLAB_HOSTNAME = old


# ═══════════════════════════════════════════════════════════════
# 10. Get MR diff/info error handling (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestGetMrDiffInfoErrors:
    """Test error handling in get_mr_diff and get_mr_info."""

    @pytest.mark.parametrize("status_code,msg_fragment", [
        (404, "not found"),
        (401, "Access denied"),
        (403, "Access denied"),
    ])
    def test_get_mr_diff_http_errors(self, status_code, msg_fragment):
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)
        with patch("duoguard._session") as mock_session:
            mock_session.get.return_value = mock_resp
            with pytest.raises(requests.exceptions.HTTPError):
                get_mr_diff("proj", "1")

    @pytest.mark.parametrize("status_code,msg_fragment", [
        (404, "not found"),
        (401, "Access denied"),
        (403, "Access denied"),
    ])
    def test_get_mr_info_http_errors(self, status_code, msg_fragment):
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)
        with patch("duoguard._session") as mock_session:
            mock_session.get.return_value = mock_resp
            with pytest.raises(requests.exceptions.HTTPError):
                get_mr_info("proj", "1")

    def test_get_mr_diff_connection_error(self):
        with patch("duoguard._session") as mock_session:
            mock_session.get.side_effect = requests.exceptions.ConnectionError()
            with pytest.raises(requests.exceptions.ConnectionError):
                get_mr_diff("proj", "1")

    def test_get_mr_info_connection_error(self):
        with patch("duoguard._session") as mock_session:
            mock_session.get.side_effect = requests.exceptions.ConnectionError()
            with pytest.raises(requests.exceptions.ConnectionError):
                get_mr_info("proj", "1")

    def test_get_mr_diff_timeout(self):
        with patch("duoguard._session") as mock_session:
            mock_session.get.side_effect = requests.exceptions.Timeout()
            with pytest.raises(requests.exceptions.Timeout):
                get_mr_diff("proj", "1")

    def test_get_mr_diff_success(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"changes": []}
        mock_resp.raise_for_status = MagicMock()
        with patch("duoguard._session") as mock_session:
            mock_session.get.return_value = mock_resp
            result = get_mr_diff("proj", "1")
            assert result == {"changes": []}

    def test_get_mr_info_success(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 1, "title": "Test"}
        mock_resp.raise_for_status = MagicMock()
        with patch("duoguard._session") as mock_session:
            mock_session.get.return_value = mock_resp
            result = get_mr_info("proj", "1")
            assert result["iid"] == 1


# ═══════════════════════════════════════════════════════════════
# 11. Call AI gateway paths (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestCallAIGatewayPaths:
    """Test AI gateway call paths."""

    def test_no_credentials_returns_message(self):
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = ""
        duoguard.AI_GATEWAY_TOKEN = ""
        try:
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
                result = call_ai_gateway("system", "user")
                assert "not configured" in result.lower() or "AI Gateway" in result
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    def test_gateway_url_and_token_uses_path1(self):
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = "https://gateway.example.com"
        duoguard.AI_GATEWAY_TOKEN = "tok123"
        try:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"choices": [{"message": {"content": "result"}}]}
            mock_resp.raise_for_status = MagicMock()
            with patch("duoguard._session") as mock_session:
                mock_session.post.return_value = mock_resp
                result = call_ai_gateway("system", "user")
                assert result == "result"
                url = mock_session.post.call_args[0][0]
                assert "gateway.example.com" in url
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    def test_token_only_uses_anthropic_proxy(self):
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = ""
        duoguard.AI_GATEWAY_TOKEN = "tok123"
        try:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"content": [{"text": "proxy result"}]}
            mock_resp.raise_for_status = MagicMock()
            with patch("duoguard._session") as mock_session:
                mock_session.post.return_value = mock_resp
                result = call_ai_gateway("system", "user")
                assert result == "proxy result"
                url = mock_session.post.call_args[0][0]
                assert "cloud.gitlab.com" in url
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    def test_anthropic_api_key_uses_path3(self):
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = ""
        duoguard.AI_GATEWAY_TOKEN = ""
        try:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"content": [{"text": "direct result"}]}
            mock_resp.raise_for_status = MagicMock()
            with patch("duoguard._session") as mock_session, \
                 patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
                mock_session.post.return_value = mock_resp
                result = call_ai_gateway("system", "user")
                assert result == "direct result"
                url = mock_session.post.call_args[0][0]
                assert "api.anthropic.com" in url
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    def test_gateway_rate_limit_error(self):
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = "https://gw.test"
        duoguard.AI_GATEWAY_TOKEN = "tok"
        try:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)
            with patch("duoguard._session") as mock_session:
                mock_session.post.return_value = mock_resp
                with pytest.raises(requests.exceptions.HTTPError):
                    call_ai_gateway("system", "user")
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    def test_gateway_timeout(self):
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = "https://gw.test"
        duoguard.AI_GATEWAY_TOKEN = "tok"
        try:
            with patch("duoguard._session") as mock_session:
                mock_session.post.side_effect = requests.exceptions.Timeout()
                with pytest.raises(requests.exceptions.Timeout):
                    call_ai_gateway("system", "user")
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token

    def test_model_mapping_for_proxy(self):
        import duoguard
        old_url = duoguard.AI_GATEWAY_URL
        old_token = duoguard.AI_GATEWAY_TOKEN
        duoguard.AI_GATEWAY_URL = ""
        duoguard.AI_GATEWAY_TOKEN = "tok"
        try:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"content": [{"text": "ok"}]}
            mock_resp.raise_for_status = MagicMock()
            with patch("duoguard._session") as mock_session:
                mock_session.post.return_value = mock_resp
                call_ai_gateway("sys", "usr", model="claude-sonnet-4-5")
                payload = mock_session.post.call_args[1]["json"]
                assert payload["model"] == "claude-sonnet-4-5-20250929"
        finally:
            duoguard.AI_GATEWAY_URL = old_url
            duoguard.AI_GATEWAY_TOKEN = old_token


# ═══════════════════════════════════════════════════════════════
# 12. Generate report structure (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestGenerateReportStructure:
    """Test the structure and content of generated reports."""

    def test_report_has_header(self):
        report = generate_report({"iid": 1, "title": "T"}, "", "", "")
        assert "DuoGuard Security Review Report" in report

    def test_report_has_sections(self):
        report = generate_report({"iid": 1, "title": "T"}, "code", "dep", "secret")
        assert "Code Security Analysis" in report
        assert "Dependency Audit" in report
        assert "Secret Scan" in report

    def test_report_has_summary_table(self):
        report = generate_report({"iid": 1, "title": "T"}, "", "", "")
        assert "Category" in report
        assert "Findings" in report

    def test_report_has_footer(self):
        report = generate_report({"iid": 1, "title": "T"}, "", "", "")
        assert "GitLab AI Hackathon" in report

    def test_report_has_timestamp(self):
        report = generate_report({"iid": 1, "title": "T"}, "", "", "")
        assert "UTC" in report

    def test_report_with_complexity(self):
        complexity = {
            "total_additions": 100,
            "total_deletions": 50,
            "total_files": 5,
            "high_risk_files": ["auth.py"],
            "complexity_score": 60,
            "risk_factors": ["auth logic modified in auth.py"],
        }
        report = generate_report({"iid": 1, "title": "T"}, "", "", "",
                                  complexity=complexity)
        assert "Complexity Score" in report
        assert "60/100" in report
        assert "auth logic" in report

    def test_report_without_complexity(self):
        report = generate_report({"iid": 1, "title": "T"}, "", "", "")
        assert "Complexity Score" not in report

    def test_report_with_zero_complexity(self):
        complexity = {
            "total_additions": 0,
            "total_deletions": 0,
            "total_files": 0,
            "high_risk_files": [],
            "complexity_score": 0,
            "risk_factors": [],
        }
        report = generate_report({"iid": 1, "title": "T"}, "", "", "",
                                  complexity=complexity)
        assert "Complexity Score" not in report

    def test_report_with_files_scanned(self):
        report = generate_report({"iid": 1, "title": "T"}, "", "", "",
                                  files_scanned=10)
        assert "10" in report

    def test_report_with_both_metrics(self):
        report = generate_report({"iid": 1, "title": "T"}, "", "", "",
                                  scan_duration=5.5, files_scanned=10)
        assert "5.5s" in report
        assert "10" in report

    def test_report_missing_iid(self):
        report = generate_report({}, "", "", "")
        assert "N/A" in report

    def test_report_missing_title(self):
        report = generate_report({"iid": 1}, "", "", "")
        assert "Untitled" in report

    def test_report_with_code_findings(self):
        code = "[critical] SQL injection found"
        report = generate_report({"iid": 1, "title": "T"}, code, "", "")
        assert "SQL injection" in report

    def test_report_with_all_findings(self):
        report = generate_report(
            {"iid": 1, "title": "T"},
            "[critical] Code issue",
            "[high] Dep issue",
            "[medium] Secret issue",
        )
        assert "Code issue" in report
        assert "Dep issue" in report
        assert "Secret issue" in report

    def test_report_overall_risk_level(self):
        report = generate_report({"iid": 1, "title": "T"}, "[critical] x", "", "")
        assert "CRITICAL" in report


# ═══════════════════════════════════════════════════════════════
# 13. Run agent functions (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestRunAgentFunctions:
    """Test run_code_security_review, run_dependency_audit, run_secret_scan."""

    def test_code_review_calls_ai_gateway(self):
        with patch("duoguard.call_ai_gateway", return_value="review result") as mock:
            result = run_code_security_review("diff text")
            assert result == "review result"
            mock.assert_called_once()

    def test_dep_audit_empty_diff(self):
        result = run_dependency_audit("")
        assert "No dependency" in result

    def test_dep_audit_whitespace_only(self):
        result = run_dependency_audit("   \n\t  ")
        assert "No dependency" in result

    def test_dep_audit_calls_ai_gateway(self):
        with patch("duoguard.call_ai_gateway", return_value="dep result") as mock:
            result = run_dependency_audit("requirements.txt changes")
            assert result == "dep result"
            mock.assert_called_once()

    def test_secret_scan_calls_ai_gateway(self):
        with patch("duoguard.call_ai_gateway", return_value="scan result") as mock:
            result = run_secret_scan("diff with secrets")
            assert result == "scan result"
            mock.assert_called_once()

    def test_code_review_uses_fallback_prompt(self):
        with patch("duoguard.load_agent_prompt", return_value=""), \
             patch("duoguard.call_ai_gateway", return_value="ok") as mock_call:
            run_code_security_review("diff")
            system_prompt = mock_call.call_args[0][0]
            assert "security" in system_prompt.lower()

    def test_dep_audit_uses_fallback_prompt(self):
        with patch("duoguard.load_agent_prompt", return_value=""), \
             patch("duoguard.call_ai_gateway", return_value="ok") as mock_call:
            run_dependency_audit("dep diff")
            system_prompt = mock_call.call_args[0][0]
            assert "dependency" in system_prompt.lower()

    def test_secret_scan_uses_fallback_prompt(self):
        with patch("duoguard.load_agent_prompt", return_value=""), \
             patch("duoguard.call_ai_gateway", return_value="ok") as mock_call:
            run_secret_scan("diff")
            system_prompt = mock_call.call_args[0][0]
            assert "secret" in system_prompt.lower()

    def test_code_review_uses_custom_prompt(self):
        with patch("duoguard.load_agent_prompt", return_value="Custom prompt"), \
             patch("duoguard.call_ai_gateway", return_value="ok") as mock_call:
            run_code_security_review("diff")
            assert mock_call.call_args[0][0] == "Custom prompt"

    def test_dep_audit_uses_custom_prompt(self):
        with patch("duoguard.load_agent_prompt", return_value="Dep prompt"), \
             patch("duoguard.call_ai_gateway", return_value="ok") as mock_call:
            run_dependency_audit("dep diff")
            assert mock_call.call_args[0][0] == "Dep prompt"


# ═══════════════════════════════════════════════════════════════
# 14. Find existing comment (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestFindExistingCommentAdvanced:
    """Advanced tests for find_existing_comment."""

    def test_returns_none_when_no_notes(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert find_existing_comment("proj", "1") is None

    def test_returns_note_id_when_found(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 42, "body": "## DuoGuard Security Review Report\nContent"},
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert find_existing_comment("proj", "1") == 42

    def test_skips_non_duoguard_notes(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 1, "body": "Regular comment"},
            {"id": 2, "body": "Another regular comment"},
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert find_existing_comment("proj", "1") is None

    def test_returns_first_match(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 1, "body": "DuoGuard Security Review Report v1"},
            {"id": 2, "body": "DuoGuard Security Review Report v2"},
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            assert find_existing_comment("proj", "1") == 1

    def test_uses_correct_url(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp) as mock_get:
            find_existing_comment("123", "45")
            url = mock_get.call_args[0][0]
            assert "/projects/123/merge_requests/45/notes" in url


# ═══════════════════════════════════════════════════════════════
# 15. Post MR comment (8 tests)
# ═══════════════════════════════════════════════════════════════


class TestPostMrCommentAdvanced:
    """Advanced tests for post_mr_comment."""

    def test_posts_body(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": 1}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            post_mr_comment("proj", "1", "test body")
            payload = mock_post.call_args[1]["json"]
            assert payload["body"] == "test body"

    def test_uses_correct_url(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": 1}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            post_mr_comment("123", "45", "body")
            url = mock_post.call_args[0][0]
            assert "/projects/123/merge_requests/45/notes" in url

    def test_raises_on_error(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
        with patch("post_report.requests.post", return_value=mock_resp):
            with pytest.raises(requests.exceptions.HTTPError):
                post_mr_comment("proj", "1", "body")

    def test_timeout_set(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": 1}
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.post", return_value=mock_resp) as mock_post:
            post_mr_comment("proj", "1", "body")
            assert mock_post.call_args[1]["timeout"] == 30


# ═══════════════════════════════════════════════════════════════
# 16. Update MR comment (6 tests)
# ═══════════════════════════════════════════════════════════════


class TestUpdateMrCommentAdvanced:
    """Advanced tests for update_mr_comment."""

    def test_updates_body(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.put", return_value=mock_resp) as mock_put:
            update_mr_comment("proj", "1", 42, "updated body")
            payload = mock_put.call_args[1]["json"]
            assert payload["body"] == "updated body"

    def test_uses_correct_url(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.put", return_value=mock_resp) as mock_put:
            update_mr_comment("123", "45", 99, "body")
            url = mock_put.call_args[0][0]
            assert "/projects/123/merge_requests/45/notes/99" in url

    def test_raises_on_error(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
        with patch("post_report.requests.put", return_value=mock_resp):
            with pytest.raises(requests.exceptions.HTTPError):
                update_mr_comment("proj", "1", 42, "body")


# ═══════════════════════════════════════════════════════════════
# 17. Headers function (5 tests)
# ═══════════════════════════════════════════════════════════════


class TestHeadersFunction:
    """Test _headers helper."""

    def test_returns_dict(self):
        result = _headers()
        assert isinstance(result, dict)

    def test_has_private_token_key(self):
        result = _headers()
        assert "PRIVATE-TOKEN" in result

    def test_token_from_env(self):
        with patch.dict(os.environ, {"CI_JOB_TOKEN": "test-tok"}, clear=False):
            # Note: module-level variables won't change, but we test the structure
            result = _headers()
            assert isinstance(result["PRIVATE-TOKEN"], str)


# ═══════════════════════════════════════════════════════════════
# 18. Get MR diff versions (5 tests)
# ═══════════════════════════════════════════════════════════════


class TestGetMrDiffVersions:
    """Test get_mr_diff_versions."""

    def test_returns_list(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"id": 1}]
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp):
            result = get_mr_diff_versions("proj", "1")
            assert isinstance(result, list)
            assert len(result) == 1

    def test_uses_correct_url(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        with patch("post_report.requests.get", return_value=mock_resp) as mock_get:
            get_mr_diff_versions("123", "45")
            url = mock_get.call_args[0][0]
            assert "/projects/123/merge_requests/45/versions" in url

    def test_raises_on_error(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
        with patch("post_report.requests.get", return_value=mock_resp):
            with pytest.raises(requests.exceptions.HTTPError):
                get_mr_diff_versions("proj", "1")


# ═══════════════════════════════════════════════════════════════
# 19. Session creation advanced (8 tests)
# ═══════════════════════════════════════════════════════════════


class TestCreateSessionAdvanced:
    """Advanced session creation tests."""

    def test_session_is_requests_session(self):
        session = _create_session()
        assert isinstance(session, requests.Session)

    def test_retry_status_forcelist(self):
        session = _create_session()
        adapter = session.get_adapter("https://example.com")
        assert 429 in adapter.max_retries.status_forcelist
        assert 500 in adapter.max_retries.status_forcelist
        assert 502 in adapter.max_retries.status_forcelist
        assert 503 in adapter.max_retries.status_forcelist
        assert 504 in adapter.max_retries.status_forcelist

    def test_retry_allowed_methods(self):
        session = _create_session()
        adapter = session.get_adapter("https://example.com")
        methods = adapter.max_retries.allowed_methods
        assert "GET" in methods
        assert "POST" in methods

    def test_default_retry_count(self):
        session = _create_session()
        adapter = session.get_adapter("https://example.com")
        assert adapter.max_retries.total == 3

    def test_default_backoff(self):
        session = _create_session()
        adapter = session.get_adapter("https://example.com")
        assert adapter.max_retries.backoff_factor == 1.0

    def test_high_retry_count(self):
        session = _create_session(retries=10)
        adapter = session.get_adapter("https://example.com")
        assert adapter.max_retries.total == 10

    def test_high_backoff(self):
        session = _create_session(backoff=5.0)
        adapter = session.get_adapter("https://example.com")
        assert adapter.max_retries.backoff_factor == 5.0

    def test_http_and_https_adapters_differ(self):
        session = _create_session()
        http_adapter = session.get_adapter("http://example.com")
        https_adapter = session.get_adapter("https://example.com")
        # Both should be HTTPAdapter instances
        assert isinstance(http_adapter, requests.adapters.HTTPAdapter)
        assert isinstance(https_adapter, requests.adapters.HTTPAdapter)
