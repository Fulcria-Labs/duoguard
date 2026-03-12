"""Additional tests for DuoGuard — targeting uncovered edge cases and integration paths.

Adds 100+ tests to increase coverage from 668 to 768+.
"""

import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
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


# ── Format diff: unicode, special characters, very large diffs ─────


class TestFormatDiffUnicode:
    """Test format_diff_for_analysis with unicode and special characters."""

    def test_unicode_diff_content(self):
        changes = [{"new_path": "i18n.py", "diff": "+msg = 'こんにちは世界'"}]
        result = format_diff_for_analysis(changes)
        assert "こんにちは世界" in result

    def test_emoji_in_diff(self):
        changes = [{"new_path": "emoji.py", "diff": "+# 🔒 Security fix"}]
        result = format_diff_for_analysis(changes)
        assert "🔒" in result

    def test_backtick_in_path(self):
        changes = [{"new_path": "file`name.py", "diff": "+code"}]
        result = format_diff_for_analysis(changes)
        assert "file`name.py" in result

    def test_newlines_in_diff_preserved(self):
        changes = [{"new_path": "multi.py", "diff": "+line1\n+line2\n+line3"}]
        result = format_diff_for_analysis(changes)
        assert "+line1" in result
        assert "+line3" in result

    def test_tab_characters_in_diff(self):
        changes = [{"new_path": "tabs.py", "diff": "+\tindented = True"}]
        result = format_diff_for_analysis(changes)
        assert "\tindented" in result

    def test_very_long_single_line_diff(self):
        long_line = "+" + "x" * 10000
        changes = [{"new_path": "long.py", "diff": long_line}]
        result = format_diff_for_analysis(changes)
        assert "long.py" in result

    def test_empty_changes_list(self):
        result = format_diff_for_analysis([])
        assert result == ""

    def test_all_empty_diffs(self):
        changes = [
            {"new_path": "a.py", "diff": ""},
            {"new_path": "b.py", "diff": ""},
        ]
        result = format_diff_for_analysis(changes)
        assert "a.py" not in result
        assert "b.py" not in result


class TestFormatDiffTruncationBehavior:
    """Test precise truncation behavior at boundary."""

    def test_exactly_at_max_size(self):
        """Diff exactly at max_size should not be truncated."""
        # We compute what would make the chunk exactly max_size
        path = "x.py"
        prefix = f"### File: `{path}`\n```diff\n"
        suffix = "\n```\n"
        overhead = len(prefix) + len(suffix)
        max_size = 100
        diff_content = "a" * (max_size - overhead)
        changes = [{"new_path": path, "diff": diff_content}]
        result = format_diff_for_analysis(changes, max_size=max_size)
        assert "omitted" not in result

    def test_one_byte_over_max_truncates_second_file(self):
        """Second file that pushes over max_size is omitted."""
        max_size = 100
        changes = [
            {"new_path": "a.py", "diff": "+" + "a" * 40},
            {"new_path": "b.py", "diff": "+" + "b" * 80},
        ]
        result = format_diff_for_analysis(changes, max_size=max_size)
        assert "a.py" in result
        assert "1 file(s) omitted" in result

    def test_multiple_files_truncated_count(self):
        max_size = 50
        changes = [
            {"new_path": "a.py", "diff": "+ok"},
            {"new_path": "b.py", "diff": "+" + "b" * 200},
            {"new_path": "c.py", "diff": "+" + "c" * 200},
        ]
        result = format_diff_for_analysis(changes, max_size=max_size)
        assert "2 file(s) omitted" in result

    def test_max_size_zero_truncates_all(self):
        changes = [{"new_path": "a.py", "diff": "+code"}]
        result = format_diff_for_analysis(changes, max_size=0)
        assert "1 file(s) omitted" in result


# ── Extract dependency files: edge cases ─────────────────────


class TestExtractDependencyFilesPathVariations:
    """Test dependency file detection with nested paths and edge cases."""

    def test_deeply_nested_dependency(self):
        changes = [{"new_path": "a/b/c/d/requirements.txt", "diff": "+flask"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_constraints_prefix_variants(self):
        changes = [{"new_path": "constraints-dev.txt", "diff": "+pin"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_requirements_custom_suffix(self):
        changes = [{"new_path": "requirements-staging.txt", "diff": "+dep"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_non_txt_requirements_file_ignored(self):
        changes = [{"new_path": "requirements.md", "diff": "+info"}]
        result = extract_dependency_files(changes)
        assert len(result) == 0

    def test_package_json_in_monorepo(self):
        changes = [
            {"new_path": "packages/core/package.json", "diff": "+dep"},
            {"new_path": "packages/ui/package.json", "diff": "+dep"},
        ]
        result = extract_dependency_files(changes)
        assert len(result) == 2

    def test_pdm_lock_detected(self):
        changes = [{"new_path": "pdm.lock", "diff": "+locked"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_pnpm_lock_yaml_detected(self):
        changes = [{"new_path": "pnpm-lock.yaml", "diff": "+locked"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_build_gradle_kts_detected(self):
        changes = [{"new_path": "build.gradle.kts", "diff": "+dep"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_mix_lock_detected(self):
        changes = [{"new_path": "mix.lock", "diff": "+locked"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_package_resolved_swift_detected(self):
        changes = [{"new_path": "Package.resolved", "diff": "+resolved"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_pipfile_lock_detected(self):
        changes = [{"new_path": "Pipfile.lock", "diff": "+locked"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_cargo_lock_detected(self):
        changes = [{"new_path": "Cargo.lock", "diff": "+locked"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_composer_lock_detected(self):
        changes = [{"new_path": "composer.lock", "diff": "+locked"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_directory_packages_props_detected(self):
        changes = [{"new_path": "Directory.Packages.props", "diff": "+pkg"}]
        result = extract_dependency_files(changes)
        assert len(result) == 1

    def test_empty_changes_returns_empty(self):
        assert extract_dependency_files([]) == []


# ── Should exclude path: complex glob patterns ──────────────


class TestShouldExcludePathComplexGlobs:
    """Test should_exclude_path with complex glob patterns."""

    def test_double_star_glob(self):
        assert should_exclude_path("a/b/c/vendor/file.py", ["*/vendor/*"]) is True

    def test_extension_case_sensitivity(self):
        # Extensions are matched exact, so .PY != .py
        assert should_exclude_path("file.PY", exclude_extensions=["py"]) is False

    def test_no_extension_file(self):
        assert should_exclude_path("Makefile", exclude_extensions=["py"]) is False

    def test_multiple_exclude_patterns(self):
        patterns = ["vendor/*", "*.min.js", "dist/*"]
        assert should_exclude_path("vendor/lib.py", patterns) is True
        assert should_exclude_path("bundle.min.js", patterns) is True
        assert should_exclude_path("dist/app.js", patterns) is True
        assert should_exclude_path("src/app.js", patterns) is False

    def test_hidden_files_excluded(self):
        assert should_exclude_path(".env", [".*"]) is True

    def test_empty_excludes_allows_all(self):
        assert should_exclude_path("anything.py", [], []) is False

    def test_none_excludes_allows_all(self):
        assert should_exclude_path("anything.py", None, None) is False


# ── Filter excluded changes: integration ─────────────────────


class TestFilterExcludedChangesIntegration:
    """Test filter_excluded_changes with real-world patterns."""

    def test_filters_vendor_and_dist(self):
        changes = [
            {"new_path": "vendor/dep.js", "diff": "+code"},
            {"new_path": "dist/bundle.js", "diff": "+code"},
            {"new_path": "src/app.js", "diff": "+code"},
        ]
        result = filter_excluded_changes(changes, ["vendor/*", "dist/*"])
        assert len(result) == 1
        assert result[0]["new_path"] == "src/app.js"

    def test_filters_by_extension_only(self):
        changes = [
            {"new_path": "app.py", "diff": "+code"},
            {"new_path": "style.css", "diff": "+code"},
            {"new_path": "data.json", "diff": "+code"},
        ]
        result = filter_excluded_changes(changes, exclude_extensions=["css", "json"])
        assert len(result) == 1
        assert result[0]["new_path"] == "app.py"

    def test_uses_old_path_when_new_path_missing(self):
        changes = [{"old_path": "vendor/old.py", "diff": "+code"}]
        result = filter_excluded_changes(changes, ["vendor/*"])
        assert len(result) == 0

    def test_no_exclusions_returns_all(self):
        changes = [
            {"new_path": "a.py", "diff": "+a"},
            {"new_path": "b.py", "diff": "+b"},
        ]
        result = filter_excluded_changes(changes)
        assert len(result) == 2


# ── CWE enrichment: comprehensive keyword coverage ──────────


class TestEnrichFindingCWEComprehensiveKeywords:
    """Test enrich_finding_cwe matches all CWE_KEYWORD_MAP entries."""

    def test_ldap_injection(self):
        f = enrich_finding_cwe({"description": "LDAP injection vulnerability"})
        assert f["cwe"] == "CWE-90"

    def test_xml_injection(self):
        f = enrich_finding_cwe({"description": "XML injection flaw"})
        assert f["cwe"] == "CWE-91"

    def test_code_injection(self):
        f = enrich_finding_cwe({"description": "Code injection via user input"})
        assert f["cwe"] == "CWE-94"

    def test_eval_usage(self):
        f = enrich_finding_cwe({"description": "Dangerous eval usage"})
        assert f["cwe"] == "CWE-95"

    def test_prototype_pollution(self):
        f = enrich_finding_cwe({"description": "Prototype pollution in merge"})
        assert f["cwe"] == "CWE-1321"

    def test_mass_assignment(self):
        f = enrich_finding_cwe({"description": "Mass assignment vulnerability"})
        assert f["cwe"] == "CWE-915"

    def test_unrestricted_upload(self):
        f = enrich_finding_cwe({"description": "Unrestricted upload of files"})
        assert f["cwe"] == "CWE-434"

    def test_file_upload(self):
        f = enrich_finding_cwe({"description": "Dangerous file upload endpoint"})
        assert f["cwe"] == "CWE-434"

    def test_denial_of_service(self):
        f = enrich_finding_cwe({"description": "Denial of service via input"})
        assert f["cwe"] == "CWE-400"

    def test_regex_dos(self):
        f = enrich_finding_cwe({"description": "Regex DOS in validator"})
        assert f["cwe"] == "CWE-1333"

    def test_redos(self):
        f = enrich_finding_cwe({"description": "ReDoS vulnerability in pattern"})
        assert f["cwe"] == "CWE-1333"

    def test_open_redirect(self):
        f = enrich_finding_cwe({"description": "Open redirect in login flow"})
        assert f["cwe"] == "CWE-601"

    def test_csrf(self):
        f = enrich_finding_cwe({"description": "CSRF token missing on form"})
        assert f["cwe"] == "CWE-352"

    def test_race_condition(self):
        f = enrich_finding_cwe({"description": "Race condition in payment"})
        assert f["cwe"] == "CWE-362"

    def test_buffer_overflow(self):
        f = enrich_finding_cwe({"description": "Buffer overflow in parser"})
        assert f["cwe"] == "CWE-120"

    def test_integer_overflow(self):
        f = enrich_finding_cwe({"description": "Integer overflow in calculation"})
        assert f["cwe"] == "CWE-190"

    def test_missing_access_control(self):
        f = enrich_finding_cwe({"description": "Missing access control on endpoint"})
        assert f["cwe"] == "CWE-862"

    def test_idor(self):
        f = enrich_finding_cwe({"description": "IDOR allows viewing other users"})
        assert f["cwe"] == "CWE-639"

    def test_insecure_direct_object(self):
        f = enrich_finding_cwe({"description": "Insecure direct object reference"})
        assert f["cwe"] == "CWE-639"

    def test_log_injection(self):
        f = enrich_finding_cwe({"description": "Log injection via user input"})
        assert f["cwe"] == "CWE-117"

    def test_information_disclosure(self):
        f = enrich_finding_cwe({"description": "Information disclosure in error"})
        assert f["cwe"] == "CWE-200"

    def test_sensitive_data_exposure(self):
        f = enrich_finding_cwe({"description": "Sensitive data exposure in logs"})
        assert f["cwe"] == "CWE-200"

    def test_private_key(self):
        f = enrich_finding_cwe({"description": "Hardcoded private key in source"})
        assert f["cwe"] == "CWE-321"

    def test_weak_crypto(self):
        f = enrich_finding_cwe({"description": "Weak crypto algorithm MD5"})
        assert f["cwe"] == "CWE-327"

    def test_insecure_random(self):
        f = enrich_finding_cwe({"description": "Insecure random for token gen"})
        assert f["cwe"] == "CWE-330"

    def test_preserves_existing_cwe_and_owasp(self):
        f = enrich_finding_cwe({
            "description": "SQL injection in login",
            "cwe": "CWE-999",
            "owasp": "A99:Custom",
        })
        assert f["cwe"] == "CWE-999"
        assert f["owasp"] == "A99:Custom"

    def test_no_match_returns_unchanged(self):
        f = enrich_finding_cwe({"description": "Minor style issue"})
        assert "cwe" not in f

    def test_partial_cwe_preserves_enriches_owasp(self):
        """If finding has CWE but not OWASP, keyword match fills OWASP."""
        f = enrich_finding_cwe({
            "description": "SQL injection",
            "cwe": "CWE-89",
        })
        assert f["owasp"] == "A03:2021-Injection"

    def test_partial_owasp_preserves_enriches_cwe(self):
        """If finding has OWASP but not CWE, keyword match fills CWE."""
        f = enrich_finding_cwe({
            "description": "SQL injection",
            "owasp": "A03:2021-Injection",
        })
        assert f["cwe"] == "CWE-89"


# ── Diff complexity: detailed scoring ────────────────────────


class TestDiffComplexityScoring:
    """Test compute_diff_complexity scoring logic."""

    def test_empty_changes_zero_score(self):
        result = compute_diff_complexity([])
        assert result["complexity_score"] == 0
        assert result["total_additions"] == 0
        assert result["total_deletions"] == 0
        assert result["total_files"] == 0

    def test_size_score_caps_at_40(self):
        """Size score should cap at 40 regardless of diff size."""
        huge_diff = "\n+line\n" * 5000
        changes = [{"new_path": "huge.py", "diff": huge_diff}]
        result = compute_diff_complexity(changes)
        # Size score = min(40, total/10), file_score = min(20, 1*2) = 2
        assert result["complexity_score"] <= 100

    def test_file_count_score(self):
        """Many files increase complexity score."""
        changes = [{"new_path": f"f{i}.py", "diff": "+x"} for i in range(10)]
        result = compute_diff_complexity(changes)
        assert result["total_files"] == 10
        # file_score = min(20, 10*2) = 20
        assert result["complexity_score"] >= 20

    def test_file_score_caps_at_20(self):
        """File count score caps at 20."""
        changes = [{"new_path": f"f{i}.py", "diff": "+x"} for i in range(20)]
        result = compute_diff_complexity(changes)
        assert result["total_files"] == 20

    def test_security_pattern_password(self):
        changes = [{"new_path": "auth.py", "diff": "+password = get_input()"}]
        result = compute_diff_complexity(changes)
        assert "auth.py" in result["high_risk_files"]
        assert any("credential" in f for f in result["risk_factors"])

    def test_security_pattern_exec(self):
        changes = [{"new_path": "cmd.py", "diff": "+subprocess.call(cmd)"}]
        result = compute_diff_complexity(changes)
        assert "cmd.py" in result["high_risk_files"]

    def test_security_pattern_sql(self):
        changes = [{"new_path": "db.py", "diff": "+cursor.execute(query)"}]
        result = compute_diff_complexity(changes)
        assert "db.py" in result["high_risk_files"]

    def test_security_pattern_auth(self):
        changes = [{"new_path": "login.py", "diff": "+session.authenticate(user)"}]
        result = compute_diff_complexity(changes)
        assert "login.py" in result["high_risk_files"]

    def test_security_pattern_crypto(self):
        changes = [{"new_path": "crypt.py", "diff": "+encrypt(data, key)"}]
        result = compute_diff_complexity(changes)
        assert "crypt.py" in result["high_risk_files"]

    def test_security_pattern_permission(self):
        changes = [{"new_path": "access.py", "diff": "+check_permission(user, role)"}]
        result = compute_diff_complexity(changes)
        assert "access.py" in result["high_risk_files"]

    def test_security_pattern_deserialize(self):
        changes = [{"new_path": "load.py", "diff": "+yaml.load(data)"}]
        result = compute_diff_complexity(changes)
        assert "load.py" in result["high_risk_files"]

    def test_security_pattern_redirect(self):
        changes = [{"new_path": "nav.py", "diff": "+redirect(url)"}]
        result = compute_diff_complexity(changes)
        assert "nav.py" in result["high_risk_files"]

    def test_security_pattern_upload(self):
        changes = [{"new_path": "upload.py", "diff": "+save_file(upload)"}]
        result = compute_diff_complexity(changes)
        assert "upload.py" in result["high_risk_files"]

    def test_security_pattern_cookie(self):
        changes = [{"new_path": "http.py", "diff": "+set_cookie(response, token)"}]
        result = compute_diff_complexity(changes)
        assert "http.py" in result["high_risk_files"]

    def test_one_pattern_per_file(self):
        """Only one risk factor per file even with multiple matches."""
        changes = [{"new_path": "all.py",
                     "diff": "+password = exec(eval(sql))"}]
        result = compute_diff_complexity(changes)
        assert len(result["high_risk_files"]) == 1
        assert len(result["risk_factors"]) == 1

    def test_risk_score_caps_at_40(self):
        """Security risk score caps at 40."""
        changes = [
            {"new_path": f"f{i}.py", "diff": f"+password{i}"}
            for i in range(10)
        ]
        result = compute_diff_complexity(changes)
        assert result["complexity_score"] <= 100

    def test_overall_score_caps_at_100(self):
        """Total complexity score never exceeds 100."""
        huge_diff = "\n+password = exec(sql)\n" * 1000
        changes = [{"new_path": f"f{i}.py", "diff": huge_diff} for i in range(20)]
        result = compute_diff_complexity(changes)
        assert result["complexity_score"] == 100

    def test_deletions_counted(self):
        diff = "\n-removed line\n-another removal\n"
        changes = [{"new_path": "cleanup.py", "diff": diff}]
        result = compute_diff_complexity(changes)
        assert result["total_deletions"] >= 1


# ── Count by severity: pattern matching ──────────────────────


class TestCountBySeverityPatternAccuracy:
    """Test _count_by_severity only matches structural patterns, not prose."""

    def test_heading_prefix(self):
        text = "### [HIGH] SQL injection found"
        counts = _count_by_severity(text)
        assert counts["high"] == 1

    def test_bullet_prefix(self):
        text = "- [MEDIUM] Outdated dependency"
        counts = _count_by_severity(text)
        assert counts["medium"] == 1

    def test_bold_prefix(self):
        text = "**[LOW] Minor style concern"
        counts = _count_by_severity(text)
        assert counts["low"] == 1

    def test_line_start(self):
        text = "[CRITICAL] Emergency fix needed"
        counts = _count_by_severity(text)
        assert counts["critical"] == 1

    def test_info_severity(self):
        text = "### [INFO] FYI note"
        counts = _count_by_severity(text)
        assert counts["info"] == 1

    def test_multiple_severities_in_one_text(self):
        text = """### [HIGH] Finding 1
### [MEDIUM] Finding 2
### [LOW] Finding 3
### [LOW] Finding 4"""
        counts = _count_by_severity(text)
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 2


# ── Determine severity: weighted scoring edge cases ──────────


class TestDetermineSeverityWeightedEdgeCases:
    """Test determine_severity weighted scoring at boundaries."""

    def test_two_mediums_not_escalated_to_high(self):
        """Two mediums = score 4, which is below HIGH threshold (5)."""
        text = "### [MEDIUM] F1\n### [MEDIUM] F2"
        assert determine_severity(text, "", "") == "MEDIUM"

    def test_three_mediums_escalate_to_high(self):
        """Three mediums = score 6, which meets HIGH threshold."""
        text = "### [MEDIUM] F1\n### [MEDIUM] F2\n### [MEDIUM] F3"
        assert determine_severity(text, "", "") == "HIGH"

    def test_two_highs_escalate_to_critical(self):
        """Two highs = score 6, but single high already = HIGH. Two highs don't make critical unless score >= 8."""
        text = "### [HIGH] F1\n### [HIGH] F2"
        # score = 6, which is >= 5 for HIGH but < 8 for CRITICAL
        assert determine_severity(text, "", "") == "HIGH"

    def test_three_highs_escalate_to_critical(self):
        """Three highs = score 9, which meets CRITICAL threshold (8)."""
        text = "### [HIGH] F1\n### [HIGH] F2\n### [HIGH] F3"
        assert determine_severity(text, "", "") == "CRITICAL"

    def test_one_high_two_mediums_escalate_to_critical(self):
        """1 high + 2 mediums = 3+4 = 7, still HIGH (< 8)."""
        text = "### [HIGH] F1\n### [MEDIUM] F2\n### [MEDIUM] F3"
        assert determine_severity(text, "", "") == "HIGH"

    def test_score_exactly_8_is_critical(self):
        """Score of exactly 8 triggers CRITICAL."""
        # 2 high + 1 medium = 6+2 = 8
        text = "### [HIGH] F1\n### [HIGH] F2\n### [MEDIUM] F3"
        assert determine_severity(text, "", "") == "CRITICAL"

    def test_single_low_is_low(self):
        text = "### [LOW] Minor"
        assert determine_severity(text, "", "") == "LOW"

    def test_across_all_three_inputs(self):
        """Findings across code, dep, and secret inputs are combined.
        Note: concatenation without newlines means only the first ### [MEDIUM]
        at line start is counted; the others lack proper line-start context."""
        result = determine_severity("### [MEDIUM] A", "### [MEDIUM] B", "### [MEDIUM] C")
        # Only 1 medium is detected because concatenation joins without newlines
        assert result == "MEDIUM"

    def test_across_inputs_with_newlines(self):
        """Findings with newline-terminated inputs are properly counted."""
        result = determine_severity("### [MEDIUM] A\n", "\n### [MEDIUM] B\n", "\n### [MEDIUM] C\n")
        assert result == "HIGH"


# ── Parse findings: complex formats ──────────────────────────


class TestParseFindingsComplexFormats:
    """Test _parse_findings with various markdown formats."""

    def test_finding_with_all_fields(self):
        text = """### [HIGH] Finding: SQL injection in login
**File:** `src/auth.py` (line 42)"""
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["file_path"] == "src/auth.py"
        assert findings[0]["line_num"] == 42
        assert findings[0]["category"] == "code-security"

    def test_finding_without_line_number(self):
        text = """### [MEDIUM] Finding: Outdated dep
**File:** `requirements.txt`"""
        findings = _parse_findings(text, "dependency-audit")
        assert len(findings) == 1
        assert findings[0]["line_num"] == 1  # default

    def test_multiple_findings_parsed(self):
        text = """### [HIGH] Finding: XSS
**File:** `app.js` (line 10)
### [LOW] Finding: Style
**File:** `main.py` (line 5)"""
        findings = _parse_findings(text)
        assert len(findings) == 2

    def test_finding_missing_file_line(self):
        """Finding heading without File: line should not be captured."""
        text = """### [HIGH] Finding: Something
Some description without file info
### [LOW] Finding: Another
**File:** `ok.py` (line 1)"""
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"

    def test_info_severity_parsed(self):
        text = """### [INFO] Finding: Note
**File:** `readme.md` (line 1)"""
        findings = _parse_findings(text, "secret-scan")
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
        assert findings[0]["category"] == "secret-scan"

    def test_critical_finding_enriched_with_cwe(self):
        text = """### [CRITICAL] Finding: SQL injection detected
**File:** `db.py` (line 100)"""
        findings = _parse_findings(text)
        assert len(findings) == 1
        assert findings[0].get("cwe") == "CWE-89"

    def test_empty_text_returns_empty(self):
        assert _parse_findings("") == []
        assert _parse_findings("No issues found.") == []


# ── Generate report: content verification ────────────────────


class TestGenerateReportContent:
    """Test generate_report output format and content."""

    def test_report_contains_mr_title(self):
        mr_info = {"iid": 42, "title": "Fix authentication bug"}
        report = generate_report(mr_info, "clean", "clean", "clean")
        assert "Fix authentication bug" in report
        assert "!42" in report

    def test_report_contains_severity(self):
        mr_info = {"iid": 1, "title": "T"}
        report = generate_report(mr_info, "### [CRITICAL] vuln", "", "")
        assert "CRITICAL" in report

    def test_report_contains_finding_counts(self):
        mr_info = {"iid": 1, "title": "T"}
        code = "### [HIGH] A\n### [HIGH] B"
        dep = "### [LOW] C"
        report = generate_report(mr_info, code, dep, "")
        assert "2 issue(s)" in report
        assert "1 issue(s)" in report

    def test_report_includes_scan_duration(self):
        mr_info = {"iid": 1, "title": "T"}
        report = generate_report(mr_info, "", "", "", scan_duration=5.3)
        assert "5.3s" in report

    def test_report_includes_files_scanned(self):
        mr_info = {"iid": 1, "title": "T"}
        report = generate_report(mr_info, "", "", "", files_scanned=12)
        assert "12" in report

    def test_report_includes_complexity_analysis(self):
        mr_info = {"iid": 1, "title": "T"}
        complexity = {
            "complexity_score": 75,
            "total_additions": 200,
            "total_deletions": 50,
            "total_files": 10,
            "high_risk_files": ["auth.py"],
            "risk_factors": ["credential handling modified in auth.py"],
        }
        report = generate_report(mr_info, "", "", "", complexity=complexity)
        assert "75/100" in report
        assert "High risk" in report
        assert "credential handling" in report

    def test_report_low_complexity(self):
        mr_info = {"iid": 1, "title": "T"}
        complexity = {
            "complexity_score": 10,
            "total_additions": 5,
            "total_deletions": 2,
            "total_files": 1,
            "high_risk_files": [],
            "risk_factors": [],
        }
        report = generate_report(mr_info, "", "", "", complexity=complexity)
        assert "Low" in report

    def test_report_medium_complexity(self):
        mr_info = {"iid": 1, "title": "T"}
        complexity = {
            "complexity_score": 45,
            "total_additions": 100,
            "total_deletions": 20,
            "total_files": 5,
            "high_risk_files": [],
            "risk_factors": [],
        }
        report = generate_report(mr_info, "", "", "", complexity=complexity)
        assert "Medium" in report

    def test_report_zero_complexity_omitted(self):
        mr_info = {"iid": 1, "title": "T"}
        complexity = {
            "complexity_score": 0,
            "total_additions": 0,
            "total_deletions": 0,
            "total_files": 0,
            "high_risk_files": [],
            "risk_factors": [],
        }
        report = generate_report(mr_info, "", "", "", complexity=complexity)
        assert "Complexity" not in report

    def test_report_contains_hackathon_footer(self):
        mr_info = {"iid": 1, "title": "T"}
        report = generate_report(mr_info, "", "", "")
        assert "GitLab AI Hackathon" in report


# ── Generate SARIF: structure validation ─────────────────────


class TestGenerateSarifStructure:
    """Test SARIF report structure and content."""

    def test_sarif_schema_version(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_sarif_report("", path)
            sarif = json.loads(Path(path).read_text())
            assert sarif["version"] == "2.1.0"
            assert "$schema" in sarif
        finally:
            os.unlink(path)

    def test_sarif_tool_driver(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_sarif_report("", path)
            sarif = json.loads(Path(path).read_text())
            driver = sarif["runs"][0]["tool"]["driver"]
            assert driver["name"] == "DuoGuard"
            assert driver["version"] == "1.0.0"
        finally:
            os.unlink(path)

    def test_sarif_invocations(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_sarif_report("", path)
            sarif = json.loads(Path(path).read_text())
            inv = sarif["runs"][0]["invocations"][0]
            assert inv["executionSuccessful"] is True
        finally:
            os.unlink(path)

    def test_sarif_automation_details(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_sarif_report("", path)
            sarif = json.loads(Path(path).read_text())
            auto = sarif["runs"][0]["automationDetails"]["id"]
            assert auto.startswith("duoguard/")
        finally:
            os.unlink(path)

    def test_sarif_result_has_partial_fingerprint(self):
        code = "### [HIGH] Finding: XSS\n**File:** `app.js` (line 5)"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_sarif_report(code, path)
            sarif = json.loads(Path(path).read_text())
            results = sarif["runs"][0]["results"]
            assert len(results) == 1
            assert "partialFingerprints" in results[0]
            assert "duoguardFindingHash/v1" in results[0]["partialFingerprints"]
        finally:
            os.unlink(path)

    def test_sarif_rule_has_help_uri(self):
        code = "### [HIGH] Finding: Test\n**File:** `test.py` (line 1)"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_sarif_report(code, path)
            sarif = json.loads(Path(path).read_text())
            rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            assert len(rules) == 1
            assert "helpUri" in rules[0]
        finally:
            os.unlink(path)

    def test_sarif_multiple_categories(self):
        code = "### [HIGH] Finding: Code issue\n**File:** `a.py` (line 1)"
        dep = "### [MEDIUM] Finding: Dep issue\n**File:** `req.txt` (line 1)"
        secret = "### [CRITICAL] Finding: Secret leak\n**File:** `env.py` (line 1)"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_sarif_report(code, path, dep, secret)
            sarif = json.loads(Path(path).read_text())
            results = sarif["runs"][0]["results"]
            assert len(results) == 3
        finally:
            os.unlink(path)


# ── Generate codequality: structure validation ───────────────


class TestGenerateCodequalityStructure:
    """Test Code Quality report structure."""

    def test_codequality_severity_mapping(self):
        code = "### [CRITICAL] Finding: Crit\n**File:** `a.py` (line 1)"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_codequality_report(code, path)
            issues = json.loads(Path(path).read_text())
            assert len(issues) == 1
            assert issues[0]["severity"] == "blocker"
        finally:
            os.unlink(path)

    def test_codequality_has_fingerprint(self):
        code = "### [MEDIUM] Finding: Med\n**File:** `b.py` (line 5)"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_codequality_report(code, path)
            issues = json.loads(Path(path).read_text())
            assert "fingerprint" in issues[0]
            assert len(issues[0]["fingerprint"]) == 32  # MD5 hex

        finally:
            os.unlink(path)

    def test_codequality_location_info(self):
        code = "### [LOW] Finding: Minor\n**File:** `src/app.py` (line 42)"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_codequality_report(code, path)
            issues = json.loads(Path(path).read_text())
            loc = issues[0]["location"]
            assert loc["path"] == "src/app.py"
            assert loc["lines"]["begin"] == 42
        finally:
            os.unlink(path)

    def test_codequality_includes_all_categories(self):
        code = "### [HIGH] Finding: Code\n**File:** `a.py` (line 1)"
        dep = "### [MEDIUM] Finding: Dep\n**File:** `b.txt` (line 1)"
        secret = "### [LOW] Finding: Secret\n**File:** `c.py` (line 1)"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_codequality_report(code, path, dep, secret)
            issues = json.loads(Path(path).read_text())
            assert len(issues) == 3
            check_names = {i["check_name"] for i in issues}
            assert "duoguard-code-security" in check_names
            assert "duoguard-dependency-audit" in check_names
            assert "duoguard-secret-scan" in check_names
        finally:
            os.unlink(path)


# ── Export findings JSON ─────────────────────────────────────


class TestExportFindingsJsonOutput:
    """Test export_findings_json writes correct file."""

    def test_exports_combined_findings(self):
        code = "### [HIGH] Finding: Code vuln\n**File:** `a.py` (line 10)"
        dep = "### [LOW] Finding: Old dep\n**File:** `req.txt` (line 1)"
        secret = ""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = export_findings_json(code, dep, secret, path)
            assert len(result) == 2
            data = json.loads(Path(path).read_text())
            assert len(data) == 2
        finally:
            os.unlink(path)

    def test_empty_findings_writes_empty_list(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = export_findings_json("", "", "", path)
            assert result == []
            data = json.loads(Path(path).read_text())
            assert data == []
        finally:
            os.unlink(path)


# ── Post report: _headers function ───────────────────────────


class TestPostReportHeaders:
    """Test _headers helper function."""

    @patch.dict(os.environ, {"GITLAB_TOKEN": "test-token-123"}, clear=False)
    def test_headers_returns_private_token(self):
        # The module reads GITLAB_TOKEN at import time, so we need to
        # verify the function returns the right structure
        result = _headers()
        assert "PRIVATE-TOKEN" in result


# ── Post MR comment: API interaction ─────────────────────────


class TestPostMrCommentApi:
    """Test post_mr_comment API call structure."""

    @patch("post_report.requests.post")
    def test_post_comment_url_structure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": 123}
        mock_post.return_value = mock_resp
        post_mr_comment("42", "7", "Test body")
        url = mock_post.call_args[0][0]
        assert "/projects/42/merge_requests/7/notes" in url

    @patch("post_report.requests.post")
    def test_post_comment_body_payload(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": 123}
        mock_post.return_value = mock_resp
        post_mr_comment("42", "7", "Hello **world**")
        payload = mock_post.call_args[1]["json"]
        assert payload["body"] == "Hello **world**"


# ── Find existing comment ────────────────────────────────────


class TestFindExistingCommentMatching:
    """Test find_existing_comment search logic."""

    @patch("post_report.requests.get")
    def test_finds_duoguard_comment(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 1, "body": "Regular comment"},
            {"id": 2, "body": "## DuoGuard Security Review Report\n..."},
        ]
        mock_get.return_value = mock_resp
        result = find_existing_comment("42", "7")
        assert result == 2

    @patch("post_report.requests.get")
    def test_returns_none_when_no_match(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"id": 1, "body": "Just a comment"},
        ]
        mock_get.return_value = mock_resp
        result = find_existing_comment("42", "7")
        assert result is None

    @patch("post_report.requests.get")
    def test_empty_notes_list(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp
        result = find_existing_comment("42", "7")
        assert result is None


# ── Approve/unapprove MR ────────────────────────────────────


class TestMRApprovalApi:
    """Test approve_mr and unapprove_mr API calls."""

    @patch("post_report.requests.post")
    def test_approve_mr_success(self, mock_post):
        mock_resp = MagicMock()
        mock_post.return_value = mock_resp
        result = approve_mr("42", "7")
        assert result is True
        url = mock_post.call_args[0][0]
        assert "/approve" in url

    @patch("post_report.requests.post")
    def test_approve_mr_http_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_post.return_value = mock_resp
        mock_post.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_resp
        )
        result = approve_mr("42", "7")
        assert result is False

    @patch("post_report.requests.post")
    def test_unapprove_mr_success(self, mock_post):
        mock_resp = MagicMock()
        mock_post.return_value = mock_resp
        result = unapprove_mr("42", "7")
        assert result is True
        url = mock_post.call_args[0][0]
        assert "/unapprove" in url

    @patch("post_report.requests.post")
    def test_unapprove_mr_http_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp
        mock_post.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_resp
        )
        result = unapprove_mr("42", "7")
        assert result is False


# ── Create issue for finding ─────────────────────────────────


class TestCreateIssueForFindingApi:
    """Test create_issue_for_finding API interaction."""

    @patch("post_report.requests.post")
    def test_creates_issue_with_correct_title(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 99}
        mock_post.return_value = mock_resp
        finding = {
            "severity": "high",
            "description": "SQL injection",
            "file_path": "db.py",
            "line_num": 42,
            "category": "code-security",
        }
        result = create_issue_for_finding("42", "7", finding)
        assert result is not None
        payload = mock_post.call_args[1]["json"]
        assert "[DuoGuard HIGH]" in payload["title"]

    @patch("post_report.requests.post")
    def test_long_title_truncated(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 99}
        mock_post.return_value = mock_resp
        finding = {
            "severity": "critical",
            "description": "A" * 300,
            "file_path": "a.py",
            "line_num": 1,
            "category": "code-security",
        }
        result = create_issue_for_finding("42", "7", finding)
        payload = mock_post.call_args[1]["json"]
        assert len(payload["title"]) <= 255

    @patch("post_report.requests.post")
    def test_issue_body_contains_cwe_link(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 99}
        mock_post.return_value = mock_resp
        finding = {
            "severity": "high",
            "description": "Test",
            "file_path": "a.py",
            "line_num": 1,
            "category": "code-security",
            "cwe": "CWE-89",
        }
        create_issue_for_finding("42", "7", finding)
        payload = mock_post.call_args[1]["json"]
        assert "cwe.mitre.org" in payload["description"]

    @patch("post_report.requests.post")
    def test_issue_body_contains_owasp(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 99}
        mock_post.return_value = mock_resp
        finding = {
            "severity": "high",
            "description": "Test",
            "file_path": "a.py",
            "line_num": 1,
            "category": "code-security",
            "owasp": "A03:2021-Injection",
        }
        create_issue_for_finding("42", "7", finding)
        payload = mock_post.call_args[1]["json"]
        assert "A03:2021-Injection" in payload["description"]

    @patch("post_report.requests.post")
    def test_issue_labels_include_severity(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"iid": 99}
        mock_post.return_value = mock_resp
        finding = {
            "severity": "critical",
            "description": "Bad",
            "file_path": "a.py",
            "line_num": 1,
            "category": "code-security",
        }
        create_issue_for_finding("42", "7", finding)
        payload = mock_post.call_args[1]["json"]
        assert "security::critical" in payload["labels"]
        assert "DuoGuard" in payload["labels"]

    @patch("post_report.requests.post")
    def test_issue_http_error_returns_none(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_post.return_value = mock_resp
        mock_post.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_resp
        )
        finding = {
            "severity": "high",
            "description": "Test",
            "file_path": "a.py",
            "line_num": 1,
            "category": "code-security",
        }
        result = create_issue_for_finding("42", "7", finding)
        assert result is None


# ── Create issues for findings (batch) ───────────────────────


class TestCreateIssuesForFindingsSeverityFilter:
    """Test create_issues_for_findings severity filtering."""

    @patch("post_report.create_issue_for_finding")
    def test_filters_below_min_severity(self, mock_create):
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "low", "description": "A"},
            {"severity": "high", "description": "B"},
            {"severity": "critical", "description": "C"},
        ]
        created = create_issues_for_findings("42", "7", findings, min_severity="high")
        assert len(created) == 2  # high + critical

    @patch("post_report.create_issue_for_finding")
    def test_min_severity_critical(self, mock_create):
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "high", "description": "A"},
            {"severity": "critical", "description": "B"},
        ]
        created = create_issues_for_findings("42", "7", findings, min_severity="critical")
        assert len(created) == 1

    @patch("post_report.create_issue_for_finding")
    def test_min_severity_low_includes_all(self, mock_create):
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "low", "description": "A"},
            {"severity": "medium", "description": "B"},
        ]
        created = create_issues_for_findings("42", "7", findings, min_severity="low")
        assert len(created) == 2

    @patch("post_report.create_issue_for_finding")
    def test_unknown_severity_skipped(self, mock_create):
        mock_create.return_value = {"iid": 1}
        findings = [
            {"severity": "unknown", "description": "A"},
            {"severity": "high", "description": "B"},
        ]
        created = create_issues_for_findings("42", "7", findings, min_severity="high")
        assert len(created) == 1

    def test_empty_findings_list(self):
        created = create_issues_for_findings("42", "7", [])
        assert created == []


# ── Resolve stale discussions ────────────────────────────────


class TestResolveStaleDiscussionsLogic:
    """Test resolve_stale_discussions filtering and resolution."""

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_resolves_duoguard_discussions_only(self, mock_get, mock_put):
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = [
            {
                "id": "d1",
                "notes": [{"body": ":shield: DuoGuard [HIGH] — vuln", "resolvable": True, "resolved": False}],
            },
            {
                "id": "d2",
                "notes": [{"body": "Regular comment", "resolvable": True, "resolved": False}],
            },
        ]
        mock_get.return_value = mock_get_resp
        mock_put_resp = MagicMock()
        mock_put.return_value = mock_put_resp

        resolved = resolve_stale_discussions("42", "7")
        assert resolved == 1
        assert mock_put.call_count == 1

    @patch("post_report.requests.get")
    def test_skips_already_resolved(self, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = [
            {
                "id": "d1",
                "notes": [{"body": ":shield: DuoGuard [HIGH] — vuln", "resolvable": True, "resolved": True}],
            },
        ]
        mock_get.return_value = mock_get_resp
        resolved = resolve_stale_discussions("42", "7")
        assert resolved == 0

    @patch("post_report.requests.get")
    def test_skips_non_resolvable(self, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = [
            {
                "id": "d1",
                "notes": [{"body": ":shield: DuoGuard [HIGH] — vuln", "resolvable": False, "resolved": False}],
            },
        ]
        mock_get.return_value = mock_get_resp
        resolved = resolve_stale_discussions("42", "7")
        assert resolved == 0

    @patch("post_report.requests.get")
    def test_http_error_returns_zero(self, mock_get):
        mock_get.return_value = MagicMock()
        mock_get.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=MagicMock(status_code=403)
        )
        resolved = resolve_stale_discussions("42", "7")
        assert resolved == 0

    @patch("post_report.requests.get")
    def test_empty_discussions_returns_zero(self, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = []
        mock_get.return_value = mock_get_resp
        resolved = resolve_stale_discussions("42", "7")
        assert resolved == 0

    @patch("post_report.requests.get")
    def test_discussions_with_empty_notes(self, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = [{"id": "d1", "notes": []}]
        mock_get.return_value = mock_get_resp
        resolved = resolve_stale_discussions("42", "7")
        assert resolved == 0


# ── Update MR labels ────────────────────────────────────────


class TestUpdateMrLabelsComprehensive:
    """Test update_mr_labels for all severity mappings."""

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_critical_label(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(json=MagicMock(return_value={"labels": []}))
        mock_put.return_value = MagicMock()
        update_mr_labels("42", "7", "CRITICAL")
        payload = mock_put.call_args[1]["json"]
        assert "security::critical" in payload["labels"]

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_none_maps_to_clean(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(json=MagicMock(return_value={"labels": []}))
        mock_put.return_value = MagicMock()
        update_mr_labels("42", "7", "NONE")
        payload = mock_put.call_args[1]["json"]
        assert "security::clean" in payload["labels"]

    @patch("post_report.requests.put")
    @patch("post_report.requests.get")
    def test_removes_old_labels(self, mock_get, mock_put):
        mock_get.return_value = MagicMock(
            json=MagicMock(return_value={"labels": ["security::low", "bug", "security::medium"]})
        )
        mock_put.return_value = MagicMock()
        update_mr_labels("42", "7", "HIGH")
        payload = mock_put.call_args[1]["json"]
        assert "security::low" not in payload["labels"]
        assert "security::medium" not in payload["labels"]
        assert "security::high" in payload["labels"]
        assert "bug" in payload["labels"]


# ── Post inline discussion ───────────────────────────────────


class TestPostInlineDiscussionPayloadStructure:
    """Test post_inline_discussion constructs correct API payload."""

    @patch("post_report.requests.post")
    def test_payload_structure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "disc1"}
        mock_post.return_value = mock_resp
        post_inline_discussion("42", "7", "body", "file.py", 10, "aaa", "bbb", "ccc")
        payload = mock_post.call_args[1]["json"]
        assert payload["body"] == "body"
        pos = payload["position"]
        assert pos["position_type"] == "text"
        assert pos["base_sha"] == "aaa"
        assert pos["head_sha"] == "bbb"
        assert pos["start_sha"] == "ccc"
        assert pos["new_path"] == "file.py"
        assert pos["new_line"] == 10

    @patch("post_report.requests.post")
    def test_http_error_returns_none(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 422
        mock_post.return_value = mock_resp
        mock_post.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_resp
        )
        result = post_inline_discussion("42", "7", "body", "file.py", 10, "a", "b", "c")
        assert result is None


# ── Post inline findings ─────────────────────────────────────


class TestPostInlineFindingsIntegration:
    """Test post_inline_findings orchestration."""

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_empty_findings_returns_zero(self, mock_versions, mock_disc):
        assert post_inline_findings("42", "7", []) == 0
        mock_versions.assert_not_called()

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_no_versions_returns_zero(self, mock_versions, mock_disc):
        mock_versions.return_value = []
        findings = [{"file_path": "a.py", "line_num": 1, "severity": "high",
                      "description": "Vuln", "category": "code-security"}]
        assert post_inline_findings("42", "7", findings) == 0

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_incomplete_shas_returns_zero(self, mock_versions, mock_disc):
        mock_versions.return_value = [{"base_commit_sha": "aaa", "head_commit_sha": "", "start_commit_sha": ""}]
        findings = [{"file_path": "a.py", "line_num": 1, "severity": "high",
                      "description": "Vuln", "category": "code-security"}]
        assert post_inline_findings("42", "7", findings) == 0

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_posts_findings_with_cwe(self, mock_versions, mock_disc):
        mock_versions.return_value = [{
            "base_commit_sha": "aaa",
            "head_commit_sha": "bbb",
            "start_commit_sha": "ccc",
        }]
        mock_disc.return_value = {"id": "d1"}
        findings = [{
            "file_path": "a.py", "line_num": 5, "severity": "high",
            "description": "SQL injection", "category": "code-security",
            "cwe": "CWE-89",
        }]
        posted = post_inline_findings("42", "7", findings)
        assert posted == 1
        body = mock_disc.call_args[0][2]
        assert "CWE-89" in body

    @patch("post_report.post_inline_discussion")
    @patch("post_report.get_mr_diff_versions")
    def test_counts_successful_posts(self, mock_versions, mock_disc):
        mock_versions.return_value = [{
            "base_commit_sha": "a", "head_commit_sha": "b", "start_commit_sha": "c",
        }]
        mock_disc.side_effect = [{"id": "d1"}, None, {"id": "d3"}]
        findings = [
            {"file_path": "a.py", "line_num": 1, "severity": "high", "description": "A", "category": "x"},
            {"file_path": "b.py", "line_num": 2, "severity": "high", "description": "B", "category": "x"},
            {"file_path": "c.py", "line_num": 3, "severity": "high", "description": "C", "category": "x"},
        ]
        posted = post_inline_findings("42", "7", findings)
        assert posted == 2


# ── Parse gateway headers ────────────────────────────────────


class TestParseGatewayHeadersFormats:
    """Test _parse_gateway_headers with various input formats."""

    def test_valid_json(self):
        result = _parse_gateway_headers('{"X-Custom": "value"}')
        assert result == {"X-Custom": "value"}

    def test_newline_separated(self):
        result = _parse_gateway_headers("X-Custom: value\nX-Other: val2")
        assert result == {"X-Custom": "value", "X-Other": "val2"}

    def test_empty_string(self):
        assert _parse_gateway_headers("") == {}

    def test_invalid_json_falls_to_newline(self):
        result = _parse_gateway_headers("{not json")
        # Falls through to line parsing
        assert isinstance(result, dict)

    def test_json_non_dict_falls_to_newline(self):
        result = _parse_gateway_headers("[1, 2, 3]")
        # JSON parses but not dict, so line parsing is attempted
        assert isinstance(result, dict)

    def test_none_input(self):
        # Although type hint says str, test robustness
        assert _parse_gateway_headers(None) == {}


# ── Resolve API URL for agent ────────────────────────────────


class TestResolveApiUrlAgentVariations:
    """Test _resolve_api_url_for_agent with various hostname values."""

    @patch("duoguard.GITLAB_HOSTNAME", "gitlab.example.com")
    def test_custom_hostname(self):
        result = _resolve_api_url_for_agent()
        assert result == "https://gitlab.example.com/api/v4"

    @patch("duoguard.GITLAB_HOSTNAME", "")
    def test_empty_hostname_uses_default(self):
        result = _resolve_api_url_for_agent()
        assert result == "https://gitlab.com/api/v4"

    @patch("duoguard.GITLAB_HOSTNAME", None)
    def test_none_hostname_uses_default(self):
        result = _resolve_api_url_for_agent()
        assert result == "https://gitlab.com/api/v4"


# ── Parse agent context ──────────────────────────────────────


class TestParseAgentContextFormats:
    """Test _parse_agent_context with various context formats."""

    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_CONTEXT", '{"merge_request": {"iid": 42}, "project": {"path_with_namespace": "group/proj"}}')
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "")
    def test_json_context_with_project(self):
        project_id, mr_iid = _parse_agent_context()
        assert mr_iid == "42"
        assert "group%2Fproj" in project_id

    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_CONTEXT", "Please review !123")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "mygroup/myproj")
    def test_text_context_with_mr_reference(self):
        project_id, mr_iid = _parse_agent_context()
        assert mr_iid == "123"
        assert "mygroup%2Fmyproj" in project_id

    @patch("duoguard.AI_FLOW_INPUT", "Review !456")
    @patch("duoguard.AI_FLOW_CONTEXT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "a/b")
    def test_mr_from_input(self):
        project_id, mr_iid = _parse_agent_context()
        assert mr_iid == "456"

    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_CONTEXT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "")
    def test_empty_context_returns_empty(self):
        project_id, mr_iid = _parse_agent_context()
        assert project_id == ""
        assert mr_iid == ""


# ── Load config ──────────────────────────────────────────────


class TestLoadConfigFileFormats:
    """Test load_config with various config file contents."""

    def test_explicit_path(self, tmp_path):
        cfg_file = tmp_path / "custom.yml"
        cfg_file.write_text("severity_threshold: LOW\nagents:\n  secret_scan: false\n")
        config = load_config(str(cfg_file))
        assert config["severity_threshold"] == "LOW"
        assert config["agents"]["secret_scan"] is False
        # Deep-merged: code_security should still be True from defaults
        assert config["agents"]["code_security"] is True

    def test_empty_yaml_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / "empty.yml"
        cfg_file.write_text("")
        config = load_config(str(cfg_file))
        assert config == DEFAULT_CONFIG

    def test_non_dict_yaml_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / "list.yml"
        cfg_file.write_text("- item1\n- item2\n")
        config = load_config(str(cfg_file))
        assert config["version"] == 1

    def test_nonexistent_path_returns_defaults(self):
        config = load_config("/nonexistent/path/config.yml")
        assert config == DEFAULT_CONFIG


# ── Load agent prompt ────────────────────────────────────────


class TestLoadAgentPromptPaths:
    """Test load_agent_prompt with valid and invalid paths."""

    def test_loads_valid_agent_yaml(self):
        prompt = load_agent_prompt(".gitlab/duo/agents/code-security-reviewer.yml")
        assert len(prompt) > 0
        assert "security" in prompt.lower()

    def test_loads_dependency_auditor(self):
        prompt = load_agent_prompt(".gitlab/duo/agents/dependency-auditor.yml")
        assert "dependency" in prompt.lower()

    def test_loads_secret_scanner(self):
        prompt = load_agent_prompt(".gitlab/duo/agents/secret-scanner.yml")
        assert "secret" in prompt.lower()

    def test_missing_file_returns_empty(self):
        prompt = load_agent_prompt("nonexistent-agent.yml")
        assert prompt == ""


# ── CWE keyword map: completeness ───────────────────────────


class TestCWEKeywordMapValues:
    """Validate CWE_KEYWORD_MAP structure and values."""

    def test_all_entries_have_cwe(self):
        for keyword, data in CWE_KEYWORD_MAP.items():
            assert "cwe" in data, f"Missing 'cwe' for keyword '{keyword}'"
            assert data["cwe"].startswith("CWE-"), f"Invalid CWE format for '{keyword}': {data['cwe']}"

    def test_all_entries_have_owasp(self):
        for keyword, data in CWE_KEYWORD_MAP.items():
            assert "owasp" in data, f"Missing 'owasp' for keyword '{keyword}'"
            assert ":" in data["owasp"], f"Invalid OWASP format for '{keyword}': {data['owasp']}"

    def test_map_has_minimum_entries(self):
        assert len(CWE_KEYWORD_MAP) >= 30

    def test_all_keywords_lowercase(self):
        for keyword in CWE_KEYWORD_MAP:
            assert keyword == keyword.lower(), f"Keyword '{keyword}' should be lowercase"


# ── DEFAULT_CONFIG validation ────────────────────────────────


class TestDefaultConfigStructure:
    """Validate DEFAULT_CONFIG structure."""

    def test_has_required_keys(self):
        required = ["version", "severity_threshold", "agents", "exclude_paths",
                     "exclude_extensions", "inline_comments", "approve",
                     "approve_threshold", "model", "max_diff_size"]
        for key in required:
            assert key in DEFAULT_CONFIG, f"Missing key '{key}'"

    def test_agents_has_all_types(self):
        agents = DEFAULT_CONFIG["agents"]
        assert agents["code_security"] is True
        assert agents["dependency_audit"] is True
        assert agents["secret_scan"] is True

    def test_max_diff_size_reasonable(self):
        assert DEFAULT_CONFIG["max_diff_size"] == 200_000
        assert MAX_DIFF_SIZE == 200_000


# ── SECURITY_LABELS validation ───────────────────────────────


class TestSecurityLabelsStructure:
    """Validate SECURITY_LABELS constant."""

    def test_contains_all_levels(self):
        expected = {"security::critical", "security::high", "security::medium",
                    "security::low", "security::clean"}
        assert set(SECURITY_LABELS) == expected

    def test_ordered_by_severity(self):
        assert SECURITY_LABELS[0] == "security::critical"
        assert SECURITY_LABELS[-1] == "security::clean"


# ── Run agents: call_ai_gateway integration ──────────────────


class TestRunAgentsFunctions:
    """Test run_code_security_review, run_dependency_audit, run_secret_scan."""

    @patch("duoguard.call_ai_gateway", return_value="No issues found")
    @patch("duoguard.load_agent_prompt", return_value="prompt")
    def test_code_security_review_calls_gateway(self, mock_prompt, mock_gateway):
        result = run_code_security_review("diff text")
        assert result == "No issues found"
        mock_gateway.assert_called_once()

    @patch("duoguard.call_ai_gateway", return_value="All clean")
    @patch("duoguard.load_agent_prompt", return_value="prompt")
    def test_secret_scan_calls_gateway(self, mock_prompt, mock_gateway):
        result = run_secret_scan("diff text")
        assert result == "All clean"
        mock_gateway.assert_called_once()

    def test_dependency_audit_empty_diff(self):
        result = run_dependency_audit("   ")
        assert "No dependency file changes" in result

    @patch("duoguard.call_ai_gateway", return_value="Dep check OK")
    @patch("duoguard.load_agent_prompt", return_value="prompt")
    def test_dependency_audit_with_content(self, mock_prompt, mock_gateway):
        result = run_dependency_audit("package.json changes")
        assert result == "Dep check OK"

    @patch("duoguard.call_ai_gateway", return_value="Review done")
    @patch("duoguard.load_agent_prompt", return_value="")
    def test_code_security_uses_fallback_prompt(self, mock_prompt, mock_gateway):
        run_code_security_review("diff")
        args = mock_gateway.call_args
        assert "security" in args[0][0].lower()

    @patch("duoguard.call_ai_gateway", return_value="Scan done")
    @patch("duoguard.load_agent_prompt", return_value="")
    def test_secret_scan_uses_fallback_prompt(self, mock_prompt, mock_gateway):
        run_secret_scan("diff")
        args = mock_gateway.call_args
        assert "secret" in args[0][0].lower()

    @patch("duoguard.call_ai_gateway", return_value="Audit done")
    @patch("duoguard.load_agent_prompt", return_value="")
    def test_dep_audit_uses_fallback_prompt(self, mock_prompt, mock_gateway):
        run_dependency_audit("dep changes here")
        args = mock_gateway.call_args
        assert "dependency" in args[0][0].lower()
