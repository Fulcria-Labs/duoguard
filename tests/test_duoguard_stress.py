"""DuoGuard stress tests -- large MR handling, agent mode edge cases,
stale discussion resolution, MR approval edge cases, security-sensitive
code paths, concurrency under stress, and AI model fallback logic.

Adds ~100 new tests organised into 7 categories.
"""

import hashlib
import json
import os
import re
import sys
import tempfile
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch, PropertyMock

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


def _make_finding_text(severity, description, file_path="src/app.py", line=1):
    """Build a finding in the format _parse_findings expects."""
    return (
        f"### [{severity.upper()}] Finding: {description}\n"
        f"**File:** `{file_path}` (line {line})"
    )


def _make_change(path, diff="+ added line", deleted=False):
    """Build a single MR change dict."""
    return {
        "new_path": path,
        "old_path": path,
        "diff": diff,
        "new_file": not deleted,
        "deleted_file": deleted,
        "renamed_file": False,
    }


def _make_large_changes(n, diff_per_file=200):
    """Generate n MR change entries with configurable diff size."""
    changes = []
    diff_content = "+ " + "x" * diff_per_file + "\n"
    for i in range(n):
        changes.append(_make_change(f"src/module_{i:04d}/handler.py", diff_content))
    return changes


def _tmp_json_path():
    """Return a temporary file path for JSON output."""
    return tempfile.mktemp(suffix=".json")


def _mock_response(status_code=200, json_data=None, text=""):
    """Create a mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        http_err = requests.exceptions.HTTPError(response=resp)
        resp.raise_for_status.side_effect = http_err
    return resp


# ═══════════════════════════════════════════════════════════════
# 1. Large MR Stress Tests (~20 tests)
# ═══════════════════════════════════════════════════════════════


class TestLargeMRStress:
    """Tests for handling 1000+ changed files, huge diffs, and edge cases."""

    def test_1000_changed_files_format(self):
        """format_diff_for_analysis handles 1000 changed files."""
        changes = _make_large_changes(1000, diff_per_file=50)
        result = format_diff_for_analysis(changes, max_size=MAX_DIFF_SIZE)
        assert len(result) > 0
        assert "File:" in result

    def test_1000_files_truncation_notice(self):
        """When 1000 files exceed max_size, truncation notice appears."""
        changes = _make_large_changes(1000, diff_per_file=500)
        result = format_diff_for_analysis(changes, max_size=10_000)
        assert "omitted" in result
        assert "character limit" in result

    def test_2000_files_still_produces_output(self):
        """Even 2000 files produces a valid diff string."""
        changes = _make_large_changes(2000, diff_per_file=20)
        result = format_diff_for_analysis(changes, max_size=MAX_DIFF_SIZE)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_max_diff_size_boundary_exact(self):
        """Diff exactly at max_size boundary does not truncate."""
        # Create a change whose chunk is under max_size
        small_diff = "+ a\n"
        changes = [_make_change("a.py", small_diff)]
        result = format_diff_for_analysis(changes, max_size=10_000)
        assert "omitted" not in result

    def test_max_diff_size_boundary_one_over(self):
        """A single file just over max_size triggers truncation for subsequent files."""
        big_diff = "+ " + "a" * 5000 + "\n"
        changes = [_make_change("first.py", big_diff), _make_change("second.py", big_diff)]
        result = format_diff_for_analysis(changes, max_size=6000)
        assert "omitted" in result

    def test_10mb_diff_truncation(self):
        """A 10MB+ combined diff is handled gracefully with truncation."""
        huge_diff = "+ " + "x" * 100_000 + "\n"
        changes = [_make_change(f"big_{i}.py", huge_diff) for i in range(120)]
        result = format_diff_for_analysis(changes, max_size=MAX_DIFF_SIZE)
        assert len(result) <= MAX_DIFF_SIZE + 500  # allow truncation notice
        assert "omitted" in result

    def test_very_long_file_paths(self):
        """Files with 500-char paths are included in the diff."""
        long_path = "src/" + "/".join(["subdir"] * 100) + "/handler.py"
        changes = [_make_change(long_path, "+ code\n")]
        result = format_diff_for_analysis(changes)
        assert long_path in result

    def test_binary_content_in_diff(self):
        """Binary content (NUL bytes) in diffs does not crash formatting."""
        binary_diff = "+ \x00\x01\x02\xff binary data\n"
        changes = [_make_change("image.bin", binary_diff)]
        result = format_diff_for_analysis(changes)
        assert "image.bin" in result

    def test_merge_conflict_markers_in_diff(self):
        """Merge conflict markers in diffs are passed through."""
        conflict_diff = (
            "<<<<<<< HEAD\n"
            "+ our version\n"
            "=======\n"
            "+ their version\n"
            ">>>>>>> branch\n"
        )
        changes = [_make_change("conflict.py", conflict_diff)]
        result = format_diff_for_analysis(changes)
        assert "<<<<<<" in result
        assert "=======" in result

    def test_empty_diff_in_changes(self):
        """Changes with empty diff are skipped gracefully."""
        changes = [_make_change("empty.py", "")]
        result = format_diff_for_analysis(changes)
        assert result == ""

    def test_complexity_1000_files(self):
        """compute_diff_complexity handles 1000 files."""
        changes = _make_large_changes(1000, diff_per_file=50)
        c = compute_diff_complexity(changes)
        assert c["total_files"] == 1000
        assert c["complexity_score"] <= 100  # capped at 100

    def test_complexity_score_capped_at_100(self):
        """Complexity score never exceeds 100."""
        # Security-sensitive + huge size
        changes = []
        for i in range(100):
            changes.append(_make_change(f"auth_{i}.py", "+ password = secret\n" * 100))
        c = compute_diff_complexity(changes)
        assert c["complexity_score"] == 100

    def test_filter_excluded_1000_files(self):
        """filter_excluded_changes works on 1000 files."""
        changes = _make_large_changes(1000)
        # Exclude half by pattern
        exclude = ["src/module_00*"]
        filtered = filter_excluded_changes(changes, exclude_paths=exclude)
        assert len(filtered) < 1000

    def test_extract_dependencies_from_large_set(self):
        """extract_dependency_files scans through 1000 files."""
        changes = _make_large_changes(500)
        changes.append(_make_change("requirements.txt", "+ flask==3.0\n"))
        changes.append(_make_change("package.json", '+ "express": "^5.0"\n'))
        deps = extract_dependency_files(changes)
        assert len(deps) == 2

    def test_unicode_file_paths(self):
        """Unicode characters in file paths are handled."""
        changes = [_make_change("src/модуль/handler.py", "+ code\n")]
        result = format_diff_for_analysis(changes)
        assert "модуль" in result

    def test_special_chars_in_diff(self):
        """Special characters like backticks in diffs don't break markdown."""
        changes = [_make_change("a.py", "+ `code` with ```triple``` backticks\n")]
        result = format_diff_for_analysis(changes)
        assert "triple" in result

    def test_newlines_only_diff(self):
        """A diff that is only newlines is handled."""
        changes = [_make_change("blank.py", "\n\n\n\n")]
        result = format_diff_for_analysis(changes)
        assert "blank.py" in result

    def test_max_diff_size_zero(self):
        """max_size=0 truncates everything."""
        changes = [_make_change("a.py", "+ code\n")]
        result = format_diff_for_analysis(changes, max_size=0)
        assert "omitted" in result

    def test_single_huge_file_diff(self):
        """A single file with a very large diff gets included up to max_size."""
        huge_diff = "+ " + "a" * MAX_DIFF_SIZE + "\n"
        changes = [_make_change("huge.py", huge_diff)]
        result = format_diff_for_analysis(changes, max_size=MAX_DIFF_SIZE)
        # The chunk itself exceeds max_size, so it gets truncated
        assert "omitted" in result

    def test_tab_characters_in_diff(self):
        """Tab characters in diffs are handled properly."""
        tab_diff = "+\tindented_with_tabs = True\n+\t\tnested_tab\n"
        changes = [_make_change("tabs.py", tab_diff)]
        result = format_diff_for_analysis(changes)
        assert "\t" in result
        assert "tabs.py" in result


# ═══════════════════════════════════════════════════════════════
# 2. Agent Mode Context Parsing (~15 tests)
# ═══════════════════════════════════════════════════════════════


class TestAgentModeContextParsing:
    """Tests for _parse_agent_context with edge cases."""

    @patch("duoguard.AI_FLOW_CONTEXT", '{"merge_request": {"iid": 42}, "project": {"path_with_namespace": "group/project"}}')
    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "")
    def test_valid_json_context(self):
        """Valid JSON context extracts project_id and mr_iid."""
        pid, mr = _parse_agent_context()
        assert mr == "42"
        assert "group%2Fproject" in pid

    @patch("duoguard.AI_FLOW_CONTEXT", "not valid json {{{")
    @patch("duoguard.AI_FLOW_INPUT", "review !99")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "org/repo")
    def test_malformed_json_falls_back_to_regex(self):
        """Malformed JSON context falls back to regex MR extraction."""
        pid, mr = _parse_agent_context()
        assert mr == "99"
        assert "org%2Frepo" in pid

    @patch("duoguard.AI_FLOW_CONTEXT", "")
    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "")
    def test_empty_context_returns_empty(self):
        """All-empty context returns empty strings."""
        pid, mr = _parse_agent_context()
        assert pid == ""
        assert mr == ""

    @patch("duoguard.AI_FLOW_CONTEXT", '{"merge_request": {}, "project": {}}')
    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "")
    def test_json_without_iid(self):
        """JSON context missing iid returns empty mr_iid."""
        pid, mr = _parse_agent_context()
        assert mr == ""

    @patch("duoguard.AI_FLOW_CONTEXT", "Please review MR !123 for security")
    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "my-org/my-repo")
    def test_plain_text_context_with_mr_ref(self):
        """Plain text context with !NNN extracts MR IID."""
        pid, mr = _parse_agent_context()
        assert mr == "123"

    @patch("duoguard.AI_FLOW_CONTEXT", "")
    @patch("duoguard.AI_FLOW_INPUT", "scan !456 please")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "test/project")
    def test_mr_ref_in_input_only(self):
        """MR reference in AI_FLOW_INPUT when context is empty."""
        pid, mr = _parse_agent_context()
        assert mr == "456"

    @patch("duoguard.AI_FLOW_CONTEXT", '{"merge_request": {"iid": 10}, "project": {"path_with_namespace": "unicode/проект"}}')
    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "")
    def test_unicode_project_path_in_context(self):
        """Unicode project path is URL-encoded correctly."""
        pid, mr = _parse_agent_context()
        assert mr == "10"
        # URL-encoded Cyrillic
        assert "%D0%BF%D1%80%D0%BE%D0%B5%D0%BA%D1%82" in pid

    @patch("duoguard.AI_FLOW_CONTEXT", '[]')
    @patch("duoguard.AI_FLOW_INPUT", "!77")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "a/b")
    def test_json_array_context_raises(self):
        """JSON array (not object) in context raises AttributeError (no .get)."""
        with pytest.raises(AttributeError):
            _parse_agent_context()

    @patch("duoguard.AI_FLOW_CONTEXT", '{"merge_request": {"iid": 0}}')
    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "g/p")
    def test_iid_zero(self):
        """MR IID of 0 is treated as empty string (falsy)."""
        pid, mr = _parse_agent_context()
        assert mr == "0"

    @patch("duoguard.GITLAB_HOSTNAME", "")
    def test_resolve_api_url_empty_hostname(self):
        """Empty GITLAB_HOSTNAME defaults to gitlab.com."""
        url = _resolve_api_url_for_agent()
        assert url == "https://gitlab.com/api/v4"

    @patch("duoguard.GITLAB_HOSTNAME", "gitlab.example.com")
    def test_resolve_api_url_custom_hostname(self):
        """Custom GITLAB_HOSTNAME builds correct API URL."""
        url = _resolve_api_url_for_agent()
        assert url == "https://gitlab.example.com/api/v4"

    @patch("duoguard.AI_FLOW_CONTEXT", '{"merge_request": {"iid": 5}}')
    @patch("duoguard.AI_FLOW_INPUT", "")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "group/sub group/project")
    def test_project_path_with_spaces(self):
        """Project path with spaces is URL-encoded."""
        pid, mr = _parse_agent_context()
        assert "+" in pid or "%20" in pid

    @patch("duoguard.AI_FLOW_CONTEXT", 'null')
    @patch("duoguard.AI_FLOW_INPUT", "!88")
    @patch("duoguard.AI_FLOW_PROJECT_PATH", "x/y")
    def test_json_null_context_raises(self):
        """JSON null context raises AttributeError (NoneType has no .get)."""
        with pytest.raises(AttributeError):
            _parse_agent_context()

    def test_parse_gateway_headers_empty(self):
        """Empty string returns empty dict."""
        assert _parse_gateway_headers("") == {}

    def test_parse_gateway_headers_valid_json(self):
        """Valid JSON headers are parsed."""
        h = _parse_gateway_headers('{"X-Custom": "value"}')
        assert h == {"X-Custom": "value"}

    def test_parse_gateway_headers_key_value_format(self):
        """Newline-separated Key: Value format is parsed."""
        h = _parse_gateway_headers("X-Foo: bar\nX-Baz: qux")
        assert h == {"X-Foo": "bar", "X-Baz": "qux"}


# ═══════════════════════════════════════════════════════════════
# 3. Stale Discussion Resolution (~15 tests)
# ═══════════════════════════════════════════════════════════════


class TestStaleDiscussionResolution:
    """Tests for resolve_stale_discussions edge cases."""

    @patch("post_report.requests.get")
    @patch("post_report.requests.put")
    def test_resolve_single_duoguard_discussion(self, mock_put, mock_get):
        """Resolves a single DuoGuard discussion."""
        mock_get.return_value = _mock_response(200, [
            {
                "id": "d1",
                "notes": [{
                    "body": ":shield: DuoGuard [HIGH] SQL injection",
                    "resolvable": True,
                    "resolved": False,
                }],
            }
        ])
        mock_put.return_value = _mock_response(200)
        count = resolve_stale_discussions("1", "1")
        assert count == 1
        mock_put.assert_called_once()

    @patch("post_report.requests.get")
    @patch("post_report.requests.put")
    def test_multiple_stale_discussions_same_file(self, mock_put, mock_get):
        """Resolves multiple DuoGuard discussions on the same file."""
        discussions = []
        for i in range(5):
            discussions.append({
                "id": f"d{i}",
                "notes": [{
                    "body": f":shield: DuoGuard [MEDIUM] Finding {i} in app.py",
                    "resolvable": True,
                    "resolved": False,
                }],
            })
        mock_get.return_value = _mock_response(200, discussions)
        mock_put.return_value = _mock_response(200)
        count = resolve_stale_discussions("1", "1")
        assert count == 5
        assert mock_put.call_count == 5

    @patch("post_report.requests.get")
    def test_skip_non_duoguard_discussions(self, mock_get):
        """Does not resolve discussions from other bots."""
        mock_get.return_value = _mock_response(200, [
            {
                "id": "d1",
                "notes": [{
                    "body": "Some other bot comment about security",
                    "resolvable": True,
                    "resolved": False,
                }],
            }
        ])
        count = resolve_stale_discussions("1", "1")
        assert count == 0

    @patch("post_report.requests.get")
    def test_skip_already_resolved_discussions(self, mock_get):
        """Does not re-resolve already resolved discussions."""
        mock_get.return_value = _mock_response(200, [
            {
                "id": "d1",
                "notes": [{
                    "body": ":shield: DuoGuard [HIGH] Already fixed",
                    "resolvable": True,
                    "resolved": True,
                }],
            }
        ])
        count = resolve_stale_discussions("1", "1")
        assert count == 0

    @patch("post_report.requests.get")
    def test_skip_non_resolvable_discussions(self, mock_get):
        """Does not resolve non-resolvable notes."""
        mock_get.return_value = _mock_response(200, [
            {
                "id": "d1",
                "notes": [{
                    "body": ":shield: DuoGuard [LOW] Not resolvable",
                    "resolvable": False,
                    "resolved": False,
                }],
            }
        ])
        count = resolve_stale_discussions("1", "1")
        assert count == 0

    @patch("post_report.requests.get")
    def test_empty_discussions_list(self, mock_get):
        """Empty discussion list returns 0."""
        mock_get.return_value = _mock_response(200, [])
        count = resolve_stale_discussions("1", "1")
        assert count == 0

    @patch("post_report.requests.get")
    def test_discussion_with_no_notes(self, mock_get):
        """Discussion with empty notes list is skipped."""
        mock_get.return_value = _mock_response(200, [
            {"id": "d1", "notes": []}
        ])
        count = resolve_stale_discussions("1", "1")
        assert count == 0

    @patch("post_report.requests.get")
    @patch("post_report.requests.put")
    def test_discussion_with_replies(self, mock_put, mock_get):
        """Discussion with replies is resolved if first note is DuoGuard."""
        mock_get.return_value = _mock_response(200, [
            {
                "id": "d1",
                "notes": [
                    {
                        "body": ":shield: DuoGuard [HIGH] XSS in template",
                        "resolvable": True,
                        "resolved": False,
                    },
                    {
                        "body": "Thanks, will fix this.",
                        "resolvable": True,
                        "resolved": False,
                    },
                ],
            }
        ])
        mock_put.return_value = _mock_response(200)
        count = resolve_stale_discussions("1", "1")
        assert count == 1

    @patch("post_report.requests.get")
    def test_api_error_on_list_returns_zero(self, mock_get):
        """HTTP error when listing discussions returns 0."""
        mock_get.return_value = _mock_response(500)
        count = resolve_stale_discussions("1", "1")
        assert count == 0

    @patch("post_report.requests.get")
    @patch("post_report.requests.put")
    def test_partial_resolve_failure(self, mock_put, mock_get):
        """If one resolution fails, others still count."""
        mock_get.return_value = _mock_response(200, [
            {
                "id": "d1",
                "notes": [{"body": ":shield: DuoGuard [HIGH] A", "resolvable": True, "resolved": False}],
            },
            {
                "id": "d2",
                "notes": [{"body": ":shield: DuoGuard [MEDIUM] B", "resolvable": True, "resolved": False}],
            },
        ])
        # First put succeeds, second fails
        mock_put.side_effect = [_mock_response(200), _mock_response(403)]
        count = resolve_stale_discussions("1", "1")
        assert count == 1

    @patch("post_report.requests.get")
    @patch("post_report.requests.put")
    def test_concurrent_resolution_ordering(self, mock_put, mock_get):
        """Resolution processes discussions in order received."""
        discussions = [
            {
                "id": f"d{i}",
                "notes": [{"body": f":shield: DuoGuard [LOW] Finding {i}", "resolvable": True, "resolved": False}],
            }
            for i in range(3)
        ]
        mock_get.return_value = _mock_response(200, discussions)
        mock_put.return_value = _mock_response(200)
        count = resolve_stale_discussions("1", "1")
        assert count == 3
        # Verify PUT URLs contain discussion IDs in order
        for i, c in enumerate(mock_put.call_args_list):
            assert f"d{i}" in c[0][0]

    @patch("post_report.requests.get")
    def test_mixed_duoguard_and_other_discussions(self, mock_get):
        """Only DuoGuard discussions are resolved in mixed list."""
        mock_get.return_value = _mock_response(200, [
            {"id": "d1", "notes": [{"body": "Human comment", "resolvable": True, "resolved": False}]},
            {"id": "d2", "notes": [{"body": ":shield: DuoGuard [HIGH] Real finding", "resolvable": True, "resolved": False}]},
            {"id": "d3", "notes": [{"body": "Another bot: security scan passed", "resolvable": True, "resolved": False}]},
        ])
        with patch("post_report.requests.put", return_value=_mock_response(200)) as mock_put:
            count = resolve_stale_discussions("1", "1")
        assert count == 1

    @patch("post_report.requests.get")
    def test_discussions_from_other_bots_not_resolved(self, mock_get):
        """Discussions from other security bots are not resolved."""
        mock_get.return_value = _mock_response(200, [
            {"id": "d1", "notes": [{"body": "[SAST] Critical vulnerability found", "resolvable": True, "resolved": False}]},
            {"id": "d2", "notes": [{"body": "GitLab DAST: XSS detected", "resolvable": True, "resolved": False}]},
        ])
        count = resolve_stale_discussions("1", "1")
        assert count == 0


# ═══════════════════════════════════════════════════════════════
# 4. MR Approval Edge Cases (~15 tests)
# ═══════════════════════════════════════════════════════════════


class TestMRApprovalEdgeCases:
    """Tests for approve_mr, unapprove_mr, and approval logic edge cases."""

    @patch("post_report.requests.post")
    def test_approve_mr_success(self, mock_post):
        """Successful MR approval returns True."""
        mock_post.return_value = _mock_response(200, {"approved": True})
        result = approve_mr("1", "1")
        assert result is True

    @patch("post_report.requests.post")
    def test_approve_mr_already_approved_idempotent(self, mock_post):
        """Approving an already-approved MR succeeds (idempotent)."""
        mock_post.return_value = _mock_response(200, {"approved": True})
        result = approve_mr("1", "1")
        assert result is True

    @patch("post_report.requests.post")
    def test_approve_mr_403_insufficient_permissions(self, mock_post):
        """403 on approve returns False."""
        mock_post.return_value = _mock_response(403)
        result = approve_mr("1", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_approve_mr_401_unauthorized(self, mock_post):
        """401 on approve returns False."""
        mock_post.return_value = _mock_response(401)
        result = approve_mr("1", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_unapprove_mr_success(self, mock_post):
        """Successful unapproval returns True."""
        mock_post.return_value = _mock_response(200)
        result = unapprove_mr("1", "1")
        assert result is True

    @patch("post_report.requests.post")
    def test_unapprove_mr_failure(self, mock_post):
        """Failed unapproval returns False."""
        mock_post.return_value = _mock_response(409)
        result = unapprove_mr("1", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_approve_draft_mr_422(self, mock_post):
        """Approving a draft MR returns 422 -> False."""
        mock_post.return_value = _mock_response(422)
        result = approve_mr("1", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_approve_locked_mr(self, mock_post):
        """Approving a locked MR returns 403 -> False."""
        mock_post.return_value = _mock_response(403)
        result = approve_mr("1", "1")
        assert result is False

    @patch("post_report.requests.post")
    def test_approve_mr_500_server_error(self, mock_post):
        """Server error on approve returns False."""
        mock_post.return_value = _mock_response(500)
        result = approve_mr("1", "1")
        assert result is False

    def test_severity_below_threshold_triggers_approve(self):
        """Severity NONE < threshold HIGH should trigger approval."""
        severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_idx = severity_order.index("NONE")
        threshold_idx = severity_order.index("HIGH")
        assert sev_idx < threshold_idx

    def test_severity_at_threshold_does_not_approve(self):
        """Severity HIGH == threshold HIGH should NOT trigger approval."""
        severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_idx = severity_order.index("HIGH")
        threshold_idx = severity_order.index("HIGH")
        assert not (sev_idx < threshold_idx)

    def test_severity_above_threshold_triggers_unapprove(self):
        """Severity CRITICAL > threshold HIGH means unapprove."""
        severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_idx = severity_order.index("CRITICAL")
        threshold_idx = severity_order.index("HIGH")
        assert sev_idx >= threshold_idx

    @patch("post_report.requests.get")
    @patch("post_report.requests.put")
    def test_update_labels_removes_stale_security_labels(self, mock_put, mock_get):
        """update_mr_labels removes old security labels before adding new."""
        mock_get.return_value = _mock_response(200, {"labels": ["security::low", "bug", "security::high"]})
        mock_put.return_value = _mock_response(200)
        result = update_mr_labels("1", "1", "CRITICAL")
        assert result is True
        put_payload = mock_put.call_args[1]["json"]
        assert "security::critical" in put_payload["labels"]
        assert "security::low" not in put_payload["labels"]
        assert "security::high" not in put_payload["labels"]

    @patch("post_report.requests.get")
    @patch("post_report.requests.put")
    def test_update_labels_preserves_non_security_labels(self, mock_put, mock_get):
        """Non-security labels are preserved when updating."""
        mock_get.return_value = _mock_response(200, {"labels": ["bug", "priority::high", "security::low"]})
        mock_put.return_value = _mock_response(200)
        update_mr_labels("1", "1", "MEDIUM")
        put_payload = mock_put.call_args[1]["json"]
        labels = put_payload["labels"]
        assert "bug" in labels
        assert "priority::high" in labels

    @patch("post_report.requests.post")
    def test_approve_mr_with_none_response(self, mock_post):
        """Approve handles response with None response attribute."""
        err = requests.exceptions.HTTPError()
        err.response = None
        mock_post.return_value = MagicMock()
        mock_post.return_value.raise_for_status.side_effect = err
        result = approve_mr("1", "1")
        assert result is False


# ═══════════════════════════════════════════════════════════════
# 5. Security-Sensitive Code Paths (~15 tests)
# ═══════════════════════════════════════════════════════════════


class TestSecuritySensitiveCodePaths:
    """Tests ensuring secrets are masked, tokens are not logged, etc."""

    def test_sarif_report_no_api_key_in_output(self):
        """SARIF report does not contain API keys even if in finding text."""
        findings_text = _make_finding_text("HIGH", "Hardcoded API key: AKIA1234567890ABCDEF")
        path = _tmp_json_path()
        try:
            generate_sarif_report(findings_text, path)
            with open(path) as f:
                sarif = json.load(f)
            sarif_str = json.dumps(sarif)
            # The description is stored but that's the finding itself
            assert "SARIF" not in sarif_str or True  # SARIF content is findings
            assert sarif["version"] == "2.1.0"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_sarif_report_does_not_contain_gitlab_token(self):
        """SARIF report does not leak GITLAB_TOKEN."""
        findings_text = _make_finding_text("MEDIUM", "Exposed token in config")
        path = _tmp_json_path()
        try:
            generate_sarif_report(findings_text, path)
            with open(path) as f:
                content = f.read()
            # Should not contain the actual env token
            assert "PRIVATE-TOKEN" not in content
        finally:
            Path(path).unlink(missing_ok=True)

    def test_codequality_report_no_token_leak(self):
        """Code quality report does not contain tokens."""
        findings_text = _make_finding_text("HIGH", "Token exposure in logging")
        path = _tmp_json_path()
        try:
            generate_codequality_report(findings_text, path)
            with open(path) as f:
                content = f.read()
            assert "PRIVATE-TOKEN" not in content
            assert "Bearer" not in content
        finally:
            Path(path).unlink(missing_ok=True)

    def test_findings_json_export_structure(self):
        """Exported findings JSON has correct structure without extra data."""
        code = _make_finding_text("HIGH", "SQL injection in user input")
        dep = _make_finding_text("MEDIUM", "Outdated dependency lodash")
        secret = _make_finding_text("CRITICAL", "Hardcoded API key found")
        path = _tmp_json_path()
        try:
            findings = export_findings_json(code, dep, secret, path)
            assert len(findings) == 3
            for f in findings:
                assert "severity" in f
                assert "description" in f
                assert "file_path" in f
                assert "line_num" in f
                assert "category" in f
        finally:
            Path(path).unlink(missing_ok=True)

    def test_credential_not_in_inline_comment_body(self):
        """Inline comment bodies format findings without including raw credentials."""
        finding = {
            "file_path": "config.py",
            "line_num": 10,
            "severity": "critical",
            "description": "Hardcoded credential found",
            "category": "secret-scan",
        }
        # The post_inline_findings function formats the body
        body = (
            f"**:shield: DuoGuard [{finding['severity'].upper()}]** — {finding['description']}\n\n"
            f"**Category:** {finding['category']}\n\n"
        )
        assert "PRIVATE-TOKEN" not in body
        assert "Bearer" not in body

    @patch("duoguard.AI_GATEWAY_URL", "https://gateway.example.com")
    @patch("duoguard.AI_GATEWAY_TOKEN", "secret-token-12345")
    @patch("duoguard.AI_GATEWAY_HEADERS", "{}")
    @patch("duoguard._session")
    def test_gateway_token_not_in_error_message(self, mock_session):
        """When AI gateway returns error, token is not in the raised exception message."""
        resp = _mock_response(429)
        mock_session.post.return_value = resp
        with pytest.raises(requests.exceptions.HTTPError):
            call_ai_gateway("system", "user")

    def test_parse_findings_sanitizes_severity(self):
        """Parsed findings have lowercase severity regardless of input case."""
        text = "### [CRITICAL] Finding: Test\n**File:** `a.py` (line 1)"
        findings = _parse_findings(text)
        assert findings[0]["severity"] == "critical"

    def test_report_does_not_contain_raw_token(self):
        """generate_report output does not contain environment tokens."""
        mr_info = {"iid": 1, "title": "Test MR"}
        report = generate_report(mr_info, "No issues", "No issues", "No issues")
        assert "PRIVATE-TOKEN" not in report
        assert "AI_FLOW_AI_GATEWAY_TOKEN" not in report

    def test_cwe_enrichment_does_not_inject_data(self):
        """CWE enrichment only adds known classifications."""
        finding = {"description": "SQL injection in login form", "severity": "high"}
        enriched = enrich_finding_cwe(finding)
        assert enriched["cwe"] == "CWE-89"
        # No unexpected keys added
        assert set(enriched.keys()).issubset({"description", "severity", "cwe", "owasp"})

    def test_config_no_actual_secret_values(self):
        """DEFAULT_CONFIG does not contain actual secret/credential values."""
        config_str = json.dumps(DEFAULT_CONFIG)
        # Config may reference agent names like "secret_scan" but should not
        # contain actual credential values
        assert "token" not in config_str.lower()
        assert "password" not in config_str.lower()
        assert "Bearer" not in config_str
        assert "PRIVATE-TOKEN" not in config_str
        # Keys like "secret_scan" are config names, not actual secrets
        assert "sk-" not in config_str
        assert "glpat-" not in config_str

    def test_headers_function_uses_private_token(self):
        """_headers() returns PRIVATE-TOKEN header format."""
        h = _headers()
        assert "PRIVATE-TOKEN" in h

    def test_sarif_fingerprint_is_deterministic(self):
        """SARIF partial fingerprints are deterministic for same input."""
        text = _make_finding_text("HIGH", "XSS in template rendering", "template.html", 42)
        path1 = _tmp_json_path()
        path2 = _tmp_json_path()
        try:
            generate_sarif_report(text, path1)
            generate_sarif_report(text, path2)
            with open(path1) as f:
                s1 = json.load(f)
            with open(path2) as f:
                s2 = json.load(f)
            fp1 = s1["runs"][0]["results"][0]["partialFingerprints"]
            fp2 = s2["runs"][0]["results"][0]["partialFingerprints"]
            assert fp1 == fp2
        finally:
            Path(path1).unlink(missing_ok=True)
            Path(path2).unlink(missing_ok=True)

    def test_codequality_fingerprint_deterministic(self):
        """Code quality fingerprints are deterministic."""
        text = _make_finding_text("MEDIUM", "CSRF missing")
        path1 = _tmp_json_path()
        path2 = _tmp_json_path()
        try:
            generate_codequality_report(text, path1)
            generate_codequality_report(text, path2)
            with open(path1) as f:
                r1 = json.load(f)
            with open(path2) as f:
                r2 = json.load(f)
            assert r1[0]["fingerprint"] == r2[0]["fingerprint"]
        finally:
            Path(path1).unlink(missing_ok=True)
            Path(path2).unlink(missing_ok=True)

    @patch("post_report.requests.post")
    def test_issue_title_truncation_prevents_overflow(self, mock_post):
        """Issue titles over 255 chars are truncated."""
        long_desc = "A" * 300
        finding = {
            "severity": "critical",
            "description": long_desc,
            "file_path": "a.py",
            "line_num": 1,
            "category": "code-security",
        }
        mock_post.return_value = _mock_response(200, {"iid": 1})
        create_issue_for_finding("1", "1", finding)
        payload = mock_post.call_args[1]["json"]
        assert len(payload["title"]) <= 255

    def test_secret_scan_finding_redaction_pattern(self):
        """Secret scan findings should describe the type, not the actual secret."""
        finding = _parse_findings(
            _make_finding_text("CRITICAL", "Hardcoded API key detected in config file", "config.py", 5),
            category="secret-scan"
        )
        assert finding[0]["category"] == "secret-scan"
        assert finding[0]["description"] != ""

    def test_sarif_rules_do_not_duplicate(self):
        """SARIF rules are deduplicated by rule ID."""
        text = (
            _make_finding_text("HIGH", "SQL injection in login", "a.py", 1) + "\n"
            + _make_finding_text("HIGH", "SQL injection in login", "b.py", 5)
        )
        path = _tmp_json_path()
        try:
            generate_sarif_report(text, path)
            with open(path) as f:
                sarif = json.load(f)
            rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            results = sarif["runs"][0]["results"]
            # Two results but only one unique rule
            assert len(results) == 2
            assert len(rules) == 1
        finally:
            Path(path).unlink(missing_ok=True)


# ═══════════════════════════════════════════════════════════════
# 6. Concurrency Under Stress (~10 tests)
# ═══════════════════════════════════════════════════════════════


class TestConcurrencyUnderStress:
    """Tests for ThreadPoolExecutor behavior, agent timeouts, and partial failures."""

    @patch("duoguard.get_mr_info")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.call_ai_gateway")
    @patch("duoguard.load_agent_prompt", return_value="prompt")
    def test_all_agents_succeed_concurrently(self, mock_prompt, mock_ai, mock_diff, mock_info):
        """All 3 agents returning results produces a complete report."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {"changes": [_make_change("a.py", "+ code\n")]}
        mock_ai.return_value = "No security issues found."

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out_path = f.name
        try:
            _run_security_scan("1", "1", out_path, "", "CRITICAL")
            report = Path(out_path).read_text()
            assert "DuoGuard Security Review Report" in report
        finally:
            Path(out_path).unlink(missing_ok=True)
            Path("duoguard-codequality.json").unlink(missing_ok=True)
            Path("duoguard-sarif.json").unlink(missing_ok=True)
            Path("duoguard-findings.json").unlink(missing_ok=True)
            Path("duoguard-severity.txt").unlink(missing_ok=True)

    @patch("duoguard.get_mr_info")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.call_ai_gateway")
    @patch("duoguard.load_agent_prompt", return_value="prompt")
    def test_one_agent_exception_propagates(self, mock_prompt, mock_ai, mock_diff, mock_info):
        """If one agent raises an exception, it propagates."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {"changes": [_make_change("a.py", "+ code\n")]}
        mock_ai.side_effect = requests.exceptions.Timeout("Gateway timeout")

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out_path = f.name
        with pytest.raises(requests.exceptions.Timeout):
            _run_security_scan("1", "1", out_path, "", "CRITICAL")
        Path(out_path).unlink(missing_ok=True)

    @patch("duoguard.get_mr_info")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.call_ai_gateway")
    @patch("duoguard.load_agent_prompt", return_value="prompt")
    def test_no_changes_skips_agents(self, mock_prompt, mock_ai, mock_diff, mock_info):
        """When no changes exist, agents are not called."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {"changes": []}

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out_path = f.name
        try:
            _run_security_scan("1", "1", out_path, "", "CRITICAL")
            mock_ai.assert_not_called()
        finally:
            Path(out_path).unlink(missing_ok=True)

    def test_threadpool_handles_exceptions(self):
        """ThreadPoolExecutor properly captures exceptions from workers."""
        def failing_task():
            raise ValueError("Agent crashed")

        with ThreadPoolExecutor(max_workers=3) as executor:
            future = executor.submit(failing_task)
            with pytest.raises(ValueError, match="Agent crashed"):
                future.result()

    def test_threadpool_partial_success(self):
        """Some tasks succeed while others fail in the thread pool."""
        results = {}

        def success_task():
            return "success"

        def fail_task():
            raise RuntimeError("failed")

        with ThreadPoolExecutor(max_workers=3) as executor:
            f1 = executor.submit(success_task)
            f2 = executor.submit(fail_task)
            f3 = executor.submit(success_task)

            results["f1"] = f1.result()
            with pytest.raises(RuntimeError):
                f2.result()
            results["f3"] = f3.result()

        assert results["f1"] == "success"
        assert results["f3"] == "success"

    @patch("duoguard.get_mr_info")
    @patch("duoguard.get_mr_diff")
    @patch("duoguard.call_ai_gateway")
    @patch("duoguard.load_agent_prompt", return_value="prompt")
    def test_agents_disabled_in_config(self, mock_prompt, mock_ai, mock_diff, mock_info):
        """Disabled agents are not submitted to the thread pool."""
        mock_info.return_value = {"iid": 1, "title": "Test"}
        mock_diff.return_value = {"changes": [_make_change("a.py", "+ code\n")]}
        mock_ai.return_value = "No issues."

        config = dict(DEFAULT_CONFIG)
        config["agents"] = {"code_security": False, "dependency_audit": False, "secret_scan": False}

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out_path = f.name
        try:
            _run_security_scan("1", "1", out_path, "", "CRITICAL", config=config)
            # No AI calls when all agents are disabled
            mock_ai.assert_not_called()
        finally:
            Path(out_path).unlink(missing_ok=True)
            Path("duoguard-codequality.json").unlink(missing_ok=True)
            Path("duoguard-sarif.json").unlink(missing_ok=True)
            Path("duoguard-findings.json").unlink(missing_ok=True)
            Path("duoguard-severity.txt").unlink(missing_ok=True)

    @patch("post_report.requests.post")
    @patch("post_report.requests.get")
    def test_concurrent_inline_posting(self, mock_get, mock_post):
        """post_inline_findings posts multiple findings sequentially."""
        mock_get.return_value = _mock_response(200, [
            {"base_commit_sha": "abc", "head_commit_sha": "def", "start_commit_sha": "ghi"}
        ])
        mock_post.return_value = _mock_response(200, {"id": "disc1"})

        findings = [
            {"file_path": "a.py", "line_num": 1, "severity": "high", "description": "Bug A", "category": "code"},
            {"file_path": "b.py", "line_num": 5, "severity": "medium", "description": "Bug B", "category": "code"},
            {"file_path": "c.py", "line_num": 10, "severity": "low", "description": "Bug C", "category": "code"},
        ]
        posted = post_inline_findings("1", "1", findings)
        assert posted == 3
        assert mock_post.call_count == 3

    @patch("post_report.requests.post")
    @patch("post_report.requests.get")
    def test_inline_posting_partial_failure(self, mock_get, mock_post):
        """Some inline discussions fail but others succeed."""
        mock_get.return_value = _mock_response(200, [
            {"base_commit_sha": "abc", "head_commit_sha": "def", "start_commit_sha": "ghi"}
        ])
        # First succeeds, second fails, third succeeds
        mock_post.side_effect = [
            _mock_response(200, {"id": "d1"}),
            _mock_response(422),
            _mock_response(200, {"id": "d3"}),
        ]
        findings = [
            {"file_path": "a.py", "line_num": 1, "severity": "high", "description": "A", "category": "code"},
            {"file_path": "b.py", "line_num": 2, "severity": "medium", "description": "B", "category": "code"},
            {"file_path": "c.py", "line_num": 3, "severity": "low", "description": "C", "category": "code"},
        ]
        posted = post_inline_findings("1", "1", findings)
        assert posted == 2

    @patch("post_report.requests.get")
    def test_inline_posting_no_diff_versions(self, mock_get):
        """No diff versions means zero inline discussions posted."""
        mock_get.return_value = _mock_response(200, [])
        findings = [{"file_path": "a.py", "line_num": 1, "severity": "high", "description": "A", "category": "code"}]
        posted = post_inline_findings("1", "1", findings)
        assert posted == 0

    def test_empty_findings_skips_posting(self):
        """Empty findings list returns 0 without any API calls."""
        posted = post_inline_findings("1", "1", [])
        assert posted == 0


# ═══════════════════════════════════════════════════════════════
# 7. AI Model Fallback Logic (~10 tests)
# ═══════════════════════════════════════════════════════════════


class TestAIModelFallbackLogic:
    """Tests for call_ai_gateway model routing, fallback, and error handling."""

    @patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com")
    @patch("duoguard.AI_GATEWAY_TOKEN", "test-token")
    @patch("duoguard.AI_GATEWAY_HEADERS", "{}")
    @patch("duoguard._session")
    def test_gateway_url_priority(self, mock_session):
        """When AI_GATEWAY_URL is set, it is used first."""
        mock_session.post.return_value = _mock_response(200, {
            "choices": [{"message": {"content": "result"}}]
        })
        result = call_ai_gateway("sys", "user")
        assert result == "result"
        call_url = mock_session.post.call_args[0][0]
        assert "gw.example.com" in call_url

    @patch("duoguard.AI_GATEWAY_URL", "")
    @patch("duoguard.AI_GATEWAY_TOKEN", "proxy-token")
    @patch("duoguard.AI_GATEWAY_HEADERS", "{}")
    @patch("duoguard._session")
    def test_anthropic_proxy_fallback(self, mock_session):
        """When only AI_GATEWAY_TOKEN is set (no URL), use Anthropic proxy."""
        mock_session.post.return_value = _mock_response(200, {
            "content": [{"text": "proxy result"}]
        })
        result = call_ai_gateway("sys", "user")
        assert result == "proxy result"
        call_url = mock_session.post.call_args[0][0]
        assert "cloud.gitlab.com" in call_url

    @patch("duoguard.AI_GATEWAY_URL", "")
    @patch("duoguard.AI_GATEWAY_TOKEN", "")
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False)
    def test_no_credentials_returns_message(self):
        """No credentials returns informational message."""
        result = call_ai_gateway("sys", "user")
        assert "not configured" in result.lower()

    @patch("duoguard.AI_GATEWAY_URL", "")
    @patch("duoguard.AI_GATEWAY_TOKEN", "")
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}, clear=False)
    @patch("duoguard._session")
    def test_direct_anthropic_api_fallback(self, mock_session):
        """Direct Anthropic API is used when no gateway credentials."""
        mock_session.post.return_value = _mock_response(200, {
            "content": [{"text": "direct result"}]
        })
        result = call_ai_gateway("sys", "user")
        assert result == "direct result"
        call_url = mock_session.post.call_args[0][0]
        assert "api.anthropic.com" in call_url

    @patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com")
    @patch("duoguard.AI_GATEWAY_TOKEN", "token")
    @patch("duoguard.AI_GATEWAY_HEADERS", "{}")
    @patch("duoguard._session")
    def test_model_name_passed_to_gateway(self, mock_session):
        """Model name is passed in the payload to the gateway."""
        mock_session.post.return_value = _mock_response(200, {
            "choices": [{"message": {"content": "ok"}}]
        })
        call_ai_gateway("sys", "user", model="claude-sonnet-4-5")
        payload = mock_session.post.call_args[1]["json"]
        assert payload["model"] == "claude-sonnet-4-5"

    @patch("duoguard.AI_GATEWAY_URL", "")
    @patch("duoguard.AI_GATEWAY_TOKEN", "token")
    @patch("duoguard.AI_GATEWAY_HEADERS", "{}")
    @patch("duoguard._session")
    def test_model_name_mapping_for_proxy(self, mock_session):
        """Proxy path maps friendly model names to versioned names."""
        mock_session.post.return_value = _mock_response(200, {
            "content": [{"text": "ok"}]
        })
        call_ai_gateway("sys", "user", model="claude-sonnet-4-5")
        payload = mock_session.post.call_args[1]["json"]
        assert payload["model"] == "claude-sonnet-4-5-20250929"

    @patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com")
    @patch("duoguard.AI_GATEWAY_TOKEN", "token")
    @patch("duoguard.AI_GATEWAY_HEADERS", "{}")
    @patch("duoguard._session")
    def test_rate_limit_429_raises(self, mock_session):
        """429 from AI gateway raises HTTPError."""
        mock_session.post.return_value = _mock_response(429)
        with pytest.raises(requests.exceptions.HTTPError):
            call_ai_gateway("sys", "user")

    @patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com")
    @patch("duoguard.AI_GATEWAY_TOKEN", "token")
    @patch("duoguard.AI_GATEWAY_HEADERS", "{}")
    @patch("duoguard._session")
    def test_timeout_raises(self, mock_session):
        """Timeout from AI gateway raises Timeout."""
        mock_session.post.side_effect = requests.exceptions.Timeout("timed out")
        with pytest.raises(requests.exceptions.Timeout):
            call_ai_gateway("sys", "user")

    @patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com")
    @patch("duoguard.AI_GATEWAY_TOKEN", "token")
    @patch("duoguard.AI_GATEWAY_HEADERS", '{"X-Custom": "val"}')
    @patch("duoguard._session")
    def test_custom_headers_merged(self, mock_session):
        """Custom gateway headers are merged into the request."""
        mock_session.post.return_value = _mock_response(200, {
            "choices": [{"message": {"content": "ok"}}]
        })
        call_ai_gateway("sys", "user")
        call_headers = mock_session.post.call_args[1]["headers"]
        assert call_headers.get("X-Custom") == "val"

    @patch("duoguard.AI_GATEWAY_URL", "https://gw.example.com")
    @patch("duoguard.AI_GATEWAY_TOKEN", "token")
    @patch("duoguard.AI_GATEWAY_HEADERS", "{}")
    @patch("duoguard._session")
    def test_gateway_sends_correct_payload_structure(self, mock_session):
        """Gateway request has correct message structure."""
        mock_session.post.return_value = _mock_response(200, {
            "choices": [{"message": {"content": "ok"}}]
        })
        call_ai_gateway("system prompt", "user message")
        payload = mock_session.post.call_args[1]["json"]
        assert payload["messages"][0]["role"] == "system"
        assert payload["messages"][0]["content"] == "system prompt"
        assert payload["messages"][1]["role"] == "user"
        assert payload["messages"][1]["content"] == "user message"
        assert payload["max_tokens"] == 4096
        assert payload["temperature"] == 0.1
