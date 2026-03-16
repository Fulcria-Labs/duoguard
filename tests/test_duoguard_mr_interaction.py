"""Tests for DuoGuard GitLab MR interaction functions.

Covers: post_mr_note, post_inline_discussions, set_mr_labels,
approve_or_reject_mr, create_issues_for_findings.

These functions post results directly back to GitLab merge requests
when running in agent mode (single-process execution).
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from duoguard import (
    approve_or_reject_mr,
    create_issues_for_findings,
    post_inline_discussions,
    post_mr_note,
    set_mr_labels,
)


# ── Helpers ──────────────────────────────────────────────────────


def _ok_response(status=200, json_data=None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data or {}
    resp.raise_for_status.return_value = None
    return resp


def _error_response(status=403):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=resp
    )
    return resp


def _sample_findings(n=3, with_lines=True):
    findings = []
    for i in range(n):
        f = {
            "severity": ["CRITICAL", "HIGH", "MEDIUM"][i % 3],
            "description": f"Finding {i}: SQL injection in query builder",
            "file_path": f"src/app{i}.py",
            "category": "code-security",
            "cwe_id": f"CWE-{89 + i}",
        }
        if with_lines:
            f["line_num"] = 10 + i * 5
        findings.append(f)
    return findings


def _sample_mr_changes(paths=None):
    paths = paths or ["src/app0.py", "src/app1.py", "src/app2.py"]
    return {
        "changes": [{"new_path": p, "diff": f"+code_{i}"} for i, p in enumerate(paths)],
        "diff_refs": {
            "base_sha": "aaa111",
            "head_sha": "bbb222",
            "start_sha": "ccc333",
        },
    }


# ═══════════════════════════════════════════════════════════════
# post_mr_note
# ═══════════════════════════════════════════════════════════════


class TestPostMrNote:
    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_posts_note_successfully(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"id": 42})
        result = post_mr_note("123", "5", "## Report\nAll good.")
        assert result is True
        mock_session.post.assert_called_once()
        args, kwargs = mock_session.post.call_args
        assert "/merge_requests/5/notes" in args[0]
        assert kwargs["json"]["body"] == "## Report\nAll good."

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_returns_false_on_http_error(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.HTTPError("403")
        result = post_mr_note("123", "5", "body")
        assert result is False

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_returns_false_on_connection_error(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.ConnectionError()
        result = post_mr_note("123", "5", "body")
        assert result is False

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "")
    def test_skips_when_no_token(self, mock_session):
        result = post_mr_note("123", "5", "body")
        assert result is False
        mock_session.post.assert_not_called()

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_uses_url_encoded_project_id(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        post_mr_note("my/project", "5", "body")
        url = mock_session.post.call_args[0][0]
        assert "my%2Fproject" in url

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_sends_private_token_header(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        post_mr_note("123", "5", "body")
        headers = mock_session.post.call_args[1]["headers"]
        assert headers["PRIVATE-TOKEN"] == "glpat-test"

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_posts_empty_body(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        result = post_mr_note("123", "5", "")
        assert result is True

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_posts_large_body(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        body = "x" * 100_000
        result = post_mr_note("123", "5", body)
        assert result is True


# ═══════════════════════════════════════════════════════════════
# post_inline_discussions
# ═══════════════════════════════════════════════════════════════


class TestPostInlineDiscussions:
    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_posts_discussions_for_valid_findings(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        findings = _sample_findings(2)
        changes = _sample_mr_changes()
        posted = post_inline_discussions("123", "5", findings, changes)
        assert posted == 2
        assert mock_session.post.call_count == 2

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_skips_findings_without_line_num(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        findings = _sample_findings(2, with_lines=False)
        changes = _sample_mr_changes()
        posted = post_inline_discussions("123", "5", findings, changes)
        assert posted == 0
        mock_session.post.assert_not_called()

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_skips_findings_for_unknown_paths(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        findings = [{"severity": "HIGH", "description": "Bad",
                      "file_path": "unknown.py", "line_num": 5,
                      "category": "code"}]
        changes = _sample_mr_changes(["src/app.py"])
        posted = post_inline_discussions("123", "5", findings, changes)
        assert posted == 0

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "")
    def test_returns_zero_when_no_token(self, mock_session):
        findings = _sample_findings()
        changes = _sample_mr_changes()
        posted = post_inline_discussions("123", "5", findings, changes)
        assert posted == 0

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_handles_partial_failures(self, mock_session):
        responses = [_ok_response(201), _ok_response(422), _ok_response(201)]
        mock_session.post.side_effect = responses
        findings = _sample_findings(3)
        changes = _sample_mr_changes()
        posted = post_inline_discussions("123", "5", findings, changes)
        # 422 doesn't count as posted (status not in 200,201)
        assert posted == 2

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_includes_diff_refs_in_position(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        findings = [{"severity": "HIGH", "description": "SQL injection",
                      "file_path": "src/app0.py", "line_num": 10,
                      "category": "code", "cwe_id": "CWE-89"}]
        changes = _sample_mr_changes()
        post_inline_discussions("123", "5", findings, changes)
        payload = mock_session.post.call_args[1]["json"]
        pos = payload["position"]
        assert pos["head_sha"] == "bbb222"
        assert pos["base_sha"] == "aaa111"
        assert pos["start_sha"] == "ccc333"
        assert pos["new_line"] == 10
        assert pos["new_path"] == "src/app0.py"

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_body_includes_severity_and_cwe(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        findings = [{"severity": "CRITICAL", "description": "RCE found",
                      "file_path": "src/app0.py", "line_num": 10,
                      "category": "code-security", "cwe_id": "CWE-78"}]
        changes = _sample_mr_changes()
        post_inline_discussions("123", "5", findings, changes)
        body = mock_session.post.call_args[1]["json"]["body"]
        assert "[CRITICAL]" in body
        assert "CWE-78" in body
        assert "RCE found" in body

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_strips_leading_slash_from_path(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        findings = [{"severity": "HIGH", "description": "Vuln",
                      "file_path": "/src/app0.py", "line_num": 10,
                      "category": "code"}]
        changes = _sample_mr_changes()
        posted = post_inline_discussions("123", "5", findings, changes)
        assert posted == 1

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_handles_connection_error_gracefully(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.ConnectionError()
        findings = _sample_findings(1)
        changes = _sample_mr_changes()
        posted = post_inline_discussions("123", "5", findings, changes)
        assert posted == 0

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_empty_findings_returns_zero(self, mock_session):
        changes = _sample_mr_changes()
        posted = post_inline_discussions("123", "5", [], changes)
        assert posted == 0
        mock_session.post.assert_not_called()

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_no_diff_refs_still_posts(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        findings = _sample_findings(1)
        changes = {"changes": [{"new_path": "src/app0.py", "diff": "+x"}], "diff_refs": {}}
        posted = post_inline_discussions("123", "5", findings, changes)
        assert posted == 1
        pos = mock_session.post.call_args[1]["json"]["position"]
        assert "head_sha" not in pos

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_severity_emoji_mapping(self, mock_session):
        mock_session.post.return_value = _ok_response(201)
        for sev, emoji in [("CRITICAL", "🔴"), ("HIGH", "🟠"), ("MEDIUM", "🟡"), ("LOW", "🔵")]:
            findings = [{"severity": sev, "description": "Test",
                          "file_path": "src/app0.py", "line_num": 1, "category": "code"}]
            changes = _sample_mr_changes()
            post_inline_discussions("123", "5", findings, changes)
            body = mock_session.post.call_args[1]["json"]["body"]
            assert emoji in body


# ═══════════════════════════════════════════════════════════════
# set_mr_labels
# ═══════════════════════════════════════════════════════════════


class TestSetMrLabels:
    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_sets_critical_label(self, mock_session):
        mock_session.get.return_value = _ok_response(200, {"labels": []})
        mock_session.put.return_value = _ok_response(200)
        result = set_mr_labels("123", "5", "CRITICAL")
        assert result is True
        put_call = mock_session.put.call_args
        assert "security::critical" in put_call[1]["json"]["labels"]

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_sets_clean_label_for_none(self, mock_session):
        mock_session.get.return_value = _ok_response(200, {"labels": []})
        mock_session.put.return_value = _ok_response(200)
        set_mr_labels("123", "5", "NONE")
        labels = mock_session.put.call_args[1]["json"]["labels"]
        assert "security::clean" in labels

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_removes_existing_security_labels(self, mock_session):
        mock_session.get.return_value = _ok_response(200, {
            "labels": ["security::high", "bugfix", "security::medium"]
        })
        mock_session.put.return_value = _ok_response(200)
        set_mr_labels("123", "5", "LOW")
        labels = mock_session.put.call_args[1]["json"]["labels"]
        assert "security::high" not in labels
        assert "security::medium" not in labels
        assert "bugfix" in labels
        assert "security::low" in labels

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "")
    def test_returns_false_when_no_token(self, mock_session):
        result = set_mr_labels("123", "5", "HIGH")
        assert result is False

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_handles_get_failure(self, mock_session):
        mock_session.get.side_effect = requests.exceptions.HTTPError()
        result = set_mr_labels("123", "5", "HIGH")
        assert result is False

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_handles_put_failure(self, mock_session):
        mock_session.get.return_value = _ok_response(200, {"labels": []})
        mock_session.put.side_effect = requests.exceptions.HTTPError()
        result = set_mr_labels("123", "5", "HIGH")
        assert result is False

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_all_severity_levels_map_correctly(self, mock_session):
        mock_session.get.return_value = _ok_response(200, {"labels": []})
        mock_session.put.return_value = _ok_response(200)
        for sev, expected in [("CRITICAL", "security::critical"),
                               ("HIGH", "security::high"),
                               ("MEDIUM", "security::medium"),
                               ("LOW", "security::low"),
                               ("NONE", "security::clean")]:
            set_mr_labels("123", "5", sev)
            labels = mock_session.put.call_args[1]["json"]["labels"]
            assert expected in labels

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_preserves_non_security_labels(self, mock_session):
        mock_session.get.return_value = _ok_response(200, {
            "labels": ["feature", "priority::high", "team::backend"]
        })
        mock_session.put.return_value = _ok_response(200)
        set_mr_labels("123", "5", "HIGH")
        labels = mock_session.put.call_args[1]["json"]["labels"]
        assert "feature" in labels
        assert "priority::high" in labels
        assert "team::backend" in labels

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_unknown_severity_gets_reviewed_label(self, mock_session):
        mock_session.get.return_value = _ok_response(200, {"labels": []})
        mock_session.put.return_value = _ok_response(200)
        set_mr_labels("123", "5", "UNKNOWN")
        labels = mock_session.put.call_args[1]["json"]["labels"]
        assert "security::reviewed" in labels


# ═══════════════════════════════════════════════════════════════
# approve_or_reject_mr
# ═══════════════════════════════════════════════════════════════


class TestApproveOrRejectMr:
    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_approves_when_below_threshold(self, mock_session):
        mock_session.post.return_value = _ok_response(200)
        cfg = {"approve": True, "approve_threshold": "HIGH"}
        result = approve_or_reject_mr("123", "5", "LOW", cfg)
        assert result == "approved"
        assert "/approve" in mock_session.post.call_args[0][0]

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_unapproved_when_at_threshold(self, mock_session):
        cfg = {"approve": True, "approve_threshold": "HIGH"}
        result = approve_or_reject_mr("123", "5", "HIGH", cfg)
        assert result == "unapproved"
        mock_session.post.assert_not_called()

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_unapproved_when_above_threshold(self, mock_session):
        cfg = {"approve": True, "approve_threshold": "HIGH"}
        result = approve_or_reject_mr("123", "5", "CRITICAL", cfg)
        assert result == "unapproved"

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_returns_none_when_disabled(self, mock_session):
        cfg = {"approve": False}
        result = approve_or_reject_mr("123", "5", "LOW", cfg)
        assert result is None

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_returns_none_when_key_missing(self, mock_session):
        cfg = {}
        result = approve_or_reject_mr("123", "5", "LOW", cfg)
        assert result is None

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "")
    def test_returns_none_when_no_token(self, mock_session):
        cfg = {"approve": True, "approve_threshold": "HIGH"}
        result = approve_or_reject_mr("123", "5", "LOW", cfg)
        assert result is None

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_approves_none_severity(self, mock_session):
        mock_session.post.return_value = _ok_response(200)
        cfg = {"approve": True, "approve_threshold": "HIGH"}
        result = approve_or_reject_mr("123", "5", "NONE", cfg)
        assert result == "approved"

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_approves_medium_when_threshold_critical(self, mock_session):
        mock_session.post.return_value = _ok_response(200)
        cfg = {"approve": True, "approve_threshold": "CRITICAL"}
        result = approve_or_reject_mr("123", "5", "MEDIUM", cfg)
        assert result == "approved"

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_handles_approve_api_failure(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.HTTPError()
        cfg = {"approve": True, "approve_threshold": "HIGH"}
        result = approve_or_reject_mr("123", "5", "NONE", cfg)
        assert result is None

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_threshold_low_rejects_medium(self, mock_session):
        cfg = {"approve": True, "approve_threshold": "LOW"}
        result = approve_or_reject_mr("123", "5", "MEDIUM", cfg)
        assert result == "unapproved"

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_threshold_none_always_rejects(self, mock_session):
        cfg = {"approve": True, "approve_threshold": "NONE"}
        result = approve_or_reject_mr("123", "5", "NONE", cfg)
        assert result == "unapproved"

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_uses_url_encoded_project_id(self, mock_session):
        mock_session.post.return_value = _ok_response(200)
        cfg = {"approve": True, "approve_threshold": "HIGH"}
        approve_or_reject_mr("my/project", "5", "LOW", cfg)
        url = mock_session.post.call_args[0][0]
        assert "my%2Fproject" in url


# ═══════════════════════════════════════════════════════════════
# create_issues_for_findings
# ═══════════════════════════════════════════════════════════════


class TestCreateIssuesForFindings:
    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_creates_issues_for_critical_findings(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 1})
        findings = [{"severity": "CRITICAL", "description": "RCE",
                      "file_path": "app.py", "line_num": 5,
                      "category": "code", "cwe_id": "CWE-78"}]
        created = create_issues_for_findings("123", findings, "5")
        assert created == 1
        payload = mock_session.post.call_args[1]["json"]
        assert "[DuoGuard]" in payload["title"]
        assert "[CRITICAL]" in payload["title"]

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_creates_issues_for_high_findings(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 2})
        findings = [{"severity": "HIGH", "description": "SQLi",
                      "file_path": "db.py", "line_num": 10,
                      "category": "code", "cwe_id": "CWE-89"}]
        created = create_issues_for_findings("123", findings, "5")
        assert created == 1

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_skips_medium_and_low_findings(self, mock_session):
        findings = [{"severity": "MEDIUM", "description": "Info disclosure",
                      "file_path": "app.py", "line_num": 1, "category": "code"},
                     {"severity": "LOW", "description": "Debug enabled",
                      "file_path": "app.py", "line_num": 2, "category": "code"}]
        created = create_issues_for_findings("123", findings, "5")
        assert created == 0
        mock_session.post.assert_not_called()

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_respects_max_issues_limit(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 1})
        findings = [{"severity": "CRITICAL", "description": f"Finding {i}",
                      "file_path": f"f{i}.py", "line_num": i,
                      "category": "code"} for i in range(10)]
        created = create_issues_for_findings("123", findings, "5", max_issues=3)
        assert created == 3
        assert mock_session.post.call_count == 3

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "")
    def test_returns_zero_when_no_token(self, mock_session):
        findings = _sample_findings()
        created = create_issues_for_findings("123", findings, "5")
        assert created == 0

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_returns_zero_for_empty_findings(self, mock_session):
        created = create_issues_for_findings("123", [], "5")
        assert created == 0
        mock_session.post.assert_not_called()

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_handles_api_failure_gracefully(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.ConnectionError()
        findings = [{"severity": "CRITICAL", "description": "Bad",
                      "file_path": "a.py", "line_num": 1, "category": "code"}]
        created = create_issues_for_findings("123", findings, "5")
        assert created == 0

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_issue_body_includes_cwe_link(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 1})
        findings = [{"severity": "HIGH", "description": "SQLi",
                      "file_path": "db.py", "line_num": 5,
                      "category": "code", "cwe_id": "CWE-89"}]
        create_issues_for_findings("123", findings, "5")
        body = mock_session.post.call_args[1]["json"]["description"]
        assert "cwe.mitre.org" in body
        assert "89" in body

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_issue_labels_include_severity(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 1})
        findings = [{"severity": "CRITICAL", "description": "RCE",
                      "file_path": "a.py", "line_num": 1, "category": "code"}]
        create_issues_for_findings("123", findings, "5")
        labels = mock_session.post.call_args[1]["json"]["labels"]
        assert "security::critical" in labels
        assert "DuoGuard" in labels

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_truncates_long_description_in_title(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 1})
        findings = [{"severity": "HIGH", "description": "A" * 200,
                      "file_path": "a.py", "line_num": 1, "category": "code"}]
        create_issues_for_findings("123", findings, "5")
        title = mock_session.post.call_args[1]["json"]["title"]
        assert len(title) <= 100  # [DuoGuard] [HIGH] + 80 chars

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_mixed_findings_only_creates_for_high_plus(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 1})
        findings = [
            {"severity": "CRITICAL", "description": "RCE", "file_path": "a.py",
             "line_num": 1, "category": "code"},
            {"severity": "MEDIUM", "description": "Info", "file_path": "b.py",
             "line_num": 2, "category": "code"},
            {"severity": "HIGH", "description": "SQLi", "file_path": "c.py",
             "line_num": 3, "category": "code"},
            {"severity": "LOW", "description": "Debug", "file_path": "d.py",
             "line_num": 4, "category": "code"},
        ]
        created = create_issues_for_findings("123", findings, "5")
        assert created == 2
        assert mock_session.post.call_count == 2

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_issue_body_includes_mr_reference(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 1})
        findings = [{"severity": "HIGH", "description": "Vuln",
                      "file_path": "a.py", "line_num": 1, "category": "code"}]
        create_issues_for_findings("123", findings, "42")
        body = mock_session.post.call_args[1]["json"]["description"]
        assert "MR !42" in body

    @patch("duoguard._session")
    @patch("duoguard.GITLAB_TOKEN", "glpat-test")
    def test_no_cwe_omits_link(self, mock_session):
        mock_session.post.return_value = _ok_response(201, {"iid": 1})
        findings = [{"severity": "HIGH", "description": "Bad code",
                      "file_path": "a.py", "line_num": 1, "category": "code"}]
        create_issues_for_findings("123", findings, "5")
        body = mock_session.post.call_args[1]["json"]["description"]
        assert "cwe.mitre.org" not in body


# ═══════════════════════════════════════════════════════════════
# Integration: pipeline wiring
# ═══════════════════════════════════════════════════════════════


class TestPipelineWiring:
    """Verify that _run_security_scan calls the GitLab interaction functions."""

    @patch("duoguard.create_issues_for_findings", return_value=0)
    @patch("duoguard.approve_or_reject_mr", return_value=None)
    @patch("duoguard.set_mr_labels", return_value=True)
    @patch("duoguard.post_inline_discussions", return_value=0)
    @patch("duoguard.post_mr_note", return_value=True)
    @patch("duoguard.export_findings_json", return_value=[])
    @patch("duoguard.determine_severity", return_value="NONE")
    @patch("duoguard.generate_dependency_scanning_report")
    @patch("duoguard.generate_sbom", return_value={})
    @patch("duoguard.generate_sast_report")
    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.generate_report", return_value="## Report")
    @patch("duoguard.compute_diff_complexity", return_value={
        "high_risk_files": [], "complexity_score": 10,
        "additions": 5, "deletions": 0, "files": 1, "risk_factors": []
    })
    @patch("duoguard.run_secret_scan", return_value="No issues")
    @patch("duoguard.run_dependency_audit", return_value="No issues")
    @patch("duoguard.run_code_security_review", return_value="No issues")
    @patch("duoguard.get_mr_diff", return_value={
        "changes": [{"new_path": "a.py", "diff": "+x=1"}],
        "diff_refs": {"base_sha": "a", "head_sha": "b", "start_sha": "c"},
    })
    @patch("duoguard.get_mr_info", return_value={"title": "Test MR"})
    def test_scan_calls_post_mr_note(self, _info, _diff, _code, _dep, _secret,
                                      _complex, _report, _cq, _sarif, _sast,
                                      _sbom, _depscan, _sev, _export,
                                      mock_note, _inline, _labels, _approve,
                                      _issues):
        from duoguard import _run_security_scan
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            import os
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                _run_security_scan("123", "5", "report.md", "", "CRITICAL")
            finally:
                os.chdir(old_cwd)
        mock_note.assert_called_once()

    @patch("duoguard.create_issues_for_findings", return_value=0)
    @patch("duoguard.approve_or_reject_mr", return_value=None)
    @patch("duoguard.set_mr_labels", return_value=True)
    @patch("duoguard.post_inline_discussions", return_value=0)
    @patch("duoguard.post_mr_note", return_value=True)
    @patch("duoguard.export_findings_json", return_value=[])
    @patch("duoguard.determine_severity", return_value="NONE")
    @patch("duoguard.generate_dependency_scanning_report")
    @patch("duoguard.generate_sbom", return_value={})
    @patch("duoguard.generate_sast_report")
    @patch("duoguard.generate_sarif_report")
    @patch("duoguard.generate_codequality_report")
    @patch("duoguard.generate_report", return_value="## Report")
    @patch("duoguard.compute_diff_complexity", return_value={
        "high_risk_files": [], "complexity_score": 10,
        "additions": 5, "deletions": 0, "files": 1, "risk_factors": []
    })
    @patch("duoguard.run_secret_scan", return_value="No issues")
    @patch("duoguard.run_dependency_audit", return_value="No issues")
    @patch("duoguard.run_code_security_review", return_value="No issues")
    @patch("duoguard.get_mr_diff", return_value={
        "changes": [{"new_path": "a.py", "diff": "+x=1"}],
        "diff_refs": {"base_sha": "a", "head_sha": "b", "start_sha": "c"},
    })
    @patch("duoguard.get_mr_info", return_value={"title": "Test MR"})
    def test_scan_calls_set_mr_labels(self, _info, _diff, _code, _dep, _secret,
                                       _complex, _report, _cq, _sarif, _sast,
                                       _sbom, _depscan, _sev, _export,
                                       _note, _inline, mock_labels, _approve,
                                       _issues):
        from duoguard import _run_security_scan
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            import os
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                _run_security_scan("123", "5", "report.md", "", "CRITICAL")
            finally:
                os.chdir(old_cwd)
        mock_labels.assert_called_once_with("123", "5", "NONE")
