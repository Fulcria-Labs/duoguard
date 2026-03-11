#!/usr/bin/env python3
"""Post DuoGuard security report as a GitLab MR comment.

Supports three posting modes:
  1. Summary comment — single MR note with full report
  2. Inline discussions — threaded comments on specific diff lines
  3. MR approval — approve/unapprove MR based on severity threshold
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests

GITLAB_API_URL = os.environ.get("CI_API_V4_URL", "https://gitlab.com/api/v4")
GITLAB_TOKEN = os.environ.get("CI_JOB_TOKEN", os.environ.get("GITLAB_TOKEN", ""))


def _headers() -> dict[str, str]:
    return {"PRIVATE-TOKEN": GITLAB_TOKEN}


# ── Summary comment ─────────────────────────────────────────────


def post_mr_comment(project_id: str, mr_iid: str, body: str) -> None:
    """Post a comment on a merge request."""
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/notes"
    resp = requests.post(url, headers=_headers(), json={"body": body}, timeout=30)
    resp.raise_for_status()
    note = resp.json()
    print(f"Comment posted: {note.get('id')}")


def find_existing_comment(project_id: str, mr_iid: str) -> int | None:
    """Find an existing DuoGuard comment to update instead of creating a new one."""
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/notes"
    resp = requests.get(url, headers=_headers(), params={"per_page": 100}, timeout=30)
    resp.raise_for_status()

    for note in resp.json():
        if "DuoGuard Security Review Report" in note.get("body", ""):
            return note["id"]
    return None


def update_mr_comment(project_id: str, mr_iid: str, note_id: int, body: str) -> None:
    """Update an existing MR comment."""
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/notes/{note_id}"
    resp = requests.put(url, headers=_headers(), json={"body": body}, timeout=30)
    resp.raise_for_status()
    print(f"Comment updated: {note_id}")


# ── Inline diff discussions ─────────────────────────────────────


def get_mr_diff_versions(project_id: str, mr_iid: str) -> list[dict]:
    """Fetch MR diff versions to get the latest diff refs for positioning."""
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/versions"
    resp = requests.get(url, headers=_headers(), timeout=30)
    resp.raise_for_status()
    return resp.json()


def post_inline_discussion(
    project_id: str,
    mr_iid: str,
    body: str,
    file_path: str,
    new_line: int,
    base_sha: str,
    head_sha: str,
    start_sha: str,
) -> dict | None:
    """Create an inline MR discussion on a specific diff line.

    Uses the GitLab Discussions API to post a threaded comment anchored
    to a specific line in the MR diff.  Returns the created discussion
    dict on success, or None on failure (logged but not raised so that
    other discussions can still be posted).
    """
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/discussions"
    payload = {
        "body": body,
        "position": {
            "position_type": "text",
            "base_sha": base_sha,
            "head_sha": head_sha,
            "start_sha": start_sha,
            "new_path": file_path,
            "old_path": file_path,
            "new_line": new_line,
        },
    }
    try:
        resp = requests.post(url, headers=_headers(), json=payload, timeout=30)
        resp.raise_for_status()
        discussion = resp.json()
        print(f"  Inline discussion posted on {file_path}:{new_line}")
        return discussion
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        print(f"  WARNING: Inline discussion failed for {file_path}:{new_line} (HTTP {status})")
        return None


def post_inline_findings(
    project_id: str,
    mr_iid: str,
    findings: list[dict],
) -> int:
    """Post each parsed finding as an inline MR discussion.

    Fetches the latest diff version to obtain SHA refs, then iterates
    findings and posts each as a threaded discussion.

    Returns the number of successfully posted discussions.
    """
    if not findings:
        return 0

    versions = get_mr_diff_versions(project_id, mr_iid)
    if not versions:
        print("  WARNING: No diff versions found, skipping inline comments.")
        return 0

    latest = versions[0]  # Most recent version
    base_sha = latest.get("base_commit_sha", "")
    head_sha = latest.get("head_commit_sha", "")
    start_sha = latest.get("start_commit_sha", "")

    if not (base_sha and head_sha and start_sha):
        print("  WARNING: Incomplete diff version SHAs, skipping inline comments.")
        return 0

    posted = 0
    for f in findings:
        file_path = f.get("file_path", "unknown")
        line_num = f.get("line_num", 1)
        severity = f.get("severity", "info").upper()
        description = f.get("description", "Security finding")
        category = f.get("category", "code-security")

        body = (
            f"**:shield: DuoGuard [{severity}]** — {description}\n\n"
            f"**Category:** {category}\n\n"
        )
        if f.get("cwe"):
            body += f"**CWE:** {f['cwe']}\n\n"

        result = post_inline_discussion(
            project_id, mr_iid, body,
            file_path, line_num,
            base_sha, head_sha, start_sha,
        )
        if result:
            posted += 1

    return posted


# ── Resolve stale discussions ──────────────────────────────────


def resolve_stale_discussions(project_id: str, mr_iid: str) -> int:
    """Resolve existing DuoGuard inline discussions before posting new ones.

    This prevents duplicate discussion threads on re-scans. Only resolves
    discussions that DuoGuard originally created (identified by the shield
    emoji prefix).

    Returns the number of resolved discussions.
    """
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/discussions"
    try:
        resp = requests.get(url, headers=_headers(), params={"per_page": 100}, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        return 0

    resolved = 0
    for discussion in resp.json():
        notes = discussion.get("notes", [])
        if not notes:
            continue
        first_note = notes[0]
        body = first_note.get("body", "")
        # Only resolve DuoGuard-created discussions
        if ":shield: DuoGuard [" not in body:
            continue
        if not first_note.get("resolvable", False):
            continue
        if first_note.get("resolved", False):
            continue

        # Resolve the discussion
        disc_id = discussion["id"]
        resolve_url = (
            f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}"
            f"/discussions/{disc_id}"
        )
        try:
            resp = requests.put(
                resolve_url, headers=_headers(),
                json={"resolved": True}, timeout=30,
            )
            resp.raise_for_status()
            resolved += 1
        except requests.exceptions.HTTPError:
            pass

    if resolved:
        print(f"  Resolved {resolved} stale DuoGuard discussion(s).")
    return resolved


# ── MR labels ──────────────────────────────────────────────────


SECURITY_LABELS = [
    "security::critical",
    "security::high",
    "security::medium",
    "security::low",
    "security::clean",
]


def update_mr_labels(project_id: str, mr_iid: str, severity: str) -> bool:
    """Add a security severity label to the MR and remove stale ones.

    Maps severity to ``security::<level>`` labels.  Removes any previously
    applied DuoGuard security labels before adding the current one.

    Returns True if the label was successfully applied.
    """
    label_map = {
        "CRITICAL": "security::critical",
        "HIGH": "security::high",
        "MEDIUM": "security::medium",
        "LOW": "security::low",
        "NONE": "security::clean",
    }
    new_label = label_map.get(severity, "security::clean")

    # Fetch current MR labels
    mr_url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}"
    try:
        resp = requests.get(mr_url, headers=_headers(), timeout=30)
        resp.raise_for_status()
        current_labels = resp.json().get("labels", [])
    except requests.exceptions.HTTPError:
        current_labels = []

    # Remove old security labels, add new one
    updated_labels = [l for l in current_labels if l not in SECURITY_LABELS]
    updated_labels.append(new_label)

    try:
        resp = requests.put(
            mr_url, headers=_headers(),
            json={"labels": ",".join(updated_labels)},
            timeout=30,
        )
        resp.raise_for_status()
        print(f"  MR label set to: {new_label}")
        return True
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        print(f"  WARNING: Could not update MR labels (HTTP {status}).")
        return False


# ── MR approval ─────────────────────────────────────────────────


def approve_mr(project_id: str, mr_iid: str) -> bool:
    """Approve a merge request (requires Maintainer/Owner or approval rules)."""
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/approve"
    try:
        resp = requests.post(url, headers=_headers(), timeout=30)
        resp.raise_for_status()
        print(f"MR !{mr_iid} approved by DuoGuard.")
        return True
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        print(f"  WARNING: Could not approve MR (HTTP {status}). "
              "Ensure the token has approval permissions.")
        return False


def unapprove_mr(project_id: str, mr_iid: str) -> bool:
    """Remove DuoGuard's approval from a merge request."""
    url = f"{GITLAB_API_URL}/projects/{project_id}/merge_requests/{mr_iid}/unapprove"
    try:
        resp = requests.post(url, headers=_headers(), timeout=30)
        resp.raise_for_status()
        print(f"MR !{mr_iid} approval removed by DuoGuard.")
        return True
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        print(f"  WARNING: Could not unapprove MR (HTTP {status}).")
        return False


# ── Main ────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Post DuoGuard report to MR")
    parser.add_argument("--project-id", required=True, help="GitLab project ID")
    parser.add_argument("--mr-iid", required=True, help="Merge request IID")
    parser.add_argument("--report-file", required=True, help="Path to report markdown")
    parser.add_argument("--findings-file", default="",
                        help="Path to JSON findings for inline comments")
    parser.add_argument("--approve", action="store_true",
                        help="Approve MR if severity is below threshold")
    parser.add_argument("--severity", default="NONE",
                        help="Overall severity (used with --approve)")
    parser.add_argument("--approve-threshold", default="HIGH",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                        help="Max severity to auto-approve (default: HIGH)")
    args = parser.parse_args()

    report_path = Path(args.report_file)
    if not report_path.exists():
        print(f"Report file not found: {args.report_file}")
        sys.exit(1)

    report = report_path.read_text()
    if not report.strip():
        print("Empty report, skipping comment.")
        return

    # Step 1: Post/update summary comment
    existing_id = find_existing_comment(args.project_id, args.mr_iid)
    if existing_id:
        print(f"Updating existing DuoGuard comment ({existing_id})...")
        update_mr_comment(args.project_id, args.mr_iid, existing_id, report)
    else:
        print("Posting new DuoGuard comment...")
        post_mr_comment(args.project_id, args.mr_iid, report)

    # Step 2: Post inline discussions if findings file provided
    if args.findings_file:
        findings_path = Path(args.findings_file)
        if findings_path.exists():
            findings = json.loads(findings_path.read_text())
            if findings:
                # Resolve previous DuoGuard discussions to avoid duplicates
                resolve_stale_discussions(args.project_id, args.mr_iid)
                print(f"Posting {len(findings)} inline discussion(s)...")
                posted = post_inline_findings(
                    args.project_id, args.mr_iid, findings)
                print(f"  {posted}/{len(findings)} inline discussions posted.")
        else:
            print(f"Findings file not found: {args.findings_file}")

    # Step 3: Update MR labels with severity
    if args.severity and args.severity != "NONE":
        update_mr_labels(args.project_id, args.mr_iid, args.severity)
    elif args.severity == "NONE":
        update_mr_labels(args.project_id, args.mr_iid, "NONE")

    # Step 4: MR approval based on severity
    if args.approve:
        severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_idx = severity_order.index(args.severity) if args.severity in severity_order else 0
        threshold_idx = severity_order.index(args.approve_threshold)
        if sev_idx < threshold_idx:
            approve_mr(args.project_id, args.mr_iid)
        else:
            print(f"Severity {args.severity} >= threshold {args.approve_threshold}, "
                  "not approving MR.")
            unapprove_mr(args.project_id, args.mr_iid)

    print("Done.")


if __name__ == "__main__":
    main()
