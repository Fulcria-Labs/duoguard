"""Tests for DuoGuard SAST and Dependency Scanning report generation.

Covers generate_sast_report(), generate_dependency_scanning_report(),
and their integration with existing report formats.
"""

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from duoguard import (
    _parse_findings,
    generate_sast_report,
    generate_dependency_scanning_report,
    generate_sarif_report,
    generate_codequality_report,
    generate_sbom,
    sbom_to_gitlab_dependency_report,
    generate_compliance_report,
    enrich_finding_cwe,
    CWE_KEYWORD_MAP,
    COMPLIANCE_CONTROLS,
)


# ── Test fixtures ────────────────────────────────────────────

def _make_finding_text(severity, description, file_path, line_num, category_label="Finding"):
    """Build a single markdown finding block that _parse_findings can parse."""
    return (
        f"### [{severity.upper()}] Finding: {description}\n"
        f"**File:** `{file_path}` (line {line_num})\n"
    )


def _make_multi_findings(*specs):
    """Build concatenated markdown for multiple findings.

    Each spec is (severity, description, file_path, line_num).
    """
    return "\n".join(
        _make_finding_text(sev, desc, fp, ln)
        for sev, desc, fp, ln in specs
    )


SINGLE_CODE_FINDING = _make_finding_text(
    "HIGH", "SQL injection in query builder", "src/db.py", 42
)

SINGLE_DEP_FINDING = _make_finding_text(
    "MEDIUM", "Vulnerable dependency lodash", "package.json", 10
)

SINGLE_SECRET_FINDING = _make_finding_text(
    "CRITICAL", "Hardcoded API key exposed", "config/settings.py", 7
)

MULTIPLE_CODE_FINDINGS = _make_multi_findings(
    ("CRITICAL", "Command injection via os.system", "app/utils.py", 15),
    ("HIGH", "SQL injection in login handler", "app/auth.py", 88),
    ("MEDIUM", "Open redirect in callback URL", "app/oauth.py", 33),
    ("LOW", "Missing rate limiting on endpoint", "app/api.py", 120),
    ("INFO", "Unused import detected", "app/helpers.py", 1),
)

NO_FINDINGS = "No security issues found in this merge request."

# Simple SBOM fixture
SIMPLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:test",
    "version": 1,
    "metadata": {
        "timestamp": "2026-01-01T00:00:00Z",
        "tools": [{"vendor": "DuoGuard", "name": "DuoGuard SBOM Generator", "version": "1.0.0"}],
        "component": {"type": "application", "name": "test-project", "version": "1.0.0"},
    },
    "components": [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "properties": [
                {"name": "duoguard:ecosystem", "value": "npm"},
                {"name": "duoguard:scope", "value": "runtime"},
            ],
        },
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "properties": [
                {"name": "duoguard:ecosystem", "value": "pypi"},
                {"name": "duoguard:scope", "value": "runtime"},
            ],
        },
    ],
    "dependencies": [],
}


# ═══════════════════════════════════════════════════════════════
# 1. SAST Report Structure Tests
# ═══════════════════════════════════════════════════════════════

class TestSastReportStructure:
    """Test the top-level structure of the generated SAST report."""

    def test_report_has_version(self):
        report = generate_sast_report("")
        assert report["version"] == "15.0.7"

    def test_report_has_scan_section(self):
        report = generate_sast_report("")
        assert "scan" in report

    def test_scan_type_is_sast(self):
        report = generate_sast_report("")
        assert report["scan"]["type"] == "sast"

    def test_scan_status_is_success(self):
        report = generate_sast_report("")
        assert report["scan"]["status"] == "success"

    def test_scan_has_start_time(self):
        report = generate_sast_report("")
        assert "start_time" in report["scan"]

    def test_scan_has_end_time(self):
        report = generate_sast_report("")
        assert "end_time" in report["scan"]

    def test_scan_times_are_iso_format(self):
        report = generate_sast_report("")
        assert report["scan"]["start_time"].endswith("Z")
        assert report["scan"]["end_time"].endswith("Z")

    def test_report_has_vulnerabilities_array(self):
        report = generate_sast_report("")
        assert isinstance(report["vulnerabilities"], list)

    def test_empty_input_produces_empty_vulnerabilities(self):
        report = generate_sast_report("")
        assert report["vulnerabilities"] == []

    def test_no_findings_text_produces_empty_vulnerabilities(self):
        report = generate_sast_report(NO_FINDINGS)
        assert report["vulnerabilities"] == []


class TestSastScannerMetadata:
    """Test scanner and analyzer metadata in the SAST report."""

    def test_scanner_id(self):
        report = generate_sast_report("")
        assert report["scan"]["scanner"]["id"] == "duoguard-sast"

    def test_scanner_name(self):
        report = generate_sast_report("")
        assert report["scan"]["scanner"]["name"] == "DuoGuard SAST"

    def test_scanner_version(self):
        report = generate_sast_report("")
        assert report["scan"]["scanner"]["version"] == "1.0.0"

    def test_scanner_vendor(self):
        report = generate_sast_report("")
        assert report["scan"]["scanner"]["vendor"]["name"] == "DuoGuard"

    def test_analyzer_id(self):
        report = generate_sast_report("")
        assert report["scan"]["analyzer"]["id"] == "duoguard-sast-analyzer"

    def test_analyzer_name(self):
        report = generate_sast_report("")
        assert report["scan"]["analyzer"]["name"] == "DuoGuard SAST Analyzer"

    def test_analyzer_version(self):
        report = generate_sast_report("")
        assert report["scan"]["analyzer"]["version"] == "1.0.0"

    def test_analyzer_vendor(self):
        report = generate_sast_report("")
        assert report["scan"]["analyzer"]["vendor"]["name"] == "DuoGuard"


# ═══════════════════════════════════════════════════════════════
# 2. SAST Vulnerability Entry Tests
# ═══════════════════════════════════════════════════════════════

class TestSastVulnerabilityEntries:
    """Test individual vulnerability entries in the SAST report."""

    def test_single_finding_produces_one_vulnerability(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        assert len(report["vulnerabilities"]) == 1

    def test_vulnerability_has_id(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert "id" in vuln

    def test_vulnerability_id_is_uuid(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        # Should not raise
        uuid.UUID(vuln["id"])

    def test_vulnerability_category_is_sast(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert vuln["category"] == "sast"

    def test_vulnerability_has_name(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert vuln["name"] == "SQL injection in query builder"

    def test_vulnerability_has_message(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert vuln["message"] == "SQL injection in query builder"

    def test_vulnerability_has_description(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert "SQL injection" in vuln["description"]

    def test_vulnerability_has_severity(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert vuln["severity"] == "High"

    def test_vulnerability_has_scanner_info(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert vuln["scanner"]["id"] == "duoguard-sast"
        assert vuln["scanner"]["name"] == "DuoGuard SAST"

    def test_vulnerability_has_identifiers(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert isinstance(vuln["identifiers"], list)

    def test_vulnerability_has_location(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert vuln["location"]["file"] == "src/db.py"
        assert vuln["location"]["start_line"] == 42

    def test_vulnerability_has_links(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert isinstance(vuln["links"], list)


# ═══════════════════════════════════════════════════════════════
# 3. Severity Level Mapping Tests
# ═══════════════════════════════════════════════════════════════

class TestSastSeverityMapping:
    """Verify all severity levels are mapped correctly (capitalized)."""

    def test_critical_maps_to_Critical(self):
        text = _make_finding_text("CRITICAL", "Test critical", "a.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["severity"] == "Critical"

    def test_high_maps_to_High(self):
        text = _make_finding_text("HIGH", "Test high", "a.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["severity"] == "High"

    def test_medium_maps_to_Medium(self):
        text = _make_finding_text("MEDIUM", "Test medium", "a.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["severity"] == "Medium"

    def test_low_maps_to_Low(self):
        text = _make_finding_text("LOW", "Test low", "a.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["severity"] == "Low"

    def test_info_maps_to_Info(self):
        text = _make_finding_text("INFO", "Test info", "a.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["severity"] == "Info"

    def test_all_severities_in_one_report(self):
        text = _make_multi_findings(
            ("CRITICAL", "Critical issue", "a.py", 1),
            ("HIGH", "High issue", "b.py", 2),
            ("MEDIUM", "Medium issue", "c.py", 3),
            ("LOW", "Low issue", "d.py", 4),
            ("INFO", "Info issue", "e.py", 5),
        )
        report = generate_sast_report(text)
        severities = [v["severity"] for v in report["vulnerabilities"]]
        assert severities == ["Critical", "High", "Medium", "Low", "Info"]


# ═══════════════════════════════════════════════════════════════
# 4. CWE Identifier Tests
# ═══════════════════════════════════════════════════════════════

class TestSastCweIdentifiers:
    """Test that CWE identifiers are included when findings have CWE enrichment."""

    def test_sql_injection_has_cwe_89(self):
        text = _make_finding_text("HIGH", "SQL injection in user input", "db.py", 10)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        assert len(vuln["identifiers"]) >= 1
        cwe_id = vuln["identifiers"][0]
        assert cwe_id["type"] == "cwe"
        assert cwe_id["name"] == "CWE-89"
        assert cwe_id["value"] == "89"

    def test_xss_has_cwe_79(self):
        text = _make_finding_text("HIGH", "XSS vulnerability in output", "web.py", 5)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == "CWE-79"

    def test_command_injection_has_cwe_78(self):
        text = _make_finding_text("CRITICAL", "Command injection in subprocess", "run.py", 20)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == "CWE-78"

    def test_path_traversal_has_cwe_22(self):
        text = _make_finding_text("HIGH", "Path traversal in file handler", "fs.py", 8)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == "CWE-22"

    def test_hardcoded_secret_has_cwe_798(self):
        text = _make_finding_text("CRITICAL", "Hardcoded secret in config", "config.py", 3)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == "CWE-798"

    def test_cwe_url_format(self):
        text = _make_finding_text("HIGH", "SQL injection found", "db.py", 1)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert cwe_ids[0]["url"] == "https://cwe.mitre.org/data/definitions/89.html"

    def test_no_cwe_for_generic_finding(self):
        text = _make_finding_text("LOW", "Minor style issue detected", "app.py", 1)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        assert vuln["identifiers"] == []

    def test_ssrf_has_cwe_918(self):
        text = _make_finding_text("HIGH", "SSRF in URL fetch", "api.py", 50)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == "CWE-918"

    def test_deserialization_has_cwe_502(self):
        text = _make_finding_text("CRITICAL", "Insecure deserialization of user data", "data.py", 30)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == "CWE-502"

    def test_xxe_has_cwe_611(self):
        text = _make_finding_text("HIGH", "XXE in XML parser", "parser.py", 18)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == "CWE-611"


# ═══════════════════════════════════════════════════════════════
# 5. OWASP Links Tests
# ═══════════════════════════════════════════════════════════════

class TestSastOwaspLinks:
    """Test OWASP links in vulnerability entries."""

    def test_sql_injection_has_owasp_link(self):
        text = _make_finding_text("HIGH", "SQL injection in query", "db.py", 1)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        assert len(vuln["links"]) >= 1
        assert "owasp.org" in vuln["links"][0]["url"]

    def test_xss_has_owasp_link(self):
        text = _make_finding_text("HIGH", "Cross-site scripting in template", "web.py", 1)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        assert len(vuln["links"]) >= 1

    def test_generic_finding_has_no_owasp_link(self):
        text = _make_finding_text("LOW", "Minor code smell", "app.py", 1)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        assert vuln["links"] == []

    def test_owasp_link_has_name(self):
        text = _make_finding_text("HIGH", "SQL injection detected", "db.py", 1)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        link = vuln["links"][0]
        assert "name" in link
        assert "A03" in link["name"]


# ═══════════════════════════════════════════════════════════════
# 6. Multiple Finding Category Tests
# ═══════════════════════════════════════════════════════════════

class TestSastMultipleCategories:
    """Test SAST report with findings from all three scan categories."""

    def test_code_findings_only(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        assert len(report["vulnerabilities"]) == 1

    def test_all_three_categories(self):
        report = generate_sast_report(
            SINGLE_CODE_FINDING,
            dep_findings=SINGLE_DEP_FINDING,
            secret_findings=SINGLE_SECRET_FINDING,
        )
        assert len(report["vulnerabilities"]) == 3

    def test_dep_findings_included(self):
        report = generate_sast_report(
            "", dep_findings=SINGLE_DEP_FINDING
        )
        assert len(report["vulnerabilities"]) == 1
        assert "lodash" in report["vulnerabilities"][0]["name"]

    def test_secret_findings_included(self):
        report = generate_sast_report(
            "", secret_findings=SINGLE_SECRET_FINDING
        )
        assert len(report["vulnerabilities"]) == 1
        assert "API key" in report["vulnerabilities"][0]["name"]

    def test_code_and_dep_combined(self):
        report = generate_sast_report(
            SINGLE_CODE_FINDING, dep_findings=SINGLE_DEP_FINDING
        )
        assert len(report["vulnerabilities"]) == 2

    def test_code_and_secret_combined(self):
        report = generate_sast_report(
            SINGLE_CODE_FINDING, secret_findings=SINGLE_SECRET_FINDING
        )
        assert len(report["vulnerabilities"]) == 2

    def test_dep_and_secret_combined(self):
        report = generate_sast_report(
            "", dep_findings=SINGLE_DEP_FINDING, secret_findings=SINGLE_SECRET_FINDING
        )
        assert len(report["vulnerabilities"]) == 2


# ═══════════════════════════════════════════════════════════════
# 7. Unique UUID Tests
# ═══════════════════════════════════════════════════════════════

class TestSastUniqueUuids:
    """Test that vulnerability IDs are unique UUIDs."""

    def test_single_finding_uuid(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vid = report["vulnerabilities"][0]["id"]
        parsed = uuid.UUID(vid)
        assert str(parsed) == vid

    def test_multiple_findings_have_unique_ids(self):
        report = generate_sast_report(MULTIPLE_CODE_FINDINGS)
        ids = [v["id"] for v in report["vulnerabilities"]]
        assert len(ids) == len(set(ids))

    def test_ids_are_valid_uuid4(self):
        report = generate_sast_report(MULTIPLE_CODE_FINDINGS)
        for vuln in report["vulnerabilities"]:
            parsed = uuid.UUID(vuln["id"])
            assert parsed.version == 4

    def test_repeated_calls_produce_different_ids(self):
        r1 = generate_sast_report(SINGLE_CODE_FINDING)
        r2 = generate_sast_report(SINGLE_CODE_FINDING)
        assert r1["vulnerabilities"][0]["id"] != r2["vulnerabilities"][0]["id"]


# ═══════════════════════════════════════════════════════════════
# 8. File Path and Line Number Tests
# ═══════════════════════════════════════════════════════════════

class TestSastFilePathsAndLines:
    """Test that file paths and line numbers are correctly captured."""

    def test_file_path_from_finding(self):
        text = _make_finding_text("HIGH", "Bug", "src/models/user.py", 55)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["location"]["file"] == "src/models/user.py"

    def test_line_number_from_finding(self):
        text = _make_finding_text("HIGH", "Bug", "app.py", 123)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["location"]["start_line"] == 123

    def test_nested_directory_path(self):
        text = _make_finding_text("MEDIUM", "Issue", "a/b/c/d/e.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["location"]["file"] == "a/b/c/d/e.py"

    def test_line_number_one(self):
        text = _make_finding_text("LOW", "Issue", "app.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["location"]["start_line"] == 1

    def test_large_line_number(self):
        text = _make_finding_text("LOW", "Issue", "app.py", 99999)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["location"]["start_line"] == 99999

    def test_multiple_files_different_paths(self):
        text = _make_multi_findings(
            ("HIGH", "Bug in auth", "src/auth.py", 10),
            ("MEDIUM", "Bug in db", "src/db.py", 20),
        )
        report = generate_sast_report(text)
        paths = [v["location"]["file"] for v in report["vulnerabilities"]]
        assert paths == ["src/auth.py", "src/db.py"]

    def test_dotfile_path(self):
        text = _make_finding_text("MEDIUM", "Config issue", ".env.example", 3)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["location"]["file"] == ".env.example"


# ═══════════════════════════════════════════════════════════════
# 9. File Output Tests
# ═══════════════════════════════════════════════════════════════

class TestSastFileOutput:
    """Test writing the SAST report to a file."""

    def test_writes_json_file(self, tmp_path):
        out = str(tmp_path / "gl-sast-report.json")
        generate_sast_report(SINGLE_CODE_FINDING, output_path=out)
        assert Path(out).exists()

    def test_file_is_valid_json(self, tmp_path):
        out = str(tmp_path / "gl-sast-report.json")
        generate_sast_report(SINGLE_CODE_FINDING, output_path=out)
        with open(out) as f:
            data = json.load(f)
        assert data["version"] == "15.0.7"

    def test_file_content_matches_return(self, tmp_path):
        out = str(tmp_path / "gl-sast-report.json")
        report = generate_sast_report(SINGLE_CODE_FINDING, output_path=out)
        with open(out) as f:
            file_data = json.load(f)
        # Compare structure (UUIDs and timestamps match since same call)
        assert file_data["version"] == report["version"]
        assert len(file_data["vulnerabilities"]) == len(report["vulnerabilities"])

    def test_no_file_when_output_path_none(self, tmp_path):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        # No assertion on file — just make sure it returns dict without error
        assert isinstance(report, dict)

    def test_empty_report_writes_valid_json(self, tmp_path):
        out = str(tmp_path / "empty.json")
        generate_sast_report("", output_path=out)
        with open(out) as f:
            data = json.load(f)
        assert data["vulnerabilities"] == []

    def test_multiple_findings_file_output(self, tmp_path):
        out = str(tmp_path / "multi.json")
        generate_sast_report(MULTIPLE_CODE_FINDINGS, output_path=out)
        with open(out) as f:
            data = json.load(f)
        assert len(data["vulnerabilities"]) == 5


# ═══════════════════════════════════════════════════════════════
# 10. SARIF and SAST Consistency Tests
# ═══════════════════════════════════════════════════════════════

class TestSarifSastConsistency:
    """Test that SARIF and SAST reports are consistent for the same findings."""

    def test_same_number_of_findings(self, tmp_path):
        sarif_path = str(tmp_path / "sarif.json")
        generate_sarif_report(SINGLE_CODE_FINDING, sarif_path)
        sast = generate_sast_report(SINGLE_CODE_FINDING)
        with open(sarif_path) as f:
            sarif = json.load(f)
        sarif_count = len(sarif["runs"][0]["results"])
        sast_count = len(sast["vulnerabilities"])
        assert sarif_count == sast_count

    def test_same_finding_count_multiple(self, tmp_path):
        sarif_path = str(tmp_path / "sarif.json")
        generate_sarif_report(MULTIPLE_CODE_FINDINGS, sarif_path)
        sast = generate_sast_report(MULTIPLE_CODE_FINDINGS)
        with open(sarif_path) as f:
            sarif = json.load(f)
        assert len(sarif["runs"][0]["results"]) == len(sast["vulnerabilities"])

    def test_same_file_paths(self, tmp_path):
        text = _make_finding_text("HIGH", "SQL injection", "src/db.py", 42)
        sarif_path = str(tmp_path / "sarif.json")
        generate_sarif_report(text, sarif_path)
        sast = generate_sast_report(text)
        with open(sarif_path) as f:
            sarif = json.load(f)
        sarif_file = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        sast_file = sast["vulnerabilities"][0]["location"]["file"]
        assert sarif_file == sast_file

    def test_same_line_numbers(self, tmp_path):
        text = _make_finding_text("HIGH", "SQL injection", "db.py", 42)
        sarif_path = str(tmp_path / "sarif.json")
        generate_sarif_report(text, sarif_path)
        sast = generate_sast_report(text)
        with open(sarif_path) as f:
            sarif = json.load(f)
        sarif_line = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
        sast_line = sast["vulnerabilities"][0]["location"]["start_line"]
        assert sarif_line == sast_line

    def test_empty_produces_consistent_results(self, tmp_path):
        sarif_path = str(tmp_path / "sarif.json")
        generate_sarif_report("", sarif_path)
        sast = generate_sast_report("")
        with open(sarif_path) as f:
            sarif = json.load(f)
        assert len(sarif["runs"][0]["results"]) == 0
        assert len(sast["vulnerabilities"]) == 0

    def test_all_categories_consistent(self, tmp_path):
        sarif_path = str(tmp_path / "sarif.json")
        generate_sarif_report(
            SINGLE_CODE_FINDING, sarif_path,
            dep_findings=SINGLE_DEP_FINDING,
            secret_findings=SINGLE_SECRET_FINDING,
        )
        sast = generate_sast_report(
            SINGLE_CODE_FINDING,
            dep_findings=SINGLE_DEP_FINDING,
            secret_findings=SINGLE_SECRET_FINDING,
        )
        with open(sarif_path) as f:
            sarif = json.load(f)
        assert len(sarif["runs"][0]["results"]) == len(sast["vulnerabilities"])


# ═══════════════════════════════════════════════════════════════
# 11. Dependency Scanning Report Tests
# ═══════════════════════════════════════════════════════════════

class TestDependencyScanningReport:
    """Test generate_dependency_scanning_report()."""

    def test_report_has_version(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert report["version"] == "15.0.7"

    def test_report_scan_type(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert report["scan"]["type"] == "dependency_scanning"

    def test_report_scan_status(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert report["scan"]["status"] == "success"

    def test_report_has_dependencies(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert len(report["dependencies"]) == 2

    def test_no_findings_empty_vulnerabilities(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert report["vulnerabilities"] == []

    def test_with_dep_findings(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        assert len(report["vulnerabilities"]) == 1

    def test_vuln_category_is_dependency_scanning(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        assert report["vulnerabilities"][0]["category"] == "dependency_scanning"

    def test_vuln_has_scanner(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        assert report["vulnerabilities"][0]["scanner"]["id"] == "duoguard-sbom"

    def test_vuln_severity_capitalized(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        assert report["vulnerabilities"][0]["severity"] == "Medium"

    def test_vuln_has_id_uuid(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        uuid.UUID(report["vulnerabilities"][0]["id"])

    def test_file_output(self, tmp_path):
        out = str(tmp_path / "dep-report.json")
        generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING, output_path=out
        )
        assert Path(out).exists()
        with open(out) as f:
            data = json.load(f)
        assert data["version"] == "15.0.7"

    def test_empty_sbom(self):
        empty_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [],
            "dependencies": [],
        }
        report = generate_dependency_scanning_report(empty_sbom)
        assert report["dependencies"] == []

    def test_multiple_dep_findings(self):
        multi_dep = _make_multi_findings(
            ("HIGH", "Vulnerable dependency requests", "requirements.txt", 5),
            ("CRITICAL", "Known malware package", "requirements.txt", 10),
        )
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=multi_dep
        )
        assert len(report["vulnerabilities"]) == 2

    def test_dep_vuln_has_location(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        vuln = report["vulnerabilities"][0]
        assert "file" in vuln["location"]

    def test_dep_vuln_has_identifiers(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        vuln = report["vulnerabilities"][0]
        assert isinstance(vuln["identifiers"], list)

    def test_dep_vuln_has_links(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        vuln = report["vulnerabilities"][0]
        assert isinstance(vuln["links"], list)


# ═══════════════════════════════════════════════════════════════
# 12. Edge Cases: Unicode, Long Descriptions, Special Characters
# ═══════════════════════════════════════════════════════════════

class TestSastEdgeCases:
    """Test edge cases with unusual input."""

    def test_unicode_in_description(self):
        text = _make_finding_text("HIGH", "SQL injection avec des caracteres speciaux", "app.py", 1)
        report = generate_sast_report(text)
        assert len(report["vulnerabilities"]) == 1

    def test_unicode_emoji_in_description(self):
        text = _make_finding_text("MEDIUM", "Buffer overflow detected", "app.cpp", 5)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["name"] == "Buffer overflow detected"

    def test_long_description(self):
        long_desc = "A" * 500
        text = _make_finding_text("HIGH", long_desc, "app.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["name"] == long_desc

    def test_special_chars_in_path(self):
        text = _make_finding_text("MEDIUM", "Issue found", "src/my-app/utils_v2.py", 10)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["location"]["file"] == "src/my-app/utils_v2.py"

    def test_backslash_in_description(self):
        text = _make_finding_text("LOW", "Path uses backslash \\ character", "a.py", 1)
        report = generate_sast_report(text)
        assert len(report["vulnerabilities"]) == 1

    def test_single_quote_in_description(self):
        text = _make_finding_text("MEDIUM", "It's a vulnerability", "a.py", 1)
        report = generate_sast_report(text)
        assert "It's" in report["vulnerabilities"][0]["name"]

    def test_double_quote_in_description(self):
        text = _make_finding_text("LOW", 'Uses "eval" function', "a.py", 1)
        report = generate_sast_report(text)
        assert len(report["vulnerabilities"]) == 1

    def test_empty_string_input(self):
        report = generate_sast_report("")
        assert report["vulnerabilities"] == []

    def test_whitespace_only_input(self):
        report = generate_sast_report("   \n\n   \t  ")
        assert report["vulnerabilities"] == []

    def test_malformed_finding_text(self):
        report = generate_sast_report("### [HIGH] Not properly formatted\nrandom text")
        assert report["vulnerabilities"] == []

    def test_finding_without_file_line(self):
        # Only heading, no **File:** line -> should not produce a finding
        text = "### [HIGH] Finding: Issue\n"
        report = generate_sast_report(text)
        assert report["vulnerabilities"] == []


# ═══════════════════════════════════════════════════════════════
# 13. Multiple Findings Same File Tests
# ═══════════════════════════════════════════════════════════════

class TestSastMultipleFindingsSameFile:
    """Test behavior when multiple findings are in the same file."""

    def test_two_findings_same_file(self):
        text = _make_multi_findings(
            ("HIGH", "SQL injection", "app.py", 10),
            ("MEDIUM", "XSS vulnerability", "app.py", 25),
        )
        report = generate_sast_report(text)
        assert len(report["vulnerabilities"]) == 2
        files = [v["location"]["file"] for v in report["vulnerabilities"]]
        assert files == ["app.py", "app.py"]

    def test_same_file_different_lines(self):
        text = _make_multi_findings(
            ("HIGH", "Bug A", "util.py", 5),
            ("HIGH", "Bug B", "util.py", 50),
        )
        report = generate_sast_report(text)
        lines = [v["location"]["start_line"] for v in report["vulnerabilities"]]
        assert lines == [5, 50]

    def test_five_findings_same_file(self):
        specs = [
            ("CRITICAL", f"Issue {i}", "main.py", i * 10)
            for i in range(1, 6)
        ]
        text = _make_multi_findings(*specs)
        report = generate_sast_report(text)
        assert len(report["vulnerabilities"]) == 5

    def test_unique_ids_same_file(self):
        text = _make_multi_findings(
            ("HIGH", "Bug A", "same.py", 1),
            ("HIGH", "Bug B", "same.py", 2),
            ("HIGH", "Bug C", "same.py", 3),
        )
        report = generate_sast_report(text)
        ids = [v["id"] for v in report["vulnerabilities"]]
        assert len(ids) == len(set(ids))


# ═══════════════════════════════════════════════════════════════
# 14. Large Number of Findings Tests
# ═══════════════════════════════════════════════════════════════

class TestSastLargeFindings:
    """Test with large number of findings."""

    def test_50_findings(self):
        specs = [
            ("HIGH", f"Finding number {i}", f"file_{i}.py", i)
            for i in range(1, 51)
        ]
        text = _make_multi_findings(*specs)
        report = generate_sast_report(text)
        assert len(report["vulnerabilities"]) == 50

    def test_100_findings(self):
        specs = [
            ("MEDIUM", f"Issue {i}", f"module_{i // 10}/file_{i}.py", i)
            for i in range(1, 101)
        ]
        text = _make_multi_findings(*specs)
        report = generate_sast_report(text)
        assert len(report["vulnerabilities"]) == 100

    def test_large_findings_all_have_unique_ids(self):
        specs = [
            ("LOW", f"Finding {i}", f"file_{i}.py", i)
            for i in range(1, 201)
        ]
        text = _make_multi_findings(*specs)
        report = generate_sast_report(text)
        ids = [v["id"] for v in report["vulnerabilities"]]
        assert len(ids) == 200
        assert len(set(ids)) == 200

    def test_large_findings_file_output(self, tmp_path):
        specs = [
            ("HIGH", f"Finding {i}", f"file_{i}.py", i)
            for i in range(1, 51)
        ]
        text = _make_multi_findings(*specs)
        out = str(tmp_path / "large.json")
        generate_sast_report(text, output_path=out)
        with open(out) as f:
            data = json.load(f)
        assert len(data["vulnerabilities"]) == 50


# ═══════════════════════════════════════════════════════════════
# 15. Compliance Report Integration Tests
# ═══════════════════════════════════════════════════════════════

class TestSastComplianceIntegration:
    """Test that SAST findings work with the compliance report system."""

    def test_sast_findings_map_to_compliance(self):
        text = _make_finding_text("HIGH", "SQL injection in query", "db.py", 10)
        parsed = _parse_findings(text, "code-security")
        compliance = generate_compliance_report(parsed)
        assert compliance["total_findings"] == 1
        assert compliance["findings_with_compliance_mapping"] == 1

    def test_sast_and_compliance_cwe_match(self):
        text = _make_finding_text("CRITICAL", "Command injection via subprocess", "run.py", 5)
        sast = generate_sast_report(text)
        parsed = _parse_findings(text, "code-security")
        compliance = generate_compliance_report(parsed)
        # SAST has CWE-78
        sast_cwe = sast["vulnerabilities"][0]["identifiers"][0]["name"]
        assert sast_cwe == "CWE-78"
        # Compliance should map CWE-78
        assert compliance["findings_with_compliance_mapping"] == 1

    def test_no_findings_compliance_is_compliant(self):
        compliance = generate_compliance_report([])
        assert compliance["overall_posture"] == "COMPLIANT"

    def test_critical_finding_non_compliant(self):
        text = _make_finding_text("CRITICAL", "Hardcoded credential found", "cfg.py", 1)
        parsed = _parse_findings(text, "code-security")
        compliance = generate_compliance_report(parsed)
        assert compliance["overall_posture"] == "NON_COMPLIANT"

    def test_mixed_findings_compliance(self):
        text = _make_multi_findings(
            ("HIGH", "SQL injection in login", "auth.py", 10),
            ("LOW", "Minor style issue", "style.py", 1),
        )
        parsed = _parse_findings(text, "code-security")
        compliance = generate_compliance_report(parsed)
        assert compliance["total_findings"] == 2


# ═══════════════════════════════════════════════════════════════
# 16. Description Content Tests
# ═══════════════════════════════════════════════════════════════

class TestSastDescriptionContent:
    """Test the description field in vulnerability entries."""

    def test_description_contains_severity(self):
        text = _make_finding_text("HIGH", "SQL injection", "db.py", 1)
        report = generate_sast_report(text)
        assert "HIGH" in report["vulnerabilities"][0]["description"]

    def test_description_contains_finding_name(self):
        text = _make_finding_text("MEDIUM", "XSS in template", "web.py", 5)
        report = generate_sast_report(text)
        assert "XSS in template" in report["vulnerabilities"][0]["description"]

    def test_description_contains_category(self):
        text = _make_finding_text("LOW", "Issue", "app.py", 1)
        report = generate_sast_report(text)
        assert "code-security" in report["vulnerabilities"][0]["description"]

    def test_dep_description_contains_category(self):
        report = generate_sast_report("", dep_findings=SINGLE_DEP_FINDING)
        assert "dependency-audit" in report["vulnerabilities"][0]["description"]

    def test_secret_description_contains_category(self):
        report = generate_sast_report("", secret_findings=SINGLE_SECRET_FINDING)
        assert "secret-scan" in report["vulnerabilities"][0]["description"]


# ═══════════════════════════════════════════════════════════════
# 17. Dependency Scanning Report with CWE Tests
# ═══════════════════════════════════════════════════════════════

class TestDepScanningCwe:
    """Test CWE identifiers in dependency scanning report."""

    def test_vulnerable_dep_with_cwe(self):
        dep_text = _make_finding_text(
            "HIGH", "Deserialization vulnerability in dependency", "requirements.txt", 5
        )
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=dep_text
        )
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == "CWE-502"

    def test_dep_without_cwe(self):
        dep_text = _make_finding_text(
            "LOW", "Outdated dependency version", "package.json", 8
        )
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=dep_text
        )
        vuln = report["vulnerabilities"][0]
        assert vuln["identifiers"] == []


# ═══════════════════════════════════════════════════════════════
# 18. Parametric Severity Tests
# ═══════════════════════════════════════════════════════════════

_SEVERITY_PAIRS = [
    ("CRITICAL", "Critical"),
    ("HIGH", "High"),
    ("MEDIUM", "Medium"),
    ("LOW", "Low"),
    ("INFO", "Info"),
]


class TestSastSeverityParametric:
    """Parametric tests for severity mapping."""

    @pytest.mark.parametrize("input_sev,expected", _SEVERITY_PAIRS)
    def test_severity_mapping(self, input_sev, expected):
        text = _make_finding_text(input_sev, f"Test {input_sev}", "app.py", 1)
        report = generate_sast_report(text)
        assert report["vulnerabilities"][0]["severity"] == expected

    @pytest.mark.parametrize("input_sev,expected", _SEVERITY_PAIRS)
    def test_dep_scanning_severity_mapping(self, input_sev, expected):
        dep_text = _make_finding_text(input_sev, f"Dep {input_sev}", "pkg.json", 1)
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=dep_text
        )
        assert report["vulnerabilities"][0]["severity"] == expected


# ═══════════════════════════════════════════════════════════════
# 19. Parametric CWE Tests
# ═══════════════════════════════════════════════════════════════

_CWE_FINDING_PAIRS = [
    ("SQL injection in query", "CWE-89"),
    ("XSS vulnerability found", "CWE-79"),
    ("Command injection detected", "CWE-78"),
    ("Path traversal in handler", "CWE-22"),
    ("SSRF in url fetcher", "CWE-918"),
    ("Hardcoded password in config", "CWE-798"),
    ("Hardcoded credential exposure", "CWE-798"),
    ("Private key embedded", "CWE-321"),
    ("Weak crypto algorithm used", "CWE-327"),
    ("Open redirect in callback", "CWE-601"),
    ("CSRF token missing", "CWE-352"),
    ("Race condition in handler", "CWE-362"),
    ("Buffer overflow risk", "CWE-120"),
    ("IDOR vulnerability", "CWE-639"),
    ("Log injection possible", "CWE-117"),
    ("Eval function with user input", "CWE-95"),
    ("Prototype pollution risk", "CWE-1321"),
    ("Mass assignment vulnerability", "CWE-915"),
    ("Unrestricted upload allowed", "CWE-434"),
    ("Denial of service via regex", "CWE-400"),
]


class TestSastCweParametric:
    """Parametric tests for CWE enrichment in SAST reports."""

    @pytest.mark.parametrize("desc,expected_cwe", _CWE_FINDING_PAIRS)
    def test_cwe_enrichment(self, desc, expected_cwe):
        text = _make_finding_text("HIGH", desc, "app.py", 1)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1
        assert cwe_ids[0]["name"] == expected_cwe


# ═══════════════════════════════════════════════════════════════
# 20. CodeQuality and SAST Consistency Tests
# ═══════════════════════════════════════════════════════════════

class TestCodeQualitySastConsistency:
    """Test that CodeQuality and SAST reports produce same finding count."""

    def test_same_finding_count(self, tmp_path):
        cq_path = str(tmp_path / "cq.json")
        generate_codequality_report(
            SINGLE_CODE_FINDING, cq_path,
            dep_findings=SINGLE_DEP_FINDING,
            secret_findings=SINGLE_SECRET_FINDING,
        )
        sast = generate_sast_report(
            SINGLE_CODE_FINDING,
            dep_findings=SINGLE_DEP_FINDING,
            secret_findings=SINGLE_SECRET_FINDING,
        )
        with open(cq_path) as f:
            cq = json.load(f)
        assert len(cq) == len(sast["vulnerabilities"])

    def test_multiple_findings_consistency(self, tmp_path):
        cq_path = str(tmp_path / "cq.json")
        generate_codequality_report(MULTIPLE_CODE_FINDINGS, cq_path)
        sast = generate_sast_report(MULTIPLE_CODE_FINDINGS)
        with open(cq_path) as f:
            cq = json.load(f)
        assert len(cq) == len(sast["vulnerabilities"])

    def test_empty_findings_consistency(self, tmp_path):
        cq_path = str(tmp_path / "cq.json")
        generate_codequality_report("", cq_path)
        sast = generate_sast_report("")
        with open(cq_path) as f:
            cq = json.load(f)
        assert len(cq) == len(sast["vulnerabilities"]) == 0


# ═══════════════════════════════════════════════════════════════
# 21. JSON Serialization Tests
# ═══════════════════════════════════════════════════════════════

class TestSastJsonSerialization:
    """Test that SAST reports are properly serializable to JSON."""

    def test_report_is_json_serializable(self):
        report = generate_sast_report(MULTIPLE_CODE_FINDINGS)
        serialized = json.dumps(report)
        assert isinstance(serialized, str)

    def test_report_roundtrip(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        serialized = json.dumps(report)
        deserialized = json.loads(serialized)
        assert deserialized["version"] == "15.0.7"
        assert len(deserialized["vulnerabilities"]) == 1

    def test_dep_report_is_json_serializable(self):
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=SINGLE_DEP_FINDING
        )
        serialized = json.dumps(report)
        assert isinstance(serialized, str)

    def test_large_report_serializable(self):
        specs = [
            ("HIGH", f"Finding {i}", f"file_{i}.py", i)
            for i in range(1, 101)
        ]
        text = _make_multi_findings(*specs)
        report = generate_sast_report(text)
        serialized = json.dumps(report)
        deserialized = json.loads(serialized)
        assert len(deserialized["vulnerabilities"]) == 100


# ═══════════════════════════════════════════════════════════════
# 22. SBOM Integration Tests
# ═══════════════════════════════════════════════════════════════

class TestSbomDependencyScanningIntegration:
    """Test generate_dependency_scanning_report with actual SBOM generation."""

    def test_from_npm_changes(self):
        changes = [
            {
                "new_path": "package.json",
                "diff": '+  "express": "^4.18.2"\n+  "lodash": "^4.17.21"',
            }
        ]
        sbom = generate_sbom(changes, project_name="test")
        report = generate_dependency_scanning_report(sbom)
        assert len(report["dependencies"]) == 2

    def test_from_pypi_changes(self):
        changes = [
            {
                "new_path": "requirements.txt",
                "diff": "+requests==2.31.0\n+flask>=3.0.0",
            }
        ]
        sbom = generate_sbom(changes, project_name="test")
        report = generate_dependency_scanning_report(sbom)
        assert len(report["dependencies"]) >= 1

    def test_dep_report_scanner_metadata(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert report["scan"]["scanner"]["id"] == "duoguard-sbom"
        assert report["scan"]["analyzer"]["id"] == "duoguard-sbom-analyzer"

    def test_dep_report_with_vulns_and_deps(self):
        dep_text = _make_finding_text(
            "HIGH", "SQL injection in ORM dependency", "requirements.txt", 3
        )
        report = generate_dependency_scanning_report(
            SIMPLE_SBOM, dep_findings=dep_text
        )
        assert len(report["dependencies"]) == 2
        assert len(report["vulnerabilities"]) == 1


# ═══════════════════════════════════════════════════════════════
# 23. Report Schema Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestSastReportSchemaValidation:
    """Validate the SAST report has all required fields per GitLab schema."""

    def test_top_level_keys(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        assert "version" in report
        assert "scan" in report
        assert "vulnerabilities" in report

    def test_scan_keys(self):
        report = generate_sast_report("")
        scan = report["scan"]
        assert "type" in scan
        assert "status" in scan
        assert "scanner" in scan
        assert "analyzer" in scan

    def test_scanner_keys(self):
        report = generate_sast_report("")
        scanner = report["scan"]["scanner"]
        assert "id" in scanner
        assert "name" in scanner
        assert "version" in scanner
        assert "vendor" in scanner

    def test_analyzer_keys(self):
        report = generate_sast_report("")
        analyzer = report["scan"]["analyzer"]
        assert "id" in analyzer
        assert "name" in analyzer
        assert "version" in analyzer
        assert "vendor" in analyzer

    def test_vulnerability_required_keys(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        required = ["id", "category", "name", "message", "description",
                     "severity", "scanner", "identifiers", "location", "links"]
        for key in required:
            assert key in vuln, f"Missing required key: {key}"

    def test_location_keys(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        loc = report["vulnerabilities"][0]["location"]
        assert "file" in loc
        assert "start_line" in loc

    def test_dep_report_top_level_keys(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert "version" in report
        assert "scan" in report
        assert "dependencies" in report
        assert "vulnerabilities" in report

    def test_dep_report_scan_keys(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        scan = report["scan"]
        assert "type" in scan
        assert "status" in scan
        assert "scanner" in scan
        assert "analyzer" in scan


# ═══════════════════════════════════════════════════════════════
# 24. Mixed Finding Types from All Agents
# ═══════════════════════════════════════════════════════════════

class TestSastMixedFindingTypes:
    """Test SAST with a realistic mix of finding types from all agents."""

    def test_realistic_scan_output(self):
        code = _make_multi_findings(
            ("CRITICAL", "SQL injection in search endpoint", "api/search.py", 45),
            ("HIGH", "XSS in user profile rendering", "templates/profile.html", 12),
            ("MEDIUM", "Missing CSRF protection on form", "views/settings.py", 78),
        )
        deps = _make_multi_findings(
            ("HIGH", "Known vulnerability in lodash", "package.json", 15),
        )
        secrets = _make_multi_findings(
            ("CRITICAL", "Hardcoded API key for AWS", "config/prod.py", 3),
            ("HIGH", "Hardcoded password in test fixture", "tests/fixtures.py", 22),
        )
        report = generate_sast_report(code, dep_findings=deps, secret_findings=secrets)
        assert len(report["vulnerabilities"]) == 6

        severities = [v["severity"] for v in report["vulnerabilities"]]
        assert severities.count("Critical") == 2
        assert severities.count("High") == 3
        assert severities.count("Medium") == 1

    def test_all_vulns_have_required_fields(self):
        code = MULTIPLE_CODE_FINDINGS
        deps = SINGLE_DEP_FINDING
        secrets = SINGLE_SECRET_FINDING
        report = generate_sast_report(code, dep_findings=deps, secret_findings=secrets)
        for vuln in report["vulnerabilities"]:
            assert vuln["id"]
            assert vuln["category"] == "sast"
            assert vuln["name"]
            assert vuln["severity"] in ("Critical", "High", "Medium", "Low", "Info")
            assert vuln["location"]["file"]
            assert isinstance(vuln["location"]["start_line"], int)


# ═══════════════════════════════════════════════════════════════
# 25. OWASP Link Parametric Tests
# ═══════════════════════════════════════════════════════════════

_OWASP_FINDING_PAIRS = [
    ("SQL injection", True),
    ("XSS attack", True),
    ("Command injection", True),
    ("SSRF detected", True),
    ("Hardcoded password", True),
    ("Minor style issue", False),
    ("Unused variable", False),
]


class TestSastOwaspParametric:
    """Parametric tests for OWASP link presence."""

    @pytest.mark.parametrize("desc,has_owasp", _OWASP_FINDING_PAIRS)
    def test_owasp_link_presence(self, desc, has_owasp):
        text = _make_finding_text("HIGH", desc, "app.py", 1)
        report = generate_sast_report(text)
        vuln = report["vulnerabilities"][0]
        if has_owasp:
            assert len(vuln["links"]) >= 1
        else:
            assert vuln["links"] == []


# ═══════════════════════════════════════════════════════════════
# 26. Regression / Correctness Tests
# ═══════════════════════════════════════════════════════════════

class TestSastRegressions:
    """Regression tests for specific scenarios."""

    def test_finding_order_preserved(self):
        text = _make_multi_findings(
            ("HIGH", "First finding", "a.py", 1),
            ("MEDIUM", "Second finding", "b.py", 2),
            ("LOW", "Third finding", "c.py", 3),
        )
        report = generate_sast_report(text)
        names = [v["name"] for v in report["vulnerabilities"]]
        assert names == ["First finding", "Second finding", "Third finding"]

    def test_report_return_type(self):
        report = generate_sast_report("")
        assert isinstance(report, dict)

    def test_dep_report_return_type(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert isinstance(report, dict)

    def test_generate_sast_with_all_empty_strings(self):
        report = generate_sast_report("", dep_findings="", secret_findings="")
        assert report["vulnerabilities"] == []
        assert report["version"] == "15.0.7"

    def test_dep_scanning_preserves_base_report_fields(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert report["scan"]["scanner"]["vendor"]["name"] == "DuoGuard"
        assert report["scan"]["analyzer"]["vendor"]["name"] == "DuoGuard"
        assert "dependency_files" in report

    def test_sast_report_version_is_string(self):
        report = generate_sast_report("")
        assert isinstance(report["version"], str)

    def test_dep_scanning_version_is_string(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert isinstance(report["version"], str)

    def test_vulnerability_line_num_is_int(self):
        text = _make_finding_text("HIGH", "Bug", "a.py", 42)
        report = generate_sast_report(text)
        assert isinstance(report["vulnerabilities"][0]["location"]["start_line"], int)

    def test_identifiers_is_list(self):
        text = _make_finding_text("HIGH", "SQL injection bug", "a.py", 1)
        report = generate_sast_report(text)
        assert isinstance(report["vulnerabilities"][0]["identifiers"], list)

    def test_links_is_list(self):
        text = _make_finding_text("HIGH", "SQL injection bug", "a.py", 1)
        report = generate_sast_report(text)
        assert isinstance(report["vulnerabilities"][0]["links"], list)

    def test_scanner_in_vulnerability_matches_report_scanner(self):
        report = generate_sast_report(SINGLE_CODE_FINDING)
        vuln = report["vulnerabilities"][0]
        assert vuln["scanner"]["id"] == report["scan"]["scanner"]["id"]

    def test_dep_report_no_output_path_returns_dict(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM, output_path=None)
        assert isinstance(report, dict)

    def test_dep_report_empty_findings_string(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM, dep_findings="")
        assert report["vulnerabilities"] == []

    def test_sast_report_scan_start_end_same(self):
        report = generate_sast_report("")
        assert report["scan"]["start_time"] == report["scan"]["end_time"]

    def test_dep_vuln_description_contains_severity(self):
        dep_text = _make_finding_text("HIGH", "Vulnerable package", "pkg.json", 1)
        report = generate_dependency_scanning_report(SIMPLE_SBOM, dep_findings=dep_text)
        assert "HIGH" in report["vulnerabilities"][0]["description"]

    def test_sast_report_with_only_dep_and_secret(self):
        report = generate_sast_report(
            "", dep_findings=SINGLE_DEP_FINDING, secret_findings=SINGLE_SECRET_FINDING
        )
        assert len(report["vulnerabilities"]) == 2
        names = {v["name"] for v in report["vulnerabilities"]}
        assert any("lodash" in n for n in names)
        assert any("API key" in n for n in names)

    def test_dep_scanning_report_has_schema_field(self):
        report = generate_dependency_scanning_report(SIMPLE_SBOM)
        assert "schema" in report
        assert "gitlab.com" in report["schema"]
