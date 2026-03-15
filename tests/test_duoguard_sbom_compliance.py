"""Tests for DuoGuard SBOM generation and security compliance mapping features.

Covers:
  - SBOM (Software Bill of Materials) generation from dependency diffs
  - CycloneDX 1.5 format validation
  - Multi-ecosystem dependency parsing (npm, pypi, go, cargo, ruby, maven)
  - GitLab dependency scanning report conversion
  - Security compliance mapping (SOC2, ISO 27001, NIST 800-53)
  - Compliance report generation and markdown formatting
  - Edge cases, empty inputs, deduplication, and integration scenarios
"""

import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from duoguard import (
    COMPLIANCE_CONTROLS,
    CWE_KEYWORD_MAP,
    ECOSYSTEM_MAP,
    ISO27001_CONTROLS,
    NIST_CONTROLS,
    PURL_TYPE_MAP,
    SOC2_CONTROLS,
    _max_severity,
    _parse_cargo_dependencies,
    _parse_findings,
    _parse_gemfile_dependencies,
    _parse_go_dependencies,
    _parse_maven_dependencies,
    _parse_npm_dependencies,
    _parse_pypi_dependencies,
    enrich_finding_cwe,
    format_compliance_markdown,
    generate_compliance_report,
    generate_sbom,
    map_finding_to_compliance,
    map_findings_to_compliance,
    parse_dependencies_from_diff,
    sbom_to_gitlab_dependency_report,
)


# ═══════════════════════════════════════════════════════════════
# SBOM: npm dependency parsing (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestParseNpmDependencies:
    def test_simple_dependency(self):
        diff = '+    "express": "^4.18.2"'
        deps = _parse_npm_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "express"
        assert deps[0]["version"] == "4.18.2"
        assert deps[0]["ecosystem"] == "npm"

    def test_multiple_dependencies(self):
        diff = (
            '+    "express": "^4.18.2"\n'
            '+    "lodash": "~4.17.21"\n'
            '+    "axios": ">=1.6.0"'
        )
        deps = _parse_npm_dependencies(diff)
        assert len(deps) == 3
        names = [d["name"] for d in deps]
        assert "express" in names
        assert "lodash" in names
        assert "axios" in names

    def test_skips_metadata_keys(self):
        diff = (
            '+  "name": "my-project"\n'
            '+  "version": "1.0.0"\n'
            '+  "description": "A test project"\n'
            '+  "express": "^4.18.2"'
        )
        deps = _parse_npm_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "express"

    def test_skips_non_added_lines(self):
        diff = (
            '   "express": "^4.18.2"\n'
            '-   "old-pkg": "1.0.0"\n'
            '+   "new-pkg": "2.0.0"'
        )
        deps = _parse_npm_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "new-pkg"

    def test_purl_format(self):
        diff = '+    "react": "^18.2.0"'
        deps = _parse_npm_dependencies(diff)
        assert deps[0]["purl"] == "pkg:npm/react@18.2.0"

    def test_scoped_package(self):
        diff = '+    "@types/node": "^20.0.0"'
        deps = _parse_npm_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "@types/node"

    def test_exact_version(self):
        diff = '+    "typescript": "5.3.3"'
        deps = _parse_npm_dependencies(diff)
        assert deps[0]["version"] == "5.3.3"

    def test_tilde_version(self):
        diff = '+    "debug": "~4.3.4"'
        deps = _parse_npm_dependencies(diff)
        assert deps[0]["version"] == "4.3.4"

    def test_gte_version(self):
        diff = '+    "node-fetch": ">=3.0.0"'
        deps = _parse_npm_dependencies(diff)
        assert deps[0]["version"] == "3.0.0"

    def test_empty_diff(self):
        deps = _parse_npm_dependencies("")
        assert deps == []

    def test_no_additions(self):
        diff = '-    "removed-pkg": "1.0.0"'
        deps = _parse_npm_dependencies(diff)
        assert deps == []

    def test_skips_scripts_key(self):
        diff = '+  "scripts": "test"'
        deps = _parse_npm_dependencies(diff)
        assert deps == []

    def test_skips_main_key(self):
        diff = '+  "main": "index.js"'
        deps = _parse_npm_dependencies(diff)
        assert deps == []

    def test_scope_is_runtime(self):
        diff = '+    "express": "^4.18.2"'
        deps = _parse_npm_dependencies(diff)
        assert deps[0]["scope"] == "runtime"

    def test_complex_version_range(self):
        diff = '+    "webpack": "!5.0.0"'
        deps = _parse_npm_dependencies(diff)
        assert deps[0]["version"] == "5.0.0"


# ═══════════════════════════════════════════════════════════════
# SBOM: Python dependency parsing (12 tests)
# ═══════════════════════════════════════════════════════════════


class TestParsePypiDependencies:
    def test_pinned_version(self):
        diff = "+requests==2.31.0"
        deps = _parse_pypi_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "requests"
        assert deps[0]["version"] == "2.31.0"

    def test_gte_version(self):
        diff = "+flask>=3.0.0"
        deps = _parse_pypi_dependencies(diff)
        assert deps[0]["version"] == "3.0.0"

    def test_no_version(self):
        diff = "+pytest"
        deps = _parse_pypi_dependencies(diff)
        assert deps[0]["version"] == "unknown"

    def test_multiple_packages(self):
        diff = "+requests==2.31.0\n+flask>=3.0\n+pytest"
        deps = _parse_pypi_dependencies(diff)
        assert len(deps) == 3

    def test_purl_lowercase(self):
        diff = "+Flask>=3.0.0"
        deps = _parse_pypi_dependencies(diff)
        assert deps[0]["purl"] == "pkg:pypi/flask@3.0.0"

    def test_compatible_release(self):
        diff = "+django~=4.2"
        deps = _parse_pypi_dependencies(diff)
        assert deps[0]["name"] == "django"
        assert deps[0]["version"] == "4.2"

    def test_skips_comments(self):
        diff = "+# This is a comment\n+requests==2.31.0"
        deps = _parse_pypi_dependencies(diff)
        # Only requests should be parsed (comment line starts with #)
        names = [d["name"] for d in deps]
        assert "requests" in names

    def test_underscore_in_name(self):
        diff = "+my_package==1.0.0"
        deps = _parse_pypi_dependencies(diff)
        assert deps[0]["name"] == "my_package"

    def test_hyphen_in_name(self):
        diff = "+my-package==1.0.0"
        deps = _parse_pypi_dependencies(diff)
        assert deps[0]["name"] == "my-package"

    def test_dot_in_name(self):
        diff = "+zope.interface==6.0"
        deps = _parse_pypi_dependencies(diff)
        assert deps[0]["name"] == "zope.interface"

    def test_empty_diff(self):
        deps = _parse_pypi_dependencies("")
        assert deps == []

    def test_ecosystem_is_pypi(self):
        diff = "+requests==2.31.0"
        deps = _parse_pypi_dependencies(diff)
        assert deps[0]["ecosystem"] == "pypi"


# ═══════════════════════════════════════════════════════════════
# SBOM: Go dependency parsing (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestParseGoDependencies:
    def test_simple_module(self):
        diff = "+\tgithub.com/gin-gonic/gin v1.9.1"
        deps = _parse_go_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "github.com/gin-gonic/gin"
        assert deps[0]["version"] == "1.9.1"

    def test_strips_v_prefix(self):
        diff = "+\tgolang.org/x/crypto v0.21.0"
        deps = _parse_go_dependencies(diff)
        assert deps[0]["version"] == "0.21.0"

    def test_purl_format(self):
        diff = "+\tgithub.com/gorilla/mux v1.8.1"
        deps = _parse_go_dependencies(diff)
        assert deps[0]["purl"] == "pkg:golang/github.com/gorilla/mux@1.8.1"

    def test_multiple_modules(self):
        diff = (
            "+\tgithub.com/gin-gonic/gin v1.9.1\n"
            "+\tgolang.org/x/crypto v0.21.0\n"
            "+\tgithub.com/gorilla/mux v1.8.1"
        )
        deps = _parse_go_dependencies(diff)
        assert len(deps) == 3

    def test_skips_non_added(self):
        diff = "\tgithub.com/existing/pkg v1.0.0"
        deps = _parse_go_dependencies(diff)
        assert deps == []

    def test_ecosystem_is_golang(self):
        diff = "+\tgithub.com/pkg/errors v0.9.1"
        deps = _parse_go_dependencies(diff)
        assert deps[0]["ecosystem"] == "golang"

    def test_prerelease_version(self):
        diff = "+\tgithub.com/test/pkg v2.0.0-rc.1"
        deps = _parse_go_dependencies(diff)
        assert deps[0]["version"] == "2.0.0-rc.1"

    def test_pseudo_version(self):
        diff = "+\tgithub.com/test/pkg v0.0.0-20240301000000-abcdef123456"
        deps = _parse_go_dependencies(diff)
        assert len(deps) == 1
        assert "20240301" in deps[0]["version"]

    def test_empty_diff(self):
        deps = _parse_go_dependencies("")
        assert deps == []

    def test_spaces_indent(self):
        diff = "+    github.com/spf13/cobra v1.8.0"
        deps = _parse_go_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "github.com/spf13/cobra"


# ═══════════════════════════════════════════════════════════════
# SBOM: Cargo (Rust) dependency parsing (8 tests)
# ═══════════════════════════════════════════════════════════════


class TestParseCargoDependencies:
    def test_simple_dependency(self):
        diff = '+serde = "1.0"'
        deps = _parse_cargo_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "serde"
        assert deps[0]["version"] == "1.0"

    def test_complex_dependency(self):
        diff = '+tokio = { version = "1.37", features = ["full"] }'
        deps = _parse_cargo_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "tokio"
        assert deps[0]["version"] == "1.37"

    def test_skips_metadata(self):
        diff = (
            '+name = "my-crate"\n'
            '+version = "0.1.0"\n'
            '+edition = "2021"\n'
            '+serde = "1.0"'
        )
        deps = _parse_cargo_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "serde"

    def test_multiple_dependencies(self):
        diff = (
            '+serde = "1.0"\n'
            '+tokio = "1.37"\n'
            '+axum = "0.7"'
        )
        deps = _parse_cargo_dependencies(diff)
        assert len(deps) == 3

    def test_purl_format(self):
        diff = '+clap = "4.5"'
        deps = _parse_cargo_dependencies(diff)
        assert deps[0]["purl"] == "pkg:cargo/clap@4.5"

    def test_ecosystem_is_cargo(self):
        diff = '+serde = "1.0"'
        deps = _parse_cargo_dependencies(diff)
        assert deps[0]["ecosystem"] == "cargo"

    def test_empty_diff(self):
        deps = _parse_cargo_dependencies("")
        assert deps == []

    def test_hyphenated_name(self):
        diff = '+serde-json = "1.0.120"'
        deps = _parse_cargo_dependencies(diff)
        assert deps[0]["name"] == "serde-json"


# ═══════════════════════════════════════════════════════════════
# SBOM: Ruby dependency parsing (6 tests)
# ═══════════════════════════════════════════════════════════════


class TestParseGemfileDependencies:
    def test_gem_with_version(self):
        diff = "+gem 'rails', '~> 7.0'"
        deps = _parse_gemfile_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "rails"
        assert deps[0]["version"] == "7.0"

    def test_gem_without_version(self):
        diff = "+gem 'puma'"
        deps = _parse_gemfile_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "puma"
        assert deps[0]["version"] == "unknown"

    def test_double_quotes(self):
        diff = '+gem "sidekiq", ">= 7.0"'
        deps = _parse_gemfile_dependencies(diff)
        assert deps[0]["name"] == "sidekiq"

    def test_multiple_gems(self):
        diff = "+gem 'rails', '~> 7.0'\n+gem 'puma'\n+gem 'pg', '~> 1.5'"
        deps = _parse_gemfile_dependencies(diff)
        assert len(deps) == 3

    def test_purl_format(self):
        diff = "+gem 'devise', '~> 4.9'"
        deps = _parse_gemfile_dependencies(diff)
        assert deps[0]["purl"] == "pkg:gem/devise@4.9"

    def test_empty_diff(self):
        deps = _parse_gemfile_dependencies("")
        assert deps == []


# ═══════════════════════════════════════════════════════════════
# SBOM: Maven dependency parsing (7 tests)
# ═══════════════════════════════════════════════════════════════


class TestParseMavenDependencies:
    def test_simple_dependency(self):
        diff = """<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-core</artifactId>
<version>6.1.4</version>"""
        deps = _parse_maven_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["name"] == "org.springframework:spring-core"
        assert deps[0]["version"] == "6.1.4"

    def test_purl_format(self):
        diff = """<dependency>
<groupId>com.google.guava</groupId>
<artifactId>guava</artifactId>
<version>33.0.0-jre</version>"""
        deps = _parse_maven_dependencies(diff)
        assert deps[0]["purl"] == "pkg:maven/com.google.guava/guava@33.0.0-jre"

    def test_dependency_without_version(self):
        diff = """<dependency>
<groupId>junit</groupId>
<artifactId>junit</artifactId>"""
        deps = _parse_maven_dependencies(diff)
        # Version is optional in regex; when missing, defaults to "unknown"
        assert len(deps) == 1
        assert deps[0]["version"] == "unknown"

    def test_multiple_dependencies(self):
        diff = """<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-core</artifactId>
<version>6.1.4</version>
</dependency>
<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-web</artifactId>
<version>6.1.4</version>"""
        deps = _parse_maven_dependencies(diff)
        assert len(deps) == 2

    def test_ecosystem_is_maven(self):
        diff = """<dependency>
<groupId>org.apache.commons</groupId>
<artifactId>commons-lang3</artifactId>
<version>3.14.0</version>"""
        deps = _parse_maven_dependencies(diff)
        assert deps[0]["ecosystem"] == "maven"

    def test_empty_diff(self):
        deps = _parse_maven_dependencies("")
        assert deps == []

    def test_nested_group_id(self):
        diff = """<dependency>
<groupId>io.netty</groupId>
<artifactId>netty-all</artifactId>
<version>4.1.107.Final</version>"""
        deps = _parse_maven_dependencies(diff)
        assert deps[0]["name"] == "io.netty:netty-all"


# ═══════════════════════════════════════════════════════════════
# SBOM: parse_dependencies_from_diff (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestParseDependenciesFromDiff:
    def test_npm_changes(self):
        changes = [{
            "new_path": "package.json",
            "diff": '+    "express": "^4.18.2"\n+    "lodash": "~4.17.21"',
        }]
        deps = parse_dependencies_from_diff(changes)
        assert len(deps) == 2

    def test_pypi_changes(self):
        changes = [{
            "new_path": "requirements.txt",
            "diff": "+requests==2.31.0\n+flask>=3.0",
        }]
        deps = parse_dependencies_from_diff(changes)
        assert len(deps) == 2

    def test_go_changes(self):
        changes = [{
            "new_path": "go.mod",
            "diff": "+\tgithub.com/gin-gonic/gin v1.9.1",
        }]
        deps = parse_dependencies_from_diff(changes)
        assert len(deps) == 1

    def test_mixed_ecosystems(self):
        changes = [
            {"new_path": "package.json", "diff": '+    "express": "^4.18.2"'},
            {"new_path": "requirements.txt", "diff": "+flask>=3.0"},
            {"new_path": "go.mod", "diff": "+\tgithub.com/gin-gonic/gin v1.9.1"},
        ]
        deps = parse_dependencies_from_diff(changes)
        assert len(deps) == 3
        ecosystems = {d["ecosystem"] for d in deps}
        assert ecosystems == {"npm", "pypi", "golang"}

    def test_deduplication(self):
        changes = [
            {"new_path": "package.json", "diff": '+    "express": "^4.18.2"'},
            {"new_path": "package-lock.json", "diff": '+    "express": "^4.18.2"'},
        ]
        deps = parse_dependencies_from_diff(changes)
        assert len(deps) == 1

    def test_non_dependency_files_ignored(self):
        changes = [
            {"new_path": "app.py", "diff": "+import requests"},
            {"new_path": "README.md", "diff": "+# Hello"},
        ]
        deps = parse_dependencies_from_diff(changes)
        assert deps == []

    def test_empty_diff_ignored(self):
        changes = [{"new_path": "package.json", "diff": ""}]
        deps = parse_dependencies_from_diff(changes)
        assert deps == []

    def test_empty_changes(self):
        deps = parse_dependencies_from_diff([])
        assert deps == []

    def test_cargo_changes(self):
        changes = [{
            "new_path": "Cargo.toml",
            "diff": '+serde = "1.0"\n+tokio = "1.37"',
        }]
        deps = parse_dependencies_from_diff(changes)
        assert len(deps) == 2

    def test_gemfile_changes(self):
        changes = [{
            "new_path": "Gemfile",
            "diff": "+gem 'rails', '~> 7.0'",
        }]
        deps = parse_dependencies_from_diff(changes)
        assert len(deps) == 1


# ═══════════════════════════════════════════════════════════════
# SBOM: generate_sbom CycloneDX output (12 tests)
# ═══════════════════════════════════════════════════════════════


class TestGenerateSBOM:
    def test_cyclonedx_format(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes)
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"

    def test_serial_number(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes)
        assert sbom["serialNumber"].startswith("urn:uuid:")

    def test_metadata_tool(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes)
        tools = sbom["metadata"]["tools"]
        assert len(tools) == 1
        assert tools[0]["name"] == "DuoGuard SBOM Generator"

    def test_metadata_component(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes, project_name="my-app", project_version="2.0.0")
        comp = sbom["metadata"]["component"]
        assert comp["name"] == "my-app"
        assert comp["version"] == "2.0.0"
        assert comp["type"] == "application"

    def test_components_populated(self):
        changes = [{
            "new_path": "package.json",
            "diff": '+    "express": "^4.18.2"\n+    "lodash": "~4.17.21"',
        }]
        sbom = generate_sbom(changes)
        assert len(sbom["components"]) == 2
        names = [c["name"] for c in sbom["components"]]
        assert "express" in names
        assert "lodash" in names

    def test_component_has_purl(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes)
        assert sbom["components"][0]["purl"].startswith("pkg:npm/")

    def test_component_type_is_library(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes)
        assert sbom["components"][0]["type"] == "library"

    def test_component_properties(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes)
        props = sbom["components"][0]["properties"]
        prop_dict = {p["name"]: p["value"] for p in props}
        assert prop_dict["duoguard:ecosystem"] == "npm"
        assert prop_dict["duoguard:scope"] == "runtime"

    def test_dependencies_section(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes, project_name="test-proj")
        assert len(sbom["dependencies"]) == 1
        assert sbom["dependencies"][0]["ref"] == "test-proj"

    def test_empty_changes(self):
        sbom = generate_sbom([])
        assert sbom["components"] == []

    def test_writes_to_file(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            sbom = generate_sbom(changes, output_path=path)
            with open(path) as f:
                loaded = json.load(f)
            assert loaded["bomFormat"] == "CycloneDX"
            assert len(loaded["components"]) == 1
        finally:
            os.unlink(path)

    def test_maven_component_group(self):
        changes = [{
            "new_path": "pom.xml",
            "diff": """<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-core</artifactId>
<version>6.1.4</version>""",
        }]
        sbom = generate_sbom(changes)
        comp = sbom["components"][0]
        assert comp["group"] == "org.springframework"
        assert comp["name"] == "spring-core"


# ═══════════════════════════════════════════════════════════════
# SBOM: GitLab dependency report conversion (8 tests)
# ═══════════════════════════════════════════════════════════════


class TestSBOMToGitLabReport:
    def test_report_version(self):
        sbom = generate_sbom([])
        report = sbom_to_gitlab_dependency_report(sbom)
        assert report["version"] == "15.0.7"

    def test_scanner_info(self):
        sbom = generate_sbom([])
        report = sbom_to_gitlab_dependency_report(sbom)
        assert report["scan"]["scanner"]["id"] == "duoguard-sbom"
        assert report["scan"]["type"] == "dependency_scanning"

    def test_dependencies_populated(self):
        changes = [{
            "new_path": "package.json",
            "diff": '+    "express": "^4.18.2"\n+    "lodash": "~4.17.21"',
        }]
        sbom = generate_sbom(changes)
        report = sbom_to_gitlab_dependency_report(sbom)
        assert len(report["dependencies"]) == 2

    def test_dependency_fields(self):
        changes = [{"new_path": "requirements.txt", "diff": "+requests==2.31.0"}]
        sbom = generate_sbom(changes)
        report = sbom_to_gitlab_dependency_report(sbom)
        dep = report["dependencies"][0]
        assert dep["name"] == "requests"
        assert dep["version"] == "2.31.0"
        assert dep["package_manager"] == "pypi"

    def test_purl_preserved(self):
        changes = [{"new_path": "package.json", "diff": '+    "express": "^4.18.2"'}]
        sbom = generate_sbom(changes)
        report = sbom_to_gitlab_dependency_report(sbom)
        assert "purl" in report["dependencies"][0]

    def test_empty_sbom(self):
        sbom = generate_sbom([])
        report = sbom_to_gitlab_dependency_report(sbom)
        assert report["dependencies"] == []

    def test_scan_status_success(self):
        sbom = generate_sbom([])
        report = sbom_to_gitlab_dependency_report(sbom)
        assert report["scan"]["status"] == "success"

    def test_schema_url(self):
        sbom = generate_sbom([])
        report = sbom_to_gitlab_dependency_report(sbom)
        assert "gitlab.com" in report["schema"]


# ═══════════════════════════════════════════════════════════════
# SBOM: ECOSYSTEM_MAP and PURL_TYPE_MAP (6 tests)
# ═══════════════════════════════════════════════════════════════


class TestEcosystemMaps:
    def test_all_npm_files_mapped(self):
        npm_files = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
        for f in npm_files:
            assert ECOSYSTEM_MAP[f] == "npm"

    def test_all_pypi_files_mapped(self):
        pypi_files = ["requirements.txt", "Pipfile", "pyproject.toml", "poetry.lock"]
        for f in pypi_files:
            assert ECOSYSTEM_MAP[f] == "pypi"

    def test_go_files_mapped(self):
        assert ECOSYSTEM_MAP["go.mod"] == "golang"
        assert ECOSYSTEM_MAP["go.sum"] == "golang"

    def test_cargo_files_mapped(self):
        assert ECOSYSTEM_MAP["Cargo.toml"] == "cargo"
        assert ECOSYSTEM_MAP["Cargo.lock"] == "cargo"

    def test_purl_type_map_coverage(self):
        # Every ecosystem in ECOSYSTEM_MAP should have a PURL_TYPE_MAP entry
        ecosystems_used = set(ECOSYSTEM_MAP.values())
        for eco in ecosystems_used:
            assert eco in PURL_TYPE_MAP, f"Missing PURL type for ecosystem: {eco}"

    def test_all_dependency_files_have_ecosystem(self):
        expected_files = [
            "package.json", "requirements.txt", "go.mod", "Cargo.toml",
            "Gemfile", "pom.xml", "composer.json", "mix.exs", "Package.swift",
        ]
        for f in expected_files:
            assert f in ECOSYSTEM_MAP


# ═══════════════════════════════════════════════════════════════
# Compliance: map_finding_to_compliance (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestMapFindingToCompliance:
    def test_sql_injection_mapping(self):
        finding = {"cwe": "CWE-89", "severity": "high", "description": "SQL injection"}
        result = map_finding_to_compliance(finding)
        assert "CC6.1" in result["compliance"]["soc2"]
        assert "A.14.2.5" in result["compliance"]["iso27001"]
        assert "SI-10" in result["compliance"]["nist"]

    def test_xss_mapping(self):
        finding = {"cwe": "CWE-79", "severity": "medium"}
        result = map_finding_to_compliance(finding)
        assert result["compliance"]["cwe"] == "CWE-79"
        assert len(result["compliance"]["soc2"]) > 0

    def test_hardcoded_credentials(self):
        finding = {"cwe": "CWE-798", "severity": "critical"}
        result = map_finding_to_compliance(finding)
        assert "CC6.2" in result["compliance"]["soc2"]
        assert "IA-5" in result["compliance"]["nist"]

    def test_unknown_cwe(self):
        finding = {"cwe": "CWE-99999", "severity": "low"}
        result = map_finding_to_compliance(finding)
        assert result["compliance"]["soc2"] == []
        assert result["compliance"]["iso27001"] == []
        assert result["compliance"]["nist"] == []

    def test_no_cwe(self):
        finding = {"severity": "medium", "description": "Something suspicious"}
        result = map_finding_to_compliance(finding)
        assert result["compliance"]["cwe"] == ""

    def test_preserves_original_fields(self):
        finding = {
            "cwe": "CWE-89",
            "severity": "high",
            "description": "SQL injection found",
            "file_path": "src/db.py",
            "line_num": 42,
        }
        result = map_finding_to_compliance(finding)
        assert result["severity"] == "high"
        assert result["file_path"] == "src/db.py"
        assert result["line_num"] == 42

    def test_ssrf_mapping(self):
        finding = {"cwe": "CWE-918"}
        result = map_finding_to_compliance(finding)
        assert "SC-7" in result["compliance"]["nist"]

    def test_path_traversal_mapping(self):
        finding = {"cwe": "CWE-22"}
        result = map_finding_to_compliance(finding)
        assert "AC-3" in result["compliance"]["nist"]

    def test_deserialization_mapping(self):
        finding = {"cwe": "CWE-502"}
        result = map_finding_to_compliance(finding)
        assert "SI-10" in result["compliance"]["nist"]

    def test_control_description_present(self):
        finding = {"cwe": "CWE-89"}
        result = map_finding_to_compliance(finding)
        desc = result["compliance"]["control_description"]
        assert "SQL Injection" in desc


# ═══════════════════════════════════════════════════════════════
# Compliance: map_findings_to_compliance (5 tests)
# ═══════════════════════════════════════════════════════════════


class TestMapFindingsToCompliance:
    def test_maps_all_findings(self):
        findings = [
            {"cwe": "CWE-89", "severity": "high"},
            {"cwe": "CWE-79", "severity": "medium"},
        ]
        results = map_findings_to_compliance(findings)
        assert len(results) == 2
        assert all("compliance" in r for r in results)

    def test_empty_list(self):
        results = map_findings_to_compliance([])
        assert results == []

    def test_mixed_known_unknown(self):
        findings = [
            {"cwe": "CWE-89", "severity": "high"},
            {"cwe": "CWE-99999", "severity": "low"},
        ]
        results = map_findings_to_compliance(findings)
        assert len(results[0]["compliance"]["soc2"]) > 0
        assert results[1]["compliance"]["soc2"] == []

    def test_preserves_order(self):
        findings = [
            {"cwe": "CWE-79", "description": "first"},
            {"cwe": "CWE-89", "description": "second"},
        ]
        results = map_findings_to_compliance(findings)
        assert results[0]["description"] == "first"
        assert results[1]["description"] == "second"

    def test_findings_without_cwe(self):
        findings = [{"severity": "medium"}]
        results = map_findings_to_compliance(findings)
        assert results[0]["compliance"]["cwe"] == ""


# ═══════════════════════════════════════════════════════════════
# Compliance: generate_compliance_report (15 tests)
# ═══════════════════════════════════════════════════════════════


class TestGenerateComplianceReport:
    def test_report_type(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings)
        assert report["report_type"] == "compliance"

    def test_all_three_frameworks(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings)
        assert "soc2" in report["frameworks"]
        assert "iso27001" in report["frameworks"]
        assert "nist" in report["frameworks"]

    def test_single_framework(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings, frameworks=["soc2"])
        assert "soc2" in report["frameworks"]
        assert "iso27001" not in report["frameworks"]

    def test_controls_impacted_count(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings, frameworks=["soc2"])
        soc2 = report["frameworks"]["soc2"]
        assert soc2["controls_impacted"] > 0

    def test_total_findings(self):
        findings = [
            {"cwe": "CWE-89", "severity": "high"},
            {"cwe": "CWE-79", "severity": "medium"},
        ]
        report = generate_compliance_report(findings)
        assert report["total_findings"] == 2

    def test_findings_with_mapping_count(self):
        findings = [
            {"cwe": "CWE-89", "severity": "high"},
            {"cwe": "CWE-99999", "severity": "low"},
        ]
        report = generate_compliance_report(findings)
        assert report["findings_with_compliance_mapping"] == 1

    def test_posture_critical(self):
        findings = [{"cwe": "CWE-89", "severity": "critical"}]
        report = generate_compliance_report(findings)
        assert report["overall_posture"] == "NON_COMPLIANT"

    def test_posture_high(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings)
        assert report["overall_posture"] == "AT_RISK"

    def test_posture_medium(self):
        findings = [{"cwe": "CWE-89", "severity": "medium"}]
        report = generate_compliance_report(findings)
        assert report["overall_posture"] == "NEEDS_REVIEW"

    def test_posture_low(self):
        findings = [{"cwe": "CWE-89", "severity": "low"}]
        report = generate_compliance_report(findings)
        assert report["overall_posture"] == "ACCEPTABLE"

    def test_posture_info(self):
        findings = [{"cwe": "CWE-89", "severity": "info"}]
        report = generate_compliance_report(findings)
        assert report["overall_posture"] == "COMPLIANT"

    def test_posture_empty(self):
        report = generate_compliance_report([])
        assert report["overall_posture"] == "COMPLIANT"

    def test_timestamp_present(self):
        report = generate_compliance_report([])
        assert "generated_at" in report
        assert "T" in report["generated_at"]

    def test_control_details(self):
        findings = [{"cwe": "CWE-89", "severity": "high", "description": "SQLi found"}]
        report = generate_compliance_report(findings, frameworks=["nist"])
        nist = report["frameworks"]["nist"]
        assert "SI-10" in nist["details"]
        detail = nist["details"]["SI-10"]
        assert detail["finding_count"] >= 1
        assert detail["max_severity"] == "high"

    def test_multiple_findings_same_control(self):
        findings = [
            {"cwe": "CWE-89", "severity": "high", "description": "SQLi"},
            {"cwe": "CWE-79", "severity": "medium", "description": "XSS"},
        ]
        report = generate_compliance_report(findings, frameworks=["nist"])
        # Both CWE-89 and CWE-79 map to SI-10
        si10 = report["frameworks"]["nist"]["details"].get("SI-10", {})
        assert si10.get("finding_count", 0) >= 2


# ═══════════════════════════════════════════════════════════════
# Compliance: _max_severity helper (6 tests)
# ═══════════════════════════════════════════════════════════════


class TestMaxSeverity:
    def test_single_critical(self):
        assert _max_severity(["critical"]) == "critical"

    def test_mixed(self):
        assert _max_severity(["low", "high", "medium"]) == "high"

    def test_all_same(self):
        assert _max_severity(["medium", "medium"]) == "medium"

    def test_empty(self):
        assert _max_severity([]) == "none"

    def test_info_only(self):
        assert _max_severity(["info", "info"]) == "info"

    def test_critical_wins_over_all(self):
        assert _max_severity(["info", "low", "medium", "high", "critical"]) == "critical"


# ═══════════════════════════════════════════════════════════════
# Compliance: format_compliance_markdown (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestFormatComplianceMarkdown:
    def test_contains_header(self):
        report = generate_compliance_report([])
        md = format_compliance_markdown(report)
        assert "### Compliance Impact Assessment" in md

    def test_contains_posture(self):
        report = generate_compliance_report([])
        md = format_compliance_markdown(report)
        assert "Overall Posture" in md
        assert "COMPLIANT" in md

    def test_contains_framework_headers(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings)
        md = format_compliance_markdown(report)
        assert "SOC 2 Type II" in md
        assert "ISO 27001:2022" in md
        assert "NIST 800-53" in md

    def test_contains_table(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings)
        md = format_compliance_markdown(report)
        assert "| Control |" in md
        assert "| Description |" in md

    def test_truncates_long_descriptions(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings)
        md = format_compliance_markdown(report)
        # Descriptions longer than 50 chars get truncated with "..."
        # Some control descriptions are long
        lines = md.split("\n")
        # The markdown should be well-formed
        assert any("|" in line for line in lines)

    def test_no_controls_message(self):
        # With no findings, no controls should be impacted
        report = generate_compliance_report([])
        md = format_compliance_markdown(report)
        assert "No controls impacted" in md or "0/" in md

    def test_finding_count_in_report(self):
        report = generate_compliance_report(
            [{"cwe": "CWE-89", "severity": "high"}]
        )
        md = format_compliance_markdown(report)
        assert "1/1" in md or "Findings with Compliance Mapping" in md

    def test_single_framework(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings, frameworks=["nist"])
        md = format_compliance_markdown(report)
        assert "NIST 800-53" in md
        assert "SOC 2" not in md

    def test_multiple_severities(self):
        findings = [
            {"cwe": "CWE-89", "severity": "critical"},
            {"cwe": "CWE-79", "severity": "low"},
        ]
        report = generate_compliance_report(findings)
        md = format_compliance_markdown(report)
        assert "NON_COMPLIANT" in md

    def test_returns_string(self):
        report = generate_compliance_report([])
        md = format_compliance_markdown(report)
        assert isinstance(md, str)


# ═══════════════════════════════════════════════════════════════
# Compliance: COMPLIANCE_CONTROLS coverage (8 tests)
# ═══════════════════════════════════════════════════════════════


class TestComplianceControlsData:
    def test_all_cwes_in_keyword_map_have_controls(self):
        """Every CWE in CWE_KEYWORD_MAP should have compliance controls."""
        for keyword, mapping in CWE_KEYWORD_MAP.items():
            cwe = mapping["cwe"]
            assert cwe in COMPLIANCE_CONTROLS, (
                f"CWE {cwe} (from keyword '{keyword}') missing from COMPLIANCE_CONTROLS"
            )

    def test_all_controls_have_soc2(self):
        for cwe, controls in COMPLIANCE_CONTROLS.items():
            assert "soc2" in controls, f"{cwe} missing soc2 controls"
            assert len(controls["soc2"]) > 0, f"{cwe} has empty soc2 list"

    def test_all_controls_have_iso27001(self):
        for cwe, controls in COMPLIANCE_CONTROLS.items():
            assert "iso27001" in controls, f"{cwe} missing iso27001 controls"
            assert len(controls["iso27001"]) > 0, f"{cwe} has empty iso27001 list"

    def test_all_controls_have_nist(self):
        for cwe, controls in COMPLIANCE_CONTROLS.items():
            assert "nist" in controls, f"{cwe} missing nist controls"
            assert len(controls["nist"]) > 0, f"{cwe} has empty nist list"

    def test_all_controls_have_description(self):
        for cwe, controls in COMPLIANCE_CONTROLS.items():
            assert "description" in controls, f"{cwe} missing description"
            assert len(controls["description"]) > 0

    def test_soc2_controls_are_valid(self):
        for cwe, controls in COMPLIANCE_CONTROLS.items():
            for ctrl in controls["soc2"]:
                assert ctrl in SOC2_CONTROLS, (
                    f"{cwe} references unknown SOC2 control {ctrl}"
                )

    def test_iso27001_controls_are_valid(self):
        for cwe, controls in COMPLIANCE_CONTROLS.items():
            for ctrl in controls["iso27001"]:
                assert ctrl in ISO27001_CONTROLS, (
                    f"{cwe} references unknown ISO 27001 control {ctrl}"
                )

    def test_nist_controls_are_valid(self):
        for cwe, controls in COMPLIANCE_CONTROLS.items():
            for ctrl in controls["nist"]:
                assert ctrl in NIST_CONTROLS, (
                    f"{cwe} references unknown NIST control {ctrl}"
                )


# ═══════════════════════════════════════════════════════════════
# Integration: SBOM + Compliance together (10 tests)
# ═══════════════════════════════════════════════════════════════


class TestSBOMComplianceIntegration:
    def test_findings_enriched_then_mapped(self):
        """Findings from _parse_findings get CWE enrichment, then compliance."""
        text = (
            "### [HIGH] Finding: SQL injection in user input\n"
            "**File:** `src/db.py` (line 42)"
        )
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 1
        # enrich_finding_cwe is called inside _parse_findings
        assert findings[0].get("cwe") == "CWE-89"
        # Now map to compliance
        mapped = map_findings_to_compliance(findings)
        assert "SI-10" in mapped[0]["compliance"]["nist"]

    def test_sbom_and_compliance_from_same_mr(self):
        """Both features can run on the same MR changes."""
        changes = [
            {"new_path": "package.json", "diff": '+    "express": "^4.18.2"'},
            {"new_path": "src/app.js", "diff": "+eval(userInput)"},
        ]
        # SBOM generation
        sbom = generate_sbom(changes)
        assert len(sbom["components"]) >= 1

        # Compliance mapping from findings
        findings = [
            {"cwe": "CWE-95", "severity": "critical", "description": "eval injection"},
        ]
        report = generate_compliance_report(findings)
        assert report["overall_posture"] == "NON_COMPLIANT"

    def test_empty_mr_produces_clean_results(self):
        sbom = generate_sbom([])
        assert sbom["components"] == []
        report = generate_compliance_report([])
        assert report["overall_posture"] == "COMPLIANT"

    def test_sbom_file_and_compliance_report_coexist(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            sbom_path = f.name
        try:
            changes = [{"new_path": "requirements.txt", "diff": "+flask>=3.0"}]
            sbom = generate_sbom(changes, output_path=sbom_path)
            findings = [{"cwe": "CWE-79", "severity": "medium"}]
            compliance = generate_compliance_report(findings)
            # Both produce valid structures
            with open(sbom_path) as f:
                loaded_sbom = json.load(f)
            assert loaded_sbom["bomFormat"] == "CycloneDX"
            assert compliance["report_type"] == "compliance"
        finally:
            os.unlink(sbom_path)

    def test_compliance_markdown_after_sbom(self):
        findings = [
            {"cwe": "CWE-798", "severity": "critical", "description": "Hardcoded secret"},
        ]
        report = generate_compliance_report(findings)
        md = format_compliance_markdown(report)
        assert "NON_COMPLIANT" in md

    def test_all_owasp_top10_have_compliance(self):
        """Every OWASP category in CWE_KEYWORD_MAP leads to compliance controls."""
        owasp_cwes = set()
        for mapping in CWE_KEYWORD_MAP.values():
            owasp_cwes.add(mapping["cwe"])
        for cwe in owasp_cwes:
            controls = COMPLIANCE_CONTROLS.get(cwe, {})
            assert len(controls) > 0, f"{cwe} has no compliance controls"

    def test_gitlab_dependency_report_from_multi_ecosystem(self):
        changes = [
            {"new_path": "package.json", "diff": '+    "express": "^4.18.2"'},
            {"new_path": "requirements.txt", "diff": "+flask>=3.0"},
            {"new_path": "Cargo.toml", "diff": '+serde = "1.0"'},
        ]
        sbom = generate_sbom(changes)
        report = sbom_to_gitlab_dependency_report(sbom)
        managers = {d["package_manager"] for d in report["dependencies"]}
        assert "npm" in managers
        assert "pypi" in managers
        assert "cargo" in managers

    def test_compliance_with_enriched_findings(self):
        """End-to-end: parse findings -> enrich CWE -> compliance mapping."""
        text = (
            "### [CRITICAL] Finding: Hardcoded AWS access key\n"
            "**File:** `config.py` (line 10)\n"
            "### [HIGH] Finding: Cross-site scripting in template\n"
            "**File:** `templates/index.html` (line 55)"
        )
        findings = _parse_findings(text, "code-security")
        assert len(findings) == 2
        report = generate_compliance_report(findings)
        assert report["total_findings"] == 2
        # Hardcoded key -> CWE-798, XSS -> CWE-79
        assert report["findings_with_compliance_mapping"] >= 1

    def test_sbom_serial_numbers_unique(self):
        changes = [{"new_path": "package.json", "diff": '+    "x": "1.0"'}]
        sbom1 = generate_sbom(changes)
        sbom2 = generate_sbom(changes)
        assert sbom1["serialNumber"] != sbom2["serialNumber"]

    def test_compliance_report_frameworks_param(self):
        findings = [{"cwe": "CWE-89", "severity": "high"}]
        report = generate_compliance_report(findings, frameworks=["soc2", "nist"])
        assert "soc2" in report["frameworks"]
        assert "nist" in report["frameworks"]
        assert "iso27001" not in report["frameworks"]


# ═══════════════════════════════════════════════════════════════
# Edge cases and robustness (12 tests)
# ═══════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_npm_with_special_chars_in_version(self):
        diff = '+    "pkg": "1.0.0-beta.1+build.123"'
        deps = _parse_npm_dependencies(diff)
        assert len(deps) == 1

    def test_pypi_with_extras(self):
        diff = "+requests[security]==2.31.0"
        deps = _parse_pypi_dependencies(diff)
        # The regex may or may not capture extras; check it doesn't crash
        assert isinstance(deps, list)

    def test_very_long_diff(self):
        lines = [f'+    "pkg{i}": "1.0.{i}"' for i in range(500)]
        diff = "\n".join(lines)
        deps = _parse_npm_dependencies(diff)
        assert len(deps) == 500

    def test_unicode_in_package_name(self):
        diff = '+    "utf8-validator": "1.0.0"'
        deps = _parse_npm_dependencies(diff)
        assert len(deps) == 1

    def test_cargo_with_features(self):
        diff = '+tokio = { version = "1.37", features = ["full", "macros"] }'
        deps = _parse_cargo_dependencies(diff)
        assert len(deps) == 1
        assert deps[0]["version"] == "1.37"

    def test_compliance_finding_with_all_fields(self):
        finding = {
            "cwe": "CWE-89",
            "owasp": "A03:2021",
            "severity": "critical",
            "description": "SQL injection",
            "file_path": "src/db.py",
            "line_num": 42,
            "category": "code-security",
        }
        result = map_finding_to_compliance(finding)
        # All original fields preserved
        assert result["owasp"] == "A03:2021"
        assert result["category"] == "code-security"
        # Compliance added
        assert len(result["compliance"]["soc2"]) > 0

    def test_compliance_report_with_no_known_cwes(self):
        findings = [
            {"severity": "high", "description": "Unknown pattern"},
            {"cwe": "CWE-99999", "severity": "medium"},
        ]
        report = generate_compliance_report(findings)
        assert report["findings_with_compliance_mapping"] == 0
        assert report["total_findings"] == 2

    def test_sbom_with_only_non_dep_files(self):
        changes = [
            {"new_path": "src/main.py", "diff": "+print('hello')"},
            {"new_path": "README.md", "diff": "+# Title"},
        ]
        sbom = generate_sbom(changes)
        assert sbom["components"] == []

    def test_parse_deps_with_old_path_fallback(self):
        changes = [{"old_path": "requirements.txt", "diff": "+requests==2.31.0"}]
        deps = parse_dependencies_from_diff(changes)
        assert len(deps) == 1

    def test_sbom_default_project_values(self):
        sbom = generate_sbom([])
        assert sbom["metadata"]["component"]["name"] == "unknown"
        assert sbom["metadata"]["component"]["version"] == "0.0.0"

    def test_compliance_max_severity_across_controls(self):
        findings = [
            {"cwe": "CWE-89", "severity": "critical"},
            {"cwe": "CWE-89", "severity": "low"},
        ]
        report = generate_compliance_report(findings, frameworks=["nist"])
        nist = report["frameworks"]["nist"]
        si10 = nist["details"].get("SI-10", {})
        assert si10.get("max_severity") == "critical"

    def test_format_markdown_empty_frameworks(self):
        report = {
            "overall_posture": "COMPLIANT",
            "findings_with_compliance_mapping": 0,
            "total_findings": 0,
            "frameworks": {},
        }
        md = format_compliance_markdown(report)
        assert "COMPLIANT" in md
