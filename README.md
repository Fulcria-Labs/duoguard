# DuoGuard - AI Security Review Flow for GitLab

An open-source, multi-agent security review flow that automatically analyzes merge requests for vulnerabilities using Claude AI on the GitLab Duo Agent Platform.

**Works automatically. Catches real bugs. Suggests actual fixes.**

## What It Does

DuoGuard orchestrates three specialized AI agents to perform comprehensive security review on every merge request:

| Agent | Purpose | Platform Tools |
|-------|---------|----------------|
| **Code Security Reviewer** | OWASP Top 10 vulnerabilities, injection flaws, auth bypasses | `build_review_merge_request_context`, `list_merge_request_diffs`, `get_repository_file` |
| **Dependency Auditor** | CVEs, license issues, typosquatting, supply chain risks | `list_merge_request_diffs`, `list_vulnerabilities`, `get_vulnerability_details` |
| **Secret Scanner** | Hardcoded API keys, tokens, credentials, private keys | `list_merge_request_diffs`, `gitlab_blob_search`, `get_repository_file` |

Results are posted as:
- **Summary MR comment** with severity ratings, CWE classifications, and fix suggestions
- **Inline diff discussions** anchored to the exact lines with findings
- **MR security labels** (`security::critical`, `security::high`, `security::clean`, etc.)
- **SARIF reports** for the GitLab Security Dashboard (with CWE/OWASP properties)
- **Code Quality JSON** for the Code Quality widget
- **Automated MR approval/rejection** based on configurable severity thresholds
- **GitLab issues** auto-created for critical/high findings with CWE links
- **Diff complexity analysis** — risk scoring and security-sensitive file detection
- **CWE/OWASP enrichment** — automatic classification of findings against OWASP Top 10 (2021)
- **Scan metrics** — files scanned, execution time in every report

## Why DuoGuard?

Traditional security scanners use pattern matching. DuoGuard uses Claude's semantic code understanding to:

- **Understand context** - Knows a `password = "test"` in a test file differs from production code
- **Detect logic flaws** - Catches broken auth flows that regex scanners miss
- **Suggest real fixes** - Provides working code snippets, not just "fix this"
- **Reduce false positives** - AI understands intent, not just patterns

## Architecture

DuoGuard supports two execution modes, both powered by the same multi-agent engine:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Trigger Sources                             │
│                                                                 │
│  @mention in MR  ──┐    Assign reviewer  ──┐    CI/CD pipeline │
│                    │                       │         │          │
│                    v                       v         v          │
│         ┌──────────────────────────────────────────────┐       │
│         │        DuoGuard Orchestrator (Python)        │       │
│         │                                              │       │
│         │  Mode: agent                  Mode: cicd     │       │
│         │  Reads: $AI_FLOW_CONTEXT      Reads: GitLab  │       │
│         │         $AI_FLOW_INPUT        API via CI vars│       │
│         └────────────────┬─────────────────────────────┘       │
│                          │                                      │
│              ┌───────────┼───────────┐                         │
│              v           v           v                         │
│     ┌──────────────┐ ┌────────┐ ┌──────────┐                 │
│     │ Code Security│ │  Dep   │ │  Secret  │  (parallel)     │
│     │  Reviewer    │ │ Auditor│ │  Scanner │                 │
│     │  (Claude)    │ │(Claude)│ │ (Claude) │                 │
│     └──────┬───────┘ └───┬────┘ └────┬─────┘                 │
│            └──────────────┼──────────┘                         │
│                           v                                     │
│              ┌───────────────────┐                              │
│              │ Report Generator  │                              │
│              └─────────┬─────────┘                              │
│                        │                                        │
│              ┌────┼────┬───────┬──────────┐                     │
│              v    v    v       v          v                     │
│          MR Note SARIF Code   Inline    MR Labels              │
│          +Approve Rpt  Quality Discuss  +Metrics               │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Option 1: External Agent (GitLab Duo Agent Platform)

Deploy DuoGuard as a GitLab Duo external agent that responds to triggers:

1. Navigate to **Automate > Agents** in your GitLab project
2. Click **New Agent** and paste the config from [`docs/external-agent-config.yml`](docs/external-agent-config.yml)
3. Enable triggers: **Assign reviewer** and/or **Mention**
4. Assign DuoGuard as a reviewer on any MR — it reviews automatically

The agent uses GitLab's managed AI Gateway credentials (`injectGatewayToken: true`) and reads MR context from `$AI_FLOW_CONTEXT`.

### Option 2: CI/CD Pipeline

Add DuoGuard to your CI/CD pipeline for automatic security review on every MR:

1. Fork this project into your GitLab group
2. Copy `.gitlab-ci.yml` and the `.gitlab/duo/` folder to your project
3. Set up CI/CD variables:
   - `AI_FLOW_AI_GATEWAY_TOKEN` (via AI Gateway) or `ANTHROPIC_API_KEY` (direct)
4. Create a merge request — DuoGuard runs automatically

### Option 3: Duo Flow (Flow Registry v1)

DuoGuard includes a Flow Registry v1 flow at `.gitlab/duo/flows/security-review.yml` that orchestrates four components:

1. `code_security_review` — AgentComponent with `build_review_merge_request_context`
2. `dependency_audit` — AgentComponent with `list_vulnerabilities` tools
3. `secret_scan` — AgentComponent with `gitlab_blob_search`
4. `synthesize_report` — OneOffComponent that posts via `create_merge_request_note`

### Option 4: Local Development

```bash
git clone https://gitlab.com/gitlab-ai-hackathon/duoguard.git
cd duoguard
pip install requests pyyaml urllib3

# Set your API key
export ANTHROPIC_API_KEY=your_key

# CI/CD mode: analyze a specific MR
python scripts/duoguard.py \
  --mode cicd \
  --project-id YOUR_PROJECT_ID \
  --mr-iid 42 \
  --output report.md

# Agent mode: uses platform environment variables
export AI_FLOW_PROJECT_PATH=group/project
export AI_FLOW_CONTEXT='{"merge_request": {"iid": 42}}'
python scripts/duoguard.py --mode agent
```

## Configuration

Create a `.duoguard.yml` in your project root to customize behavior:

```yaml
# .duoguard.yml
version: 1

# Minimum severity to fail the pipeline
severity_threshold: HIGH

# Enable/disable specific agents
agents:
  code_security: true
  dependency_audit: true
  secret_scan: true

# Exclude files from analysis
exclude_paths:
  - vendor/*
  - node_modules/*
  - "*.generated.*"
exclude_extensions:
  - min.js
  - map

# Post findings as inline diff discussions
inline_comments: true

# Auto-approve MRs below severity threshold
approve: true
approve_threshold: HIGH

# Maximum diff size (characters) to send to AI
max_diff_size: 200000
```

All settings are optional — DuoGuard works with zero configuration. The config file is auto-detected from `.duoguard.yml`, `.duoguard.yaml`, or `$DUOGUARD_CONFIG`.

## Example Output

```markdown
## DuoGuard Security Review Report

### Code Security Analysis

### [HIGH] Finding: SQL Injection via string concatenation
**File:** `app/models/user.rb` (line 45)
**CWE:** CWE-89 - SQL Injection
**Description:** User input is concatenated directly into SQL query
**Attack Scenario:** Attacker sends `'; DROP TABLE users; --` as username
**Suggested Fix:**
    User.where("name = ?", params[:name])

### Dependency Audit

| Package | From | To | Risk | Notes |
|---------|------|----|------|-------|
| lodash | 4.17.20 | 4.17.21 | LOW | Security patch for CVE-2021-23337 |

### Secret Scan

No hardcoded secrets detected. Changes look clean.

### Summary
| Category | Findings |
|----------|----------|
| Code Security | 1 issue(s) |
| Dependencies | 0 issue(s) |
| Secrets | 0 issue(s) |

**Overall Risk Level:** HIGH
```

## How GitLab Duo Powers DuoGuard

DuoGuard deeply integrates with the GitLab Duo Agent Platform:

| Feature | How DuoGuard Uses It |
|---------|---------------------|
| **External Agents** | Responds to @mention and assign_reviewer triggers on MRs |
| **Flow Registry v1** | 4-component flow: code review → dep audit → secret scan → report |
| **AI Gateway** | Claude calls via managed credentials (`injectGatewayToken: true`) or Anthropic proxy |
| **Platform Tools** | `build_review_merge_request_context`, `list_merge_request_diffs`, `list_vulnerabilities`, `gitlab_blob_search`, `create_merge_request_note` |
| **CI/CD Pipeline** | Automatic security review on `merge_request_event` |
| **SARIF Reports** | Findings appear in GitLab Security Dashboard |
| **Code Quality** | Issues surface in GitLab Code Quality widget |
| **Inline Discussions** | Findings posted as threaded comments on specific diff lines |
| **Discussion Dedup** | Resolves stale DuoGuard discussions before posting new ones |
| **MR Labels** | Auto-applies `security::<severity>` labels via Labels API |
| **MR Approval** | Auto-approve clean MRs, block risky ones via approval API |
| **Issue Creation** | Auto-create GitLab issues for critical/high findings with CWE links |
| **CWE/OWASP Enrichment** | Automatic classification against 40+ vulnerability patterns |
| **Diff Complexity** | Risk scoring with security-sensitive file detection |
| **AGENTS.md** | Repository-level customization for agent behavior |

## Project Structure

```
duoguard/
├── .gitlab/
│   └── duo/
│       ├── agents/
│       │   ├── code-security-reviewer.yml   # OWASP Top 10 analysis agent
│       │   ├── dependency-auditor.yml        # Supply chain security agent
│       │   └── secret-scanner.yml            # Credential detection agent
│       ├── flows/
│       │   └── security-review.yml           # Flow Registry v1 orchestration
│       └── agent-config.yml                  # Runtime environment config
├── scripts/
│   ├── duoguard.py                           # Multi-mode orchestration engine
│   └── post_report.py                        # MR comments, inline discussions, approval
├── docs/
│   └── external-agent-config.yml             # Config to paste in GitLab UI
├── tests/                                    # 270 tests
├── .gitlab-ci.yml                            # CI/CD pipeline
├── .duoguard.yml                             # Project configuration (optional)
├── AGENTS.md                                 # Agent customization
├── DESIGN.md                                 # Architecture decisions
├── requirements.txt
├── LICENSE
└── README.md
```

## Testing

```bash
# Run all 270 tests
python -m pytest tests/ -v

# Tests cover: diff formatting, dependency extraction, severity scoring,
# report generation, SARIF/CodeQuality output, agent context parsing,
# AI Gateway calls, Anthropic proxy, MR comment posting, inline discussions,
# discussion deduplication, MR labels, scan metrics,
# MR approval/unapproval, config loading, path exclusions, findings export,
# CWE/OWASP enrichment, diff complexity analysis, GitLab issue creation
```

## Prize Categories

- **Anthropic + GitLab Grand Prize** — Deep Claude integration: semantic security analysis, multi-agent orchestration, AI Gateway managed credentials
- **Most Technically Impressive** — Flow Registry v1 flow, parallel multi-agent execution, dual-mode (CI/CD + agent trigger), SARIF + Code Quality + inline discussions + MR labels + MR approval + discussion deduplication + CWE/OWASP enrichment + diff complexity analysis + GitLab issue creation + scan metrics, 270 tests
- **Most Impactful** — Security automation that benefits every development team, zero-config with `injectGatewayToken`, configurable via `.duoguard.yml`, OWASP Top 10 coverage

## License

MIT
