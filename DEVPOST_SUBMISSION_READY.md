# GitLab AI Hackathon - DevPost Submission (Copy-Paste Ready)

**DevPost URL:** https://gitlab-ai-hackathon.devpost.com/ (or authorizedtoact.devpost.com - verify)
**GitLab Repo:** https://gitlab.com/optimus-fulcria/duoguard

---

## Project Name
DuoGuard

## Tagline
AI-powered multi-agent security review for GitLab merge requests

## What it does
DuoGuard is an open-source, multi-agent security review flow that automatically analyzes GitLab merge requests for vulnerabilities using Claude AI on the GitLab Duo Agent Platform. Three specialized agents run in parallel to catch real bugs and suggest actual fixes:

1. **Code Security Reviewer** - Scans for OWASP Top 10 vulnerabilities, injection flaws, and auth bypasses
2. **Dependency Auditor** - Checks for CVEs, license issues, typosquatting, and supply chain risks
3. **Secret Scanner** - Detects hardcoded API keys, tokens, credentials, and private keys

Results are posted directly to the MR as summary comments, inline diff discussions, security labels, SARIF reports for the Security Dashboard, Code Quality JSON, and auto-created issues for critical findings.

## How we built it
- **GitLab Duo Agent Platform** - External Agent responding to @mention and reviewer assignment triggers
- **Flow Registry v1** - 4-component orchestration flow for parallel multi-agent execution
- **Claude AI (Anthropic)** - Semantic code understanding, not pattern matching
- **CI/CD Pipeline** - Runs automatically on every MR via `.gitlab-ci.yml`
- **Python** - Core orchestrator with GitLab API integration
- **2,035 tests** across 8 test files covering all functionality

## Challenges we ran into
- Designing the multi-agent orchestration so three agents can analyze the same MR diff in parallel without conflicts
- Mapping Claude's findings to exact diff line numbers for inline discussions
- Balancing false positive reduction (understanding context like test vs production code) with comprehensive coverage
- Building SARIF output that integrates cleanly with GitLab's Security Dashboard

## What we learned
- Claude's semantic understanding dramatically reduces false positives compared to regex-based scanners
- The GitLab Duo Agent Platform provides a powerful extensibility model for AI-native development workflows
- Flow Registry v1 enables clean separation of concerns in multi-agent systems
- CWE/OWASP enrichment makes findings actionable for security teams

## What's next for DuoGuard
- Real-time remediation: auto-generate fix MRs for common vulnerability patterns
- Learning from team preferences: adapt severity thresholds based on team-specific merge patterns
- Expand to infrastructure-as-code scanning (Terraform, Kubernetes manifests)
- Cross-MR analysis: detect vulnerabilities that span multiple merge requests

## Built With
- python
- claude-ai
- gitlab-duo-agent-platform
- gitlab-flow-registry
- sarif
- owasp

## Try it out
- **GitLab Repository:** https://gitlab.com/optimus-fulcria/duoguard
- **Demo Video:** Included in repository (duoguard-demo.mp4, duoguard-demo.gif)

## Prize Categories
- **Anthropic + GitLab Grand Prize** ($10K) - Deep Claude AI integration with semantic code understanding
- **Most Technically Impressive** ($5K) - Flow Registry v1 with parallel multi-agent execution
- **Most Impactful** ($5K) - Security automation that every development team can use

---

## How GitLab Duo is Used (if separate field)
DuoGuard is built as a GitLab Duo External Agent that:
1. Responds to @mention triggers and reviewer assignment on merge requests
2. Uses Platform Tools: `build_review_merge_request_context`, `list_merge_request_diffs`, `get_repository_file`, `list_vulnerabilities`, `get_vulnerability_details`, `gitlab_blob_search`
3. Leverages Flow Registry v1 to orchestrate 4 components in the security review pipeline
4. Posts results through GitLab's MR Notes API, Discussions API, Labels API, and SARIF upload

## How Claude/Anthropic is Used (if separate field)
Claude is the core intelligence behind all three security agents. Unlike traditional SAST tools that use regex pattern matching, DuoGuard leverages Claude's semantic understanding to:
- Distinguish test code from production code (reducing false positives)
- Detect logic flaws that pattern matchers miss (broken auth flows, TOCTOU races)
- Generate working code fix snippets tailored to the specific codebase
- Classify findings with CWE IDs and OWASP Top 10 categories

---
*Last updated: 2026-03-15*
