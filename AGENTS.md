# DuoGuard - Agent Instructions

DuoGuard is a multi-agent security review system for GitLab merge requests.

## Behavior

When triggered (via @mention, reviewer assignment, or CI/CD pipeline), DuoGuard:
1. Analyzes all changed files in the merge request
2. Runs three specialized security agents in parallel
3. Posts a structured security report as an MR comment

## Agent Roles

- **Code Security Reviewer**: OWASP Top 10, injection, auth bypasses, crypto misuse
- **Dependency Auditor**: CVEs, license compliance, typosquatting, supply chain risks
- **Secret Scanner**: API keys, tokens, credentials, private keys

## Code Style
- Python 3.12+ with type hints
- Follow PEP 8 conventions
- Use pathlib for file operations
- All API calls must have timeouts

## Security Rules
- Never log or display actual secret values
- Mask sensitive data as `<REDACTED>` or `****`
- Validate all external input
- Use parameterized queries, never string concatenation for API URLs

## Testing
- All new functions must have corresponding tests
- Use pytest with the `tmp_path` fixture for file operations
- Mock external API calls in tests

## GitLab Platform Integration
- Use `build_review_merge_request_context` for comprehensive MR context
- Use `list_merge_request_diffs` to examine changed files
- Use `get_repository_file` to read full file contents when needed
- Use `gitlab_blob_search` to search for patterns across the codebase
- Use `create_merge_request_note` to post review comments
- Findings integrate with GitLab Security Dashboard via SARIF 2.1.0
- Code quality issues appear in the GitLab Code Quality widget
