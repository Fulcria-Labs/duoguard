# DuoGuard - AI Security Review Flow for GitLab

## Concept
A multi-agent security review flow that automatically analyzes merge requests for security vulnerabilities using Claude AI on the GitLab Duo Agent Platform.

## Target Prize Categories
1. **Anthropic + GitLab Grand Prize ($10,000)** - Deep use of Claude for code security analysis
2. **Most Impactful ($5,000)** - Security automation affects every development team
3. **Most Technically Impressive ($5,000)** - Multi-agent flow with CI/CD integration

## Architecture

### Flow: Security Review Pipeline
```
MR Created/Updated
    ↓
[Trigger: review_assignment or mention]
    ↓
┌───────────────────────────────┐
│  Agent 1: Code Security       │ → Analyzes diff for OWASP Top 10
│  (Claude Sonnet 4.5)          │   patterns, injection flaws,
│                               │   auth bypasses, etc.
└───────────────────────────────┘
    ↓
┌───────────────────────────────┐
│  Agent 2: Dependency Auditor  │ → Checks new/changed dependencies
│  (Claude Sonnet 4.5)          │   for known CVEs, license issues,
│                               │   typosquatting, maintenance status
└───────────────────────────────┘
    ↓
┌───────────────────────────────┐
│  Agent 3: Secret Scanner      │ → Detects hardcoded credentials,
│  (Claude Sonnet 4.5)          │   API keys, tokens, private keys
│                               │   in code changes
└───────────────────────────────┘
    ↓
┌───────────────────────────────┐
│  Report Generator             │ → Synthesizes all findings into
│  (CI/CD Job)                  │   a structured MR comment with
│                               │   severity ratings and fix suggestions
└───────────────────────────────┘
```

## Key Differentiators
1. **Multi-agent flow** - Not just a single agent, but an orchestrated pipeline
2. **Deep Claude integration** - Leverages Claude's code understanding for semantic analysis (not just regex matching)
3. **Actionable output** - Doesn't just flag issues; provides specific fix suggestions with code snippets
4. **CI/CD native** - Runs as part of the pipeline, gates deployments on security review
5. **Severity scoring** - CVSS-aligned risk ratings for each finding
6. **Zero config** - Works out of the box on any GitLab project

## Tech Stack
- GitLab Duo Agent Platform (custom agents + flows)
- Claude Sonnet 4.5 via GitLab AI Gateway
- GitLab CI/CD for pipeline integration
- Python for report generation and orchestration scripts
- GitLab API for MR comments and status updates
