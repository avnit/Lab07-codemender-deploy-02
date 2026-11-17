# SEC L400 Capstone Grading & Verification Skills (`l400-capstone-skills`)

Centralized distribution repository for the **Financial Companion Capstone Verification & Grading Skill** (`verify-deployment`).

This repository maintains the authoritative, version-controlled implementation of the grading skill, verification scripts, scoring rubrics, and cryptographic attestation pipeline. Updates published here can be pulled and synced to any lab environment or grading runner on other computers.

---

## Directory Structure

```text
capstone-skills/
├── .agents/
│   └── skills/
│       └── verify-deployment/
│           ├── SKILL.md                          # Skill definition, prompt rules & goal rubrics
│           └── scripts/
│               ├── verify_environment.py         # Main verification engine & Web Assessor client
│               └── verify_report_signature.py    # Local cryptographic signature validator
├── .gitallowed                                   # Allowed test patterns for pre-commit checks
├── .gitignore                                    # Ignores runtime state, reports, and logs
└── README.md
```

---

## Supported Lab Goals

| Goal Identifier | Description | Total Points | Rubric Steps |
| :--- | :--- | :---: | :--- |
| `goal-1-environment-setup` | **Goal 1: Baseline Agentic Environment Setup** | 100 pts | Base Infrastructure (25 pts), Vertex AI Engines (25 pts), Cloud Run & Web UI (20 pts), Multi-Agent E2E (30 pts) |
| `goal-2-otel-instrumentation` | **Goal 2: OpenTelemetry Traces, Logs & Metrics** | 100 pts | Telemetry APIs & IAM (20 pts), Agent Engine Env Vars (30 pts), Live Traces & Logs (25 pts), Cloud Monitoring Histograms (25 pts) |
| `goal-n-remediate-app-vulnerabilities` | **Goal N: Remediate App Vulnerabilities (SAST)** | 100 pts | Client-side eval & XSS (30 pts), Hardcoded keys & JWT bypass (30 pts), SQL Injection (30 pts), Unit tests (10 pts) |

---

## How to Sync to Another Grading Environment

To incorporate the latest grading skill updates into a lab repository or separate grading machine:

### Option A: Sync into an existing lab repository
```bash
# Clone or pull the latest skills repo
git clone https://github.com/hgdg7/l400-capstone-skills.git /path/to/capstone-skills

# Copy or sync the .agents directory into your target workspace
cp -r /path/to/capstone-skills/.agents /path/to/finance-companion-baseline/
```

### Option B: Run directly against a target environment
```bash
python3 .agents/skills/verify-deployment/scripts/verify_environment.py \
  --project-id <TARGET_GCP_PROJECT_ID> \
  --goal goal-2-otel-instrumentation
```

---

## Key Features

1. **Sequential Goal Progression**: Automatically skips previously completed goals unless `--force` is specified.
2. **Cohort Key Persistence**: Prompts once for the cohort enrollment key, saves it locally in `.assessment_state.json` (gitignored), and automatically reuses it on subsequent runs.
3. **Cryptographic Anti-Cheat Attestation**: Generates a canonical JSON payload, calculates `SHA-256`, and mints an asymmetric `RS256` Google IAM OIDC token binding the student, project, score, and payload digest.
4. **Dual-Gate Web Assessor Push**: Optionally pushes attested Markdown reports and structured payloads directly to the Web Assessor endpoint via `--submit-url`.
