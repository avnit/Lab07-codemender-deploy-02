# [7] Using AI for Sec Ops — Security Agent Lab & Grading Skill (`lab_7`)

Authoritative repository for **[7] Using AI for Sec Ops - Creating your Sec Agent Lab** (*Wiz & CodeMender MCP · Security Agent Lab*), containing the **CodeMender Security MCP Server**, **CodeMender Ephemeral Runner**, and the on-demand **Goal-Based Verification & Grading Skill** (`verify-deployment`).

---

## Directory Structure

```text
Lab07-codemender-deploy-02/
├── .agents/
│   └── skills/
│       └── verify-deployment/
│           ├── SKILL.md                          # Lab 7 grading skill rules & 5-goal rubrics
│           └── scripts/
│               ├── verify_environment.py         # Main Lab 7 verification engine & Web Assessor client
│               ├── verify_lab.py                 # CLI alias entrypoint for verify_environment.py
│               └── verify_report_signature.py    # Local cryptographic OIDC JWT signature validator
├── codemender-mcp/                               # 18-tool FastMCP Cloud Run server (CodeMender, BQ, Logging, Wiz)
├── codemender-runner-mcp/                        # Isolated Cloud Run Job execution sandbox & Terraform modules
├── deploy.sh                                     # One-command deploy of both Cloud Run services (gcloud only)
├── .gitallowed                                   # Allowed test patterns for pre-commit checks
├── .gitignore                                    # Ignores runtime assessment state, reports, and secrets
└── README.md
```

---

## Deploying Both Cloud Run Services (`deploy.sh`)

A single script at the repository root deploys both MCP servers and everything they depend on. It needs only `gcloud` and `bq` (no Terraform, no Docker), never prompts, and does **not** ask for a GitHub owner or repository: the target repository is an argument of the MCP tools.

```bash
gcloud config set project <PROJECT_ID>
./deploy.sh
```

| Resource | Name | Source |
| :--- | :--- | :--- |
| Cloud Run service | `codemender-runner-mcp` | `codemender-runner-mcp/` (`docker/mcp.Dockerfile`) |
| Cloud Run service | `codemender-mcp` | `codemender-mcp/` (`Dockerfile`) |
| Cloud Run Job (sandbox both services dispatch to) | `codemender-runner` | `codemender-runner-mcp/` (`cloudbuild.yaml`) |
| Shared | Artifact Registry `codemender-runner`, bucket `codemender-reports-<project>`, BigQuery dataset `codemender` | created if missing |

Common variations:

```bash
./deploy.sh --only mcp                      # only codemender-mcp
./deploy.sh --only runner-mcp               # only codemender-runner-mcp
./deploy.sh --skip-runner-job               # services only; the job already exists
GITHUB_TOKEN=<token> ./deploy.sh            # optional: private repos + fix PRs (stored in Secret Manager)
./deploy.sh --allow-unauthenticated         # public URLs (default is IAM-only, roles/run.invoker)
```

Wiz settings (`WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `WIZ_API_ENDPOINT`) and the other optional values are read from the environment or from `codemender-mcp/.env`; run `./deploy.sh --help` for the full list. The script is idempotent: re-running it rebuilds only images whose source changed.

---

## Supported Lab 7 Goals (`--list-goals`)

| Goal Identifier | Description | Total Points | Rubric Steps |
| :--- | :--- | :---: | :--- |
| `goal-1-target-app-deployment` | **Goal 1: Deploy Vulnerable Target App & GitHub Branch Protection** | 100 pts | GCP APIs & Build IAM (20 pts), `watchlist` Multi-Container Cloud Run (30 pts), Live `CM-0001`/`CM-0002` Baseline (25 pts), GitHub Repo & `main` Protection (25 pts) |
| `goal-2-codemender-mcp-deployment` | **Goal 2: Deploy CodeMender MCP Server, Runner Sandbox & Seed BigQuery** | 100 pts | BQ Dataset, GCS Bucket & IAM (25 pts), `codemender-mcp-server` & `codemender-runner` (25 pts), GE Transport & 18 Tools (25 pts), Seeded Findings & SQL Guardrail (25 pts) |
| `goal-3-enterprise-mcp-connectors` | **Goal 3: Configure Wiz, GitHub & Cloud Logging MCP Connectors** | 100 pts | Wiz Onboarding & Secrets (25 pts), GitHub PAT & GE Custom MCP Org Policy (25 pts), Cloud Logging Remote MCP (25 pts), Seeded `logs/codemender` Correlation (25 pts) |
| `goal-4-hitl-remediation` | **Goal 4: Human-in-the-Loop Remediation & Sandbox Verification (`CM-0001`)** | 100 pts | Remediation Branch & PR (30 pts), Parameterized SQL Fix in `app/db.py` (30 pts), Sandbox Validation Audit Trail (25 pts), Human Merge Guardrail (15 pts) |
| `goal-5-cloud-armor-protection` | **Goal 5: Cloud Armor WAF & Ingress Lockdown (`watchlist`)** | 100 pts | Cloud Run LB Ingress & IaC (25 pts), Cloud Armor Default Deny & SQLi/LFI WAF (25 pts), Serverless NEG & External ALB (25 pts), Live `403` Blocking & Log Audit (25 pts) |

---

## Running Goal Verification (On-Demand Only)

```bash
# Inspect all registered Lab 7 goals and their completion status
python3 .agents/skills/verify-deployment/scripts/verify_environment.py --list-goals

# Evaluate the next uncompleted goal (reads ~/lab.env and .assessment_state.json automatically)
python3 .agents/skills/verify-deployment/scripts/verify_environment.py

# Explicitly evaluate a specific goal and submit to the Web Assessor Application (WAA)
python3 .agents/skills/verify-deployment/scripts/verify_environment.py \
  --goal goal-1-target-app-deployment \
  --github-org "<GITHUB_USERNAME_OR_ORG>" \
  --submit-url "<WEB_ASSESSOR_URL>/api/v1/submissions" \
  --enrollment-key "<COHORT_ENROLLMENT_KEY>"
```

---

## Key Features

1. **Strict On-Demand & Read-Only Policy**: Never runs automatically after deployments and never mutates workspace files, GitHub repos, or GCP resources.
2. **Sequential Goal Progression**: Automatically evaluates the next uncompleted goal so later hardening steps (e.g., Goal 5 Cloud Armor lockdown) never invalidate Goal 1 baseline scores.
3. **Cohort Key & Lab Context Persistence**: Prompts once for the Cohort Enrollment Key, remembers it alongside `project_id`, `region`, and `github_org` in `.assessment_state.json` (gitignored), and never embeds secret payloads in reports.
4. **Cryptographic Anti-Cheat Attestation**: Computes `SHA-256` over the canonical assessment JSON payload and mints an asymmetric `RS256` Google IAM OIDC JWT binding the student identity, GCP project, `lab_7`, `goal_id`, and score.
