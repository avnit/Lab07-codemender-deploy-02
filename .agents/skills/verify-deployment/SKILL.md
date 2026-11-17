---
name: verify-deployment
description: Strictly on-demand verification and assessment skill. Evaluates and grades student completion of incremental goals for [7] Using AI for Sec Ops - Creating your Sec Agent Lab ONLY when the student explicitly requests grading, verification, or scoring. NEVER invoke automatically after deployment, terraform, or configuration steps.
---

# [7] Using AI for Sec Ops - Creating your Sec Agent Lab Skill (`lab_7`)

Use this skill whenever a student asks to **verify their progress**, **assess/grade a completed lab goal**, or **submit their goal report (`assessment_report_<goal_id>.md`)** for **[7] Using AI for Sec Ops - Creating your Sec Agent Lab** (*Wiz & CodeMender MCP · Security Agent Lab*, `lab_7`) to the Web Assessor application.

## Lab & Curriculum Association (Lab 7)
- **Target Lab**: `[7] Using AI for Sec Ops - Creating your Sec Agent Lab` (`lab_7` / `lab-07-secops-codemender-agent`)
- **Lab Guide Reference**: *Wiz & CodeMender MCP · Security Agent Lab* (`Lab07-CloudRun-Service-Deploy-1`, `codemender-mcp`, `codemender-runner-mcp`, Wiz MCP, GitHub MCP, Cloud Logging MCP, and Cloud Armor)
- **Structure**: **Labs contain Goals. Goals contain Steps.**
- Every goal evaluated by this skill (`goal-1-target-app-deployment`, `goal-2-codemender-mcp-deployment`, `goal-3-enterprise-mcp-connectors`, `goal-4-hitl-remediation`, `goal-5-cloud-armor-protection`) belongs to **Lab 7** and reports under `lab_7` in the Web Assessor Application (WAA).

## Mandatory Operating Rules for the Grading Skill & Antigravity

1. **Strict On-Demand Invocation Policy (Student Request Required — Never Auto-Run After Deployment)**:
   - **Never Automatically Grade After Deployment**: Antigravity and the grading skill MUST NEVER automatically invoke or execute `verify_environment.py`, `verify_lab.py`, or any assessment checks after completing a deployment step, Terraform apply, cloud resource provisioning, script execution, or code edit.
   - **Explicit Student Trigger Only**: Verification must only be triggered when the student explicitly and directly asks for grading, verification, progress assessment, or score submission (e.g., *"grade Goal 1"*, *"verify my lab"*, *"assess my deployment"*, *"submit my score to WAA"*).
   - **Post-Deployment Protocol**: After completing any deployment or setup command requested by the student, Antigravity must:
     - Report the status and outputs of the deployment clearly.
     - Halt execution without running the grading skill.
     - Optionally inform the student: *"Deployment is complete. Whenever you are ready for this milestone to be evaluated, let me know and I will run the grading verification."*

2. **Strict Read-Only Verification Policy (Zero Workspace or Environment Mutations)**:
   - **The grading skill must strictly limit itself to verifying whether steps and goals were met.**
   - **The skill MUST NEVER modify the existing workspace or deployed environment**: The skill can never create, edit, patch, delete, or alter any files, source code, configuration files, terraform definitions, database entries, GitHub branches/PRs, GCP resources, or cloud infrastructure—even if it detects that a prerequisite or component it is looking for is missing, misconfigured, or failing.
   - Never expose raw secret material (GitHub PATs, Wiz client secrets, OAuth tokens) in Markdown reports or JSON evidence blocks; record only secret existence, version status, and boolean verification outcomes.
   - If something expected is missing or failing, the skill must simply mark the corresponding check as `FAIL`, assign 0 points, record the diagnostic reason in the assessment report, and exit cleanly without attempting any modification or remediation.

3. **Mandatory Instruction to Antigravity (Zero Automated Remediation During Grading)**:
   - **Antigravity MUST NEVER modify the existing workspace or deployed environment** in case there is something missing that the grading skill is looking for for grading.
   - When requested to verify or grade student progress, Antigravity must execute the grading verification as an objective, hands-off observer. Antigravity is strictly forbidden from "pre-fixing", patching files, deploying infrastructure, creating service accounts, applying terraform, opening PRs, or modifying code before or during the grading process to force checks to pass.
   - If checks fail or resources are missing, Antigravity must strictly report the objective results, score, and failures as reflected in the generated report to the student. Remediation is exclusively the student's task, and Antigravity may only assist in making changes if the student explicitly instructs Antigravity to perform a specific remediation *after* grading has concluded.

4. **Sequential Goal Progression Only (Do Not Re-Validate Completed Goals Unless Requested)**:
   - **Only run a validation for an already executed and completed goal if explicitly requested by the student.**
   - Once a goal has been validated (`PASS` / `100/100`, recorded in `.agents/skills/verify-deployment/.assessment_state.json`), the skill **must only evaluate the next unvalidated goal** upon the student's request (e.g., after Goal 1 is validated, the next evaluation request targets Goal 2).
   - If the student explicitly asks to re-run an already completed goal, pass `--goal <goal_id> --force`. Otherwise, omit `--goal` (or pass the next goal ID) so `verify_environment.py` automatically selects the next uncompleted goal.

5. **Ask for the Cohort Key in the Beginning and Remember It**:
   - At the very beginning (on the first grading/verification request), check `.agents/skills/verify-deployment/.assessment_state.json` (and `ASSESSOR_ENROLLMENT_KEY`).
   - If the **Cohort Enrollment Key** is not yet saved, **ask the student for the Cohort Key upfront** and pass `--enrollment-key "<COHORT_KEY>"` on the first run.
   - `verify_environment.py` automatically persists `enrollment_key` (along with `student_id`, `submit_url`, `project_id`, `region`, `github_org`, and `target_repo`) in `.agents/skills/verify-deployment/.assessment_state.json` (gitignored) and loads it automatically on all future runs so **you never prompt the user for the Cohort Key again**.

---

## Goal-Based Incremental Assessment Model

Students complete Lab 7 across **5 sequential Goals** (`goal-1-target-app-deployment` through `goal-5-cloud-armor-protection`):
- Each Goal comprises **4 Steps** totaling **100 points** (passing threshold: **85 / 100**; auto-advances on **100 / 100**).
- Because later goals remediate vulnerabilities and lock down public Cloud Run ingress (`INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` + Cloud Armor `403` blocks) that were intentionally exposed in Goal 1, **each Goal must be verified and submitted independently** as the student completes that module.
- The Web Assessor registers each completed Goal in the student's permanent record (`student_goal_grades`, retaining the **highest valid score** per goal if re-submitted) without overwriting or invalidating previously completed goals.

### Registered Lab Goals (`--list-goals`)

#### `goal-1-target-app-deployment` — **Goal 1: Deploy Vulnerable Target App & GitHub Branch Protection (100 Points Total)**
*(Covers Lab Modules: **Base Environment (`lab.env`)** & **Deploy Vulnerable Target App** Steps 1–4)*

1. **Step 1 — Required GCP APIs & Cloud Build IAM Readiness (20 pts)**
   - **1.1 Core GCP APIs Enabled (10 pts)**: Verifies `compute`, `cloudbuild`, `artifactregistry`, `run`, and `secretmanager` APIs are `ENABLED` in `<project_id>`.
   - **1.2 Cloud Build Service Account & Builder IAM Roles (10 pts)**: Verifies `<project_number>-compute@developer.gserviceaccount.com` (or custom build SA) is enabled and holds build/storage/registry/logging permissions (`roles/cloudbuild.builds.builder`, `roles/storage.admin`, `roles/artifactregistry.writer`, `roles/logging.logWriter`).
2. **Step 2 — Multi-Container `watchlist` Cloud Run Deployment (30 pts)**
   - **2.1 `watchlist` Cloud Run Service & Multi-Container Topology (`web` + `mysql` Sidecar) (20 pts)**: Verifies Cloud Run service `watchlist` is `Ready` in `<region>` running the `web` Flask container alongside the `mysql` sidecar (`3306`) and database env configuration (`CM-0003` baseline).
   - **2.2 Live Public `/health` Endpoint & MySQL Sidecar Connectivity (10 pts)**: Probes `GET <watchlist_url>/health` without IAM auth (verifying public exposure via `--no-invoker-iam-check` or `allUsers`) and confirms HTTP `200` with `status == "ok"` and `db == "mysql"`.
3. **Step 3 — Baseline Intentional Vulnerabilities Live Verification (`CM-0001` & `CM-0002`) (25 pts)**
   - **3.1 `CM-0001` (`CWE-89` SQL Injection) Reachable on `GET /api/items?source=` (13 pts)**: Confirms the baseline SQL injection PoC (`source=' OR '1'='1`) returns catalog items across sources prior to remediation.
   - **3.2 `CM-0002` (`CWE-22` Path Traversal) Reachable on `GET /api/notes?file=` (12 pts)**: Confirms the baseline path traversal PoC (`file=../not_a_secret.txt`) reads `data/not_a_secret.txt`.
4. **Step 4 — Target Repository on GitHub & `main` Branch Protection (25 pts)**
   - **4.1 Student GitHub Repository (`<GITHUB_ORG>/Lab07-CloudRun-Service-Deploy-1`) Populated (15 pts)**: Verifies the student's GitHub repository exists with default branch `main` and contains `app/db.py`, `Dockerfile`, and `.codemender/mock-findings.json`.
   - **4.2 Human-in-the-Loop Branch Protection Enabled on `main` (10 pts)**: Verifies GitHub branch protection / rulesets on `main` require >= 1 approving PR review and block force-pushes (`allow_force_pushes == false`) so the AI agent cannot merge its own PRs.

---

#### `goal-2-codemender-mcp-deployment` — **Goal 2: Deploy CodeMender MCP Server, Runner Sandbox & Seed BigQuery Findings (100 Points Total)**
*(Covers Lab Modules: **Deploy CodeMender MCP & Runner** Steps 1–4 & **Verify All MCP Servers** Steps 5.1–5.6)*

1. **Step 1 — CodeMender Storage, BigQuery Dataset & Runtime IAM (25 pts)**
   - **1.1 BigQuery Dataset `codemender` & GCS Transit Bucket `gs://codemender-reports-<project_id>` (13 pts)**: Verifies dataset `<project_id>.codemender` and the GCS transit bucket for code snapshots/SARIF exist.
   - **1.2 Runtime Service Account (`codemender-mcp-sa`) & Least-Privilege IAM (12 pts)**: Verifies `codemender-mcp-sa@<project_id>.iam.gserviceaccount.com` (or `codemender-mcp@...`) is active with BigQuery, Cloud Logging, Storage, and Cloud Run Job execution roles.
2. **Step 2 — `codemender-mcp-server` Cloud Run Service & `codemender-runner` Job (25 pts)**
   - **2.1 `codemender-mcp-server` Ready & `/healthz` Healthy (15 pts)**: Verifies Cloud Run service `codemender-mcp-server` (or `codemender-mcp`) is `Ready` and `GET /healthz` returns `status == "healthy"` bound to dataset `codemender`.
   - **2.2 Ephemeral `codemender-runner` Cloud Run Job Deployed (10 pts)**: Verifies Cloud Run Job `codemender-runner` exists in `<region>` with a valid sandbox container image.
3. **Step 3 — Gemini Enterprise HTTP Transport Compatibility & 18-Tool Registry (25 pts)**
   - **3.1 `MCPCompatibilityMiddleware` (`OPTIONS 204`, `DELETE 200`, `initialize`) (10 pts)**: Executes live preflight `OPTIONS /mcp` (`204`), `DELETE /mcp` (`200`), and JSON-RPC `initialize` (`200`) checks.
   - **3.2 All 18 CodeMender, BigQuery, Cloud Logging & Wiz Tools Registered (`tools/list`) (15 pts)**: Calls JSON-RPC `tools/list` on `/mcp` and confirms all 18 expected tools (`cm_find`, `cm_validate`, `cm_fix`, `cm_apply_patch`, `cm_job_status`, `cm_list_findings`, `cm_get_finding`, `list_codemender_issues`, `get_issue_details`, `get_issues_summary`, `get_bigquery_schema`, `query_codemender_bigquery`, `get_issue_logs`, `search_codemender_logs`, `list_wiz_issues`, `get_wiz_issue_details`, `get_wiz_issues_summary`, `query_wiz_graphql`) are exposed.
4. **Step 4 — Seeded `Lab07-CloudRun-Service-Deploy-1` Findings & Read-Only SQL Guardrail (25 pts)**
   - **4.1 BigQuery `codemender.findings` Populated (`CM-0001`–`CM-0004`) & `get_issues_summary` (15 pts)**: Queries `<project_id>.codemender.findings` and invokes MCP `get_issues_summary` to confirm all 4 `Lab07` findings (`CM-0001` to `CM-0004` or live `cm_find` findings) are ingested.
   - **4.2 Negative Security Guardrail (`DROP TABLE` Blocked in `query_codemender_bigquery`) (10 pts)**: Calls `query_codemender_bigquery` with a `DROP TABLE` statement on a non-existent probe table and confirms the server blocks non-`SELECT`/`WITH` DDL/DML before execution.

---

#### `goal-3-enterprise-mcp-connectors` — **Goal 3: Configure Wiz, GitHub & Cloud Logging MCP Connectors & Telemetry (100 Points Total)**
*(Covers Lab Modules: **Configure Wiz MCP Connector**, **Configure GitHub MCP Connector**, **Configure Cloud Logging MCP Connector**, & **Part 1 Investigation Readiness**)*

1. **Step 1 — Wiz Cloud Onboarding & Wiz MCP Secret Manager Credentials (25 pts)**
   - **1.1 GCP Project Onboarded to Wiz (Wiz Service Account / IAM Binding) (10 pts)**: Verifies Wiz cloud connector onboarding IAM bindings or service account in `<project_id>`.
   - **1.2 Wiz MCP Credentials Stored in Secret Manager (`wiz-mcp-client-id` & `wiz-mcp-client-secret`) (15 pts)**: Confirms Secret Manager secrets `wiz-mcp-client-id` and `wiz-mcp-client-secret` (or `wiz-client-secret`) exist with `ENABLED` versions (and validates Wiz OAuth client credentials if accessible, without logging secret values).
2. **Step 2 — GitHub MCP Credentials & Gemini Enterprise Org Policy Readiness (25 pts)**
   - **2.1 Fine-Grained GitHub PAT Stored in Secret Manager (`github-mcp-pat`) (15 pts)**: Confirms `github-mcp-pat` (or `codemender-github-token` / `github-token`) is `ENABLED` in Secret Manager.
   - **2.2 Gemini Enterprise Custom MCP Org Policy Unblocked (`disableCustomMcpServerConnector`) (10 pts)**: Confirms effective Org Policy `discoveryengine.managed.disableCustomMcpServerConnector` is not enforced on `<project_id>` (and records any active Discovery Engine Custom MCP data stores).
3. **Step 3 — Google Cloud Logging Remote MCP Server (`https://logging.googleapis.com/mcp`) (25 pts)**
   - **3.1 Cloud Logging API, Remote MCP Endpoint Enabled & `roles/logging.viewer` IAM (15 pts)**: Verifies `logging.googleapis.com` is `ENABLED`, `roles/logging.viewer` is bound, and live JSON-RPC `tools/list` against `https://logging.googleapis.com/mcp` succeeds, exposing `list_log_entries` and `list_log_names`.
   - **3.2 Live MCP Tool Invocation Against `https://logging.googleapis.com/mcp` (10 pts)**: Executes a live read-only MCP `tools/call` (`list_log_names` / `list_log_entries`) scoped to `projects/<project_id>`.
4. **Step 4 — Seeded CodeMender Telemetry in Cloud Logging & Cross-Signal Correlation (25 pts)**
   - **4.1 Seeded `logs/codemender` Telemetry (`CODEMENDER_SCAN_STARTED`, `CODEMENDER_FINDING`, `CODEMENDER_SANDBOX_ERROR`) (15 pts)**: Queries `projects/<project_id>/logs/codemender` to confirm all 3 lab log events (`CM-0001` `CWE-89` finding, scan start, and `CM-0003` sandbox error) are present.
   - **4.2 Cross-Signal Log Correlation via `codemender-mcp-server` (`get_issue_logs` / `search_codemender_logs`) (10 pts)**: Calls `get_issue_logs(issue_id="CM-0001")` / `search_codemender_logs` on `codemender-mcp-server` and verifies correlated log retrieval.

---

#### `goal-4-hitl-remediation` — **Goal 4: Human-in-the-Loop Remediation & Sandbox Verification (`CM-0001`) (100 Points Total)**
*(Covers Lab Module: **Part 2: Human-in-the-Loop Remediation** — 8-Step Guided Remediation Sequence & Audit Trail)*

1. **Step 1 — Remediation Branch & Pull Request Created on GitHub (30 pts)**
   - **1.1 Remediation Branch (`security/CM-0001-*` / `codemender/fix-*`) & Pull Request Targeting `main` (15 pts)**: Verifies a Pull Request exists on `<GITHUB_ORG>/Lab07-CloudRun-Service-Deploy-1` from a dedicated feature branch into `main`.
   - **1.2 Structured PR Description (`CM-0001` / `wiz-issue-0001`, Root Cause & Verification Verdict) (15 pts)**: Verifies the PR title/body cites `CM-0001` (or `wiz-issue-0001` / `CWE-89`), documents the `app/db.py` `search_items()` root cause, and includes sandbox verification details.
2. **Step 2 — Minimal Parameterized SQL Fix Quality (`CWE-89` in `app/db.py`) (30 pts)**
   - **2.1 `app/db.py` Replaces SQL String Interpolation with Parameterized Query (`WHERE source = ?` & `(source,)`) (30 pts)**: Inspects the PR patch / head branch `app/db.py` via GitHub API to verify `f"FROM items WHERE source = '{source}'` is removed from `search_items()` and replaced with parameterized placeholder binding `_run(conn, query, (source,))` without breaking surrounding functions.
3. **Step 3 — Isolated Sandbox Validation & BigQuery / Workflow Audit Trail (25 pts)**
   - **3.1 Ephemeral Sandbox Execution & Verification Record (25 pts)**: Confirms sandbox validation ran via `codemender-runner` Cloud Run Job executions, BigQuery `codemender.jobs` / `codemender.findings` status update (`VERIFIED`, `FIXED`, `PATCHED`, or `pr_url`), or `sandbox-validate.yml` GitHub Actions workflow run.
4. **Step 4 — Human-in-the-Loop Merge Refusal Guardrail Enforced (15 pts)**
   - **4.1 No Autonomous Bot Merge into `main` (15 pts)**: Confirms the agent did not bypass human review or auto-merge its own PR (`main` remains unmerged awaiting human Code Owner review per Step 8, or was merged solely by a human reviewer).

---

#### `goal-5-cloud-armor-protection` — **Goal 5: Cloud Armor WAF & Ingress Lockdown (`watchlist`) (100 Points Total)**
*(Covers Lab Module: **Part 3: Cloud Armor Protection** — Exercises 3.1, 3.2, & 3.3)*

1. **Step 1 — Cloud Run Ingress Lockdown & Cloud Armor Terraform / PR (25 pts)**
   - **1.1 `watchlist` Cloud Run Ingress Locked to `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` (15 pts)**: Verifies Cloud Run service `watchlist` enforces `ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"`.
   - **1.2 Cloud Armor IaC (`cloud_armor.tf` & PR `security/cloud-armor-protection`) (10 pts)**: Verifies the Cloud Armor Terraform configuration (`google_compute_security_policy`, Serverless NEG, External ALB, and `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`) in a GitHub PR/branch on `<GITHUB_ORG>/Lab07-CloudRun-Service-Deploy-1` or local `terraform/cloud_armor.tf`.
2. **Step 2 — Google Cloud Armor Security Policy & OWASP WAF Rules (25 pts)**
   - **2.1 `watchlist-cloud-armor-policy` Default `deny(403)` (`2147483647`) & Authorized CIDR `allow` Rule (`1000`) (12 pts)**: Verifies the Compute Engine Cloud Armor policy blocks all public traffic (`*` -> `deny(403)`) by default and defines an explicit `allow` rule for authorized CIDRs.
   - **2.2 Preconfigured OWASP WAF Rules (`sqli-v33-stable` & `lfi-v33-stable`) (13 pts)**: Verifies `deny(403)` WAF rules using `evaluatePreconfiguredWaf` for both SQL injection (`sqli-*`) and Local File Inclusion / Path Traversal (`lfi-*`).
3. **Step 3 — Global External Application Load Balancer & Serverless NEG Attachment (25 pts)**
   - **3.1 Serverless NEG (`watchlist-serverless-neg`) & Backend Service (`watchlist-backend`) with Policy & Logging (15 pts)**: Verifies the Serverless NEG targets `watchlist`, `watchlist-backend` attaches the Cloud Armor security policy, and `logConfig.enable == true`.
   - **3.2 URL Map, Target HTTP(S) Proxy & Global Forwarding Rule (`watchlist-forwarding-rule`) (10 pts)**: Verifies the Global Forwarding Rule is provisioned with an external IP (`LB_IP`).
4. **Step 4 — Live Perimeter Enforcement & Cloud Armor Telemetry Audit (25 pts)**
   - **4.1 Direct `.run.app` Blocked (`404`/`403`) & Load Balancer Blocks Public/SQLi/LFI Requests (`403 Forbidden`) (15 pts)**: Verifies live requests to `<watchlist_run_url>/health` are rejected and live SQLi (`/api/items?source=' OR '1'='1`) and Path Traversal (`/api/notes?file=../not_a_secret.txt`) probes to `http://<LB_IP>` return `403 Forbidden`.
   - **4.2 Cloud Logging `http_load_balancer` Cloud Armor Enforcement Logs (`enforcedSecurityPolicy`) (10 pts)**: Queries Cloud Logging for `resource.type="http_load_balancer"` entries recording `enforcedSecurityPolicy` `403` blocks on `watchlist-backend`.

---

## Cryptographic Anti-Cheat Attestation

To prevent students from sharing or editing goal reports:
1. The verification script constructs a deterministic **Canonical Assessment JSON Payload** (`secops-codemender-assessment/v2`) containing the student's authenticated GCP identity (`oauth2.googleapis.com/tokeninfo`), project ID/number, `lab_id` (`lab_7`), `goal_id`, `goal_number`, a unique UUIDv4 `submission_id` (`nonce`), timestamp, `step_breakdown`, and every check's detailed evidence, and computes its `SHA-256` digest (`payload_sha256`).
2. Using the student's live GCP credentials, the script dynamically resolves an active project service account (`codemender-mcp-sa@...`, `codemender-mcp@...`, `codemender-runner@...`, `watchlist-sa@...`, or any active `@<project_id>.iam.gserviceaccount.com`) and calls the **Google Cloud IAM Credentials API** (`:generateIdToken`) with a custom `audience` (`aud`) claim:
   ```text
   https://secops-codemender.assessment/v1?project=<project_id>&principal=<principal_email>&student=<student_id>&goal=<goal_id>&lab=lab_7&signer=<sa_email>&score=<earned>/<max>&sha256=<payload_sha256>&ts=<unix_timestamp>&nonce=<submission_id>
   ```
3. Google's IAM infrastructure mints an **asymmetric `RS256` OIDC JWT signed by Google's private key** (`iss: https://accounts.google.com`).

---

## How to Run the Verification

### Step 0: Check Remembered Cohort Key & Resolve Next Unvalidated Goal
1. **Ask for the Cohort Key in the Beginning & Remember It**:
   - Inspect `.agents/skills/verify-deployment/.assessment_state.json`.
   - If `enrollment_key` is not yet stored in `.assessment_state.json` (and `ASSESSOR_ENROLLMENT_KEY` is not set), **ask the student in chat for their Cohort Enrollment Key** at the very start before running the script, then pass `--enrollment-key "<COHORT_KEY>"` on that first invocation.
   - Once provided, `verify_environment.py` saves `enrollment_key`, `student_id`, `submit_url`, `project_id`, `region`, `github_org`, and `target_repo` into `.agents/skills/verify-deployment/.assessment_state.json` and automatically reuses them on all subsequent invocations without prompting the student again.
2. **Determine Which Goal to Assess (Sequential Progression Rule)**:
   - **Never re-run validation for an already completed goal** unless the student explicitly requests to re-validate that specific goal (in which case pass `--goal <goal_id> --force`).
   - Once a goal has been validated, evaluate **only the next unvalidated goal** upon the student's request (or omit `--goal` so `verify_environment.py` automatically selects the next uncompleted goal in sequence: `goal-1-target-app-deployment` -> `goal-2-codemender-mcp-deployment` -> `goal-3-enterprise-mcp-connectors` -> `goal-4-hitl-remediation` -> `goal-5-cloud-armor-protection`).

### Step 1: Execute the Goal Verification Script
To verify the next uncompleted goal (automatically reading `~/lab.env` and remembered settings from `.assessment_state.json`):

```bash
python3 .agents/skills/verify-deployment/scripts/verify_environment.py
```

To explicitly specify a goal or provide the Cohort Enrollment Key on the initial run:

```bash
python3 .agents/skills/verify-deployment/scripts/verify_environment.py \
  --goal goal-1-target-app-deployment \
  --student-id "<STUDENT_EMAIL>" \
  --github-org "<GITHUB_USERNAME_OR_ORG>" \
  --submit-url "<WEB_ASSESSOR_URL>/api/v1/submissions" \
  --enrollment-key "<COHORT_ENROLLMENT_KEY>"
```

Optional flags:
- `--goal <GOAL_ID>` (or short alias `1`, `goal-1`, `2`, `goal-2`, `3`, `goal-3`, `4`, `goal-4`, `5`, `goal-5`): Goal identifier (`goal-1-target-app-deployment`, `goal-2-codemender-mcp-deployment`, `goal-3-enterprise-mcp-connectors`, `goal-4-hitl-remediation`, `goal-5-cloud-armor-protection`). If omitted, automatically selects the next uncompleted goal.
- `--force`: Re-run validation for a goal even if it is already marked as completed in `.assessment_state.json`.
- `--list-goals`: Print all registered goals, their completion status, and their steps as JSON and exit.
- `--project-id <GCP_PROJECT_ID>`: Explicitly specify the GCP project ID (auto-detected from `~/lab.env`, `.assessment_state.json`, or `gcloud` if omitted).
- `--region <GCP_REGION>`: Explicitly specify the Cloud Run / NEG region (defaults to `us-central1` or `REGION` in `~/lab.env`).
- `--github-org <GITHUB_OWNER>`: GitHub username or organization hosting `Lab07-CloudRun-Service-Deploy-1` (auto-detected from `~/lab.env`, git remote, BigQuery, or `gh` CLI if omitted).
- `--target-repo <REPO_NAME>`: Target repository name (defaults to `Lab07-CloudRun-Service-Deploy-1`).
- `--student-id <STUDENT_EMAIL_OR_ID>`: Student identifier/email to bind inside the signed JWT and canonical payload (remembered in `.assessment_state.json`).
- `--submit-url <WEB_ASSESSOR_API_URL>`: Directly submit the generated goal report to the Web Assessor endpoint (remembered in `.assessment_state.json`).
- `--enrollment-key <COHORT_KEY>`: Cohort enrollment passcode required when pushing to `--submit-url` (remembered in `.assessment_state.json`, never committed to Git).
- `--output <FILE_PATH>`: Output Markdown path (defaults to `assessment_report_<goal_id>.md` in the repository root).

### Step 2: Verify the Cryptographic Signature Locally (Optional Sanity Check)
After generating the goal report, verify the cryptographic attestation and payload integrity by running:

```bash
python3 .agents/skills/verify-deployment/scripts/verify_report_signature.py assessment_report_goal-1-target-app-deployment.md
```

### Step 3: Present Results to the Student
Summarize the student's score across the goal's steps, confirm whether the goal report was accepted by the Web Assessor (when `--submit-url` was used), highlight any failing checks with actionable remediation guidance (without modifying their environment), and provide a clickable link to the generated `assessment_report_<goal_id>.md` file.
