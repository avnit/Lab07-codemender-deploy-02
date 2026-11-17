---
name: verify-deployment
description: Strictly on-demand verification and assessment skill. Evaluates and grades student completion of incremental goals for [8] Capstone Project ONLY when the student explicitly requests grading, verification, or scoring. NEVER invoke automatically after deployment, terraform, or configuration steps.
---

# [8] Capstone Project - Financial Companion Goal-Based Verification & Assessment Skill (`lab_8`)

Use this skill whenever a student asks to **verify their progress**, **assess/grade a completed lab goal**, or **submit their goal report (`assessment_report_<goal_id>.md`)** for **[8] Capstone Project - Architecting Security & Governance For Financial Companion** (`lab_8`) to the Web Assessor application.

## Lab & Curriculum Association (Lab 8)
- **Target Lab**: `[8] Capstone Project - Architecting Security & Governance For Financial Companion` (`lab_8` / `lab-08-capstone-financial-companion`)
- **Structure**: **Labs contain Goals. Goals contain Steps.**
- Every goal evaluated by this skill (`goal-1-environment-setup`, `goal-2-otel-instrumentation`, `goal-3-agent-identities`, `goal-4-agent-gateway`, `goal-5-agent-evals`, `goal-n-remediate-app-vulnerabilities`) belongs to **Lab 8** and reports under `lab_8` in the Web Assessor Application (WAA).

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
   - **The skill MUST NEVER modify the existing workspace or deployed environment**: The skill can never create, edit, patch, delete, or alter any files, source code, configuration files, terraform definitions, database entries, GCP resources, or cloud infrastructure—even if it detects that a prerequisite or component it is looking for is missing, misconfigured, or failing.
   - If something expected is missing or failing, the skill must simply mark the corresponding check as `FAIL`, assign 0 points, record the diagnostic reason in the assessment report, and exit cleanly without attempting any modification or remediation.

3. **Mandatory Instruction to Antigravity (Zero Automated Remediation During Grading)**:
   - **Antigravity MUST NEVER modify the existing workspace or deployed environment** in case there is something missing that the grading skill is looking for for grading.
   - When requested to verify or grade student progress, Antigravity must execute the grading verification as an objective, hands-off observer. Antigravity is strictly forbidden from "pre-fixing", patching files, deploying infrastructure, creating service accounts, applying terraform, or modifying code before or during the grading process to force checks to pass.
   - If checks fail or resources are missing, Antigravity must strictly report the objective results, score, and failures as reflected in the generated report to the student. Remediation is exclusively the student's task, and Antigravity may only assist in making changes if the student explicitly instructs Antigravity to perform a specific remediation *after* grading has concluded.

4. **Sequential Goal Progression Only (Do Not Re-Validate Completed Goals Unless Requested)**:
   - **Only run a validation for an already executed and completed goal if explicitly requested by the student.**
   - Once a goal has been validated (`PASS` / `100/100`, recorded in `.agents/skills/verify-deployment/.assessment_state.json`), the skill **must only evaluate the next unvalidated goal** upon the student's request (e.g., after Goal 1 is validated, the next evaluation request targets Goal 2).
   - If the student explicitly asks to re-run an already completed goal, pass `--goal <goal_id> --force`. Otherwise, omit `--goal` (or pass the next goal ID) so `verify_environment.py` automatically selects the next uncompleted goal.

5. **Ask for the Cohort Key in the Beginning and Remember It**:
   - At the very beginning (on the first grading/verification request), check `.agents/skills/verify-deployment/.assessment_state.json` (and `ASSESSOR_ENROLLMENT_KEY`).
   - If the **Cohort Enrollment Key** is not yet saved, **ask the student for the Cohort Key upfront** and pass `--enrollment-key "<COHORT_KEY>"` on the first run.
   - `verify_environment.py` automatically persists `enrollment_key` (along with `student_id`, `submit_url`, and `project_id`) in `.agents/skills/verify-deployment/.assessment_state.json` (gitignored) and loads it automatically on all future runs so **you never prompt the user for the Cohort Key again**.

---

## Goal-Based Incremental Assessment Model

Students complete the lab across sequential **Goals** (`goal-1-environment-setup`, `goal-2-otel-instrumentation`, `goal-3-agent-identities`, `goal-4-agent-gateway`, ..., `goal-n-remediate-app-vulnerabilities`).
- Each Goal comprises multiple **Steps** totaling **100 points**.
- Because later goals modify, restrict, or remove resources deployed in earlier goals, **each Goal is verified and submitted independently** as the student completes it.
- The Web Assessor registers each completed Goal in the student's permanent record (`student_goal_grades`, retaining the **highest valid score** per goal if re-submitted) without overwriting or invalidating previously completed goals.

### Registered Lab Goals (`--list-goals`)

#### `goal-1-sample goal` — **Goal 1: "Name of the goal" (25) Points Total)**
1. **Step 1 — Base Infrastructure & Data Layer (25 pts)**
   - **1.1 GCP APIs Enabled (4 pts)**: Verifies `aiplatform`, `sqladmin`, `bigquery`, `storage`, `run`, `secretmanager`, and `modelarmor` APIs are enabled.
   - **1.2 IAM Identity & Secret Manager (4 pts)**: Verifies shared runtime service account `sa-financial-assistant@<project_id>.iam.gserviceaccount.com` and Secret Manager secret `harbor-bank-root-password`.
   - **1.3 Cloud SQL Instance & Database (6 pts)**: Verifies `harbor-bank` (`POSTGRES_16`, `RUNNABLE`, `ALLOW_DATA_API`) and database `harbor_bank`.
   - **1.4 BigQuery Dataset, Extended PII Schema & Seed Data (6 pts)**: Executes live BigQuery queries against `harbor_investments.clients`, `positions`, and `trades` to confirm all 6 seeded clients (`Jordan Hale`, `Amira Sol`, `Marcus Vance`, `Elena Rostova`, `Devon Brooks`, `Priya Nair`), non-null `ssn`, `credit_card`, and `customer_address` columns, and >= 12 portfolio positions.
   - **1.5 Cloud Storage Bucket & Policy Documents (5 pts)**: Verifies bucket `<project_id>-harbor-desk` contains all 12 policy `.txt` objects across the 6 seeded clients.

2. **Step 2 — Vertex AI Agent Engine Deployment (25 pts)**
   - **2.1 `banking_agent` (6 pts)**: Deployed on Vertex AI Reasoning Engine (`us-central1`) with valid A2A card.
   - **2.2 `investment_agent` (6 pts)**: Deployed on Vertex AI Reasoning Engine (`us-central1`) with valid A2A card.
   - **2.3 `insurance_agent` (6 pts)**: Deployed on Vertex AI Reasoning Engine (`us-central1`) with valid A2A card.
   - **2.4 `financial_assistant_agent` (7 pts)**: Root coordinator deployed on Vertex AI Reasoning Engine (`us-central1`) with valid A2A card.

3. **Step 3 — Cloud Run Services & Web Interface (25 pts)**
   - **3.1 `ticker-mcp` Service & Live MCP Tool Call (10 pts)**: Verifies Cloud Run service `ticker-mcp` is `Ready` and responds to a live JSON-RPC `tools/call` (`get_stock_quote`) on `/mcp`.
   - **3.2 `financial-companion-ui` Service, Health & Live Config (10 pts)**: Verifies Cloud Run service `financial-companion-ui` is `Ready`, `/api/health` returns `ok`, and `/api/config` reports `liveMode: true` bound to the deployed `financial_assistant_agent`.

4. **Step 4 — End-to-End Live Multi-Agent Functionality (25 pts)**
   - **4.1 Banking Domain E2E (`banking_agent` + Cloud SQL MCP) (10 pts)**: Sends a live `/api/chat` request for `Jordan Hale` (`4821`), verifies `mode == "vertex_agent_engine"`, `agent == "banking_agent"`, 3-tier A2A/MCP trace hops (`financial_assistant_agent -> banking_agent -> mcp-cloud-sql`), and checks that `CHK-1001842` (`$12,480.22`) and `SAV-1009021` (`$48,210.00`) are returned.
   - **4.2 Investments Domain E2E (`investment_agent` + BigQuery MCP + `ticker-mcp`) (10 pts)**: Sends a live `/api/chat` request for `Marcus Vance` (`6154`), verifies `mode == "vertex_agent_engine"`, `agent == "investment_agent"`, 3-tier A2A/MCP trace hops (`mcp-bigquery` / `mcp-stock-price`), and checks that his BigQuery positions (`GOOGL` 30 shares, `JPM` 20 shares) and live `GOOGL` stock quote (`$188.40`) are returned.
   - **4.3 Insurance Domain E2E (`insurance_agent` + Cloud SQL MCP + GCS MCP) (10 pts)**: Sends a live `/api/chat` request for `Elena Rostova` (`7209`, policy `POL-HOME-4201`), verifies `mode == "vertex_agent_engine"`, `agent == "insurance_agent"`, 3-tier A2A/MCP trace hops (`mcp-cloud-sql` + `mcp-cloud-storage`), and checks that her policy coverage (`$480,000` dwelling, `$134/month`) is returned from GCS after Cloud SQL verification.

---

## Cryptographic Anti-Cheat Attestation

To prevent students from sharing or editing goal reports:
1. The verification script constructs a deterministic **Canonical Assessment JSON Payload** (`financial-companion-assessment/v2`) containing the student's authenticated GCP identity (`oauth2.googleapis.com/tokeninfo`), project ID/number, `goal_id`, `goal_number`, a unique UUIDv4 `submission_id` (`nonce`), timestamp, `step_breakdown`, and every check's detailed evidence, and computes its `SHA-256` digest (`payload_sha256`).
2. Using the student's live GCP credentials, the script dynamically resolves an active project service account (`sa-financial-assistant@...`, `terraform-deployer@...`, or any active `@<project_id>.iam.gserviceaccount.com` so later goals that remove `sa-financial-assistant` continue to work) and calls the **Google Cloud IAM Credentials API** (`:generateIdToken`) with a custom `audience` (`aud`) claim:
   ```text
   https://financial-companion.assessment/v1?project=<project_id>&principal=<principal_email>&student=<student_id>&goal=<goal_id>&lab=<goal_id>&signer=<sa_email>&score=<earned>/<max>&sha256=<payload_sha256>&ts=<unix_timestamp>&nonce=<submission_id>
   ```
3. Google's IAM infrastructure mints an **asymmetric `RS256` OIDC JWT signed by Google's private key** (`iss: https://accounts.google.com`).

---

## How to Run the Verification

### Step 0: Check Remembered Cohort Key & Resolve Next Unvalidated Goal
1. **Ask for the Cohort Key in the Beginning & Remember It**:
   - Inspect `.agents/skills/verify-deployment/.assessment_state.json`.
   - If `enrollment_key` is not yet stored in `.assessment_state.json` (and `ASSESSOR_ENROLLMENT_KEY` is not set), **ask the student in chat for their Cohort Enrollment Key** at the very start before running the script, then pass `--enrollment-key "<COHORT_KEY>"` on that first invocation.
   - Once provided, `verify_environment.py` saves `enrollment_key`, `student_id`, `submit_url`, and `project_id` into `.agents/skills/verify-deployment/.assessment_state.json` and automatically reuses them on all subsequent invocations without prompting the student again.
2. **Determine Which Goal to Assess (Sequential Progression Rule)**:
   - **Never re-run validation for an already completed goal** unless the student explicitly requests to re-validate that specific goal (in which case pass `--goal <goal_id> --force`).
   - Once a goal has been validated, evaluate **only the next unvalidated goal** upon the student's request (or omit `--goal` so `verify_environment.py` automatically selects the next uncompleted goal in sequence: `goal-1-environment-setup` -> `goal-2-otel-instrumentation` -> ... -> `goal-n-remediate-app-vulnerabilities`).

### Step 1: Execute the Goal Verification Script
To verify the next uncompleted goal (automatically using the remembered Cohort Key and submission settings from `.assessment_state.json`):

```bash
python3 .agents/skills/verify-deployment/scripts/verify_environment.py
```

To explicitly specify a goal or provide the Cohort Enrollment Key on the initial run:

```bash
python3 .agents/skills/verify-deployment/scripts/verify_environment.py \
  --goal goal-2-otel-instrumentation \
  --student-id "<STUDENT_EMAIL>" \
  --submit-url "<WEB_ASSESSOR_URL>/api/v1/submissions" \
  --enrollment-key "<COHORT_ENROLLMENT_KEY>"
```

Optional flags:
- `--goal <GOAL_ID>` (or short alias `1`, `goal-1`, `2`, `goal-2`, `3`, `goal-3`, `5`, `goal-5`, `n`, `goal-n`): Goal identifier (`goal-1-environment-setup`, `goal-2-otel-instrumentation`, `goal-3-agent-identities`, `goal-4-agent-gateway`, `goal-5-agent-evals`, `goal-n-remediate-app-vulnerabilities`). If omitted, automatically selects the next uncompleted goal.
- `--force`: Re-run validation for a goal even if it is already marked as completed in `.assessment_state.json`.
- `--list-goals`: Print all registered goals, their completion status, and their steps as JSON and exit.
- `--project-id <GCP_PROJECT_ID>`: Explicitly specify the GCP project ID (auto-detected or loaded from `.assessment_state.json` if omitted).
- `--student-id <STUDENT_EMAIL_OR_ID>`: Student identifier/email to bind inside the signed JWT and canonical payload (remembered in `.assessment_state.json`).
- `--submit-url <WEB_ASSESSOR_API_URL>`: Directly submit the generated goal report to the Web Assessor endpoint (remembered in `.assessment_state.json`).
- `--enrollment-key <COHORT_KEY>`: Cohort enrollment passcode required when pushing to `--submit-url` (remembered in `.assessment_state.json`, never committed to Git).
- `--output <FILE_PATH>`: Output Markdown path (defaults to `assessment_report_<goal_id>.md` in the repository root).

### Step 2: Verify the Cryptographic Signature Locally (Optional Sanity Check)
After generating the goal report, verify the cryptographic attestation and payload integrity by running:

```bash
python3 .agents/skills/verify-deployment/scripts/verify_report_signature.py assessment_report_goal-2-otel-instrumentation.md
```

### Step 3: Present Results to the Student
Summarize the student's score across the goal's steps, confirm whether the goal report was accepted by the Web Assessor (when `--submit-url` was used), highlight any failing checks with actionable remediation steps, and provide a clickable link to the generated `assessment_report_<goal_id>.md` file.
