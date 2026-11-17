#!/usr/bin/env python3
"""
Financial Companion — Student Progress & Deployment Verification Script

Verifies the 4 core assessment pillars:
  1. Base Infrastructure & Data Layer (APIs, IAM, Secret Manager, Cloud SQL, BigQuery, GCS)
  2. Vertex AI Agent Engine Deployment (banking, investment, insurance, financial_assistant)
  3. Cloud Run Services & Web Interface (ticker-mcp, financial-companion-ui)
  4. End-to-End Live Multi-Agent Functionality (Banking, Investments, Insurance via A2A + MCP)

Cryptographically binds the student's GCP identity, project ID, timestamp, and exact check
results (SHA-256 of canonical evidence JSON) by minting a Google-signed RS256 OIDC ID token
via the IAM Credentials API (generateIdToken), and outputs `assessment_report.md`.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid


# ============================================================================
# LAB ASSOCIATION & METADATA (MANDATORY LAB MAPPING)
# ============================================================================
LAB_METADATA: Dict[str, Any] = {
    "lab_id": "lab_8",
    "lab_number": 8,
    "cli_lab_id": "lab-08-capstone-financial-companion",
    "title": "Capstone Project - Architecting Security & Governance For Financial Companion",
    "short_title": "Lab 8: Capstone Project - Architecting Security & Governance For Financial Companion",
    "max_points": 100,
    "passing_score": 85,
    "passing_percentage": 85,
}


GOAL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "goal-1-environment-setup": {
        "goal_id": "goal-1-environment-setup",
        "goal_number": 1,
        "title": "Goal 1: Baseline Agentic Environment Setup",
        "description": "Deploy the base GCP data layer, 4 Vertex AI Reasoning Engine ADK agents, Cloud Run services, and verify live A2A/MCP multi-agent execution.",
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: Base Infrastructure & Data Layer",
                "pillar": "Pillar 1: Base Infrastructure & Data Layer",
                "max_points": 25,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: Vertex AI Agent Engine Deployment",
                "pillar": "Pillar 2: Vertex AI Agent Engine Deployment",
                "max_points": 25,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Cloud Run Services & Web Interface",
                "pillar": "Pillar 3: Cloud Run Services & Web Interface",
                "max_points": 20,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: End-to-End Live Multi-Agent Functionality",
                "pillar": "Pillar 4: End-to-End Live Multi-Agent Functionality",
                "max_points": 30,
            },
        ],
    },
    "goal-2-otel-instrumentation": {
        "goal_id": "goal-2-otel-instrumentation",
        "goal_number": 2,
        "title": "Goal 2: Instrumentation of GCP OpenTelemetry traces, logs and metrics for all 4 agents",
        "description": "Enable and verify GCP OpenTelemetry traces, logs, and metrics instrumentation across all 4 Vertex AI Reasoning Engine ADK agents via environment variables and IAM telemetry roles.",
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: OpenTelemetry APIs & Service Account Telemetry IAM Roles",
                "pillar": "Pillar 1: OpenTelemetry APIs & Service Account Telemetry IAM Roles",
                "max_points": 20,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: OpenTelemetry Environment Variables on All 4 Agents",
                "pillar": "Pillar 2: OpenTelemetry Environment Variables on All 4 Agents",
                "max_points": 30,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Live OpenTelemetry Traces & Logs Export Across All 4 Agents",
                "pillar": "Pillar 3: Live OpenTelemetry Traces & Logs Export Across All 4 Agents",
                "max_points": 25,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Live OpenTelemetry Metrics Export Across All 4 Agents",
                "pillar": "Pillar 4: Live OpenTelemetry Metrics Export Across All 4 Agents",
                "max_points": 25,
            },
        ],
    },
    "goal-3-agent-identities": {
        "goal_id": "goal-3-agent-identities",
        "goal_number": 3,
        "title": "Goal 3: Per-Agent Identities & Least-Privilege IAM",
        "description": "Replace the shared service account with dedicated per-agent identities and verify least-privilege IAM configuration across all 4 Vertex AI reasoning engines.",
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: Vertex AI Agent Identity Provisioning on All 4 Engines",
                "pillar": "Pillar 1: Vertex AI Agent Identity Provisioning on All 4 Engines",
                "max_points": 30,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: Terraform Infrastructure Definition & IaC Conformance",
                "pillar": "Pillar 2: Terraform Infrastructure Definition & IaC Conformance",
                "max_points": 20,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Shared Service Account Elimination at Runtime",
                "pillar": "Pillar 3: Shared Service Account Elimination at Runtime",
                "max_points": 25,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Agent Identity Deployment Health & Runtime Inspection",
                "pillar": "Pillar 4: Agent Identity Deployment Health & Runtime Inspection",
                "max_points": 25,
            },
        ],
    },
    "goal-4-agent-gateway": {
        "goal_id": "goal-4-agent-gateway",
        "goal_number": 4,
        "title": "Goal 4: Agent Gateway, Model Armor & PII Guardrails",
        "description": "Enforce Agent Gateway controls, Model Armor prompt/response filtering, PII masking, and authorization checks across A2A and MCP.",
        "max_points": 100,
        "implemented": False,
        "steps": [],
    },
    "goal-5-agent-evals": {
        "goal_id": "goal-5-agent-evals",
        "goal_number": 5,
        "title": "Goal 5: Automated Agent Security Profiling & Regression Evaluation",
        "description": "Execute automated multi-agent evaluations using Vertex AI Gemini as a judge to profile initial security vulnerabilities (Confused Deputy, cross-client PII leakage, IDOR), verify post-hardening remediation, and guarantee zero functional regressions.",
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: Evaluation Suite & Dataset Verification",
                "pillar": "Pillar 1: Evaluation Suite & Dataset Verification",
                "max_points": 20,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: Pre-Hardening Baseline Evaluation Artifact",
                "pillar": "Pillar 2: Pre-Hardening Baseline Evaluation Artifact",
                "max_points": 25,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Post-Hardening Evaluation & Security Uplift",
                "pillar": "Pillar 3: Post-Hardening Evaluation & Security Uplift",
                "max_points": 40,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Zero-Regression Functional Guarantee",
                "pillar": "Pillar 4: Zero-Regression Functional Guarantee",
                "max_points": 15,
            },
        ],
    },
    "goal-n-remediate-app-vulnerabilities": {
        "goal_id": "goal-n-remediate-app-vulnerabilities",
        "goal_number": "N",
        "title": "Goal N: Remediate Application Vulnerabilities (SAST)",
        "description": "Detect and remediate Critical static application security testing (SAST) vulnerabilities across web_ui/static/app.js and web_ui/server.py without breaking Web UI functionality.",
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: Frontend Code Injection (eval) & DOM XSS Remediation in web_ui/static/app.js (CWE-95 / CWE-79)",
                "pillar": "Pillar 1: Frontend Code Injection (eval) & DOM XSS Remediation in web_ui/static/app.js (CWE-95 / CWE-79)",
                "max_points": 30,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: Hardcoded Master API Key, JWT Secret & Admin Header Bypass Remediation (CWE-798 / CWE-287 / CWE-312)",
                "pillar": "Pillar 2: Hardcoded Master API Key, JWT Secret & Admin Header Bypass Remediation (CWE-798 / CWE-287 / CWE-312)",
                "max_points": 30,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Backend SQL Injection Remediation in web_ui/server.py (CWE-89)",
                "pillar": "Pillar 3: Backend SQL Injection Remediation in web_ui/server.py (CWE-89)",
                "max_points": 30,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Web UI Functional Integrity & Regression Verification",
                "pillar": "Pillar 4: Web UI Functional Integrity & Regression Verification",
                "max_points": 10,
            },
        ],
    },
}

# Backward-compatible alias map for `--lab` or short goal names
GOAL_ALIASES: Dict[str, str] = {
    "1": "goal-1-environment-setup",
    "goal-1": "goal-1-environment-setup",
    "lab1-baseline": "goal-1-environment-setup",
    "2": "goal-2-otel-instrumentation",
    "goal-2": "goal-2-otel-instrumentation",
    "goal-2-observability": "goal-2-otel-instrumentation",
    "goal-2-otel": "goal-2-otel-instrumentation",
    "lab2-observability": "goal-2-otel-instrumentation",
    "otel": "goal-2-otel-instrumentation",
    "observability": "goal-2-otel-instrumentation",
    "goal-4-observability": "goal-2-otel-instrumentation",
    "3": "goal-3-agent-identities",
    "goal-3": "goal-3-agent-identities",
    "goal-2-agent-identities": "goal-3-agent-identities",
    "lab3-identities": "goal-3-agent-identities",
    "4": "goal-4-agent-gateway",
    "goal-4": "goal-4-agent-gateway",
    "goal-3-agent-gateway": "goal-4-agent-gateway",
    "lab4-gateway": "goal-4-agent-gateway",
    "n": "goal-n-remediate-app-vulnerabilities",
    "N": "goal-n-remediate-app-vulnerabilities",
    "goal-n": "goal-n-remediate-app-vulnerabilities",
    "goal-N": "goal-n-remediate-app-vulnerabilities",
    "goal-n-web-sast-remediation": "goal-n-remediate-app-vulnerabilities",
    "5": "goal-5-agent-evals",
    "goal-5": "goal-5-agent-evals",
    "goal-5-agent-evals": "goal-5-agent-evals",
    "goal-5-evals": "goal-5-agent-evals",
    "evals": "goal-5-agent-evals",
    "eval": "goal-5-agent-evals",
    "agent-evals": "goal-5-agent-evals",
    "goal-5-remediate-app-vulnerabilities": "goal-n-remediate-app-vulnerabilities",
    "goal-5-web-sast-remediation": "goal-n-remediate-app-vulnerabilities",
    "sast": "goal-n-remediate-app-vulnerabilities",
    "web-sast": "goal-n-remediate-app-vulnerabilities",
}


def _build_ssl_context() -> ssl.SSLContext:
    """Builds a verified TLS context compatible with macOS Python and Linux."""
    cafile = os.environ.get("SSL_CERT_FILE", "")
    if not cafile or not Path(cafile).is_file():
        if Path("/etc/ssl/cert.pem").is_file():
            cafile = "/etc/ssl/cert.pem"
        else:
            try:
                import certifi  # type: ignore
                cafile = certifi.where()
            except Exception:
                cafile = ""
    if cafile:
        return ssl.create_default_context(cafile=cafile)
    return ssl.create_default_context()


_SSL_CTX = _build_ssl_context()


EXPECTED_APIS = [
    "aiplatform.googleapis.com",
    "sqladmin.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "modelarmor.googleapis.com",
]

EXPECTED_CLIENTS = [
    "Jordan Hale",
    "Amira Sol",
    "Marcus Vance",
    "Elena Rostova",
    "Devon Brooks",
    "Priya Nair",
]

EXPECTED_POLICIES = [
    "policies/amira-sol/POL-RENTERS-5510.txt",
    "policies/devon-brooks/POL-AUTO-5188.txt",
    "policies/devon-brooks/POL-RENTERS-5102.txt",
    "policies/elena-rostova/POL-HOME-4201.txt",
    "policies/elena-rostova/POL-LIFE-4295.txt",
    "policies/jordan-hale/POL-AUTO-8821.txt",
    "policies/jordan-hale/POL-HOME-1044.txt",
    "policies/jordan-hale/POL-LIFE-3002.txt",
    "policies/marcus-vance/POL-AUTO-3190.txt",
    "policies/marcus-vance/POL-HOME-3108.txt",
    "policies/priya-nair/POL-HOME-6401.txt",
    "policies/priya-nair/POL-LIFE-6480.txt",
]

EXPECTED_AGENTS = [
    "banking_agent",
    "investment_agent",
    "insurance_agent",
    "financial_assistant_agent",
]


def _run_cmd(args: List[str], cwd: Optional[Path] = None, timeout: int = 30) -> Tuple[int, str, str]:
    """Safely executes an allow-listed CLI binary without shell=True."""
    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def _http_json(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
    timeout: int = 90,
) -> Tuple[int, Any, str]:
    """Performs an HTTPS JSON request using standard library urllib."""
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    data_bytes = None
    if body is not None:
        data_bytes = json.dumps(body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url=url, data=data_bytes, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return resp.status, None, raw
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace") if err.fp else str(err)
        try:
            return err.code, json.loads(raw), raw
        except json.JSONDecodeError:
            return err.code, None, raw
    except Exception as exc:
        return 0, None, str(exc)


def _decode_jwt_unverified(jwt_token: str) -> Dict[str, Any]:
    """Decodes JWT header and payload without modifying or stripping signature."""
    parts = jwt_token.split(".")
    if len(parts) != 3:
        return {}

    def _b64_decode(segment: str) -> Dict[str, Any]:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(raw.decode("utf-8"))

    try:
        return {
            "header": _b64_decode(parts[0]),
            "payload": _b64_decode(parts[1]),
        }
    except Exception:
        return {}


def get_access_token() -> Tuple[str, str]:
    """Retrieves an active GCP OAuth2 access token and reports its source."""
    for env_key in ("GCP_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"):
        env_token = os.environ.get(env_key, "").strip()
        if env_token:
            return env_token, f"env:{env_key}"

    token_file = os.environ.get("CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "").strip()
    if not token_file and Path("/tmp/gcp_12h_token.txt").is_file():
        token_file = "/tmp/gcp_12h_token.txt"

    if token_file and Path(token_file).is_file():
        token_val = Path(token_file).read_text(encoding="utf-8").strip()
        if token_val:
            return token_val, f"file:{token_file}"

    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        rc, out, _ = _run_cmd([gcloud_bin, "auth", "print-access-token"])
        if rc == 0 and out:
            return out.splitlines()[-1].strip(), "gcloud:print-access-token"

    raise RuntimeError(
        "Unable to obtain a GCP access token. Authenticate with `gcloud auth login` "
        "or set `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`."
    )


def resolve_project_id(explicit_project: Optional[str], repo_root: Path) -> str:
    """Resolves the target GCP project ID from CLI flag, env, terraform state, or gcloud."""
    if explicit_project:
        return explicit_project.strip()

    for env_key in ("GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "CLOUDSDK_CORE_PROJECT"):
        val = os.environ.get(env_key, "").strip()
        if val:
            return val

    tf_state = repo_root / "terraform" / "terraform.tfstate"
    if tf_state.is_file():
        try:
            state_data = json.loads(tf_state.read_text(encoding="utf-8"))
            outputs = state_data.get("outputs", {})
            proj_val = outputs.get("project_id", {}).get("value")
            if proj_val:
                return str(proj_val).strip()
            sa_val = str(outputs.get("service_account", {}).get("value", ""))
            m_sa = re.search(r"@([a-z0-9\-]+)\.iam\.gserviceaccount\.com", sa_val)
            if m_sa:
                return m_sa.group(1)
            fa_val = str(outputs.get("financial_assistant_agent", {}).get("value", ""))
            m_fa = re.search(r"projects/([a-z0-9\-]+)/locations/", fa_val)
            if m_fa:
                return m_fa.group(1)
        except Exception:
            pass

    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        rc, out, _ = _run_cmd([gcloud_bin, "config", "get-value", "project"])
        if rc == 0 and out and out != "(unset)":
            return out.splitlines()[-1].strip()

    raise RuntimeError("Could not resolve GCP project ID. Pass `--project-id <PROJECT_ID>`.")


def resolve_student_identity(
    access_token: str,
    project_id: str,
    auth_headers: Dict[str, str],
    explicit_student_id: Optional[str],
) -> Dict[str, Any]:
    """Resolves and verifies the authenticated GCP identity via Google OAuth2 tokeninfo & IAM."""
    url = f"https://oauth2.googleapis.com/tokeninfo?access_token={urllib.parse.quote(access_token)}"
    status, data, _ = _http_json(url)
    token_email = ""
    token_sub = ""
    token_azp = ""
    expires_in = 0
    if status == 200 and isinstance(data, dict):
        token_email = str(data.get("email", ""))
        token_sub = str(data.get("sub", ""))
        token_azp = str(data.get("azp", ""))
        try:
            expires_in = int(data.get("expires_in", 0))
        except (TypeError, ValueError):
            expires_in = 0

    # If the token is a service account access token without email scope, resolve azp via IAM
    if not token_email and token_azp:
        sa_url = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{urllib.parse.quote(token_azp)}"
        st_sa, data_sa, _ = _http_json(sa_url, headers=auth_headers)
        if st_sa == 200 and isinstance(data_sa, dict) and data_sa.get("email"):
            token_email = str(data_sa["email"])
            if not token_sub:
                token_sub = str(data_sa.get("uniqueId", token_azp))

    gcloud_account = ""
    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        rc, out, _ = _run_cmd([gcloud_bin, "config", "get-value", "account"])
        if rc == 0 and out and out != "(unset)":
            gcloud_account = out.splitlines()[-1].strip()

    student_id = (
        explicit_student_id
        or os.environ.get("STUDENT_ID", "").strip()
        or gcloud_account
        or token_email
        or f"sub:{token_sub or token_azp}"
    )

    return {
        "student_id": student_id,
        "authenticated_principal_email": token_email or gcloud_account or "unknown",
        "authenticated_principal_sub": token_sub or token_azp or "unknown",
        "authorized_party_azp": token_azp or "unknown",
        "gcloud_config_account": gcloud_account or "unknown",
        "token_expires_in_seconds": expires_in,
    }


def get_project_metadata(project_id: str, auth_headers: Dict[str, str]) -> Dict[str, Any]:
    """Fetches project number and lifecycle state from Cloud Resource Manager API."""
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{urllib.parse.quote(project_id)}"
    status, data, _ = _http_json(url, headers=auth_headers)
    if status == 200 and isinstance(data, dict):
        return {
            "project_id": data.get("projectId", project_id),
            "project_number": str(data.get("projectNumber", "")),
            "name": data.get("name", project_id),
            "lifecycle_state": data.get("lifecycleState", "UNKNOWN"),
        }
    return {
        "project_id": project_id,
        "project_number": "unknown",
        "name": project_id,
        "lifecycle_state": "UNKNOWN",
    }


def make_check(
    check_id: str,
    pillar: str,
    title: str,
    passed: bool,
    max_points: int,
    earned_points: int,
    summary: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    step_num = check_id.split(".")[0] if "." in check_id else "1"
    step_id = f"step-{step_num}"
    step_title = pillar.replace(f"Pillar {step_num}:", f"Step {step_num}:")
    return {
        "check_id": check_id,
        "step_id": step_id,
        "step": step_title,
        "pillar": pillar,
        "title": title,
        "status": "PASS" if passed else "FAIL",
        "passed": bool(passed),
        "max_points": max_points,
        "earned_points": earned_points if passed else max(0, earned_points),
        "summary": summary,
        "evidence": evidence,
    }


def run_pillar_1_checks(project_id: str, auth_headers: Dict[str, str]) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    pillar_name = "Pillar 1: Base Infrastructure & Data Layer"

    # Check 1.1: Required GCP APIs Enabled (4 pts)
    url_apis = (
        f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services"
        f"?filter=state:ENABLED&pageSize=200"
    )
    st, data, raw = _http_json(url_apis, headers=auth_headers)
    enabled_apis = set()
    if st == 200 and isinstance(data, dict):
        for svc in data.get("services", []):
            name = svc.get("config", {}).get("name") or svc.get("name", "").split("/")[-1]
            if name:
                enabled_apis.add(name)
    missing_apis = [api for api in EXPECTED_APIS if api not in enabled_apis]
    apis_ok = st == 200 and len(missing_apis) == 0
    checks.append(
        make_check(
            check_id="1.1",
            pillar=pillar_name,
            title="Required GCP APIs Enabled",
            passed=apis_ok,
            max_points=4,
            earned_points=4 if apis_ok else 0,
            summary=(
                f"All {len(EXPECTED_APIS)} core GCP APIs are ENABLED."
                if apis_ok
                else f"Missing or disabled APIs: {missing_apis} (HTTP {st})"
            ),
            evidence={
                "required_apis": EXPECTED_APIS,
                "missing_apis": missing_apis,
                "enabled_count": len(enabled_apis),
            },
        )
    )

    # Check 1.2: Shared Runtime Service Account & Secret Manager (4 pts)
    sa_email = f"sa-financial-assistant@{project_id}.iam.gserviceaccount.com"
    url_sa = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{urllib.parse.quote(sa_email)}"
    st_sa, data_sa, _ = _http_json(url_sa, headers=auth_headers)
    sa_ok = st_sa == 200 and isinstance(data_sa, dict) and not data_sa.get("disabled", False)

    url_sec_reg = (
        f"https://secretmanager.us-central1.rep.googleapis.com/v1/projects/{project_id}"
        f"/locations/us-central1/secrets/harbor-bank-root-password/versions/latest"
    )
    st_sec, data_sec, _ = _http_json(url_sec_reg, headers=auth_headers)
    if st_sec != 200:
        url_sec_global = (
            f"https://secretmanager.googleapis.com/v1/projects/{project_id}"
            f"/secrets/harbor-bank-root-password/versions/latest"
        )
        st_sec, data_sec, _ = _http_json(url_sec_global, headers=auth_headers)
    sec_ok = st_sec == 200 and isinstance(data_sec, dict) and data_sec.get("state") == "ENABLED"

    both_ok = sa_ok and sec_ok
    checks.append(
        make_check(
            check_id="1.2",
            pillar=pillar_name,
            title="Shared Runtime Service Account & Secret Manager Secret",
            passed=both_ok,
            max_points=4,
            earned_points=4 if both_ok else (2 if (sa_ok or sec_ok) else 0),
            summary=(
                f"Service account `{sa_email}` is active and secret `harbor-bank-root-password` is ENABLED."
                if both_ok
                else f"SA active={sa_ok} (HTTP {st_sa}), Secret ENABLED={sec_ok} (HTTP {st_sec})."
            ),
            evidence={
                "service_account_email": sa_email,
                "service_account_unique_id": data_sa.get("uniqueId", "") if isinstance(data_sa, dict) else "",
                "secret_version_name": data_sec.get("name", "") if isinstance(data_sec, dict) else "",
                "secret_state": data_sec.get("state", "") if isinstance(data_sec, dict) else "",
            },
        )
    )

    # Check 1.3: Cloud SQL Instance & Database (6 pts)
    url_sql = f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project_id}/instances/harbor-bank"
    st_sql, data_sql, _ = _http_json(url_sql, headers=auth_headers)
    sql_state = data_sql.get("state", "") if isinstance(data_sql, dict) else ""
    sql_version = data_sql.get("databaseVersion", "") if isinstance(data_sql, dict) else ""
    data_api_access = (
        data_sql.get("settings", {}).get("dataApiAccess", "") if isinstance(data_sql, dict) else ""
    )

    url_db = (
        f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project_id}"
        f"/instances/harbor-bank/databases/harbor_bank"
    )
    st_db, data_db, _ = _http_json(url_db, headers=auth_headers)
    sql_ok = (
        st_sql == 200
        and sql_state == "RUNNABLE"
        and data_api_access == "ALLOW_DATA_API"
        and st_db == 200
    )
    checks.append(
        make_check(
            check_id="1.3",
            pillar=pillar_name,
            title="Cloud SQL Instance (`harbor-bank`) & Database (`harbor_bank`)",
            passed=sql_ok,
            max_points=6,
            earned_points=6 if sql_ok else 0,
            summary=(
                f"Cloud SQL `harbor-bank` ({sql_version}) is {sql_state} with `{data_api_access}` and database `harbor_bank`."
                if sql_ok
                else f"Cloud SQL state={sql_state}, dataApiAccess={data_api_access}, db HTTP={st_db}."
            ),
            evidence={
                "instance_name": "harbor-bank",
                "state": sql_state,
                "database_version": sql_version,
                "data_api_access": data_api_access,
                "database_name": data_db.get("name", "") if isinstance(data_db, dict) else "",
            },
        )
    )

    # Check 1.4: BigQuery Dataset, Extended PII Schema & Seed Data (6 pts)
    url_bq = f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/queries"
    bq_sql = (
        f"SELECT name, ssn, credit_card, customer_address "
        f"FROM `{project_id}.harbor_investments.clients` ORDER BY client_id"
    )
    st_bq, data_bq, _ = _http_json(
        url_bq,
        method="POST",
        headers=auth_headers,
        body={"query": bq_sql, "useLegacySql": False},
    )
    bq_clients: List[Dict[str, Any]] = []
    if st_bq == 200 and isinstance(data_bq, dict):
        for row in data_bq.get("rows", []):
            vals = [cell.get("v") for cell in row.get("f", [])]
            if len(vals) >= 4:
                bq_clients.append(
                    {
                        "full_name": str(vals[0] or ""),
                        "has_full_ssn": bool(vals[1] and len(str(vals[1])) >= 11),
                        "has_credit_card": bool(vals[2] and len(str(vals[2])) >= 13),
                        "has_customer_address": bool(vals[3] and len(str(vals[3])) >= 10),
                    }
                )

    st_pos, data_pos, _ = _http_json(
        url_bq,
        method="POST",
        headers=auth_headers,
        body={
            "query": f"SELECT COUNT(*) FROM `{project_id}.harbor_investments.positions`",
            "useLegacySql": False,
        },
    )
    positions_count = 0
    if st_pos == 200 and isinstance(data_pos, dict):
        rows = data_pos.get("rows", [])
        if rows:
            positions_count = int(rows[0].get("f", [{}])[0].get("v", 0))

    found_names = [c["full_name"] for c in bq_clients]
    all_clients_present = all(name in found_names for name in EXPECTED_CLIENTS)
    all_pii_populated = len(bq_clients) >= 6 and all(
        c["has_full_ssn"] and c["has_credit_card"] and c["has_customer_address"] for c in bq_clients
    )
    bq_ok = all_clients_present and all_pii_populated and positions_count >= 13
    checks.append(
        make_check(
            check_id="1.4",
            pillar=pillar_name,
            title="BigQuery Dataset (`harbor_investments`), PII Columns & Seeded Clients",
            passed=bq_ok,
            max_points=6,
            earned_points=6 if bq_ok else 0,
            summary=(
                f"BigQuery `harbor_investments` contains all {len(bq_clients)} clients with populated `ssn`, `credit_card`, and `customer_address`, plus {positions_count} portfolio positions."
                if bq_ok
                else f"BigQuery clients={found_names}, all_pii_populated={all_pii_populated}, positions={positions_count}."
            ),
            evidence={
                "client_count": len(bq_clients),
                "client_names": found_names,
                "all_pii_columns_populated": all_pii_populated,
                "positions_count": positions_count,
            },
        )
    )

    # Check 1.5: Cloud Storage Bucket & Policy Documents (5 pts)
    bucket_name = f"{project_id}-harbor-desk"
    url_gcs = f"https://storage.googleapis.com/storage/v1/b/{urllib.parse.quote(bucket_name)}/o?prefix=policies/"
    st_gcs, data_gcs, _ = _http_json(url_gcs, headers=auth_headers)
    found_objects = []
    if st_gcs == 200 and isinstance(data_gcs, dict):
        found_objects = sorted(item.get("name", "") for item in data_gcs.get("items", []))
    missing_policies = [p for p in EXPECTED_POLICIES if p not in found_objects]
    gcs_ok = st_gcs == 200 and len(missing_policies) == 0
    checks.append(
        make_check(
            check_id="1.5",
            pillar=pillar_name,
            title="Cloud Storage Bucket & 12 Seeded Insurance Policy Files",
            passed=gcs_ok,
            max_points=5,
            earned_points=5 if gcs_ok else 0,
            summary=(
                f"Bucket `gs://{bucket_name}` exists and contains all {len(EXPECTED_POLICIES)} policy `.txt` files."
                if gcs_ok
                else f"Bucket `gs://{bucket_name}` missing policies: {missing_policies} (HTTP {st_gcs})."
            ),
            evidence={
                "bucket": bucket_name,
                "object_count": len(found_objects),
                "objects": found_objects,
                "missing_policies": missing_policies,
            },
        )
    )

    return checks


def run_pillar_2_checks(
    project_id: str, auth_headers: Dict[str, str]
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    checks: List[Dict[str, Any]] = []
    pillar_name = "Pillar 2: Vertex AI Agent Engine Deployment"
    url_re = (
        f"https://us-central1-aiplatform.googleapis.com/v1beta1/projects/{project_id}"
        f"/locations/us-central1/reasoningEngines"
    )
    st, data, _ = _http_json(url_re, headers=auth_headers)
    engines_by_name: Dict[str, Dict[str, Any]] = {}
    if st == 200 and isinstance(data, dict):
        for eng in data.get("reasoningEngines", []):
            disp = eng.get("displayName", "")
            # Keep the most recently updated engine if duplicates exist
            if disp and disp not in engines_by_name:
                engines_by_name[disp] = eng

    agent_specs = [
        ("2.1", "banking_agent", 6, "Banking Specialist ADK Reasoning Engine"),
        ("2.2", "investment_agent", 6, "Investment Specialist ADK Reasoning Engine"),
        ("2.3", "insurance_agent", 6, "Insurance Specialist ADK Reasoning Engine"),
        ("2.4", "financial_assistant_agent", 7, "Root Coordinator ADK Reasoning Engine"),
    ]

    resource_names: Dict[str, str] = {}
    for check_id, agent_name, pts, label in agent_specs:
        eng = engines_by_name.get(agent_name)
        if eng:
            res_name = eng.get("name", "")
            resource_names[agent_name] = res_name
            spec = eng.get("spec", {})
            eff_id = spec.get("effectiveIdentity", "") or spec.get("serviceAccount", "")
            # Agents serve their A2A card from the agents-cli scaffold's route on the engine.
            card_url = (
                f"https://us-central1-aiplatform.googleapis.com/reasoningEngines/v1/{res_name}"
                "/api/a2a/app/.well-known/agent-card.json"
            )
            card_st, agent_card, _ = _http_json(card_url, headers=auth_headers, timeout=180)
            if card_st != 200 or not isinstance(agent_card, dict):
                agent_card = {}
            interfaces = agent_card.get("supportedInterfaces") or []
            a2a_ext_methods = [
                str(i.get("protocolBinding", "")) for i in interfaces if isinstance(i, dict)
            ]
            env_vars = {
                e.get("name", ""): e.get("value", "")
                for e in spec.get("deploymentSpec", {}).get("env", [])
                if isinstance(e, dict) and e.get("name")
            }
            has_a2a_card = agent_card.get("name") == agent_name
            passed = bool(res_name and has_a2a_card and eff_id)
            checks.append(
                make_check(
                    check_id=check_id,
                    pillar=pillar_name,
                    title=f"`{agent_name}` ({label})",
                    passed=passed,
                    max_points=pts,
                    earned_points=pts if passed else 0,
                    summary=(
                        f"`{agent_name}` deployed at `{res_name}` with A2A card (`{', '.join(sorted(set(a2a_ext_methods))) or 'JSONRPC'}`) and identity `{eff_id}`."
                        if passed
                        else f"`{agent_name}` found at `{res_name}` but missing A2A card metadata."
                    ),
                    evidence={
                        "display_name": agent_name,
                        "resource_name": res_name,
                        "effective_identity": eff_id,
                        "has_agent_card": has_a2a_card,
                        "a2a_extension_methods": a2a_ext_methods,
                        "google_cloud_location": env_vars.get("GOOGLE_CLOUD_LOCATION", ""),
                        "a2a_url": card_url,
                        "create_time": eng.get("createTime", ""),
                        "update_time": eng.get("updateTime", ""),
                    },
                )
            )
        else:
            checks.append(
                make_check(
                    check_id=check_id,
                    pillar=pillar_name,
                    title=f"`{agent_name}` ({label})",
                    passed=False,
                    max_points=pts,
                    earned_points=0,
                    summary=f"`{agent_name}` Reasoning Engine not found in `us-central1`.",
                    evidence={"display_name": agent_name, "found": False},
                )
            )

    return checks, resource_names


def run_pillar_3_checks(
    project_id: str, auth_headers: Dict[str, str]
) -> Tuple[List[Dict[str, Any]], str, str]:
    checks: List[Dict[str, Any]] = []
    pillar_name = "Pillar 3: Cloud Run Services & Web Interface"

    url_run = f"https://run.googleapis.com/v2/projects/{project_id}/locations/us-central1/services"
    st_run, data_run, _ = _http_json(url_run, headers=auth_headers)
    services_by_short_name: Dict[str, Dict[str, Any]] = {}
    if st_run == 200 and isinstance(data_run, dict):
        for svc in data_run.get("services", []):
            short_name = svc.get("name", "").split("/")[-1]
            services_by_short_name[short_name] = svc

    # Check 3.1: ticker-mcp Cloud Run service & live MCP tool call (10 pts)
    ticker_svc = services_by_short_name.get("ticker-mcp", {})
    ticker_uri = ticker_svc.get("uri", "")
    ticker_mcp_url = f"{ticker_uri}/mcp" if ticker_uri else ""
    mcp_quote_ok = False
    mcp_quote_resp: Any = None
    if ticker_mcp_url:
        st_mcp, data_mcp, raw_mcp = _http_json(
            ticker_mcp_url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            body={
                "jsonrpc": "2.0",
                "id": "verify-1",
                "method": "tools/call",
                "params": {"name": "get_stock_quote", "arguments": {"query": "GOOGL"}},
            },
        )
        mcp_quote_resp = data_mcp if data_mcp is not None else raw_mcp[:300]
        mcp_quote_ok = st_mcp == 200 and ("GOOGL" in raw_mcp and "price_cents" in raw_mcp)

    checks.append(
        make_check(
            check_id="3.1",
            pillar=pillar_name,
            title="Cloud Run `ticker-mcp` Service & Live MCP `get_stock_quote` Call",
            passed=mcp_quote_ok,
            max_points=10,
            earned_points=10 if mcp_quote_ok else (5 if ticker_uri else 0),
            summary=(
                f"`ticker-mcp` is live at `{ticker_mcp_url}` and returned a valid real-time `GOOGL` quote."
                if mcp_quote_ok
                else f"`ticker-mcp` URI=`{ticker_uri}`, live quote test passed={mcp_quote_ok}."
            ),
            evidence={
                "service_uri": ticker_uri,
                "mcp_endpoint": ticker_mcp_url,
                "latest_ready_revision": ticker_svc.get("latestReadyRevision", ""),
                "sample_quote_response": mcp_quote_resp,
            },
        )
    )

    # Check 3.2: financial-companion-ui Cloud Run service, /api/health & /api/config (10 pts)
    ui_svc = services_by_short_name.get("financial-companion-ui", {})
    ui_uri = ui_svc.get("uri", "")
    health_ok = False
    config_ok = False
    config_data: Dict[str, Any] = {}
    if ui_uri:
        st_h, data_h, _ = _http_json(f"{ui_uri}/api/health")
        health_ok = st_h == 200 and isinstance(data_h, dict) and data_h.get("status") == "ok"
        st_c, data_c, _ = _http_json(f"{ui_uri}/api/config")
        if st_c == 200 and isinstance(data_c, dict):
            config_data = data_c
            res_field = str(
                data_c.get("vertexResourceName") or data_c.get("rootAgentResourceName") or ""
            )
            config_ok = bool(
                data_c.get("liveMode") is True
                and data_c.get("projectId") == project_id
                and "reasoningEngines/" in res_field
            )

    ui_passed = health_ok and config_ok
    checks.append(
        make_check(
            check_id="3.2",
            pillar=pillar_name,
            title="Cloud Run `financial-companion-ui` Web Interface, Health & Live Config",
            passed=ui_passed,
            max_points=10,
            earned_points=10 if ui_passed else (5 if health_ok else 0),
            summary=(
                f"`financial-companion-ui` is live at `{ui_uri}` (`liveMode=True`, bound to `{config_data.get('vertexResourceName', '')}`)."
                if ui_passed
                else f"Web UI URI=`{ui_uri}`, health_ok={health_ok}, config_ok={config_ok}."
            ),
            evidence={
                "service_uri": ui_uri,
                "latest_ready_revision": ui_svc.get("latestReadyRevision", ""),
                "health_ok": health_ok,
                "config": config_data,
            },
        )
    )

    return checks, ticker_mcp_url, ui_uri


def _extract_reply_text(data: Dict[str, Any]) -> str:
    if isinstance(data.get("reply"), str) and data["reply"].strip():
        return data["reply"].strip()
    blocks = data.get("blocks", [])
    if isinstance(blocks, list):
        parts = [str(b.get("text", "")).strip() for b in blocks if isinstance(b, dict) and b.get("text")]
        if parts:
            return "\n\n".join(parts)
    return ""


def _call_chat_with_retry(
    ui_uri: str, message: str, user_id: str, retries: int = 2
) -> Tuple[int, Dict[str, Any], str, float]:
    """Calls POST /api/chat on the deployed Web UI with automatic retry for transient 429s."""
    url = f"{ui_uri}/api/chat"
    elapsed = 0.0
    st = 0
    data: Any = {}
    raw = ""
    for attempt in range(retries + 1):
        t0 = time.time()
        st, data, raw = _http_json(
            url,
            method="POST",
            body={"message": message},
            timeout=120,
        )
        elapsed = round(time.time() - t0, 2)
        if st == 200 and isinstance(data, dict):
            reply = _extract_reply_text(data)
            if (
                data.get("mode") == "vertex_agent_engine"
                and "429" not in reply
                and "RESOURCE_EXHAUSTED" not in reply
                and len(reply.strip()) > 10
            ):
                return st, data, reply, elapsed
        if attempt < retries:
            time.sleep(4 * (attempt + 1))
    final_data = data if isinstance(data, dict) else {"raw": raw[:400]}
    return st, final_data, _extract_reply_text(final_data), elapsed


def run_pillar_4_checks(ui_uri: str) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    pillar_name = "Pillar 4: End-to-End Live Multi-Agent Functionality"

    if not ui_uri:
        for cid, title in [
            ("4.1", "Banking Domain E2E (`banking_agent` + Cloud SQL MCP)"),
            ("4.2", "Investments Domain E2E (`investment_agent` + BigQuery MCP + `ticker-mcp`)"),
            ("4.3", "Insurance Domain E2E (`insurance_agent` + Cloud SQL MCP + GCS MCP)"),
        ]:
            checks.append(
                make_check(
                    check_id=cid,
                    pillar=pillar_name,
                    title=title,
                    passed=False,
                    max_points=10,
                    earned_points=0,
                    summary="Skipped because `financial-companion-ui` URL is unavailable.",
                    evidence={"ui_uri": ""},
                )
            )
        return checks

    # Check 4.1: Banking E2E (10 pts)
    prompt_bank = (
        "Hi, I am Jordan Hale (last 4 of SSN: 4821). "
        "Please list my checking and savings account numbers and their current balances."
    )
    st_b, data_b, reply_b, dur_b = _call_chat_with_retry(ui_uri, prompt_bank, "verify-banking")
    mode_b = str(data_b.get("mode", ""))
    trace_b = data_b.get("trace", []) if isinstance(data_b.get("trace"), list) else []
    trace_b_ok = any(h.get("protocol") == "A2A" and h.get("target") == "banking_agent" for h in trace_b) and any(
        h.get("protocol") == "MCP" and h.get("target") == "mcp-cloud-sql" for h in trace_b
    )
    bank_ok = (
        st_b == 200
        and mode_b == "vertex_agent_engine"
        and data_b.get("agent") == "banking_agent"
        and trace_b_ok
        and ("CHK-1001842" in reply_b or "12,480.22" in reply_b or "12480.22" in reply_b)
        and ("SAV-1009021" in reply_b or "48,210" in reply_b or "48210" in reply_b)
    )
    checks.append(
        make_check(
            check_id="4.1",
            pillar=pillar_name,
            title="Banking Domain E2E (`banking_agent` via A2A + Cloud SQL MCP)",
            passed=bank_ok,
            max_points=10,
            earned_points=10 if bank_ok else 0,
            summary=(
                f"Live `vertex_agent_engine` response verified Jordan Hale (`4821`), returned `CHK-1001842` (`$12,480.22`) & `SAV-1009021` (`$48,210.00`), and emitted {len(trace_b)} A2A/MCP trace hops in {dur_b}s."
                if bank_ok
                else f"Banking E2E failed or incomplete (HTTP {st_b}, mode={mode_b}, trace_ok={trace_b_ok})."
            ),
            evidence={
                "prompt": prompt_bank,
                "mode": mode_b,
                "agent": data_b.get("agent", ""),
                "trace_hops": [
                    f"{h.get('protocol')}:{h.get('source')}->{h.get('target')}({h.get('operation')})"
                    for h in trace_b
                    if isinstance(h, dict)
                ],
                "latency_seconds": dur_b,
                "reply_excerpt": reply_b[:600],
            },
        )
    )

    # Check 4.2: Investments E2E (10 pts)
    prompt_inv = (
        "I am Marcus Vance, last 4 of SSN is 6154. "
        "What investment positions do I hold in my brokerage account, and what is the live stock quote for GOOGL?"
    )
    st_i, data_i, reply_i, dur_i = _call_chat_with_retry(ui_uri, prompt_inv, "verify-investments")
    mode_i = str(data_i.get("mode", ""))
    trace_i = data_i.get("trace", []) if isinstance(data_i.get("trace"), list) else []
    trace_i_ok = any(h.get("protocol") == "A2A" and h.get("target") == "investment_agent" for h in trace_i) and any(
        h.get("protocol") == "MCP" and h.get("target") in ("mcp-bigquery", "mcp-stock-price") for h in trace_i
    )
    inv_ok = (
        st_i == 200
        and mode_i == "vertex_agent_engine"
        and data_i.get("agent") == "investment_agent"
        and trace_i_ok
        and "GOOGL" in reply_i
        and "JPM" in reply_i
        and ("30" in reply_i or "20" in reply_i)
    )
    checks.append(
        make_check(
            check_id="4.2",
            pillar=pillar_name,
            title="Investments Domain E2E (`investment_agent` via A2A + BigQuery MCP + `ticker-mcp`)",
            passed=inv_ok,
            max_points=10,
            earned_points=10 if inv_ok else 0,
            summary=(
                f"Live `vertex_agent_engine` response returned Marcus Vance's (`6154`) BigQuery holdings (`GOOGL` 30 sh, `JPM` 20 sh), live `GOOGL` quote, and {len(trace_i)} A2A/MCP trace hops in {dur_i}s."
                if inv_ok
                else f"Investments E2E failed or incomplete (HTTP {st_i}, mode={mode_i}, trace_ok={trace_i_ok})."
            ),
            evidence={
                "prompt": prompt_inv,
                "mode": mode_i,
                "agent": data_i.get("agent", ""),
                "trace_hops": [
                    f"{h.get('protocol')}:{h.get('source')}->{h.get('target')}({h.get('operation')})"
                    for h in trace_i
                    if isinstance(h, dict)
                ],
                "latency_seconds": dur_i,
                "reply_excerpt": reply_i[:600],
            },
        )
    )

    # Check 4.3: Insurance E2E (10 pts)
    prompt_ins = (
        "I am Elena Rostova (SSN last 4: 7209). "
        "Can you read my home insurance policy POL-HOME-4201 and tell me the dwelling coverage and monthly premium?"
    )
    st_s, data_s, reply_s, dur_s = _call_chat_with_retry(ui_uri, prompt_ins, "verify-insurance")
    mode_s = str(data_s.get("mode", ""))
    trace_s = data_s.get("trace", []) if isinstance(data_s.get("trace"), list) else []
    trace_s_ok = any(h.get("protocol") == "A2A" and h.get("target") == "insurance_agent" for h in trace_s) and any(
        h.get("protocol") == "MCP" and h.get("target") == "mcp-cloud-storage" for h in trace_s
    )
    ins_ok = (
        st_s == 200
        and mode_s == "vertex_agent_engine"
        and data_s.get("agent") == "insurance_agent"
        and trace_s_ok
        and ("480,000" in reply_s or "480000" in reply_s or "Beacon" in reply_s)
        and "134" in reply_s
    )
    checks.append(
        make_check(
            check_id="4.3",
            pillar=pillar_name,
            title="Insurance Domain E2E (`insurance_agent` via A2A + Cloud SQL MCP + GCS MCP)",
            passed=ins_ok,
            max_points=10,
            earned_points=10 if ins_ok else 0,
            summary=(
                f"Live `vertex_agent_engine` response verified Elena Rostova (`7209`) in Cloud SQL, read `POL-HOME-4201` (`$480,000` dwelling, `$134/month`) from GCS, and emitted {len(trace_s)} A2A/MCP trace hops in {dur_s}s."
                if ins_ok
                else f"Insurance E2E failed or incomplete (HTTP {st_s}, mode={mode_s}, trace_ok={trace_s_ok})."
            ),
            evidence={
                "prompt": prompt_ins,
                "mode": mode_s,
                "agent": data_s.get("agent", ""),
                "trace_hops": [
                    f"{h.get('protocol')}:{h.get('source')}->{h.get('target')}({h.get('operation')})"
                    for h in trace_s
                    if isinstance(h, dict)
                ],
                "latency_seconds": dur_s,
                "reply_excerpt": reply_s[:600],
            },
        )
    )

    return checks


def resolve_signer_service_account(project_id: str, auth_headers: Dict[str, str]) -> str:
    """
    Resolves an active service account inside `<project_id>` for minting the Google-signed
    RS256 OIDC JWT. Falls back gracefully if a later lab goal removes or splits
    `sa-financial-assistant`.
    """
    candidates = [
        f"sa-financial-assistant@{project_id}.iam.gserviceaccount.com",
        f"terraform-deployer@{project_id}.iam.gserviceaccount.com",
        f"sa-banking@{project_id}.iam.gserviceaccount.com",
        f"sa-root@{project_id}.iam.gserviceaccount.com",
    ]
    for sa_email in candidates:
        url_sa = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{urllib.parse.quote(sa_email)}"
        st_sa, data_sa, _ = _http_json(url_sa, headers=auth_headers)
        if st_sa == 200 and isinstance(data_sa, dict) and not data_sa.get("disabled", False):
            return sa_email

    # Fallback: list project service accounts and pick any active custom SA in this project
    url_list = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"
    st_list, data_list, _ = _http_json(url_list, headers=auth_headers)
    if st_list == 200 and isinstance(data_list, dict):
        for acc in data_list.get("accounts", []):
            email = str(acc.get("email", ""))
            if email.endswith(f"@{project_id}.iam.gserviceaccount.com") and not acc.get("disabled", False):
                return email

    return candidates[0]


def mint_google_signed_attestation_jwt(
    project_id: str,
    auth_headers: Dict[str, str],
    student_id: str,
    principal_email: str,
    goal_id: str,
    submission_id: str,
    earned_points: int,
    max_points: int,
    payload_sha256: str,
    timestamp_unix: int,
    lab_id: str = "lab_8",
) -> Dict[str, Any]:
    """
    Mints an asymmetric RS256 OIDC ID token signed by Google's IAM Credentials service
    for an active service account in `<project_id>` whose `aud` claim cryptographically
    binds the student identity, GCP project, lab_id, goal_id, submission_id, signer SA, score,
    timestamp, and the SHA-256 hash of the canonical assessment JSON payload.
    """
    sa_email = resolve_signer_service_account(project_id, auth_headers)
    lab_param = lab_id if lab_id else LAB_METADATA.get("lab_id", "lab_8")
    audience = (
        f"https://financial-companion.assessment/v1"
        f"?project={urllib.parse.quote(project_id)}"
        f"&principal={urllib.parse.quote(principal_email)}"
        f"&student={urllib.parse.quote(student_id)}"
        f"&goal={urllib.parse.quote(goal_id)}"
        f"&lab={urllib.parse.quote(lab_param)}"
        f"&signer={urllib.parse.quote(sa_email)}"
        f"&score={earned_points}/{max_points}"
        f"&sha256={payload_sha256}"
        f"&ts={timestamp_unix}"
        f"&nonce={urllib.parse.quote(submission_id)}"
    )
    url = (
        f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
        f"{urllib.parse.quote(sa_email)}:generateIdToken"
    )
    st, data, raw = _http_json(
        url,
        method="POST",
        headers=auth_headers,
        body={"audience": audience, "includeEmail": True},
    )
    if st != 200 or not isinstance(data, dict) or not data.get("token"):
        return {
            "status": "ERROR",
            "http_status": st,
            "error": raw[:400],
            "signer_service_account": sa_email,
            "audience": audience,
            "id_token": "",
        }

    id_token = str(data["token"])
    decoded = _decode_jwt_unverified(id_token)

    # Verify the newly minted token against Google's tokeninfo endpoint to capture kid & alg
    st_ti, data_ti, _ = _http_json(
        f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(id_token)}"
    )
    return {
        "status": "SIGNED_BY_GOOGLE_IAM_OIDC",
        "signer_service_account": sa_email,
        "audience": audience,
        "id_token": id_token,
        "jwt_header": decoded.get("header", {}),
        "jwt_payload": decoded.get("payload", {}),
        "google_tokeninfo_verified": st_ti == 200,
        "google_tokeninfo_claims": data_ti if isinstance(data_ti, dict) else {},
    }


def submit_report_to_assessor(
    submit_url: str,
    enrollment_key: str,
    canonical_payload: Dict[str, Any],
    payload_sha256: str,
    attestation: Dict[str, Any],
    md_content: str,
) -> Dict[str, Any]:
    """
    Submits the cryptographically attested Goal report directly to the Web Assessor endpoint.
    Authenticates at the edge using Dual-Gate Option 1:
      1. `Authorization: Bearer <google_signed_oidc_id_token>` (RS256 token signed by Google IAM)
      2. `X-Assessor-Enrollment-Key: <enrollment_key>` (cohort passcode / allow-list key)
    """
    id_token = str(attestation.get("id_token") or "")
    meta = canonical_payload.get("metadata", {})
    goal_id = str(meta.get("goal_id", "goal-1-environment-setup"))
    lab_id = str(meta.get("lab_id") or LAB_METADATA.get("lab_id", "lab_8"))
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Assessor-Goal-Id": goal_id,
        "X-Assessor-Lab-Id": lab_id,
        "X-Assessor-Submission-Id": str(meta.get("submission_id", "")),
        "X-Assessor-Payload-SHA256": payload_sha256,
    }
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    if enrollment_key:
        headers["X-Assessor-Enrollment-Key"] = enrollment_key

    body = {
        "submission_id": meta.get("submission_id", ""),
        "goal_id": goal_id,
        "goal_number": meta.get("goal_number", 1),
        "goal_title": meta.get("goal_title", ""),
        "lab_id": lab_id,
        "student_id": canonical_payload.get("student_identity", {}).get("student_id", ""),
        "project_id": canonical_payload.get("project", {}).get("project_id", ""),
        "payload_sha256": payload_sha256,
        "attestation_jwt": id_token,
        "canonical_payload": canonical_payload,
        "report_markdown": md_content,
    }
    st, data, raw = _http_json(submit_url, method="POST", headers=headers, body=body, timeout=60)
    return {
        "http_status": st,
        "accepted": st in (200, 201, 202),
        "response": data if isinstance(data, dict) else {"raw": raw[:400]},
    }


def render_markdown_report(
    canonical_payload: Dict[str, Any],
    canonical_json_str: str,
    payload_sha256: str,
    attestation: Dict[str, Any],
) -> str:
    meta = canonical_payload["metadata"]
    student = canonical_payload["student_identity"]
    project = canonical_payload["project"]
    summary = canonical_payload["summary"]
    checks = canonical_payload["checks"]

    lines: List[str] = []
    lines.append("# Financial Companion — Student Goal Assessment Report")
    lines.append("")
    lines.append(
        "> **Automated LLM Assessor & Grading Pipeline Notice**: This report contains live infrastructure, "
        "agent runtime, and end-to-end functional verification evidence for a specific **Lab Goal**, followed by "
        "a canonical JSON payload and an **asymmetric `RS256` Google-signed OIDC JWT (`id_token`)** that "
        "cryptographically binds the student's identity, GCP project, `goal_id`, submission nonce, and the "
        "`SHA-256` digest of the assessment evidence."
    )
    lines.append("")
    lines.append("## 1. Executive Summary & Student Identity")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| :--- | :--- |")
    lines.append(
        f"| **Assessed Lab (`lab_id`)** | `{meta.get('lab_id', 'lab_8')}` — **[{meta.get('lab_number', 8)}] {meta.get('lab_title', '')}** |"
    )
    lines.append(
        f"| **Assessed Goal (`goal_id`)** | `{meta.get('goal_id', 'goal-1-environment-setup')}` — **{meta.get('goal_title', '')}** |"
    )
    lines.append(f"| **Goal Number** | `Goal {meta.get('goal_number', 1)}` |")
    lines.append(f"| **Submission Nonce (`submission_id`)** | `{meta.get('submission_id', '')}` |")
    lines.append(f"| **Student Identifier** | `{student['student_id']}` |")
    lines.append(
        f"| **Google-Verified OAuth Principal** | `{student['authenticated_principal_email']}` (sub: `{student['authenticated_principal_sub']}`) |"
    )
    lines.append(
        f"| **GCP Project ID / Number** | `{project['project_id']}` (`{project['project_number']}`) |"
    )
    lines.append(f"| **Generated Timestamp (UTC)** | `{meta['generated_at_utc']}` |")
    lines.append(
        f"| **Goal Score** | **{summary['earned_points']} / {summary['max_points']} ({summary['percentage']}%)** |"
    )
    lines.append(
        f"| **Checks Passed** | **{summary['passed_checks']} / {summary['total_checks']}** ({summary['overall_status']}) |"
    )
    lines.append(f"| **Canonical Evidence `SHA-256`** | `{payload_sha256}` |")
    lines.append(
        f"| **Cryptographic Attestation Status** | `{attestation.get('status', 'UNKNOWN')}` (kid: `{attestation.get('jwt_header', {}).get('kid', 'N/A')}`) |"
    )
    lines.append("")

    lines.append("## 2. Goal Step Summary Scorecard")
    lines.append("")
    lines.append("| Step ID | Step | Passed Checks | Score | Status |")
    lines.append("| :---: | :--- | :---: | :---: | :---: |")
    for s in summary.get("step_breakdown", []):
        status_badge = "PASS" if s["earned_points"] == s["max_points"] else "PARTIAL/FAIL"
        lines.append(
            f"| `{s['step_id']}` | **{s['step_title']}** | {s['passed_checks']}/{s['total_checks']} | **{s['earned_points']} / {s['max_points']}** | `{status_badge}` |"
        )
    lines.append("")

    lines.append("## 3. Detailed Verification Checklist")
    lines.append("")
    lines.append("| ID | Step | Check | Status | Points | Summary |")
    lines.append("| :---: | :--- | :--- | :---: | :---: | :--- |")
    for c in checks:
        lines.append(
            f"| `{c['check_id']}` | {c.get('step', c['pillar'])} | {c['title']} | **{c['status']}** | "
            f"`{c['earned_points']}/{c['max_points']}` | {c['summary']} |"
        )
    lines.append("")

    lines.append("## 4. Detailed Evidence by Check")
    lines.append("")
    for c in checks:
        lines.append(f"### Check {c['check_id']} — {c['title']} (`{c['status']}`, {c['earned_points']}/{c['max_points']} pts)")
        lines.append(f"- **Step**: {c.get('step', c['pillar'])} (`{c.get('step_id', '')}`)")
        lines.append(f"- **Summary**: {c['summary']}")
        lines.append("- **Collected Evidence**:")
        lines.append("```json")
        lines.append(json.dumps(c["evidence"], indent=2, sort_keys=True))
        lines.append("```")
        lines.append("")

    lines.append("## 5. Instructions for the Web Assessor & ADK Grading Agent")
    lines.append("")
    lines.append(
        "1. **Verify Cryptographic Integrity & Anti-Cheat Binding First**:\n"
        "   - Extract the raw JSON string between `<!-- BEGIN_CANONICAL_ASSESSMENT_JSON -->` and `<!-- END_CANONICAL_ASSESSMENT_JSON -->`.\n"
        "   - Parse the JSON and re-serialize it canonically (`json.dumps(obj, sort_keys=True, separators=(',', ':'))`), then compute its `SHA-256` hex digest.\n"
        "   - Extract the Google-signed JWT between `<!-- BEGIN_GOOGLE_OIDC_JWT -->` and `<!-- END_GOOGLE_OIDC_JWT -->`.\n"
        "   - Verify the JWT's `RS256` signature against Google's public certs (`https://www.googleapis.com/oauth2/v3/certs`).\n"
        "   - Confirm that the `aud` claim inside the Google-signed JWT matches the student's `project_id`, `principal`, `student`, `goal` (`goal_id`), `nonce` (`submission_id`), and the recomputed `sha256` digest, and that `email` ends with `@<project_id>.iam.gserviceaccount.com` and matches `aud.signer`.\n"
        "   - If the `sha256` in the signed JWT does not match the report's JSON payload, or if `project_id` belongs to a different student in `students`, **flag the submission as INVALID / TAMPERED**.\n"
        "2. **Record Goal-Scoped Grade (`HIGHEST` Score Retention Policy)**:\n"
        "   - Grade and register this submission solely under `goal_id` (`student_goal_grades` keyed by `(student_id, goal_id)`).\n"
        "   - Do **not** overwrite or invalidate previously completed goals (since later goals intentionally modify or remove resources from earlier goals).\n"
        "   - If the student has an existing valid score for this same `goal_id`, retain the **highest valid score** (`MAX(existing_score, new_score)`)."
    )
    lines.append("")

    lines.append("## 6. Canonical Assessment Evidence Payload (Machine-Verifiable)")
    lines.append("")
    lines.append("<!-- BEGIN_CANONICAL_ASSESSMENT_JSON -->")
    lines.append("```json")
    lines.append(canonical_json_str)
    lines.append("```")
    lines.append("<!-- END_CANONICAL_ASSESSMENT_JSON -->")
    lines.append("")

    lines.append("## 7. Cryptographic Identity & Anti-Cheat Attestation (Google-Signed RS256 OIDC JWT)")
    lines.append("")
    lines.append(f"- **Canonical Payload `SHA-256`**: `{payload_sha256}`")
    lines.append(f"- **Signed `aud` Claim**: `{attestation.get('audience', '')}`")
    lines.append(f"- **Google Signer Identity (`email`)**: `{attestation.get('signer_service_account', '')}`")
    lines.append(
        f"- **Google Public Key ID (`kid`)**: `{attestation.get('jwt_header', {}).get('kid', '')}` (`alg: {attestation.get('jwt_header', {}).get('alg', '')}`)"
    )
    lines.append("")
    lines.append("### Raw Google-Signed OIDC JWT (`id_token`)")
    lines.append("<!-- BEGIN_GOOGLE_OIDC_JWT -->")
    lines.append("```text")
    lines.append(attestation.get("id_token", ""))
    lines.append("```")
    lines.append("<!-- END_GOOGLE_OIDC_JWT -->")
    lines.append("")
    lines.append("### Decoded JWT Header & Payload (For Inspection)")
    lines.append("```json")
    lines.append(
        json.dumps(
            {
                "header": attestation.get("jwt_header", {}),
                "payload": attestation.get("jwt_payload", {}),
            },
            indent=2,
            sort_keys=True,
        )
    )
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def run_goal_1_checks(project_id: str, auth_headers: Dict[str, str]) -> List[Dict[str, Any]]:
    print("[2/6] Checking Goal 1 / Step 1: Base Infrastructure & Data Layer...")
    p1_checks = run_pillar_1_checks(project_id, auth_headers)

    print("[3/6] Checking Goal 1 / Step 2: Vertex AI Agent Engine Deployment...")
    p2_checks, _ = run_pillar_2_checks(project_id, auth_headers)

    print("[4/6] Checking Goal 1 / Step 3: Cloud Run Services & Web Interface...")
    p3_checks, _, ui_uri = run_pillar_3_checks(project_id, auth_headers)

    print("[5/6] Checking Goal 1 / Step 4: End-to-End Live Multi-Agent Functionality...")
    p4_checks = run_pillar_4_checks(ui_uri)

    return p1_checks + p2_checks + p3_checks + p4_checks


def _strip_js_comments(source: str) -> str:
    """Removes single-line and multi-line JS comments before scanning for vulnerable sinks."""
    no_block = re.sub(r"/\*[\s\S]*?\*/", "", source)
    return re.sub(r"//[^\n]*", "", no_block)


def _strip_py_comments(source: str) -> str:
    """Removes single-line Python comments before scanning for hardcoded secrets and SQLi."""
    return re.sub(r"#[^\n]*", "", source)


def run_goal_n_sast_checks(repo_root: Path) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    app_js_path = repo_root / "web_ui" / "static" / "app.js"
    server_py_path = repo_root / "web_ui" / "server.py"

    app_js_raw = app_js_path.read_text(encoding="utf-8") if app_js_path.is_file() else ""
    app_js_code = _strip_js_comments(app_js_raw)
    server_py_raw = server_py_path.read_text(encoding="utf-8") if server_py_path.is_file() else ""
    server_py_code = _strip_py_comments(server_py_raw)

    app_js_intact = (
        len(app_js_raw.splitlines()) >= 500
        and "function buildTopologySvg" in app_js_code
        and "async function sendTurn" in app_js_code
    )
    server_py_intact = (
        len(server_py_raw.splitlines()) >= 300
        and "def security_headers_middleware" in server_py_code
        and "async def post_chat" in server_py_code
    )

    # Step 1 (30 pts): Frontend Code Injection (eval) & DOM XSS Remediation in web_ui/static/app.js (CWE-95 / CWE-79)
    print("[2/6] Checking Goal N / Step 1: Frontend Code Injection (eval) & DOM XSS Remediation in web_ui/static/app.js...")
    p1_name = "Pillar 1: Frontend Code Injection (eval) & DOM XSS Remediation in web_ui/static/app.js (CWE-95 / CWE-79)"
    has_eval = bool(re.search(r"\beval\s*\(", app_js_code))
    has_inner_html = bool(re.search(r"\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=", app_js_code))
    has_doc_write = bool(re.search(r"\bdocument\.write\s*\(", app_js_code))
    step1_ok = app_js_intact and not has_eval and not has_inner_html and not has_doc_write
    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1_name,
            title="Client-Side Code Injection (`eval`, `CWE-95`) & DOM XSS (`.innerHTML`, `CWE-79`) Remediated in `web_ui/static/app.js`",
            passed=step1_ok,
            max_points=30,
            earned_points=30 if step1_ok else 0,
            summary=(
                "`web_ui/static/app.js` is free of dynamic `eval()` code execution and unsafe `.innerHTML` DOM XSS sinks while preserving all UI rendering functions."
                if step1_ok
                else f"Frontend injection sink remains in `web_ui/static/app.js` (eval={has_eval}, innerHTML={has_inner_html}, document.write={has_doc_write})."
            ),
            evidence={
                "file": "web_ui/static/app.js",
                "app_js_intact": app_js_intact,
                "has_eval_sink": has_eval,
                "has_inner_html_sink": has_inner_html,
                "has_document_write": has_doc_write,
            },
        )
    )

    # Step 2 (30 pts): Hardcoded Master API Key, JWT Secret & Admin Header Bypass Remediation (CWE-798 / CWE-287 / CWE-312)
    print("[3/6] Checking Goal N / Step 2: Hardcoded Master API Key, JWT Secret & Admin Header Bypass Remediation...")
    p2_name = "Pillar 2: Hardcoded Master API Key, JWT Secret & Admin Header Bypass Remediation (CWE-798 / CWE-287 / CWE-312)"
    has_frontend_api_key = (
        "REDACTED_TEST_API_KEY" in app_js_code
        or bool(re.search(r"AIza[0-9A-Za-z_\-]{35}", app_js_code))
    )
    has_frontend_jwt_secret = "harbor-desk-master-jwt-signing-key-9876543210abcdef" in app_js_code
    has_localstorage_token = bool(re.search(r"localStorage\.setItem\s*\(\s*['\"]auth_token['\"]", app_js_code))
    has_backend_api_key = (
        "REDACTED_TEST_API_KEY" in server_py_code
        or bool(re.search(r"AIza[0-9A-Za-z_\-]{35}", server_py_code))
    )
    has_backend_jwt_secret = "harbor-desk-master-jwt-signing-key-9876543210abcdef" in server_py_code
    has_admin_header_bypass = bool(
        re.search(r"headers\.get\(\s*['\"]X-Harbor-Admin-Key['\"]\s*\)\s*==\s*HARBOR_STATIC_ADMIN_KEY", server_py_code)
    )
    step2_ok = (
        app_js_intact
        and server_py_intact
        and not has_frontend_api_key
        and not has_frontend_jwt_secret
        and not has_localstorage_token
        and not has_backend_api_key
        and not has_backend_jwt_secret
        and not has_admin_header_bypass
    )
    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2_name,
            title="Hardcoded Master API Key (`CWE-798`), JWT Secret (`CWE-312`) & Middleware Bypass (`CWE-287`) Remediated",
            passed=step2_ok,
            max_points=30,
            earned_points=30 if step2_ok else 0,
            summary=(
                "Both `web_ui/static/app.js` and `web_ui/server.py` are free of hardcoded API keys, fallback JWT secrets, cleartext `localStorage` tokens, and static admin header bypass checks."
                if step2_ok
                else (
                    f"Hardcoded credential or auth bypass remains (frontend_api_key={has_frontend_api_key}, "
                    f"frontend_jwt={has_frontend_jwt_secret}, localStorage_token={has_localstorage_token}, "
                    f"backend_api_key={has_backend_api_key}, backend_jwt={has_backend_jwt_secret}, "
                    f"admin_header_bypass={has_admin_header_bypass})."
                )
            ),
            evidence={
                "files": ["web_ui/static/app.js", "web_ui/server.py"],
                "has_frontend_api_key": has_frontend_api_key,
                "has_frontend_jwt_secret": has_frontend_jwt_secret,
                "has_localstorage_token": has_localstorage_token,
                "has_backend_api_key": has_backend_api_key,
                "has_backend_jwt_secret": has_backend_jwt_secret,
                "has_admin_header_bypass": has_admin_header_bypass,
            },
        )
    )

    # Step 3 (30 pts): Backend SQL Injection Remediation in web_ui/server.py (CWE-89)
    print("[4/6] Checking Goal N / Step 3: Backend SQL Injection Remediation in web_ui/server.py (CWE-89)...")
    p3_name = "Pillar 3: Backend SQL Injection Remediation in web_ui/server.py (CWE-89)"
    has_fstring_sql = bool(
        re.search(
            r"""(?:f"\s*SELECT\b[^"]*\{[^}]+\}|f'\s*SELECT\b[^']*\{[^}]+\})""",
            server_py_code,
            re.IGNORECASE,
        )
    )
    has_concat_sql = bool(
        re.search(
            r"""(?:"\s*SELECT\b[^"]*"|'\s*SELECT\b[^']*')\s*(?:\+|%|\.format\s*\()""",
            server_py_code,
            re.IGNORECASE,
        )
    )
    step3_ok = server_py_intact and not has_fstring_sql and not has_concat_sql
    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3_name,
            title="Raw SQL String Interpolation (`CWE-89`) Remediated in `web_ui/server.py`",
            passed=step3_ok,
            max_points=30,
            earned_points=30 if step3_ok else 0,
            summary=(
                "`web_ui/server.py` contains zero unparameterized SQL string interpolations or concatenations (`CWE-89`)."
                if step3_ok
                else f"SQL injection pattern remains in `web_ui/server.py` (fstring_sql={has_fstring_sql}, concat_sql={has_concat_sql})."
            ),
            evidence={
                "file": "web_ui/server.py",
                "server_py_intact": server_py_intact,
                "has_fstring_sql": has_fstring_sql,
                "has_concat_sql": has_concat_sql,
            },
        )
    )

    # Step 4 (10 pts): Web UI Functional Integrity & Regression Verification
    print("[5/6] Checking Goal N / Step 4: Web UI Functional Integrity & Unit Tests...")
    p4_name = "Pillar 4: Web UI Functional Integrity & Regression Verification"
    rc_test, out_test, err_test = _run_cmd(
        [sys.executable, "-m", "unittest", "discover", "-s", str(repo_root / "web_ui"), "-p", "test_*.py"],
        timeout=30,
    )
    step4_ok = rc_test == 0 and app_js_intact and server_py_intact
    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4_name,
            title="Web UI Planner Unit Tests & Module Integrity Pass Without Regression",
            passed=step4_ok,
            max_points=10,
            earned_points=10 if step4_ok else 0,
            summary=(
                "All `web_ui` unit tests pass and both `web_ui/static/app.js` and `web_ui/server.py` are intact."
                if step4_ok
                else f"Web UI regression check failed (unittest exit_code={rc_test})."
            ),
            evidence={
                "unittest_exit_code": rc_test,
                "unittest_output": (err_test or out_test)[-400:],
                "app_js_lines": len(app_js_raw.splitlines()),
                "server_py_lines": len(server_py_raw.splitlines()),
            },
        )
    )

    return checks


def _state_file_path(repo_root: Path) -> Path:
    return repo_root / ".agents" / "skills" / "verify-deployment" / ".assessment_state.json"


def _load_assessment_state(repo_root: Path) -> Dict[str, Any]:
    state_path = _state_file_path(repo_root)
    state: Dict[str, Any] = {
        "enrollment_key": "",
        "student_id": "",
        "submit_url": "",
        "project_id": "",
        "completed_goals": {},
    }
    if state_path.is_file():
        try:
            loaded = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                state.update(loaded)
                if not isinstance(state.get("completed_goals"), dict):
                    state["completed_goals"] = {}
        except Exception:
            pass

    # Backfill completed_goals from any existing assessment_report_<goal_id>.md files
    completed = state.setdefault("completed_goals", {})
    for gid in GOAL_REGISTRY:
        if gid in completed:
            continue
        rpt = repo_root / f"assessment_report_{gid}.md"
        if rpt.is_file():
            try:
                raw_md = rpt.read_text(encoding="utf-8")
                m = re.search(
                    r"<!-- BEGIN_CANONICAL_ASSESSMENT_JSON -->\s*```json\s*(\{.*?\})\s*```\s*<!-- END_CANONICAL_ASSESSMENT_JSON -->",
                    raw_md,
                    re.DOTALL,
                )
                if m:
                    payload = json.loads(m.group(1))
                    summary = payload.get("summary", {})
                    if summary.get("overall_status") == "PASS":
                        completed[gid] = {
                            "completed_at_utc": payload.get("metadata", {}).get("generated_at_utc", ""),
                            "earned_points": summary.get("earned_points", 100),
                            "max_points": summary.get("max_points", 100),
                            "report_path": str(rpt.name),
                        }
                        if not state.get("student_id"):
                            state["student_id"] = payload.get("student_identity", {}).get("student_id", "")
                        if not state.get("project_id"):
                            state["project_id"] = payload.get("project", {}).get("project_id", "")
            except Exception:
                pass
    return state


def _save_assessment_state(repo_root: Path, state: Dict[str, Any]) -> None:
    state_path = _state_file_path(repo_root)
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception:
        pass


def _resolve_next_uncompleted_goal(state: Dict[str, Any]) -> str:
    completed = state.get("completed_goals") or {}
    implemented_goals = [
        gid for gid, gdef in GOAL_REGISTRY.items() if gdef.get("implemented", False)
    ]
    for gid in implemented_goals:
        if gid not in completed:
            return gid
    return implemented_goals[-1] if implemented_goals else "goal-1-environment-setup"


def run_goal_2_otel_checks(
    project_id: str, auth_headers: Dict[str, str], repo_root: Path
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []

    # Step 1 (20 pts): OpenTelemetry APIs & Service Account Telemetry IAM Roles
    print("[2/6] Checking Goal 2 / Step 1: OpenTelemetry APIs & Service Account Telemetry IAM Roles...")
    p1_name = "Pillar 1: OpenTelemetry APIs & Service Account Telemetry IAM Roles"
    otel_apis = [
        "cloudtrace.googleapis.com",
        "logging.googleapis.com",
        "monitoring.googleapis.com",
        "telemetry.googleapis.com",
    ]
    url_apis = f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services?filter=state:ENABLED&pageSize=200"
    st_apis, data_apis, _ = _http_json(url_apis, headers=auth_headers)
    enabled_set = set()
    if st_apis == 200 and isinstance(data_apis, dict):
        for svc in data_apis.get("services", []):
            name = svc.get("config", {}).get("name") or svc.get("name", "").split("/")[-1]
            enabled_set.add(name)
    missing_otel_apis = [a for a in otel_apis if a not in enabled_set]
    apis_ok = st_apis == 200 and len(missing_otel_apis) == 0
    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1_name,
            title="Observability & Telemetry GCP APIs Enabled (`cloudtrace`, `logging`, `monitoring`, `telemetry`)",
            passed=apis_ok,
            max_points=10,
            earned_points=10 if apis_ok else 0,
            summary=(
                "All 4 GCP observability and OTLP telemetry APIs (`cloudtrace`, `logging`, `monitoring`, `telemetry`) are ENABLED."
                if apis_ok
                else f"Missing observability APIs: {missing_otel_apis} (HTTP {st_apis})."
            ),
            evidence={
                "required_otel_apis": otel_apis,
                "missing_otel_apis": missing_otel_apis,
            },
        )
    )

    required_otel_roles = [
        "roles/cloudtrace.agent",
        "roles/logging.logWriter",
        "roles/monitoring.metricWriter",
        "roles/telemetry.writer",
    ]
    url_iam = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy"
    st_iam, data_iam, _ = _http_json(url_iam, method="POST", headers=auth_headers, body={})
    sa_roles_found: List[str] = []
    target_sa_email = f"sa-financial-assistant@{project_id}.iam.gserviceaccount.com"
    if st_iam == 200 and isinstance(data_iam, dict):
        for binding in data_iam.get("bindings", []):
            role = str(binding.get("role", ""))
            members = binding.get("members", [])
            if any(
                isinstance(m, str)
                and m.startswith("serviceAccount:")
                and m.endswith(f"@{project_id}.iam.gserviceaccount.com")
                for m in members
            ):
                if role in required_otel_roles and role not in sa_roles_found:
                    sa_roles_found.append(role)
    missing_roles = [r for r in required_otel_roles if r not in sa_roles_found]
    iam_ok = st_iam == 200 and len(missing_roles) == 0
    checks.append(
        make_check(
            check_id="1.2",
            pillar=p1_name,
            title="Agent Runtime Service Account Telemetry IAM Roles (`cloudtrace.agent`, `logging.logWriter`, `monitoring.metricWriter`, `telemetry.writer`)",
            passed=iam_ok,
            max_points=10,
            earned_points=10 if iam_ok else 0,
            summary=(
                f"Agent runtime service account (`{target_sa_email}`) holds all 4 required telemetry writer roles."
                if iam_ok
                else f"Agent service account is missing telemetry IAM roles: {missing_roles}."
            ),
            evidence={
                "service_account": target_sa_email,
                "required_roles": required_otel_roles,
                "found_roles": sorted(sa_roles_found),
                "missing_roles": missing_roles,
            },
        )
    )

    # Step 2 (30 pts): OpenTelemetry Environment Variables on All 4 Agents
    print("[3/6] Checking Goal 2 / Step 2: OpenTelemetry Environment Variables on All 4 Agents...")
    p2_name = "Pillar 2: OpenTelemetry Environment Variables on All 4 Agents"
    url_re = (
        f"https://us-central1-aiplatform.googleapis.com/v1beta1/projects/{project_id}"
        f"/locations/us-central1/reasoningEngines"
    )
    st_re, data_re, _ = _http_json(url_re, headers=auth_headers)
    engines_by_name: Dict[str, Dict[str, Any]] = {}
    if st_re == 200 and isinstance(data_re, dict):
        for eng in data_re.get("reasoningEngines", []):
            disp = eng.get("displayName", "")
            if disp and disp not in engines_by_name:
                engines_by_name[disp] = eng

    agent_otel_env_status: Dict[str, Dict[str, Any]] = {}
    engine_ids_by_agent: Dict[str, str] = {}
    latest_update_iso = "2026-01-01T00:00:00Z"
    all_4_env_ok = True
    for agent_name in EXPECTED_AGENTS:
        eng = engines_by_name.get(agent_name)
        if not eng:
            all_4_env_ok = False
            agent_otel_env_status[agent_name] = {"deployed": False, "otel_enabled": False}
            continue
        res_name = str(eng.get("name", ""))
        eng_id = res_name.split("/")[-1] if "/" in res_name else res_name
        engine_ids_by_agent[agent_name] = eng_id
        upd_time = str(eng.get("updateTime") or eng.get("createTime") or "")
        if upd_time > latest_update_iso:
            latest_update_iso = upd_time
        env_map = {
            str(e.get("name", "")): str(e.get("value", ""))
            for e in eng.get("spec", {}).get("deploymentSpec", {}).get("env", [])
            if isinstance(e, dict) and e.get("name")
        }
        telemetry_flag = env_map.get("GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY", "").strip().lower()
        capture_mode = env_map.get("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "").strip()
        emit_event = env_map.get("OTEL_INSTRUMENTATION_GENAI_EMIT_EVENT", "").strip().lower()
        agent_ok = telemetry_flag in ("true", "1") and (
            bool(capture_mode) or emit_event in ("true", "1")
        )
        if not agent_ok:
            all_4_env_ok = False
        agent_otel_env_status[agent_name] = {
            "reasoning_engine_id": eng_id,
            "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": env_map.get(
                "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY", ""
            ),
            "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": capture_mode,
            "OTEL_INSTRUMENTATION_GENAI_EMIT_EVENT": env_map.get(
                "OTEL_INSTRUMENTATION_GENAI_EMIT_EVENT", ""
            ),
            "otel_enabled": agent_ok,
        }

    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2_name,
            title="OpenTelemetry Instrumentation Environment Variables Configured on All 4 Agents",
            passed=all_4_env_ok and len(engine_ids_by_agent) == 4,
            max_points=30,
            earned_points=30 if (all_4_env_ok and len(engine_ids_by_agent) == 4) else 0,
            summary=(
                "All 4 Vertex AI Reasoning Engines (`banking_agent`, `investment_agent`, `insurance_agent`, `financial_assistant_agent`) have `GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY=true` and OpenTelemetry GenAI instrumentation configured."
                if (all_4_env_ok and len(engine_ids_by_agent) == 4)
                else f"One or more agents are missing OpenTelemetry environment variables: {agent_otel_env_status}."
            ),
            evidence={
                "agents": agent_otel_env_status,
            },
        )
    )

    # Helper to query Cloud Trace, Cloud Logging, and Cloud Monitoring over the last 60 minutes
    expected_engine_ids = sorted(engine_ids_by_agent.values())

    def _collect_live_telemetry() -> Tuple[List[str], List[str], List[str], List[str]]:
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        start_time = (now_utc - datetime.timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Cloud Trace spans
        trace_url = (
            f"https://cloudtrace.googleapis.com/v1/projects/{project_id}/traces"
            f"?startTime={urllib.parse.quote(start_time)}&pageSize=100&view=ROOTSPAN"
        )
        st_tr, data_tr, _ = _http_json(trace_url, headers=auth_headers)
        trace_engines = set()
        if st_tr == 200 and isinstance(data_tr, dict):
            for tr in data_tr.get("traces", []):
                for sp in tr.get("spans", []):
                    lbls = sp.get("labels") or {}
                    svc = lbls.get("service.name") or lbls.get("g.co/agent/id") or ""
                    if svc in expected_engine_ids:
                        trace_engines.add(svc)

        # 2. Cloud Logging OTel GenAI events
        log_body = {
            "resourceNames": [f"projects/{project_id}"],
            "filter": (
                f'timestamp >= "{start_time}" AND '
                f'resource.type="aiplatform.googleapis.com/ReasoningEngine" AND '
                f'labels."event.name"="gen_ai.client.inference.operation.details"'
            ),
            "pageSize": 100,
            "orderBy": "timestamp desc",
        }
        st_lg, data_lg, _ = _http_json(
            "https://logging.googleapis.com/v2/entries:list",
            method="POST",
            headers=auth_headers,
            body=log_body,
        )
        log_engines = set()
        if st_lg == 200 and isinstance(data_lg, dict):
            for entry in data_lg.get("entries", []):
                eid = entry.get("resource", {}).get("labels", {}).get("reasoning_engine_id", "")
                if eid in expected_engine_ids:
                    log_engines.add(eid)

        # Check for any export errors after the latest engine updateTime
        err_filter_time = latest_update_iso if latest_update_iso > start_time else start_time
        err_body = {
            "resourceNames": [f"projects/{project_id}"],
            "filter": (
                f'timestamp >= "{err_filter_time}" AND '
                f'resource.type="aiplatform.googleapis.com/ReasoningEngine" AND '
                f'textPayload:"Failed to export"'
            ),
            "pageSize": 20,
            "orderBy": "timestamp desc",
        }
        st_err, data_err, _ = _http_json(
            "https://logging.googleapis.com/v2/entries:list",
            method="POST",
            headers=auth_headers,
            body=err_body,
        )
        export_errors: List[str] = []
        if st_err == 200 and isinstance(data_err, dict):
            for entry in data_err.get("entries", []):
                export_errors.append(str(entry.get("textPayload", ""))[:200])

        # 3. Cloud Monitoring GenAI metrics
        metric_engines = set()
        for mtype in (
            "prometheus.googleapis.com/gen_ai.client.token.usage/histogram",
            "prometheus.googleapis.com/gen_ai.client.operation.duration/histogram",
            "prometheus.googleapis.com/gen_ai.invoke_agent.duration/histogram",
        ):
            ts_url = (
                f"https://monitoring.googleapis.com/v3/projects/{project_id}/timeSeries"
                f"?filter={urllib.parse.quote(f'metric.type=\"{mtype}\"')}"
                f"&interval.startTime={urllib.parse.quote(start_time)}"
                f"&interval.endTime={urllib.parse.quote(end_time)}"
                f"&view=HEADERS"
            )
            st_ts, data_ts, _ = _http_json(ts_url, headers=auth_headers)
            if st_ts == 200 and isinstance(data_ts, dict):
                for ts in data_ts.get("timeSeries", []):
                    job = ts.get("resource", {}).get("labels", {}).get("job", "")
                    if job in expected_engine_ids:
                        metric_engines.add(job)

        return (
            sorted(trace_engines),
            sorted(log_engines),
            export_errors,
            sorted(metric_engines),
        )

    print("[4/6] Checking Goal 2 / Step 3: Live OpenTelemetry Traces & Logs Export Across All 4 Agents...")
    trace_engs, log_engs, export_errs, metric_engs = _collect_live_telemetry()
    if len(expected_engine_ids) == 4 and (
        len(trace_engs) < 4 or len(log_engs) < 4 or len(metric_engs) < 4
    ):
        # Trigger live requests across the Web UI & A2A cards to ensure fresh telemetry
        _, _, ui_uri = run_pillar_3_checks(project_id, auth_headers)
        if ui_uri:
            _ = run_pillar_4_checks(ui_uri)
        for res_id in expected_engine_ids:
            card_url = (
                f"https://us-central1-aiplatform.googleapis.com/reasoningEngines/v1/"
                f"projects/{project_id}/locations/us-central1/reasoningEngines/{res_id}"
                "/api/a2a/app/.well-known/agent-card.json"
            )
            _http_json(card_url, headers=auth_headers, timeout=60)
        time.sleep(8)
        trace_engs, log_engs, export_errs, metric_engs = _collect_live_telemetry()

    p3_name = "Pillar 3: Live OpenTelemetry Traces & Logs Export Across All 4 Agents"
    traces_ok = len(expected_engine_ids) == 4 and len(trace_engs) == 4
    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3_name,
            title="Cloud Trace OpenTelemetry Spans Exported Across All 4 Agents",
            passed=traces_ok,
            max_points=15,
            earned_points=15 if traces_ok else 0,
            summary=(
                f"Cloud Trace contains live OpenTelemetry spans from all 4 Reasoning Engines ({trace_engs})."
                if traces_ok
                else f"Cloud Trace spans found for {len(trace_engs)}/4 Reasoning Engines ({trace_engs}, expected {expected_engine_ids})."
            ),
            evidence={
                "expected_reasoning_engine_ids": expected_engine_ids,
                "engines_with_cloud_trace_spans": trace_engs,
            },
        )
    )

    logs_ok = len(expected_engine_ids) == 4 and len(log_engs) == 4 and len(export_errs) == 0
    checks.append(
        make_check(
            check_id="3.2",
            pillar=p3_name,
            title="Cloud Logging OpenTelemetry GenAI Events (`gen_ai.client.inference.operation.details`) Exported Across All 4 Agents",
            passed=logs_ok,
            max_points=10,
            earned_points=10 if logs_ok else 0,
            summary=(
                f"All 4 Reasoning Engines ({log_engs}) emitted structured `gen_ai.client.inference.operation.details` OpenTelemetry log events with zero export errors."
                if logs_ok
                else f"OTel GenAI log events found for {len(log_engs)}/4 engines ({log_engs}), export_errors={len(export_errs)}."
            ),
            evidence={
                "expected_reasoning_engine_ids": expected_engine_ids,
                "engines_with_otel_genai_logs": log_engs,
                "recent_export_errors": export_errs,
            },
        )
    )

    print("[5/6] Checking Goal 2 / Step 4: Live OpenTelemetry Metrics Export Across All 4 Agents...")
    p4_name = "Pillar 4: Live OpenTelemetry Metrics Export Across All 4 Agents"
    metrics_ok = len(expected_engine_ids) == 4 and len(metric_engs) == 4
    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4_name,
            title="Cloud Monitoring OpenTelemetry GenAI Histograms (`gen_ai.client.token.usage`, `gen_ai.invoke_agent.duration`) Exported Across All 4 Agents",
            passed=metrics_ok,
            max_points=25,
            earned_points=25 if metrics_ok else 0,
            summary=(
                f"Cloud Monitoring reported active OpenTelemetry GenAI histogram time series across all 4 Reasoning Engines ({metric_engs})."
                if metrics_ok
                else f"Cloud Monitoring GenAI metrics found for {len(metric_engs)}/4 Reasoning Engines ({metric_engs}, expected {expected_engine_ids})."
            ),
            evidence={
                "expected_reasoning_engine_ids": expected_engine_ids,
                "engines_with_cloud_monitoring_metrics": metric_engs,
                "verified_metric_types": [
                    "prometheus.googleapis.com/gen_ai.client.token.usage/histogram",
                    "prometheus.googleapis.com/gen_ai.client.operation.duration/histogram",
                    "prometheus.googleapis.com/gen_ai.invoke_agent.duration/histogram",
                ],
            },
        )
    )

    return checks


def run_goal_3_agent_identities_checks(
    project_id: str, auth_headers: Dict[str, str], repo_root: Path
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []

    # Fetch Vertex AI Reasoning Engines
    url_re = (
        f"https://us-central1-aiplatform.googleapis.com/v1beta1/projects/{project_id}"
        f"/locations/us-central1/reasoningEngines"
    )
    st_re, data_re, _ = _http_json(url_re, headers=auth_headers)
    engines_by_name: Dict[str, Dict[str, Any]] = {}
    if st_re == 200 and isinstance(data_re, dict):
        for eng in data_re.get("reasoningEngines", []):
            disp = eng.get("displayName", "")
            if disp and disp not in engines_by_name:
                engines_by_name[disp] = eng

    # Step 1: Vertex AI Agent Identity Provisioning on All 4 Engines (30 pts)
    print("[2/6] Checking Goal 3 / Step 1: Vertex AI Agent Identity Provisioning on All 4 Engines...")
    p1_name = "Pillar 1: Vertex AI Agent Identity Provisioning on All 4 Engines"

    agent_id_types: Dict[str, str] = {}
    agent_eff_ids: Dict[str, str] = {}
    agent_sas: Dict[str, Any] = {}
    engine_ids: Dict[str, str] = {}

    for agent_name in EXPECTED_AGENTS:
        eng = engines_by_name.get(agent_name, {})
        spec = eng.get("spec", {}) if isinstance(eng, dict) else {}
        agent_id_types[agent_name] = spec.get("identityType", "")
        agent_eff_ids[agent_name] = spec.get("effectiveIdentity", "")
        agent_sas[agent_name] = spec.get("serviceAccount")
        res_name = eng.get("name", "")
        engine_ids[agent_name] = res_name.split("/")[-1] if "/" in res_name else res_name

    # Check 1.1: Vertex AI Reasoning Engines Identity Type Configured as AGENT_IDENTITY (15 pts)
    all_id_type_ok = (
        len(engines_by_name) >= 4
        and all(agent_id_types.get(a) == "AGENT_IDENTITY" for a in EXPECTED_AGENTS)
    )
    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1_name,
            title="Vertex AI Reasoning Engines Identity Type Configured as AGENT_IDENTITY on All 4 Engines",
            passed=all_id_type_ok,
            max_points=15,
            earned_points=15 if all_id_type_ok else 0,
            summary=(
                "All 4 Vertex AI Reasoning Engines (`banking_agent`, `investment_agent`, `insurance_agent`, `financial_assistant_agent`) have `spec.identityType == 'AGENT_IDENTITY'`."
                if all_id_type_ok
                else f"One or more agents do not have identityType 'AGENT_IDENTITY': {agent_id_types}."
            ),
            evidence={
                "expected_agents": EXPECTED_AGENTS,
                "agent_identity_types": agent_id_types,
                "reasoning_engine_ids": engine_ids,
            },
        )
    )

    # Check 1.2: Dedicated SPIFFE Effective Identity Active & Disassociated from Service Accounts (15 pts)
    all_eff_ok = (
        len(engines_by_name) >= 4
        and all(
            bool(agent_eff_ids.get(a))
            and ("system.id.goog" in agent_eff_ids.get(a, "") or "agents.global" in agent_eff_ids.get(a, ""))
            and not agent_sas.get(a)
            for a in EXPECTED_AGENTS
        )
    )
    checks.append(
        make_check(
            check_id="1.2",
            pillar=p1_name,
            title="Dedicated SPIFFE Effective Identity Active & Disassociated from Service Accounts",
            passed=all_eff_ok,
            max_points=15,
            earned_points=15 if all_eff_ok else 0,
            summary=(
                "All 4 Reasoning Engines have active SPIFFE effective identities and empty/null `spec.serviceAccount` attributes."
                if all_eff_ok
                else f"One or more agents missing valid effective identity or have serviceAccount assigned: eff_ids={agent_eff_ids}, sas={agent_sas}."
            ),
            evidence={
                "effective_identities": agent_eff_ids,
                "service_accounts": agent_sas,
            },
        )
    )

    # Step 2: Terraform Infrastructure Definition & IaC Conformance (20 pts)
    print("[3/6] Checking Goal 3 / Step 2: Terraform Infrastructure Definition & IaC Conformance...")
    p2_name = "Pillar 2: Terraform Infrastructure Definition & IaC Conformance"

    tf_path = repo_root / "terraform" / "agents.tf"
    tf_content = tf_path.read_text(encoding="utf-8") if tf_path.is_file() else ""
    modules_id_type: Dict[str, bool] = {}
    modules_sa_null: Dict[str, bool] = {}
    for mod in ["banking", "investment", "insurance", "root"]:
        m = re.search(r'module\s+"' + mod + r'"\s*\{(.*?)\n\}', tf_content, re.DOTALL)
        if m:
            block = m.group(1)
            modules_id_type[mod] = bool(re.search(r'identity_type\s*=\s*"AGENT_IDENTITY"', block))
            modules_sa_null[mod] = bool(re.search(r'service_account\s*=\s*null', block))
        else:
            modules_id_type[mod] = False
            modules_sa_null[mod] = False

    # Check 2.1: Terraform agents module identity_type = "AGENT_IDENTITY" (10 pts)
    iac_id_type_ok = tf_path.is_file() and all(modules_id_type.values()) and len(modules_id_type) == 4
    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2_name,
            title="Terraform Agents Module Definition Declares identity_type = 'AGENT_IDENTITY'",
            passed=iac_id_type_ok,
            max_points=10,
            earned_points=10 if iac_id_type_ok else 0,
            summary=(
                "Terraform configuration (`terraform/agents.tf`) declares `identity_type = 'AGENT_IDENTITY'` across all 4 agent modules (`module.banking`, `module.investment`, `module.insurance`, `module.root`)."
                if iac_id_type_ok
                else f"Terraform configuration missing AGENT_IDENTITY in one or more modules: {modules_id_type}."
            ),
            evidence={
                "terraform_file": str(tf_path.relative_to(repo_root) if tf_path.is_file() else tf_path),
                "modules_identity_type": modules_id_type,
            },
        )
    )

    # Check 2.2: Terraform agents module service_account = null (10 pts)
    iac_sa_null_ok = tf_path.is_file() and all(modules_sa_null.values()) and len(modules_sa_null) == 4
    checks.append(
        make_check(
            check_id="2.2",
            pillar=p2_name,
            title="Terraform Agents Module Definition Eliminates Assigned Service Accounts (service_account = null)",
            passed=iac_sa_null_ok,
            max_points=10,
            earned_points=10 if iac_sa_null_ok else 0,
            summary=(
                "Terraform configuration (`terraform/agents.tf`) sets `service_account = null` across all 4 agent modules, removing shared service account assignment."
                if iac_sa_null_ok
                else f"Terraform configuration does not set service_account = null across all modules: {modules_sa_null}."
            ),
            evidence={
                "terraform_file": str(tf_path.relative_to(repo_root) if tf_path.is_file() else tf_path),
                "modules_service_account_null": modules_sa_null,
            },
        )
    )

    # Step 3: Shared Service Account Elimination at Runtime (25 pts)
    print("[4/6] Checking Goal 3 / Step 3: Shared Service Account Elimination at Runtime...")
    p3_name = "Pillar 3: Shared Service Account Elimination at Runtime"

    target_sa = f"sa-financial-assistant@{project_id}.iam.gserviceaccount.com"
    sa_decoupled = (
        len(engines_by_name) >= 4
        and all(
            not agent_sas.get(a) and target_sa not in agent_eff_ids.get(a, "")
            for a in EXPECTED_AGENTS
        )
    )
    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3_name,
            title="Shared Runtime Service Account (`sa-financial-assistant`) Decoupled from All Agent Runtimes",
            passed=sa_decoupled,
            max_points=15,
            earned_points=15 if sa_decoupled else 0,
            summary=(
                f"Shared runtime service account (`{target_sa}`) has been completely decoupled from the execution identity of all 4 Reasoning Engines."
                if sa_decoupled
                else f"Shared runtime service account (`{target_sa}`) is still assigned or present in effective identities."
            ),
            evidence={
                "target_service_account": target_sa,
                "verified_agents": EXPECTED_AGENTS,
                "runtime_service_accounts": agent_sas,
            },
        )
    )

    unique_eff_ids = set(agent_eff_ids.get(a, "") for a in EXPECTED_AGENTS if agent_eff_ids.get(a))
    unique_identities_ok = len(unique_eff_ids) == 4
    checks.append(
        make_check(
            check_id="3.2",
            pillar=p3_name,
            title="Per-Agent Cryptographic Identity Segregation & Unique Principals Enforced",
            passed=unique_identities_ok,
            max_points=10,
            earned_points=10 if unique_identities_ok else 0,
            summary=(
                f"All 4 Reasoning Engines operate under distinct, unique cryptographic effective identity principals ({len(unique_eff_ids)}/4 unique), establishing per-agent identity isolation."
                if unique_identities_ok
                else f"Effective identities are not unique across all 4 agents: found {len(unique_eff_ids)} distinct principals."
            ),
            evidence={
                "unique_principal_count": len(unique_eff_ids),
                "principals": sorted(list(unique_eff_ids)),
            },
        )
    )

    # Step 4: Agent Identity Deployment Health & Runtime Inspection (25 pts)
    print("[5/6] Checking Goal 3 / Step 4: Agent Identity Deployment Health & Runtime Inspection...")
    p4_name = "Pillar 4: Agent Identity Deployment Health & Runtime Inspection"

    all_healthy = (
        len(engines_by_name) >= 4
        and all(
            bool(engines_by_name.get(a, {}).get("createTime"))
            and bool(engines_by_name.get(a, {}).get("spec", {}).get("classMethods"))
            for a in EXPECTED_AGENTS
        )
    )
    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4_name,
            title="Live Vertex AI Reasoning Engine Resource Health & Active State across All 4 Agents",
            passed=all_healthy,
            max_points=15,
            earned_points=15 if all_healthy else 0,
            summary=(
                "All 4 Vertex AI Reasoning Engines are active, verified with valid update/create timestamps and registered ADK runtime class methods."
                if all_healthy
                else "One or more Reasoning Engines are missing or not healthy in Vertex AI."
            ),
            evidence={
                "engine_status": {
                    a: {
                        "createTime": engines_by_name.get(a, {}).get("createTime", ""),
                        "updateTime": engines_by_name.get(a, {}).get("updateTime", ""),
                        "classMethods_count": len(engines_by_name.get(a, {}).get("spec", {}).get("classMethods", [])),
                    }
                    for a in EXPECTED_AGENTS
                }
            },
        )
    )

    # Check 4.2: Web UI Service Binding to Agent-Identity-Backed Root Engine (10 pts)
    url_run = f"https://run.googleapis.com/v2/projects/{project_id}/locations/us-central1/services/financial-companion-ui"
    st_run, data_run, _ = _http_json(url_run, headers=auth_headers)
    ui_uri = data_run.get("uri", "") if st_run == 200 and isinstance(data_run, dict) else ""
    config_ok = False
    cfg_data: Dict[str, Any] = {}
    root_engine_id = engine_ids.get("financial_assistant_agent", "")
    if ui_uri:
        st_cfg, cfg_data, _ = _http_json(f"{ui_uri}/api/config", timeout=30)
        config_ok = (
            st_cfg == 200
            and isinstance(cfg_data, dict)
            and cfg_data.get("liveMode") is True
            and root_engine_id in str(cfg_data.get("vertexResourceName", ""))
        )

    checks.append(
        make_check(
            check_id="4.2",
            pillar=p4_name,
            title="Web UI Service Binding to Agent-Identity-Backed Root Engine (`financial-companion-ui` /api/config)",
            passed=config_ok,
            max_points=10,
            earned_points=10 if config_ok else 0,
            summary=(
                f"Cloud Run Web UI (`{ui_uri}`) is live, healthy, and confirmed bound to Agent-Identity-backed root engine `{root_engine_id}`."
                if config_ok
                else f"Web UI configuration check failed: ui_uri={ui_uri}, config={cfg_data}."
            ),
            evidence={
                "ui_uri": ui_uri,
                "root_engine_id": root_engine_id,
                "config_response": cfg_data,
            },
        )
    )

    return checks


def run_goal_5_eval_checks(repo_root: Path) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []

    # Step 1: Evaluation Suite & Dataset Verification (20 pts)
    p1_name = "Pillar 1: Evaluation Suite & Dataset Verification"
    dataset_path = repo_root / "eval" / "eval_dataset.json"
    runner_path = repo_root / "eval" / "run_eval.py"

    dataset_exists = dataset_path.is_file()
    runner_exists = runner_path.is_file()

    case_count = 0
    categories: Set[str] = set()
    if dataset_exists:
        try:
            raw = json.loads(dataset_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                raw_cases = raw.get("test_cases") or raw.get("cases") or []
            elif isinstance(raw, list):
                raw_cases = raw
            else:
                raw_cases = []

            if isinstance(raw_cases, list):
                case_count = len(raw_cases)
                for c in raw_cases:
                    if isinstance(c, dict) and "category" in c:
                        categories.add(str(c["category"]))
        except Exception:
            pass

    has_min_cases = case_count >= 8
    has_pii = any("pii" in c.lower() for c in categories)
    has_deputy = any("confused" in c.lower() or "deputy" in c.lower() for c in categories)
    has_isolation = any(k in c.lower() for c in categories for k in ["cross", "tenant", "idor", "lateral"])
    has_functional = any("functional" in c.lower() or "baseline" in c.lower() for c in categories)

    has_categories = has_pii and has_deputy and has_isolation and has_functional
    step1_ok = bool(dataset_exists and runner_exists and has_min_cases and has_categories)

    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1_name,
            title="Automated Evaluation Suite & Security Evaluation Dataset",
            passed=step1_ok,
            max_points=20,
            earned_points=20 if step1_ok else 0,
            summary=(
                f"Evaluation dataset `{dataset_path.name}` ({case_count} cases across {len(categories)} categories) and judge runner `{runner_path.name}` verified."
                if step1_ok
                else (
                    f"Evaluation suite incomplete (dataset_exists={dataset_exists}, runner_exists={runner_exists}, "
                    f"cases={case_count}/8, categories={sorted(list(categories))})."
                )
            ),
            evidence={
                "dataset_path": str(dataset_path),
                "runner_path": str(runner_path),
                "total_cases": case_count,
                "categories": sorted(list(categories)),
                "has_min_cases": has_min_cases,
                "has_categories": has_categories,
            },
        )
    )

    # Step 2: Pre-Hardening Baseline Evaluation Artifact (25 pts)
    p2_name = "Pillar 2: Pre-Hardening Baseline Evaluation Artifact"
    baseline_candidates = [
        repo_root / "eval_baseline.json",
        repo_root / "eval" / "eval_baseline.json",
    ]
    baseline_path = next((p for p in baseline_candidates if p.is_file()), None)

    base_score_pct = 0.0
    base_cases_evaluated = 0
    base_passed = 0
    base_failed = 0
    baseline_valid = False

    if baseline_path:
        try:
            base_data = json.loads(baseline_path.read_text(encoding="utf-8"))
            base_score_pct = float(base_data.get("score_percentage", 0.0))
            base_cases_evaluated = int(base_data.get("total_cases", 0))
            base_passed = int(base_data.get("passed_cases", 0))
            base_failed = int(base_data.get("failed_cases", 0))
            baseline_valid = (
                base_cases_evaluated >= 8
                and base_score_pct <= 55.0  # Confirms baseline captured the initial vulnerable system state
            )
        except Exception:
            pass

    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2_name,
            title="Pre-Hardening Baseline Multi-Agent Security Profile",
            passed=baseline_valid,
            max_points=25,
            earned_points=25 if baseline_valid else (10 if baseline_path else 0),
            summary=(
                f"Pre-hardening baseline `{baseline_path.name if baseline_path else ''}` recorded with {base_score_pct}% pass rate ({base_passed}/{base_cases_evaluated} passed, {base_failed} vulnerabilities detected)."
                if baseline_valid
                else (
                    f"Baseline report `{baseline_path.name}` score {base_score_pct}% did not reflect expected vulnerable baseline (<= 55.0%)."
                    if baseline_path
                    else "Missing `eval_baseline.json`. Run `./eval/run_eval.py --output eval_baseline.json` against the initial environment."
                )
            ),
            evidence={
                "baseline_file": str(baseline_path) if baseline_path else None,
                "score_percentage": base_score_pct,
                "total_cases": base_cases_evaluated,
                "passed_cases": base_passed,
                "failed_cases": base_failed,
            },
        )
    )

    # Step 3: Post-Hardening Evaluation & Security Uplift (40 pts)
    p3_name = "Pillar 3: Post-Hardening Evaluation & Security Uplift"
    remediated_candidates = [
        repo_root / "eval_post_hardening.json",
        repo_root / "eval" / "eval_post_hardening.json",
        repo_root / "eval_remediated.json",
        repo_root / "eval" / "eval_remediated.json",
    ]
    remediated_path = next((p for p in remediated_candidates if p.is_file()), None)

    rem_score_pct = 0.0
    rem_data: Dict[str, Any] = {}
    uplift = 0.0

    rem_results_map: Dict[str, Dict[str, Any]] = {}
    if remediated_path:
        try:
            rem_data = json.loads(remediated_path.read_text(encoding="utf-8"))
            rem_score_pct = float(rem_data.get("score_percentage", 0.0))
            uplift = round(rem_score_pct - base_score_pct, 1)
            for r in rem_data.get("results", []):
                if isinstance(r, dict) and "id" in r:
                    rem_results_map[str(r["id"])] = r
        except Exception:
            pass

    # Check 3.1: Remediated Score Threshold >= 90% (25 pts)
    check31_ok = bool(remediated_path and rem_score_pct >= 90.0)
    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3_name,
            title="Post-Hardening Multi-Agent Security Score Threshold (>= 90%)",
            passed=check31_ok,
            max_points=25,
            earned_points=25 if check31_ok else (10 if remediated_path else 0),
            summary=(
                f"Post-hardening evaluation `{remediated_path.name if remediated_path else ''}` achieved {rem_score_pct}% pass rate ({rem_data.get('passed_cases', 0)}/{rem_data.get('total_cases', 0)} cases passed)."
                if check31_ok
                else (
                    f"Post-hardening score {rem_score_pct}% is below the 90.0% passing threshold."
                    if remediated_path
                    else "Missing post-hardening evaluation report. Run `./eval/run_eval.py --compare eval_baseline.json --output eval_post_hardening.json`."
                )
            ),
            evidence={
                "remediated_file": str(remediated_path) if remediated_path else None,
                "score_percentage": rem_score_pct,
                "passed_cases": rem_data.get("passed_cases", 0),
                "total_cases": rem_data.get("total_cases", 0),
            },
        )
    )

    # Check 3.2: Measured Security Uplift & Attack Neutralization (15 pts)
    def _check_case_passed(pattern: str) -> bool:
        for cid, r in rem_results_map.items():
            if pattern in cid:
                return bool(r.get("passed", False))
        return False

    confused_deputy_blocked = _check_case_passed("confused") or _check_case_passed("case-05")
    xfer_blocked = _check_case_passed("transfer") or _check_case_passed("case-06")
    pii_harvest_blocked = _check_case_passed("pii") or _check_case_passed("harvest") or _check_case_passed("case-07")

    attacks_neutralized = confused_deputy_blocked and xfer_blocked and pii_harvest_blocked
    check32_ok = check31_ok and (uplift >= 50.0 or attacks_neutralized)
    checks.append(
        make_check(
            check_id="3.2",
            pillar=p3_name,
            title="Security Uplift (+50% Delta) & Lateral Attack Neutralization",
            passed=check32_ok,
            max_points=15,
            earned_points=15 if check32_ok else 0,
            summary=(
                f"Demonstrated a +{uplift}% security score uplift; Confused Deputy, cross-client transfer, and PII harvesting attacks are neutralized."
                if check32_ok
                else f"Insufficient uplift (+{uplift}%) or attacks not fully blocked (confused_deputy={confused_deputy_blocked}, xfer={xfer_blocked}, pii_harvest={pii_harvest_blocked})."
            ),
            evidence={
                "baseline_score": base_score_pct,
                "remediated_score": rem_score_pct,
                "net_uplift": uplift,
                "confused_deputy_blocked": confused_deputy_blocked,
                "cross_client_transfer_blocked": xfer_blocked,
                "cross_client_pii_harvest_blocked": pii_harvest_blocked,
            },
        )
    )

    # Step 4: Zero-Regression Functional Guarantee (15 pts)
    p4_name = "Pillar 4: Zero-Regression Functional Guarantee"
    case3_ok = _check_case_passed("authorized-buy") or _check_case_passed("case-03")
    case4_ok = _check_case_passed("authorized-premium") or _check_case_passed("case-04")
    step4_ok = bool(remediated_path and case3_ok and case4_ok)

    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4_name,
            title="Zero Functional Regressions on Legitimate In-Tenant Operations",
            passed=step4_ok,
            max_points=15,
            earned_points=15 if step4_ok else 0,
            summary=(
                "All legitimate in-tenant operations (authorized NVDA purchase and policy premium payment) executed successfully with 0 regressions."
                if step4_ok
                else f"Functional regression detected on legitimate operations (case_03_authorized_buy={case3_ok}, case_04_authorized_premium={case4_ok})."
            ),
            evidence={
                "case_03_authorized_buy_passed": case3_ok,
                "case_04_authorized_premium_passed": case4_ok,
            },
        )
    )

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Financial Companion lab goal completion and generate a cryptographically attested Markdown report."
    )
    parser.add_argument("--project-id", help="GCP project ID (auto-detected if omitted)", default=None)
    parser.add_argument("--student-id", help="Student email or identifier", default=None)
    parser.add_argument(
        "--lab-id",
        "--lab",
        dest="lab_id",
        help=f"Lab identifier (defaults to '{LAB_METADATA.get('lab_id', 'lab_8')}')",
        default=os.environ.get("ASSESSMENT_LAB_ID") or LAB_METADATA.get("lab_id", "lab_8"),
    )
    parser.add_argument(
        "--goal",
        dest="goal",
        help="Lab goal identifier (auto-selects next uncompleted goal if omitted). Short aliases like '1', 'goal-1', '2', 'goal-2', 'n', or 'goal-n' are also accepted.",
        default=os.environ.get("ASSESSMENT_GOAL_ID") or None,
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run validation even if the target goal has already been validated and completed.",
    )
    parser.add_argument(
        "--list-goals",
        action="store_true",
        help="List all registered lab goals and their steps, then exit.",
    )
    parser.add_argument(
        "--output",
        help="Output Markdown file path (defaults to assessment_report_<goal_id>.md)",
        default=None,
    )
    parser.add_argument(
        "--submit-url",
        help="Optional Web Assessor API endpoint URL (or set ASSESSOR_SUBMIT_URL) to push the report directly.",
        default=os.environ.get("ASSESSOR_SUBMIT_URL", ""),
    )
    parser.add_argument(
        "--enrollment-key",
        help="Cohort enrollment key required when pushing to --submit-url (or set ASSESSOR_ENROLLMENT_KEY). Saved after first use.",
        default=os.environ.get("ASSESSOR_ENROLLMENT_KEY", ""),
    )
    args = parser.parse_args()

    this_file = Path(__file__).resolve()
    if ".agents" in this_file.parts:
        idx = this_file.parts.index(".agents")
        repo_root = Path(*this_file.parts[:idx])
    elif len(this_file.parents) > 1 and this_file.parent.name == "scripts":
        repo_root = this_file.parents[1]
    else:
        repo_root = Path.cwd()
    state = _load_assessment_state(repo_root)

    # Persist any newly provided CLI/env values into state immediately, and load remembered values
    if args.enrollment_key and args.enrollment_key.strip():
        state["enrollment_key"] = args.enrollment_key.strip()
    elif state.get("enrollment_key"):
        args.enrollment_key = str(state["enrollment_key"])

    if args.submit_url and args.submit_url.strip():
        state["submit_url"] = args.submit_url.strip()
    elif state.get("submit_url"):
        args.submit_url = str(state["submit_url"])

    if args.student_id and args.student_id.strip():
        state["student_id"] = args.student_id.strip()
    elif state.get("student_id"):
        args.student_id = str(state["student_id"])

    if args.project_id and args.project_id.strip():
        state["project_id"] = args.project_id.strip()
    elif state.get("project_id"):
        args.project_id = str(state["project_id"])

    _save_assessment_state(repo_root, state)

    if args.list_goals:
        completed_map = state.get("completed_goals") or {}
        enriched = []
        for gid, gdef in GOAL_REGISTRY.items():
            enriched.append({
                **gdef,
                "completed": gid in completed_map,
                "completion_info": completed_map.get(gid),
            })
        print(json.dumps(enriched, indent=2))
        return 0

    explicit_goal_requested = bool(args.goal and str(args.goal).strip())
    if explicit_goal_requested:
        raw_goal = str(args.goal).strip()
        goal_id = GOAL_ALIASES.get(raw_goal, raw_goal)
    else:
        goal_id = _resolve_next_uncompleted_goal(state)
        raw_goal = goal_id

    if goal_id not in GOAL_REGISTRY:
        print(
            f"ERROR: Unknown goal '{raw_goal}'. Valid goals: {', '.join(GOAL_REGISTRY.keys())}",
            file=sys.stderr,
        )
        return 2

    goal_def = GOAL_REGISTRY[goal_id]
    if not goal_def.get("implemented", False):
        print(
            f"ERROR: Goal '{goal_id}' ({goal_def['title']}) verification steps are not yet enabled in this lab version.",
            file=sys.stderr,
        )
        return 2

    completed_goals = state.get("completed_goals") or {}
    if goal_id in completed_goals and not args.force:
        next_goal_id = _resolve_next_uncompleted_goal(state)
        comp_info = completed_goals[goal_id]
        print(
            f"NOTICE: Goal '{goal_id}' ({goal_def['title']}) has already been validated and completed "
            f"({comp_info.get('earned_points', 100)}/{comp_info.get('max_points', 100)} pts, report: {comp_info.get('report_path', '')}).\n"
            f"Per grading policy, completed goals are only re-validated when explicitly requested (--force).\n"
            f"Next goal to evaluate: '{next_goal_id}' ({GOAL_REGISTRY[next_goal_id]['title']})."
        )
        return 0

    goal_number = goal_def["goal_number"]
    goal_title = str(goal_def["title"])
    submission_id = str(uuid.uuid4())

    default_out = f"assessment_report_{goal_id}.md"
    if args.output:
        out_path = Path(args.output)
        if not out_path.is_absolute():
            out_path = (Path.cwd() / out_path).resolve()
    else:
        out_path = (repo_root / default_out).resolve()

    print(f"[1/6] Resolving GCP credentials, project metadata, and student identity for {goal_id}...")
    access_token, token_source = get_access_token()
    project_id = resolve_project_id(args.project_id, repo_root)
    auth_headers = {
        "Authorization": f"Bearer {access_token}",
        "x-goog-user-project": project_id,
    }
    student_info = resolve_student_identity(
        access_token=access_token,
        project_id=project_id,
        auth_headers=auth_headers,
        explicit_student_id=args.student_id,
    )
    project_meta = get_project_metadata(project_id, auth_headers)
    state["project_id"] = project_id
    state["student_id"] = student_info["student_id"]
    _save_assessment_state(repo_root, state)

    print(
        f"      Project: {project_meta['project_id']} (#{project_meta['project_number']}) | "
        f"Goal: {goal_id} | Student: {student_info['student_id']} | "
        f"Principal: {student_info['authenticated_principal_email']} ({token_source})"
    )

    if goal_id == "goal-1-environment-setup":
        all_checks = run_goal_1_checks(project_id, auth_headers)
    elif goal_id == "goal-2-otel-instrumentation":
        all_checks = run_goal_2_otel_checks(project_id, auth_headers, repo_root)
    elif goal_id == "goal-3-agent-identities":
        all_checks = run_goal_3_agent_identities_checks(project_id, auth_headers, repo_root)
    elif goal_id == "goal-5-agent-evals":
        all_checks = run_goal_5_eval_checks(repo_root)
    elif goal_id == "goal-n-remediate-app-vulnerabilities":
        all_checks = run_goal_n_sast_checks(repo_root)
    else:
        all_checks = []

    earned_points = sum(c["earned_points"] for c in all_checks)
    max_points = sum(c["max_points"] for c in all_checks)
    passed_checks = sum(1 for c in all_checks if c["passed"])
    total_checks = len(all_checks)
    pct = round((earned_points / max_points) * 100.0, 1) if max_points else 0.0

    step_breakdown = []
    pillar_breakdown = []
    for step_meta in goal_def.get("steps", []):
        sid = step_meta["step_id"]
        stitle = step_meta["title"]
        pname = step_meta["pillar"]
        s_items = [c for c in all_checks if c.get("step_id") == sid or c.get("pillar") == pname]
        s_passed = sum(1 for c in s_items if c["passed"])
        s_total = len(s_items)
        s_earned = sum(c["earned_points"] for c in s_items)
        s_max = sum(c["max_points"] for c in s_items)
        step_breakdown.append(
            {
                "step_id": sid,
                "step_number": step_meta["step_number"],
                "step_title": stitle,
                "passed_checks": s_passed,
                "total_checks": s_total,
                "earned_points": s_earned,
                "max_points": s_max,
            }
        )
        pillar_breakdown.append(
            {
                "pillar": pname,
                "passed_checks": s_passed,
                "total_checks": s_total,
                "earned_points": s_earned,
                "max_points": s_max,
            }
        )

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    ts_unix = int(now_dt.timestamp())
    ts_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    lab_id = (getattr(args, "lab_id", None) or LAB_METADATA.get("lab_id", "lab_8")).strip()
    lab_number = int(LAB_METADATA.get("lab_number", 8))
    lab_title = str(LAB_METADATA.get("title", "Capstone Project - Architecting Security & Governance For Financial Companion"))

    goals_breakdown = [
        {
            "goal_id": gid,
            "cli_goal_id": gdef.get("goal_id", gid),
            "goal_number": gdef.get("goal_number", idx),
            "title": gdef.get("title", ""),
            "max_points": int(gdef.get("max_points", 100)),
            "steps": [
                {
                    "step_id": s.get("step_id", f"step-{s_idx}"),
                    "step_number": s.get("step_number", s_idx),
                    "title": s.get("title", ""),
                    "max_points": int(s.get("max_points", 0)),
                }
                for s_idx, s in enumerate(gdef.get("steps", []), start=1)
            ],
        }
        for idx, (gid, gdef) in enumerate(GOAL_REGISTRY.items(), start=1)
    ]

    canonical_payload: Dict[str, Any] = {
        "schema_version": "financial-companion-assessment/v2",
        "metadata": {
            "lab_id": lab_id,
            "lab_number": lab_number,
            "lab_title": lab_title,
            "goal_id": goal_id,
            "goal_number": goal_number,
            "goal_title": goal_title,
            "submission_id": submission_id,
            "generated_at_utc": ts_iso,
            "generated_at_unix": ts_unix,
            "credential_source": token_source,
        },
        "student_identity": student_info,
        "project": project_meta,
        "summary": {
            "lab_id": lab_id,
            "goal_id": goal_id,
            "earned_points": earned_points,
            "max_points": max_points,
            "percentage": pct,
            "passed_checks": passed_checks,
            "total_checks": total_checks,
            "overall_status": "PASS" if earned_points == max_points else "PARTIAL" if earned_points >= 70 else "FAIL",
            "step_breakdown": step_breakdown,
            "pillar_breakdown": pillar_breakdown,
        },
        "checks": all_checks,
    }

    # Deterministic canonical serialization for SHA-256 hashing
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    pretty_canonical_json = json.dumps(canonical_payload, indent=2, sort_keys=True)

    print("[6/6] Minting Google-signed RS256 OIDC attestation JWT & writing Markdown report...")
    attestation = mint_google_signed_attestation_jwt(
        project_id=project_id,
        auth_headers=auth_headers,
        student_id=student_info["student_id"],
        principal_email=student_info["authenticated_principal_email"],
        goal_id=goal_id,
        submission_id=submission_id,
        earned_points=earned_points,
        max_points=max_points,
        payload_sha256=payload_sha256,
        timestamp_unix=ts_unix,
        lab_id=lab_id,
    )

    md_content = render_markdown_report(
        canonical_payload=canonical_payload,
        canonical_json_str=pretty_canonical_json,
        payload_sha256=payload_sha256,
        attestation=attestation,
    )
    out_path.write_text(md_content, encoding="utf-8")

    state["lab_id"] = lab_id
    if earned_points == max_points and max_points > 0:
        state.setdefault("completed_goals", {})[goal_id] = {
            "completed_at_utc": ts_iso,
            "earned_points": earned_points,
            "max_points": max_points,
            "report_path": out_path.name,
        }
    _save_assessment_state(repo_root, state)

    print("")
    print("=" * 76)
    print(f"GOAL VERIFICATION COMPLETE: {earned_points}/{max_points} pts ({pct}%) — {passed_checks}/{total_checks} checks passed")
    print(f"Assessed Lab      : {lab_id} ({lab_title})")
    print(f"Assessed Goal     : {goal_id} ({goal_title})")
    print(f"Submission Nonce  : {submission_id}")
    print(f"Student Principal : {student_info['authenticated_principal_email']}")
    print(f"GCP Project       : {project_meta['project_id']} (#{project_meta['project_number']})")
    print(f"Payload SHA-256   : {payload_sha256}")
    print(f"Attestation Status: {attestation.get('status')} (Google OIDC verified={attestation.get('google_tokeninfo_verified')})")
    print(f"Markdown Report   : {out_path}")

    submit_url = (args.submit_url or "").strip()
    if submit_url:
        enrollment_key = (args.enrollment_key or "").strip()
        if not enrollment_key:
            print(
                "ERROR: `--submit-url` requires `--enrollment-key <COHORT_KEY>` (or `ASSESSOR_ENROLLMENT_KEY` env var) "
                "for Dual-Gate Web Assessor authentication.",
                file=sys.stderr,
            )
            return 2
        print(f"Submitting Goal report directly to Web Assessor ({submit_url})...")
        sub_res = submit_report_to_assessor(
            submit_url=submit_url,
            enrollment_key=enrollment_key,
            canonical_payload=canonical_payload,
            payload_sha256=payload_sha256,
            attestation=attestation,
            md_content=md_content,
        )
        print(f"Web Assessor Push : HTTP {sub_res['http_status']} (accepted={sub_res['accepted']})")
        print(f"Assessor Response : {json.dumps(sub_res['response'])}")
    print("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())
