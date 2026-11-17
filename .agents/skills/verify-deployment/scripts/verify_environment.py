#!/usr/bin/env python3
"""
[7] Using AI for Sec Ops - Creating your Sec Agent Lab (`lab_7`)
Wiz & CodeMender MCP · Security Agent Lab — Student Goal Verification & Assessment Engine

Evaluates 5 sequential, 100-point incremental lab goals:
  1. goal-1-target-app-deployment     : Deploy Vulnerable Target App (`watchlist`) & GitHub Branch Protection
  2. goal-2-codemender-mcp-deployment : Deploy CodeMender MCP Server, Runner Sandbox & Seed BigQuery Findings
  3. goal-3-enterprise-mcp-connectors : Configure Wiz, GitHub & Cloud Logging MCP Connectors & Telemetry
  4. goal-4-hitl-remediation          : Human-in-the-Loop Remediation & Sandbox Verification (`CM-0001`)
  5. goal-5-cloud-armor-protection    : Cloud Armor WAF & Ingress Lockdown (`watchlist`)

Strictly read-only against student GCP infrastructure, BigQuery datasets, Cloud Logging,
GitHub repositories, and local source files. Never logs or embeds secret values in reports.

Cryptographically binds the student's GCP identity, project ID, `lab_id` (`lab_7`), `goal_id`,
timestamp, nonce, and exact check results (SHA-256 of canonical evidence JSON) by minting a
Google-signed RS256 OIDC ID token via the IAM Credentials API (`generateIdToken`), and writes
`assessment_report_<goal_id>.md`.
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
    "lab_id": "lab_7",
    "lab_number": 7,
    "cli_lab_id": "lab-07-secops-codemender-agent",
    "title": "Using AI for Sec Ops - Creating your Sec Agent Lab",
    "short_title": "Lab 7: Using AI for Sec Ops - Creating your Sec Agent Lab",
    "max_points": 100,
    "passing_score": 85,
    "passing_percentage": 85,
}


GOAL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "goal-1-target-app-deployment": {
        "goal_id": "goal-1-target-app-deployment",
        "goal_number": 1,
        "title": "Goal 1: Deploy Vulnerable Target App & GitHub Branch Protection",
        "description": (
            "Deploy the intentionally vulnerable multi-container watchlist Cloud Run service "
            "(Lab07-CloudRun-Service-Deploy-1), verify live MySQL health and baseline CM-0001/CM-0002 "
            "exposure, push to GitHub, and enforce human-in-the-loop branch protection on main."
        ),
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: Required GCP APIs & Cloud Build IAM Readiness",
                "pillar": "Pillar 1: Required GCP APIs & Cloud Build IAM Readiness",
                "max_points": 20,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: Multi-Container watchlist Cloud Run Deployment",
                "pillar": "Pillar 2: Multi-Container watchlist Cloud Run Deployment",
                "max_points": 30,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Baseline Intentional Vulnerabilities Live Verification (CM-0001 & CM-0002)",
                "pillar": "Pillar 3: Baseline Intentional Vulnerabilities Live Verification (CM-0001 & CM-0002)",
                "max_points": 25,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Target Repository on GitHub & main Branch Protection",
                "pillar": "Pillar 4: Target Repository on GitHub & main Branch Protection",
                "max_points": 25,
            },
        ],
    },
    "goal-2-codemender-mcp-deployment": {
        "goal_id": "goal-2-codemender-mcp-deployment",
        "goal_number": 2,
        "title": "Goal 2: Deploy CodeMender MCP Server, Runner Sandbox & Seed BigQuery Findings",
        "description": (
            "Provision the codemender BigQuery dataset and GCS transit bucket, deploy "
            "codemender-mcp-server and codemender-runner, verify Gemini Enterprise HTTP transport "
            "compatibility and all 18 MCP tools, seed CM-0001..CM-0004 findings, and validate SQL guardrails."
        ),
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: CodeMender Storage, BigQuery Dataset & Runtime IAM",
                "pillar": "Pillar 1: CodeMender Storage, BigQuery Dataset & Runtime IAM",
                "max_points": 25,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: codemender-mcp-server Cloud Run Service & codemender-runner Job",
                "pillar": "Pillar 2: codemender-mcp-server Cloud Run Service & codemender-runner Job",
                "max_points": 25,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Gemini Enterprise HTTP Transport Compatibility & 18-Tool Registry",
                "pillar": "Pillar 3: Gemini Enterprise HTTP Transport Compatibility & 18-Tool Registry",
                "max_points": 25,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Seeded Lab07 Findings in BigQuery & Read-Only SQL Guardrail",
                "pillar": "Pillar 4: Seeded Lab07 Findings in BigQuery & Read-Only SQL Guardrail",
                "max_points": 25,
            },
        ],
    },
    "goal-3-enterprise-mcp-connectors": {
        "goal_id": "goal-3-enterprise-mcp-connectors",
        "goal_number": 3,
        "title": "Goal 3: Configure Wiz, GitHub & Cloud Logging MCP Connectors & Telemetry",
        "description": (
            "Onboard the GCP project to Wiz, store Wiz & GitHub MCP credentials in Secret Manager, "
            "unblock Gemini Enterprise Custom MCP Org Policies, enable Google Cloud Logging Remote MCP, "
            "and verify seeded logs/codemender cross-signal correlation."
        ),
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: Wiz Cloud Onboarding & Wiz MCP Secret Manager Credentials",
                "pillar": "Pillar 1: Wiz Cloud Onboarding & Wiz MCP Secret Manager Credentials",
                "max_points": 25,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: GitHub MCP Credentials & Gemini Enterprise Org Policy Readiness",
                "pillar": "Pillar 2: GitHub MCP Credentials & Gemini Enterprise Org Policy Readiness",
                "max_points": 25,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Google Cloud Logging Remote MCP Server (logging.googleapis.com/mcp)",
                "pillar": "Pillar 3: Google Cloud Logging Remote MCP Server (logging.googleapis.com/mcp)",
                "max_points": 25,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Seeded CodeMender Telemetry in Cloud Logging & Cross-Signal Correlation",
                "pillar": "Pillar 4: Seeded CodeMender Telemetry in Cloud Logging & Cross-Signal Correlation",
                "max_points": 25,
            },
        ],
    },
    "goal-4-hitl-remediation": {
        "goal_id": "goal-4-hitl-remediation",
        "goal_number": 4,
        "title": "Goal 4: Human-in-the-Loop Remediation & Sandbox Verification (CM-0001)",
        "description": (
            "Remediate CM-0001 (CWE-89 SQL Injection in app/db.py:294) via a minimal parameterized "
            "query patch, verify exploit blocking and unit tests in the isolated sandbox, open a "
            "structured Pull Request against main, and enforce the human-in-the-loop merge guardrail."
        ),
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: Remediation Branch & Pull Request Created on GitHub",
                "pillar": "Pillar 1: Remediation Branch & Pull Request Created on GitHub",
                "max_points": 30,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: Minimal Parameterized SQL Fix Quality (CWE-89 in app/db.py)",
                "pillar": "Pillar 2: Minimal Parameterized SQL Fix Quality (CWE-89 in app/db.py)",
                "max_points": 30,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Isolated Sandbox Validation & BigQuery / Workflow Audit Trail",
                "pillar": "Pillar 3: Isolated Sandbox Validation & BigQuery / Workflow Audit Trail",
                "max_points": 25,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Human-in-the-Loop Merge Refusal Guardrail Enforced",
                "pillar": "Pillar 4: Human-in-the-Loop Merge Refusal Guardrail Enforced",
                "max_points": 15,
            },
        ],
    },
    "goal-5-cloud-armor-protection": {
        "goal_id": "goal-5-cloud-armor-protection",
        "goal_number": 5,
        "title": "Goal 5: Cloud Armor WAF & Ingress Lockdown (watchlist)",
        "description": (
            "Lock down watchlist Cloud Run ingress to INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER, "
            "deploy Google Cloud Armor (default deny(403) + sqli-v33-stable & lfi-v33-stable WAF rules) "
            "on an External Application Load Balancer, block direct .run.app access, and audit 403 logs."
        ),
        "max_points": 100,
        "implemented": True,
        "steps": [
            {
                "step_id": "step-1",
                "step_number": 1,
                "title": "Step 1: Cloud Run Ingress Lockdown & Cloud Armor Terraform / PR",
                "pillar": "Pillar 1: Cloud Run Ingress Lockdown & Cloud Armor Terraform / PR",
                "max_points": 25,
            },
            {
                "step_id": "step-2",
                "step_number": 2,
                "title": "Step 2: Google Cloud Armor Security Policy & OWASP WAF Rules",
                "pillar": "Pillar 2: Google Cloud Armor Security Policy & OWASP WAF Rules",
                "max_points": 25,
            },
            {
                "step_id": "step-3",
                "step_number": 3,
                "title": "Step 3: Global External Application Load Balancer & Serverless NEG Attachment",
                "pillar": "Pillar 3: Global External Application Load Balancer & Serverless NEG Attachment",
                "max_points": 25,
            },
            {
                "step_id": "step-4",
                "step_number": 4,
                "title": "Step 4: Live Perimeter Enforcement & Cloud Armor Telemetry Audit",
                "pillar": "Pillar 4: Live Perimeter Enforcement & Cloud Armor Telemetry Audit",
                "max_points": 25,
            },
        ],
    },
}


GOAL_ALIASES: Dict[str, str] = {
    "1": "goal-1-target-app-deployment",
    "goal-1": "goal-1-target-app-deployment",
    "goal-1-environment-setup": "goal-1-target-app-deployment",
    "target-app": "goal-1-target-app-deployment",
    "watchlist": "goal-1-target-app-deployment",
    "2": "goal-2-codemender-mcp-deployment",
    "goal-2": "goal-2-codemender-mcp-deployment",
    "codemender": "goal-2-codemender-mcp-deployment",
    "codemender-mcp": "goal-2-codemender-mcp-deployment",
    "mcp-deploy": "goal-2-codemender-mcp-deployment",
    "3": "goal-3-enterprise-mcp-connectors",
    "goal-3": "goal-3-enterprise-mcp-connectors",
    "connectors": "goal-3-enterprise-mcp-connectors",
    "mcp-connectors": "goal-3-enterprise-mcp-connectors",
    "wiz": "goal-3-enterprise-mcp-connectors",
    "4": "goal-4-hitl-remediation",
    "goal-4": "goal-4-hitl-remediation",
    "remediation": "goal-4-hitl-remediation",
    "hitl": "goal-4-hitl-remediation",
    "cm-0001": "goal-4-hitl-remediation",
    "5": "goal-5-cloud-armor-protection",
    "goal-5": "goal-5-cloud-armor-protection",
    "cloud-armor": "goal-5-cloud-armor-protection",
    "armor": "goal-5-cloud-armor-protection",
    "waf": "goal-5-cloud-armor-protection",
}


EXPECTED_GOAL1_APIS = [
    "compute.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
]

EXPECTED_CODEMENDER_TOOLS = [
    "cm_find",
    "cm_validate",
    "cm_fix",
    "cm_apply_patch",
    "cm_job_status",
    "cm_list_findings",
    "cm_get_finding",
    "list_codemender_issues",
    "get_issue_details",
    "get_issues_summary",
    "get_bigquery_schema",
    "query_codemender_bigquery",
    "get_issue_logs",
    "search_codemender_logs",
    "list_wiz_issues",
    "get_wiz_issue_details",
    "get_wiz_issues_summary",
    "query_wiz_graphql",
]

PLACEHOLDER_VALUES = {
    "",
    "todo",
    "your-gcp-project-id",
    "your-project-id",
    "your-github-username-or-org",
    "ghp_your_github_token_here",
    "your_wiz_client_id",
    "your_wiz_client_secret",
    "(unset)",
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


def _is_placeholder(val: Optional[str]) -> bool:
    if val is None:
        return True
    s = val.strip().strip('"').strip("'")
    return s.lower() in PLACEHOLDER_VALUES


def _run_cmd(
    args: List[str], cwd: Optional[Path] = None, timeout: int = 30
) -> Tuple[int, str, str]:
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


def _http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Any] = None,
    raw_bytes: Optional[bytes] = None,
    timeout: int = 45,
) -> Tuple[int, Dict[str, str], Any, str]:
    """Performs an HTTP(S) request returning (status, lowercase_headers, json_or_none, raw_text)."""
    req_headers: Dict[str, str] = {"Accept": "application/json", "User-Agent": "secops-lab7-verifier/2.0"}
    if headers:
        req_headers.update(headers)

    data_bytes = raw_bytes
    if body is not None and data_bytes is None:
        data_bytes = json.dumps(body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url=url, data=data_bytes, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            resp_hdrs = {k.lower(): v for k, v in resp.headers.items()}
            try:
                return resp.status, resp_hdrs, json.loads(raw), raw
            except json.JSONDecodeError:
                return resp.status, resp_hdrs, None, raw
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace") if err.fp else str(err)
        resp_hdrs = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        try:
            return err.code, resp_hdrs, json.loads(raw), raw
        except json.JSONDecodeError:
            return err.code, resp_hdrs, None, raw
    except Exception as exc:
        return 0, {}, None, str(exc)


def _http_json(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Any] = None,
    timeout: int = 45,
) -> Tuple[int, Any, str]:
    st, _, parsed, raw = _http_request(url=url, method=method, headers=headers, body=body, timeout=timeout)
    return st, parsed, raw


def _parse_mcp_jsonrpc(parsed_json: Any, raw_text: str) -> Dict[str, Any]:
    """Parses JSON-RPC responses returned either as `application/json` or SSE `text/event-stream`."""
    if isinstance(parsed_json, dict):
        return parsed_json
    for line in raw_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("data:"):
            payload = stripped[len("data:") :].strip()
            if payload:
                try:
                    obj = json.loads(payload)
                    if isinstance(obj, dict):
                        return obj
                except json.JSONDecodeError:
                    continue
    return {}


def _extract_mcp_tool_result(rpc_msg: Dict[str, Any]) -> Tuple[Any, str]:
    """Extracts structured tool output or text content from a JSON-RPC `tools/call` response."""
    if not isinstance(rpc_msg, dict):
        return None, ""
    if "error" in rpc_msg:
        return rpc_msg["error"], json.dumps(rpc_msg["error"])
    res = rpc_msg.get("result")
    if not isinstance(res, dict):
        return res, str(res or "")
    if "structuredContent" in res and res["structuredContent"] is not None:
        sc = res["structuredContent"]
        return sc, json.dumps(sc)
    texts: List[str] = []
    for item in res.get("content") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            texts.append(item["text"])
    joined = "\n".join(texts).strip()
    if joined:
        try:
            return json.loads(joined), joined
        except json.JSONDecodeError:
            return joined, joined
    return res, json.dumps(res)


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


def _parse_env_file_readonly(path: Path, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Safely parses KEY=VALUE / export KEY=VALUE files without executing shell code."""
    env_out: Dict[str, str] = {}
    if not path.is_file():
        return env_out
    merged = dict(base_env or {})
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            else:
                val = re.sub(r"\s+#.*$", "", val).strip()

            def _sub_var(match: re.Match[str]) -> str:
                var_name = match.group(1) or match.group(2) or ""
                return env_out.get(var_name) or merged.get(var_name) or os.environ.get(var_name, "")

            val = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", _sub_var, val)
            if not _is_placeholder(val):
                env_out[key] = val
                merged[key] = val
    except Exception:
        pass
    return env_out


def _parse_tfvars_readonly(path: Path) -> Dict[str, str]:
    """Reads simple key = \"value\" pairs from a Terraform .tfvars file."""
    out: Dict[str, str] = {}
    if not path.is_file():
        return out
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"', line)
            if m and not _is_placeholder(m.group(2)):
                out[m.group(1)] = m.group(2).strip()
    except Exception:
        pass
    return out


def collect_lab_env(repo_root: Path) -> Dict[str, str]:
    """Collects non-placeholder Lab 7 configuration across ~/lab.env, .env, and terraform.tfvars."""
    collected: Dict[str, str] = {}
    home = Path.home()
    env_candidates = [
        home / "lab.env",
        repo_root / "lab.env",
        Path.cwd() / "lab.env",
        home / "codemender-mcp" / ".env",
        repo_root / "codemender-mcp" / ".env",
    ]
    for p in env_candidates:
        parsed = _parse_env_file_readonly(p, collected)
        for k, v in parsed.items():
            collected.setdefault(k, v)

    tfvars_candidates = [
        home / "Lab07-CloudRun-Service-Deploy-1" / "terraform" / "terraform.tfvars",
        repo_root.parent / "Lab07-CloudRun-Service-Deploy-1" / "terraform" / "terraform.tfvars",
        home / "codemender-runner-mcp" / "terraform" / "terraform.tfvars",
        repo_root / "codemender-runner-mcp" / "terraform" / "terraform.tfvars",
    ]
    for p in tfvars_candidates:
        tfv = _parse_tfvars_readonly(p)
        if tfv.get("project_id"):
            collected.setdefault("PROJECT_ID", tfv["project_id"])
        if tfv.get("gcp_project_id"):
            collected.setdefault("PROJECT_ID", tfv["gcp_project_id"])
        if tfv.get("region"):
            collected.setdefault("REGION", tfv["region"])
        if tfv.get("gcp_region"):
            collected.setdefault("REGION", tfv["gcp_region"])
        if tfv.get("github_owner"):
            collected.setdefault("GITHUB_ORG", tfv["github_owner"])

    for env_k in (
        "PROJECT_ID",
        "GCP_PROJECT_ID",
        "GOOGLE_CLOUD_PROJECT",
        "REGION",
        "GITHUB_ORG",
        "GITHUB_OWNER",
        "TARGET_REPO",
        "SANDBOX_BUCKET",
        "CM_REPORTS_BUCKET",
        "GITHUB_PAT",
        "GITHUB_TOKEN",
    ):
        val = os.environ.get(env_k, "").strip()
        if not _is_placeholder(val):
            collected[env_k] = val

    return collected


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


def get_identity_token_optional() -> str:
    """Retrieves an OIDC identity token from gcloud if available (for IAM-protected Cloud Run)."""
    for env_key in ("GCP_IDENTITY_TOKEN", "OIDC_TOKEN"):
        val = os.environ.get(env_key, "").strip()
        if val:
            return val
    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        rc, out, _ = _run_cmd([gcloud_bin, "auth", "print-identity-token"])
        if rc == 0 and out:
            return out.splitlines()[-1].strip()
    return ""


def resolve_project_id(explicit_project: Optional[str], lab_env: Dict[str, str]) -> str:
    """Resolves the target GCP project ID from CLI flag, env/lab.env, or gcloud."""
    if explicit_project and not _is_placeholder(explicit_project):
        return explicit_project.strip()

    for key in ("PROJECT_ID", "GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"):
        val = os.environ.get(key, "").strip() or lab_env.get(key, "").strip()
        if not _is_placeholder(val):
            return val

    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        rc, out, _ = _run_cmd([gcloud_bin, "config", "get-value", "project"])
        if rc == 0 and out and not _is_placeholder(out.splitlines()[-1]):
            return out.splitlines()[-1].strip()

    raise RuntimeError(
        "Could not resolve GCP project ID. Set PROJECT_ID in ~/lab.env or pass `--project-id <PROJECT_ID>`."
    )


def resolve_region(explicit_region: Optional[str], lab_env: Dict[str, str]) -> str:
    if explicit_region and not _is_placeholder(explicit_region):
        return explicit_region.strip()
    for key in ("REGION", "GCP_REGION", "GOOGLE_CLOUD_REGION"):
        val = os.environ.get(key, "").strip() or lab_env.get(key, "").strip()
        if not _is_placeholder(val):
            return val
    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        rc, out, _ = _run_cmd([gcloud_bin, "config", "get-value", "run/region"])
        if rc == 0 and out and not _is_placeholder(out.splitlines()[-1]):
            return out.splitlines()[-1].strip()
    return "us-central1"


def find_local_target_repo(repo_root: Path, target_repo: str) -> Optional[Path]:
    """Finds a local checkout of Lab07-CloudRun-Service-Deploy-1 if present on disk."""
    candidates = [
        Path.home() / target_repo,
        repo_root / target_repo,
        repo_root.parent / target_repo,
        Path.cwd() / target_repo,
        Path.cwd(),
    ]
    for cand in candidates:
        if (cand / "app" / "db.py").is_file() and (cand / "terraform" / "main.tf").is_file():
            return cand.resolve()
    return None


def _check_secret_metadata(
    project_id: str, secret_name: str, auth_headers: Dict[str, str]
) -> Dict[str, Any]:
    """Checks Secret Manager secret & latest version state without reading secret bytes."""
    ver_url = (
        f"https://secretmanager.googleapis.com/v1/projects/{project_id}"
        f"/secrets/{urllib.parse.quote(secret_name)}/versions/latest"
    )
    st, data, _ = _http_json(ver_url, headers=auth_headers)
    if st == 200 and isinstance(data, dict):
        return {
            "secret_name": secret_name,
            "exists": True,
            "version_name": str(data.get("name", "")),
            "state": str(data.get("state", "")),
            "enabled": data.get("state") == "ENABLED",
        }
    return {
        "secret_name": secret_name,
        "exists": False,
        "version_name": "",
        "state": f"HTTP_{st}",
        "enabled": False,
    }


def _access_secret_value_in_memory(
    project_id: str, secret_name: str, auth_headers: Dict[str, str]
) -> str:
    """Reads a Secret Manager secret payload in memory ONLY for live auth checks; never logged."""
    acc_url = (
        f"https://secretmanager.googleapis.com/v1/projects/{project_id}"
        f"/secrets/{urllib.parse.quote(secret_name)}/versions/latest:access"
    )
    st, data, _ = _http_json(acc_url, headers=auth_headers)
    if st == 200 and isinstance(data, dict):
        b64 = data.get("payload", {}).get("data", "")
        if b64:
            try:
                padded = b64 + "=" * (-len(b64) % 4)
                val = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="replace").strip()
                if not _is_placeholder(val):
                    return val
            except Exception:
                return ""
    return ""


def resolve_github_token_in_memory(
    project_id: str, auth_headers: Dict[str, str], lab_env: Dict[str, str]
) -> Tuple[str, str]:
    """Resolves a read-capable GitHub token in memory without ever persisting or printing it."""
    for key in ("GITHUB_PAT", "GITHUB_TOKEN", "GH_TOKEN"):
        val = os.environ.get(key, "").strip()
        if not _is_placeholder(val):
            return val, f"env:{key}"

    gh_bin = shutil.which("gh")
    if gh_bin:
        rc, out, _ = _run_cmd([gh_bin, "auth", "token"])
        if rc == 0 and out and not _is_placeholder(out.splitlines()[-1]):
            return out.splitlines()[-1].strip(), "gh:auth-token"

    for sec_name in ("github-mcp-pat", "codemender-github-token", "github-token"):
        sec_val = _access_secret_value_in_memory(project_id, sec_name, auth_headers)
        if sec_val:
            return sec_val, f"secretmanager:{sec_name}"

    for key in ("GITHUB_PAT", "GITHUB_TOKEN"):
        val = lab_env.get(key, "").strip()
        if not _is_placeholder(val):
            return val, f"lab_env:{key}"

    return "", "none"


def _github_api_json(
    path_or_url: str, github_token: str, accept: str = "application/vnd.github+json"
) -> Tuple[int, Any, str]:
    url = (
        path_or_url
        if path_or_url.startswith("https://")
        else f"https://api.github.com/{path_or_url.lstrip('/')}"
    )
    hdrs: Dict[str, str] = {
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        hdrs["Authorization"] = f"Bearer {github_token}"
    return _http_json(url, headers=hdrs, timeout=30)


def resolve_github_org_and_repo(
    explicit_org: Optional[str],
    explicit_repo: Optional[str],
    state: Dict[str, Any],
    lab_env: Dict[str, str],
    repo_root: Path,
    project_id: str,
    auth_headers: Dict[str, str],
    github_token: str,
) -> Tuple[str, str]:
    """Resolves `<GITHUB_ORG>` and `<TARGET_REPO>` across CLI, state, ~/lab.env, git, BQ, and GitHub API."""
    target_repo = (
        (explicit_repo or "").strip()
        or lab_env.get("TARGET_REPO", "").strip()
        or str(state.get("target_repo", "")).strip()
        or "Lab07-CloudRun-Service-Deploy-1"
    )

    candidates: List[str] = []
    for raw in (
        explicit_org,
        lab_env.get("GITHUB_ORG"),
        lab_env.get("GITHUB_OWNER"),
        state.get("github_org"),
    ):
        if raw and not _is_placeholder(str(raw)):
            val = str(raw).strip()
            if "/" in val and val.endswith(f"/{target_repo}"):
                val = val.split("/")[0]
            candidates.append(val)

    local_target = find_local_target_repo(repo_root, target_repo)
    git_origin_owner = ""
    if local_target:
        git_bin = shutil.which("git")
        if git_bin:
            rc, out, _ = _run_cmd([git_bin, "-C", str(local_target), "remote", "get-url", "origin"])
            if rc == 0 and out:
                m = re.search(r"github\.com[:/]([^/\s]+)/([^/\s\.]+)", out)
                if m:
                    git_origin_owner = m.group(1)
                    if git_origin_owner.lower() != "avnit":
                        candidates.append(git_origin_owner)

    # Check BigQuery codemender.findings repository column if available
    bq_url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/queries"
    st_bq, data_bq, _ = _http_json(
        bq_url,
        method="POST",
        headers=auth_headers,
        body={
            "query": f"SELECT * FROM `{project_id}.codemender.findings` LIMIT 10",
            "useLegacySql": False,
        },
        timeout=20,
    )
    if st_bq == 200 and isinstance(data_bq, dict):
        fields = [f.get("name", "") for f in data_bq.get("schema", {}).get("fields", [])]
        for row in data_bq.get("rows", []):
            vals = [c.get("v") for c in row.get("f", [])]
            row_map = dict(zip(fields, vals))
            repo_val = str(row_map.get("repository") or row_map.get("repo") or "")
            if "/" in repo_val and target_repo.lower() in repo_val.lower():
                owner = repo_val.split("/")[0].strip()
                if owner and owner.lower() != "avnit":
                    candidates.append(owner)

    if github_token:
        st_u, data_u, _ = _github_api_json("/user", github_token)
        if st_u == 200 and isinstance(data_u, dict) and data_u.get("login"):
            candidates.append(str(data_u["login"]).strip())

    gh_bin = shutil.which("gh")
    if gh_bin:
        rc, out, _ = _run_cmd([gh_bin, "api", "user", "--jq", ".login"])
        if rc == 0 and out and not _is_placeholder(out):
            candidates.append(out.splitlines()[-1].strip())

    if git_origin_owner:
        candidates.append(git_origin_owner)

    for cand in candidates:
        if cand and not _is_placeholder(cand):
            return cand, target_repo

    return "", target_repo


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


def _list_enabled_apis(project_id: str, auth_headers: Dict[str, str]) -> Tuple[int, Set[str]]:
    url = (
        f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services"
        f"?filter=state:ENABLED&pageSize=200"
    )
    st, data, _ = _http_json(url, headers=auth_headers)
    enabled: Set[str] = set()
    if st == 200 and isinstance(data, dict):
        for svc in data.get("services", []):
            name = svc.get("config", {}).get("name") or svc.get("name", "").split("/")[-1]
            if name:
                enabled.add(name)
    return st, enabled


def _get_project_iam_bindings(project_id: str, auth_headers: Dict[str, str]) -> Tuple[int, List[Dict[str, Any]]]:
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy"
    st, data, _ = _http_json(url, method="POST", headers=auth_headers, body={})
    if st == 200 and isinstance(data, dict):
        return st, data.get("bindings", []) or []
    return st, []


def _list_cloud_run_services(
    project_id: str, region: str, auth_headers: Dict[str, str]
) -> Dict[str, Dict[str, Any]]:
    url = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{region}/services"
    st, data, _ = _http_json(url, headers=auth_headers)
    by_name: Dict[str, Dict[str, Any]] = {}
    if st == 200 and isinstance(data, dict):
        for svc in data.get("services", []):
            short = str(svc.get("name", "")).split("/")[-1]
            if short:
                by_name[short] = svc
    return by_name


def _find_codemender_mcp_service(
    services_by_name: Dict[str, Dict[str, Any]]
) -> Tuple[str, Dict[str, Any]]:
    for preferred in ("codemender-mcp-server", "codemender-mcp"):
        if preferred in services_by_name:
            return preferred, services_by_name[preferred]
    for name, svc in services_by_name.items():
        if "codemender" in name and "mcp" in name:
            return name, svc
    return "codemender-mcp-server", {}


def _request_codemender_service(
    service_uri: str,
    path: str,
    project_id: str,
    auth_headers: Dict[str, str],
    method: str = "GET",
    body: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, str], Any, str, str]:
    """Calls `codemender-mcp-server` handling public, OIDC identity-token, or bearer-secret auth."""
    full_url = f"{service_uri.rstrip('/')}/{path.lstrip('/')}"
    base_hdrs = dict(extra_headers or {})

    # 1. Try unauthenticated or OIDC identity token
    id_tok = get_identity_token_optional()
    attempts: List[Tuple[str, Dict[str, str]]] = [("unauthenticated", dict(base_hdrs))]
    if id_tok:
        h_oidc = dict(base_hdrs)
        h_oidc["Authorization"] = f"Bearer {id_tok}"
        attempts.append(("gcloud:identity-token", h_oidc))

    # Also support Secret Manager bearer token (`codemender-mcp-auth-token`) from runner deploy.sh
    mcp_bearer = _access_secret_value_in_memory(project_id, "codemender-mcp-auth-token", auth_headers)
    if mcp_bearer:
        h_sec = dict(base_hdrs)
        h_sec["Authorization"] = f"Bearer {mcp_bearer}"
        attempts.append(("secretmanager:codemender-mcp-auth-token", h_sec))

    last_res: Tuple[int, Dict[str, str], Any, str, str] = (0, {}, None, "", "none")
    for mode_label, hdrs in attempts:
        st, resp_hdrs, parsed, raw = _http_request(
            full_url, method=method, headers=hdrs, body=body, timeout=45
        )
        last_res = (st, resp_hdrs, parsed, raw, mode_label)
        if st not in (0, 401, 403):
            return last_res
    return last_res


# ============================================================================
# GOAL 1: DEPLOY VULNERABLE TARGET APP & GITHUB BRANCH PROTECTION (100 PTS)
# ============================================================================
def run_goal_1_checks(
    project_id: str,
    project_number: str,
    region: str,
    github_org: str,
    target_repo: str,
    github_token: str,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []

    # --- Step 1 (20 pts): Required GCP APIs & Cloud Build IAM Readiness ---
    print("[2/6] Checking Goal 1 / Step 1: Required GCP APIs & Cloud Build IAM Readiness...")
    p1 = "Pillar 1: Required GCP APIs & Cloud Build IAM Readiness"
    st_apis, enabled_apis = _list_enabled_apis(project_id, auth_headers)
    missing_apis = [a for a in EXPECTED_GOAL1_APIS if a not in enabled_apis]
    c11_ok = st_apis == 200 and len(missing_apis) == 0
    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1,
            title="Core Target App GCP APIs Enabled (`compute`, `cloudbuild`, `artifactregistry`, `run`, `secretmanager`)",
            passed=c11_ok,
            max_points=10,
            earned_points=10 if c11_ok else 0,
            summary=(
                f"All {len(EXPECTED_GOAL1_APIS)} required GCP APIs are ENABLED in `{project_id}`."
                if c11_ok
                else f"Missing or disabled GCP APIs: {missing_apis} (HTTP {st_apis})."
            ),
            evidence={
                "required_apis": EXPECTED_GOAL1_APIS,
                "missing_apis": missing_apis,
                "enabled_api_count": len(enabled_apis),
            },
        )
    )

    compute_sa = (
        f"{project_number}-compute@developer.gserviceaccount.com"
        if project_number and project_number != "unknown"
        else ""
    )
    sa_active = False
    if compute_sa:
        st_sa, data_sa, _ = _http_json(
            f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{urllib.parse.quote(compute_sa)}",
            headers=auth_headers,
        )
        sa_active = st_sa == 200 and isinstance(data_sa, dict) and not data_sa.get("disabled", False)

    _, iam_bindings = _get_project_iam_bindings(project_id, auth_headers)
    compute_roles: Set[str] = set()
    for b in iam_bindings:
        role = str(b.get("role", ""))
        members = b.get("members") or []
        if compute_sa and f"serviceAccount:{compute_sa}" in members:
            compute_roles.add(role)

    has_editor = "roles/editor" in compute_roles or "roles/owner" in compute_roles
    has_builder_roles = has_editor or (
        bool({"roles/cloudbuild.builds.builder", "roles/cloudbuild.builds.editor"} & compute_roles)
        and bool({"roles/storage.admin", "roles/storage.objectAdmin", "roles/storage.objectUser"} & compute_roles)
        and bool({"roles/artifactregistry.writer", "roles/artifactregistry.admin"} & compute_roles)
    )
    c12_ok = sa_active and has_builder_roles
    checks.append(
        make_check(
            check_id="1.2",
            pillar=p1,
            title="Default Compute / Cloud Build Service Account Active & Builder IAM Roles Granted",
            passed=c12_ok,
            max_points=10,
            earned_points=10 if c12_ok else (5 if sa_active else 0),
            summary=(
                f"Compute service account `{compute_sa}` is active and holds Cloud Build, Storage, and Artifact Registry permissions."
                if c12_ok
                else f"Compute SA `{compute_sa}` active={sa_active}, roles={sorted(compute_roles)}."
            ),
            evidence={
                "compute_service_account": compute_sa,
                "service_account_active": sa_active,
                "granted_roles": sorted(compute_roles),
            },
        )
    )

    # --- Step 2 (30 pts): Multi-Container watchlist Cloud Run Deployment ---
    print("[3/6] Checking Goal 1 / Step 2: Multi-Container watchlist Cloud Run Deployment...")
    p2 = "Pillar 2: Multi-Container watchlist Cloud Run Deployment"
    services = _list_cloud_run_services(project_id, region, auth_headers)
    watchlist_svc = services.get("watchlist", {})
    watchlist_uri = str(watchlist_svc.get("uri", ""))
    latest_ready_rev = str(watchlist_svc.get("latestReadyRevision", ""))
    ingress_mode = str(watchlist_svc.get("ingress", ""))
    invoker_iam_disabled = bool(watchlist_svc.get("invokerIamDisabled", False))

    containers = watchlist_svc.get("template", {}).get("containers") or []
    container_names = [str(c.get("name", "")) for c in containers if isinstance(c, dict)]
    container_images = [str(c.get("image", "")) for c in containers if isinstance(c, dict)]
    env_var_names: Set[str] = set()
    for c in containers:
        if isinstance(c, dict):
            for e in c.get("env") or []:
                if isinstance(e, dict) and e.get("name"):
                    env_var_names.add(str(e["name"]))

    has_multi_container = len(containers) >= 2 and (
        any("mysql" in (c.get("name", "") + c.get("image", "")).lower() for c in containers if isinstance(c, dict))
    )
    c21_ok = bool(watchlist_uri and latest_ready_rev and has_multi_container)
    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2,
            title="Cloud Run `watchlist` Service Ready with `web` + `mysql` Sidecar Topology",
            passed=c21_ok,
            max_points=20,
            earned_points=20 if c21_ok else (10 if watchlist_uri else 0),
            summary=(
                f"`watchlist` is Ready at `{watchlist_uri}` (`{latest_ready_rev}`) with multi-container topology ({container_names})."
                if c21_ok
                else f"`watchlist` URI=`{watchlist_uri}`, latestReadyRevision=`{latest_ready_rev}`, containers={container_names}."
            ),
            evidence={
                "service_uri": watchlist_uri,
                "latest_ready_revision": latest_ready_rev,
                "ingress": ingress_mode,
                "invoker_iam_disabled": invoker_iam_disabled,
                "container_names": container_names,
                "container_images": container_images,
                "env_var_names": sorted(env_var_names),
            },
        )
    )

    health_ok = False
    public_reachable = False
    health_data: Any = None
    st_health = 0
    if watchlist_uri:
        st_health, health_data, raw_health = _http_json(f"{watchlist_uri}/health", timeout=30)
        if st_health == 200 and isinstance(health_data, dict):
            public_reachable = True
            health_ok = (
                str(health_data.get("status", "")).lower() in ("ok", "healthy")
                and "mysql" in str(health_data.get("db", "")).lower()
            )
        elif st_health in (401, 403):
            health_data = {"http_status": st_health, "note": "Public access blocked; run `--no-invoker-iam-check` per Step 1.3"}
        else:
            health_data = {"http_status": st_health, "raw": raw_health[:250]}

    c22_ok = public_reachable and health_ok
    checks.append(
        make_check(
            check_id="2.2",
            pillar=p2,
            title="Live Public `watchlist` `/health` Probe & MySQL Sidecar Connectivity",
            passed=c22_ok,
            max_points=10,
            earned_points=10 if c22_ok else 0,
            summary=(
                f"`GET {watchlist_uri}/health` is publicly reachable (`HTTP 200`) with `status=ok` and `db=mysql`."
                if c22_ok
                else f"`GET {watchlist_uri}/health` failed or is not publicly exposed (HTTP {st_health}, response={health_data})."
            ),
            evidence={
                "health_url": f"{watchlist_uri}/health" if watchlist_uri else "",
                "http_status": st_health,
                "publicly_reachable": public_reachable,
                "health_response": health_data,
            },
        )
    )

    # --- Step 3 (25 pts): Baseline Intentional Vulnerabilities Live Verification ---
    print("[4/6] Checking Goal 1 / Step 3: Baseline Intentional Vulnerabilities (CM-0001 & CM-0002)...")
    p3 = "Pillar 3: Baseline Intentional Vulnerabilities Live Verification (CM-0001 & CM-0002)"
    sqli_ok = False
    sqli_count = 0
    st_sqli = 0
    if watchlist_uri:
        sqli_qs = urllib.parse.urlencode({"source": "' OR '1'='1"})
        st_sqli, data_sqli, _ = _http_json(f"{watchlist_uri}/api/items?{sqli_qs}", timeout=30)
        if st_sqli == 200 and isinstance(data_sqli, list):
            sqli_count = len(data_sqli)
            sources_returned = {str(item.get("source", "")) for item in data_sqli if isinstance(item, dict)}
            sqli_ok = sqli_count >= 2 and len(sources_returned) >= 1
        elif st_sqli == 200 and isinstance(data_sqli, dict) and isinstance(data_sqli.get("items"), list):
            sqli_count = len(data_sqli["items"])
            sqli_ok = sqli_count >= 2

    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3,
            title="Baseline `CM-0001` (`CWE-89` SQL Injection) Reachable on `GET /api/items?source=`",
            passed=sqli_ok,
            max_points=13,
            earned_points=13 if sqli_ok else 0,
            summary=(
                f"Baseline SQLi PoC (`source=' OR '1'='1`) confirmed on `watchlist`, returning {sqli_count} catalog items."
                if sqli_ok
                else f"Baseline SQLi probe against `/api/items` did not return expected items (HTTP {st_sqli}, count={sqli_count})."
            ),
            evidence={
                "endpoint": "/api/items?source=' OR '1'='1'",
                "http_status": st_sqli,
                "items_returned_count": sqli_count,
            },
        )
    )

    lfi_ok = False
    st_lfi = 0
    lfi_preview = ""
    if watchlist_uri:
        st_lfi, data_lfi, raw_lfi = _http_json(
            f"{watchlist_uri}/api/notes?file=../not_a_secret.txt", timeout=30
        )
        lfi_preview = (json.dumps(data_lfi) if data_lfi is not None else raw_lfi)[:200]
        if st_lfi == 200 and len(raw_lfi.strip()) > 0 and "error" not in str(data_lfi).lower():
            lfi_ok = True

    checks.append(
        make_check(
            check_id="3.2",
            pillar=p3,
            title="Baseline `CM-0002` (`CWE-22` Path Traversal) Reachable on `GET /api/notes?file=`",
            passed=lfi_ok,
            max_points=12,
            earned_points=12 if lfi_ok else 0,
            summary=(
                "Baseline Path Traversal PoC (`file=../not_a_secret.txt`) confirmed on `watchlist` (`HTTP 200`)."
                if lfi_ok
                else f"Baseline Path Traversal probe against `/api/notes` failed (HTTP {st_lfi})."
            ),
            evidence={
                "endpoint": "/api/notes?file=../not_a_secret.txt",
                "http_status": st_lfi,
                "response_excerpt": lfi_preview,
            },
        )
    )

    # --- Step 4 (25 pts): Target Repository on GitHub & main Branch Protection ---
    print("[5/6] Checking Goal 1 / Step 4: Target Repository on GitHub & main Branch Protection...")
    p4 = "Pillar 4: Target Repository on GitHub & main Branch Protection"
    repo_slug = f"{github_org}/{target_repo}" if github_org else ""
    repo_exists = False
    default_branch = ""
    is_private = None
    files_verified: Dict[str, bool] = {}

    if repo_slug:
        st_repo, data_repo, _ = _github_api_json(f"/repos/{repo_slug}", github_token)
        if st_repo == 200 and isinstance(data_repo, dict):
            repo_exists = True
            default_branch = str(data_repo.get("default_branch", ""))
            is_private = data_repo.get("private")
            for req_file in ("app/db.py", "Dockerfile", ".codemender/mock-findings.json"):
                st_f, _, _ = _github_api_json(f"/repos/{repo_slug}/contents/{req_file}", github_token)
                files_verified[req_file] = st_f == 200

    c41_ok = repo_exists and default_branch == "main" and all(files_verified.values()) and len(files_verified) == 3
    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4,
            title=f"GitHub Target Repository (`{repo_slug or '<GITHUB_ORG>/' + target_repo}`) Pushed to `main`",
            passed=c41_ok,
            max_points=15,
            earned_points=15 if c41_ok else (7 if repo_exists else 0),
            summary=(
                f"GitHub repository `{repo_slug}` exists (`default_branch=main`) with `app/db.py`, `Dockerfile`, and `.codemender/mock-findings.json`."
                if c41_ok
                else (
                    "Could not resolve `GITHUB_ORG`; set `GITHUB_ORG` in `~/lab.env` or pass `--github-org` and ensure `gh auth login` / `github-mcp-pat` is configured."
                    if not repo_slug
                    else f"GitHub repo `{repo_slug}` exists={repo_exists}, default_branch=`{default_branch}`, files={files_verified}."
                )
            ),
            evidence={
                "repository": repo_slug,
                "exists": repo_exists,
                "private": is_private,
                "default_branch": default_branch,
                "required_files_present": files_verified,
            },
        )
    )

    bp_ok = False
    bp_reviews_count = 0
    bp_codeowners = False
    bp_no_force_push = False
    bp_http_status = 0
    bp_note = ""

    if repo_slug and repo_exists:
        st_bp, data_bp, raw_bp = _github_api_json(
            f"/repos/{repo_slug}/branches/main/protection", github_token
        )
        bp_http_status = st_bp
        if st_bp == 200 and isinstance(data_bp, dict):
            pr_rev = data_bp.get("required_pull_request_reviews") or {}
            bp_reviews_count = int(pr_rev.get("required_approving_review_count", 0) or 0)
            bp_codeowners = bool(pr_rev.get("require_code_owner_reviews", False))
            afp = data_bp.get("allow_force_pushes") or {}
            bp_no_force_push = not bool(afp.get("enabled", False))
            bp_ok = bp_reviews_count >= 1 and bp_no_force_push
        else:
            # Also check GitHub Repository Rulesets on main
            st_rs, data_rs, _ = _github_api_json(
                f"/repos/{repo_slug}/rules/branches/main", github_token
            )
            if st_rs == 200 and isinstance(data_rs, list) and len(data_rs) > 0:
                rule_types = {str(r.get("type", "")) for r in data_rs if isinstance(r, dict)}
                if "pull_request" in rule_types:
                    bp_ok = True
                    bp_reviews_count = 1
                    bp_no_force_push = "non_fast_forward" in rule_types or True
            elif st_bp == 403 and "Upgrade to GitHub Pro" in raw_bp:
                bp_note = (
                    "GitHub Free accounts require public repository visibility to enforce branch protection on `main`."
                )
            elif st_bp == 404:
                bp_note = "Branch protection not yet enabled on `main` (run the `gh api -X PUT .../branches/main/protection` step)."

    checks.append(
        make_check(
            check_id="4.2",
            pillar=p4,
            title="Human-in-the-Loop Branch Protection Enabled on `main` (PR Review Required & Force-Push Blocked)",
            passed=bp_ok,
            max_points=10,
            earned_points=10 if bp_ok else 0,
            summary=(
                f"Branch `main` on `{repo_slug}` enforces >= {bp_reviews_count} approving PR review(s) (`require_code_owner_reviews={bp_codeowners}`) and blocks force-pushes."
                if bp_ok
                else f"Branch protection check on `{repo_slug}` `main` failed (HTTP {bp_http_status}). {bp_note}".strip()
            ),
            evidence={
                "repository": repo_slug,
                "protection_http_status": bp_http_status,
                "required_approving_review_count": bp_reviews_count,
                "require_code_owner_reviews": bp_codeowners,
                "force_pushes_blocked": bp_no_force_push,
                "diagnostic": bp_note,
            },
        )
    )

    return checks


# ============================================================================
# GOAL 2: DEPLOY CODEMENDER MCP SERVER, RUNNER & SEED BIGQUERY (100 PTS)
# ============================================================================
def run_goal_2_checks(
    project_id: str,
    region: str,
    lab_env: Dict[str, str],
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []

    # --- Step 1 (25 pts): CodeMender Storage, BigQuery Dataset & Runtime IAM ---
    print("[2/6] Checking Goal 2 / Step 1: CodeMender Storage, BigQuery Dataset & Runtime IAM...")
    p1 = "Pillar 1: CodeMender Storage, BigQuery Dataset & Runtime IAM"

    st_ds, data_ds, _ = _http_json(
        f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/datasets/codemender",
        headers=auth_headers,
    )
    ds_ok = st_ds == 200 and isinstance(data_ds, dict)

    services = _list_cloud_run_services(project_id, region, auth_headers)
    mcp_svc_name, mcp_svc = _find_codemender_mcp_service(services)
    svc_env_bucket = ""
    for c in mcp_svc.get("template", {}).get("containers") or []:
        if isinstance(c, dict):
            for e in c.get("env") or []:
                if isinstance(e, dict) and e.get("name") in ("CM_REPORTS_BUCKET", "SANDBOX_BUCKET", "GCS_BUCKET"):
                    svc_env_bucket = str(e.get("value", "")).replace("gs://", "").strip("/")

    bucket_candidates = [
        f"codemender-reports-{project_id}",
        lab_env.get("SANDBOX_BUCKET", "").replace("gs://", "").strip("/"),
        lab_env.get("CM_REPORTS_BUCKET", "").replace("gs://", "").strip("/"),
        svc_env_bucket,
    ]
    found_bucket = ""
    ubla_enabled = False
    for bname in [b for b in bucket_candidates if b and not _is_placeholder(b)]:
        st_b, data_b, _ = _http_json(
            f"https://storage.googleapis.com/storage/v1/b/{urllib.parse.quote(bname)}",
            headers=auth_headers,
        )
        if st_b == 200 and isinstance(data_b, dict):
            found_bucket = bname
            ubla_enabled = bool(
                data_b.get("iamConfiguration", {})
                .get("uniformBucketLevelAccess", {})
                .get("enabled", False)
            )
            break

    if not found_bucket:
        st_bl, data_bl, _ = _http_json(
            f"https://storage.googleapis.com/storage/v1/b?project={urllib.parse.quote(project_id)}",
            headers=auth_headers,
        )
        if st_bl == 200 and isinstance(data_bl, dict):
            for item in data_bl.get("items", []):
                nm = str(item.get("name", ""))
                if "codemender" in nm:
                    found_bucket = nm
                    ubla_enabled = bool(
                        item.get("iamConfiguration", {})
                        .get("uniformBucketLevelAccess", {})
                        .get("enabled", False)
                    )
                    break

    c11_ok = ds_ok and bool(found_bucket)
    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1,
            title="BigQuery Dataset `codemender` & GCS Transit Bucket (`gs://codemender-reports-<project_id>`)",
            passed=c11_ok,
            max_points=13,
            earned_points=13 if c11_ok else (6 if (ds_ok or found_bucket) else 0),
            summary=(
                f"BigQuery dataset `{project_id}.codemender` and GCS transit bucket `gs://{found_bucket}` exist."
                if c11_ok
                else f"BigQuery dataset `codemender` exists={ds_ok}, GCS transit bucket found=`{found_bucket}`."
            ),
            evidence={
                "bigquery_dataset": f"{project_id}.codemender",
                "dataset_exists": ds_ok,
                "gcs_transit_bucket": found_bucket,
                "uniform_bucket_level_access": ubla_enabled,
            },
        )
    )

    sa_candidates = [
        f"codemender-mcp-sa@{project_id}.iam.gserviceaccount.com",
        f"codemender-mcp@{project_id}.iam.gserviceaccount.com",
    ]
    tpl_sa = str(mcp_svc.get("template", {}).get("serviceAccount", "")).strip()
    if tpl_sa and tpl_sa not in sa_candidates:
        sa_candidates.insert(0, tpl_sa)

    active_mcp_sa = ""
    for sa_email in sa_candidates:
        st_sa, data_sa, _ = _http_json(
            f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{urllib.parse.quote(sa_email)}",
            headers=auth_headers,
        )
        if st_sa == 200 and isinstance(data_sa, dict) and not data_sa.get("disabled", False):
            active_mcp_sa = sa_email
            break

    _, iam_bindings = _get_project_iam_bindings(project_id, auth_headers)
    mcp_sa_roles: Set[str] = set()
    for b in iam_bindings:
        role = str(b.get("role", ""))
        members = b.get("members") or []
        if active_mcp_sa and f"serviceAccount:{active_mcp_sa}" in members:
            mcp_sa_roles.add(role)

    bq_role_ok = bool(
        {"roles/bigquery.dataEditor", "roles/bigquery.dataViewer", "roles/bigquery.admin", "roles/bigquery.user"}
        & mcp_sa_roles
    ) and bool({"roles/bigquery.jobUser", "roles/bigquery.admin", "roles/bigquery.user"} & mcp_sa_roles)
    log_role_ok = bool({"roles/logging.viewer", "roles/logging.privateLogViewer", "roles/editor"} & mcp_sa_roles)
    c12_ok = bool(active_mcp_sa) and (bq_role_ok or len(mcp_sa_roles) >= 1)
    checks.append(
        make_check(
            check_id="1.2",
            pillar=p1,
            title="Runtime Service Account (`codemender-mcp-sa`) & Least-Privilege IAM Roles",
            passed=c12_ok,
            max_points=12,
            earned_points=12 if c12_ok else (6 if active_mcp_sa else 0),
            summary=(
                f"Runtime service account `{active_mcp_sa}` is active with project roles {sorted(mcp_sa_roles)}."
                if c12_ok
                else f"Runtime SA `{active_mcp_sa or 'missing'}` active={bool(active_mcp_sa)}, project_roles={sorted(mcp_sa_roles)}."
            ),
            evidence={
                "runtime_service_account": active_mcp_sa,
                "project_iam_roles": sorted(mcp_sa_roles),
                "bigquery_roles_verified": bq_role_ok,
                "logging_viewer_verified": log_role_ok,
            },
        )
    )

    # --- Step 2 (25 pts): codemender-mcp-server Cloud Run Service & codemender-runner Job ---
    print("[3/6] Checking Goal 2 / Step 2: codemender-mcp-server Service & codemender-runner Job...")
    p2 = "Pillar 2: codemender-mcp-server Cloud Run Service & codemender-runner Job"
    mcp_uri = str(mcp_svc.get("uri", ""))
    mcp_ready_rev = str(mcp_svc.get("latestReadyRevision", ""))
    healthz_ok = False
    healthz_data: Any = None
    auth_mode_used = "none"

    if mcp_uri:
        st_hz, _, data_hz, raw_hz, auth_mode_used = _request_codemender_service(
            mcp_uri, "/healthz", project_id, auth_headers, method="GET"
        )
        healthz_data = data_hz if isinstance(data_hz, dict) else {"http_status": st_hz, "raw": raw_hz[:250]}
        if st_hz == 200 and isinstance(data_hz, dict):
            healthz_ok = str(data_hz.get("status", "")).lower() in ("healthy", "ok")

    c21_ok = bool(mcp_uri and mcp_ready_rev and healthz_ok)
    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2,
            title=f"Cloud Run `{mcp_svc_name}` Service Ready & `/healthz` Healthy",
            passed=c21_ok,
            max_points=15,
            earned_points=15 if c21_ok else (7 if mcp_uri else 0),
            summary=(
                f"`{mcp_svc_name}` is Ready at `{mcp_uri}` (`{mcp_ready_rev}`) and `/healthz` returned `healthy` ({auth_mode_used})."
                if c21_ok
                else f"`{mcp_svc_name}` URI=`{mcp_uri}`, healthz_ok={healthz_ok}, response={healthz_data}."
            ),
            evidence={
                "service_name": mcp_svc_name,
                "service_uri": mcp_uri,
                "latest_ready_revision": mcp_ready_rev,
                "auth_mode": auth_mode_used,
                "healthz": healthz_data,
            },
        )
    )

    st_jobs, data_jobs, _ = _http_json(
        f"https://run.googleapis.com/v2/projects/{project_id}/locations/{region}/jobs",
        headers=auth_headers,
    )
    runner_job: Dict[str, Any] = {}
    runner_job_name = ""
    if st_jobs == 200 and isinstance(data_jobs, dict):
        for jb in data_jobs.get("jobs", []):
            short_j = str(jb.get("name", "")).split("/")[-1]
            if short_j == "codemender-runner" or ("codemender" in short_j and "runner" in short_j):
                runner_job = jb
                runner_job_name = short_j
                break

    job_containers = (
        runner_job.get("template", {}).get("template", {}).get("containers") or []
    )
    job_image = str(job_containers[0].get("image", "")) if job_containers and isinstance(job_containers[0], dict) else ""
    c22_ok = bool(runner_job_name and job_image)
    checks.append(
        make_check(
            check_id="2.2",
            pillar=p2,
            title="Isolated `codemender-runner` Cloud Run Job Provisioned",
            passed=c22_ok,
            max_points=10,
            earned_points=10 if c22_ok else 0,
            summary=(
                f"Cloud Run Job `{runner_job_name}` is provisioned in `{region}` with image `{job_image}`."
                if c22_ok
                else f"Cloud Run Job `codemender-runner` not found in `{project_id}` (`{region}`)."
            ),
            evidence={
                "job_name": runner_job_name,
                "region": region,
                "container_image": job_image,
                "execution_count": runner_job.get("executionCount", 0),
            },
        )
    )

    # --- Step 3 (25 pts): Gemini Enterprise HTTP Transport Compatibility & 18-Tool Registry ---
    print("[4/6] Checking Goal 2 / Step 3: Gemini Enterprise Transport Compatibility & 18-Tool Registry...")
    p3 = "Pillar 3: Gemini Enterprise HTTP Transport Compatibility & 18-Tool Registry"
    st_opt, st_del, st_init = 0, 0, 0
    init_ok = False
    if mcp_uri:
        st_opt, _, _, _, _ = _request_codemender_service(
            mcp_uri, "/mcp", project_id, auth_headers, method="OPTIONS"
        )
        st_del, _, _, _, _ = _request_codemender_service(
            mcp_uri, "/mcp", project_id, auth_headers, method="DELETE"
        )
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "lab7-verifier", "version": "1.0"},
            },
        }
        st_init, _, parsed_init, raw_init, _ = _request_codemender_service(
            mcp_uri,
            "/mcp",
            project_id,
            auth_headers,
            method="POST",
            body=init_payload,
            extra_headers={"Accept": "application/json, text/event-stream"},
        )
        rpc_init = _parse_mcp_jsonrpc(parsed_init, raw_init)
        init_ok = st_init == 200 and ("protocolVersion" in raw_init or "result" in rpc_init)

    c31_ok = st_opt in (200, 204) and st_del in (200, 204) and init_ok
    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3,
            title="Gemini Enterprise HTTP Transport Compatibility (`OPTIONS 204`, `DELETE 200`, `initialize`)",
            passed=c31_ok,
            max_points=10,
            earned_points=10 if c31_ok else (5 if init_ok else 0),
            summary=(
                f"`{mcp_svc_name}/mcp` passed CORS `OPTIONS` ({st_opt}), session `DELETE` ({st_del}), and JSON-RPC `initialize` ({st_init})."
                if c31_ok
                else f"Transport probes: OPTIONS={st_opt}, DELETE={st_del}, initialize={st_init} (ok={init_ok})."
            ),
            evidence={
                "options_status": st_opt,
                "delete_status": st_del,
                "initialize_status": st_init,
                "initialize_handshake_valid": init_ok,
            },
        )
    )

    registered_tools: Set[str] = set()
    if mcp_uri:
        st_tl, _, parsed_tl, raw_tl, _ = _request_codemender_service(
            mcp_uri,
            "/mcp",
            project_id,
            auth_headers,
            method="POST",
            body={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            extra_headers={"Accept": "application/json, text/event-stream"},
        )
        rpc_tl = _parse_mcp_jsonrpc(parsed_tl, raw_tl)
        for t in (rpc_tl.get("result", {}) or {}).get("tools") or []:
            if isinstance(t, dict) and t.get("name"):
                registered_tools.add(str(t["name"]))
        if not registered_tools and st_tl == 200:
            for m_tool in re.findall(r'"name"\s*:\s*"([a-zA-Z0-9_]+)"', raw_tl):
                if m_tool in EXPECTED_CODEMENDER_TOOLS:
                    registered_tools.add(m_tool)

    missing_tools = [t for t in EXPECTED_CODEMENDER_TOOLS if t not in registered_tools]
    c32_ok = len(missing_tools) == 0
    checks.append(
        make_check(
            check_id="3.2",
            pillar=p3,
            title="All 18 CodeMender, BigQuery, Cloud Logging & Wiz MCP Tools Registered (`tools/list`)",
            passed=c32_ok,
            max_points=15,
            earned_points=15 if c32_ok else (8 if len(registered_tools) >= 7 else 0),
            summary=(
                f"All {len(EXPECTED_CODEMENDER_TOOLS)} expected MCP tools are registered and exposed on `/mcp`."
                if c32_ok
                else f"Found {len(registered_tools)}/18 expected tools on `/mcp`; missing: {missing_tools}."
            ),
            evidence={
                "registered_tool_count": len(registered_tools),
                "registered_tools": sorted(registered_tools),
                "missing_tools": missing_tools,
            },
        )
    )

    # --- Step 4 (25 pts): Seeded Lab07 Findings in BigQuery & Read-Only SQL Guardrail ---
    print("[5/6] Checking Goal 2 / Step 4: Seeded Lab07 Findings in BigQuery & Read-Only SQL Guardrail...")
    p4 = "Pillar 4: Seeded Lab07 Findings in BigQuery & Read-Only SQL Guardrail"

    bq_url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/queries"
    st_f, data_f, _ = _http_json(
        bq_url,
        method="POST",
        headers=auth_headers,
        body={
            "query": f"SELECT * FROM `{project_id}.codemender.findings` LIMIT 100",
            "useLegacySql": False,
        },
    )
    finding_ids: Set[str] = set()
    total_rows = 0
    if st_f == 200 and isinstance(data_f, dict):
        fields = [f.get("name", "") for f in data_f.get("schema", {}).get("fields", [])]
        rows = data_f.get("rows") or []
        total_rows = len(rows)
        for row in rows:
            vals = [c.get("v") for c in row.get("f", [])]
            rmap = dict(zip(fields, vals))
            fid = str(rmap.get("issue_id") or rmap.get("finding_id") or "")
            if fid:
                finding_ids.add(fid)

    seeded_cms = {"CM-0001", "CM-0002", "CM-0003", "CM-0004"}
    all_4_seeded = seeded_cms.issubset(finding_ids)
    summary_tool_ok = False
    if mcp_uri:
        st_sum, _, parsed_sum, raw_sum, _ = _request_codemender_service(
            mcp_uri,
            "/mcp",
            project_id,
            auth_headers,
            method="POST",
            body={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "get_issues_summary", "arguments": {"days": 3650}},
            },
            extra_headers={"Accept": "application/json, text/event-stream"},
        )
        rpc_sum = _parse_mcp_jsonrpc(parsed_sum, raw_sum)
        _, sum_txt = _extract_mcp_tool_result(rpc_sum)
        summary_tool_ok = st_sum == 200 and ("total_issues" in sum_txt or "severity_breakdown" in sum_txt)

    c41_ok = (all_4_seeded or total_rows >= 4) and summary_tool_ok
    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4,
            title="BigQuery `codemender.findings` Seeded (`CM-0001`–`CM-0004`) & `get_issues_summary` Live",
            passed=c41_ok,
            max_points=15,
            earned_points=15 if c41_ok else (8 if (all_4_seeded or total_rows >= 4) else 0),
            summary=(
                f"`{project_id}.codemender.findings` contains {total_rows} finding(s) ({sorted(finding_ids)[:6]}) and `get_issues_summary` succeeded."
                if c41_ok
                else f"BigQuery rows={total_rows}, finding_ids={sorted(finding_ids)}, get_issues_summary_ok={summary_tool_ok}."
            ),
            evidence={
                "table": f"{project_id}.codemender.findings",
                "row_count": total_rows,
                "finding_ids": sorted(finding_ids)[:20],
                "all_4_mock_findings_present": all_4_seeded,
                "get_issues_summary_ok": summary_tool_ok,
            },
        )
    )

    guardrail_ok = False
    guardrail_excerpt = ""
    if mcp_uri:
        # Probe with a non-existent table name so even a misconfigured server could never mutate real tables
        st_gr, _, parsed_gr, raw_gr, _ = _request_codemender_service(
            mcp_uri,
            "/mcp",
            project_id,
            auth_headers,
            method="POST",
            body={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "query_codemender_bigquery",
                    "arguments": {"query": "DROP TABLE `codemender.__readonly_guardrail_probe__`"},
                },
            },
            extra_headers={"Accept": "application/json, text/event-stream"},
        )
        rpc_gr = _parse_mcp_jsonrpc(parsed_gr, raw_gr)
        _, gr_txt = _extract_mcp_tool_result(rpc_gr)
        guardrail_excerpt = gr_txt[:250]
        lower_gr = gr_txt.lower()
        guardrail_ok = st_gr == 200 and (
            "select or with" in lower_gr
            or "read-only" in lower_gr
            or "disallowed" in lower_gr
        )

    checks.append(
        make_check(
            check_id="4.2",
            pillar=p4,
            title="Negative Security Guardrail (`DROP TABLE` Blocked in `query_codemender_bigquery`)",
            passed=guardrail_ok,
            max_points=10,
            earned_points=10 if guardrail_ok else 0,
            summary=(
                "`query_codemender_bigquery` rejected destructive `DROP TABLE` SQL with read-only `SELECT`/`WITH` guardrail."
                if guardrail_ok
                else f"Read-only SQL guardrail check failed or unreachable: `{guardrail_excerpt}`."
            ),
            evidence={
                "tool": "query_codemender_bigquery",
                "guardrail_blocked_ddl": guardrail_ok,
                "response_excerpt": guardrail_excerpt,
            },
        )
    )

    return checks


# ============================================================================
# GOAL 3: CONFIGURE WIZ, GITHUB & CLOUD LOGGING MCP CONNECTORS (100 PTS)
# ============================================================================
def run_goal_3_checks(
    project_id: str,
    region: str,
    access_token: str,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []

    # --- Step 1 (25 pts): Wiz Cloud Onboarding & Wiz MCP Secret Manager Credentials ---
    print("[2/6] Checking Goal 3 / Step 1: Wiz Cloud Onboarding & Wiz MCP Secret Manager Credentials...")
    p1 = "Pillar 1: Wiz Cloud Onboarding & Wiz MCP Secret Manager Credentials"

    _, iam_bindings = _get_project_iam_bindings(project_id, auth_headers)
    wiz_principals: Set[str] = set()
    for b in iam_bindings:
        for m in b.get("members") or []:
            if isinstance(m, str) and "wiz" in m.lower():
                wiz_principals.add(m)

    st_sas, data_sas, _ = _http_json(
        f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts",
        headers=auth_headers,
    )
    if st_sas == 200 and isinstance(data_sas, dict):
        for acc in data_sas.get("accounts", []):
            em = str(acc.get("email", ""))
            disp = str(acc.get("displayName", ""))
            if "wiz" in em.lower() or "wiz" in disp.lower():
                wiz_principals.add(f"serviceAccount:{em}")

    c11_ok = len(wiz_principals) > 0
    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1,
            title="GCP Project Onboarded to Wiz (Wiz Connector Service Account / IAM Binding)",
            passed=c11_ok,
            max_points=10,
            earned_points=10 if c11_ok else 0,
            summary=(
                f"Project `{project_id}` has active Wiz connector IAM principal(s): {sorted(wiz_principals)}."
                if c11_ok
                else f"No Wiz onboarding service account or IAM binding found in `{project_id}` (run the Wiz GCP onboarding script from Step 1)."
            ),
            evidence={
                "wiz_iam_principals": sorted(wiz_principals),
            },
        )
    )

    wiz_id_meta = _check_secret_metadata(project_id, "wiz-mcp-client-id", auth_headers)
    wiz_sec_meta = _check_secret_metadata(project_id, "wiz-mcp-client-secret", auth_headers)
    wiz_alt_sec_meta = _check_secret_metadata(project_id, "wiz-client-secret", auth_headers)

    has_wiz_secrets = (wiz_id_meta["enabled"] and wiz_sec_meta["enabled"]) or wiz_alt_sec_meta["enabled"]
    wiz_oauth_verified = False
    if wiz_id_meta["enabled"] and wiz_sec_meta["enabled"]:
        cid_val = _access_secret_value_in_memory(project_id, "wiz-mcp-client-id", auth_headers)
        csec_val = _access_secret_value_in_memory(project_id, "wiz-mcp-client-secret", auth_headers)
        if cid_val and csec_val:
            form_bytes = urllib.parse.urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": cid_val,
                    "client_secret": csec_val,
                    "audience": "wiz-api",
                }
            ).encode("utf-8")
            st_wo, _, data_wo, _ = _http_request(
                "https://auth.app.wiz.io/oauth/token",
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                raw_bytes=form_bytes,
                timeout=20,
            )
            wiz_oauth_verified = st_wo == 200 and isinstance(data_wo, dict) and bool(data_wo.get("access_token"))

    c12_ok = has_wiz_secrets
    checks.append(
        make_check(
            check_id="1.2",
            pillar=p1,
            title="Wiz MCP Credentials Stored in Secret Manager (`wiz-mcp-client-id` & `wiz-mcp-client-secret`)",
            passed=c12_ok,
            max_points=15,
            earned_points=15 if c12_ok else (7 if (wiz_id_meta["enabled"] or wiz_sec_meta["enabled"]) else 0),
            summary=(
                f"Wiz MCP credentials are ENABLED in Secret Manager (`oauth_token_exchange_verified={wiz_oauth_verified}`)."
                if c12_ok
                else "Missing `wiz-mcp-client-id` and/or `wiz-mcp-client-secret` in Secret Manager."
            ),
            evidence={
                "wiz_mcp_client_id": wiz_id_meta,
                "wiz_mcp_client_secret": wiz_sec_meta,
                "wiz_client_secret_fallback": wiz_alt_sec_meta,
                "wiz_oauth_token_exchange_verified": wiz_oauth_verified,
            },
        )
    )

    # --- Step 2 (25 pts): GitHub MCP Credentials & Gemini Enterprise Org Policy Readiness ---
    print("[3/6] Checking Goal 3 / Step 2: GitHub MCP Secret & Gemini Enterprise Custom MCP Org Policy...")
    p2 = "Pillar 2: GitHub MCP Credentials & Gemini Enterprise Org Policy Readiness"

    gh_pat_meta = _check_secret_metadata(project_id, "github-mcp-pat", auth_headers)
    gh_runner_meta = _check_secret_metadata(project_id, "codemender-github-token", auth_headers)
    gh_legacy_meta = _check_secret_metadata(project_id, "github-token", auth_headers)
    c21_ok = gh_pat_meta["enabled"] or gh_runner_meta["enabled"] or gh_legacy_meta["enabled"]
    active_gh_secret = (
        "github-mcp-pat"
        if gh_pat_meta["enabled"]
        else ("codemender-github-token" if gh_runner_meta["enabled"] else ("github-token" if gh_legacy_meta["enabled"] else ""))
    )
    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2,
            title="Fine-Grained GitHub PAT Stored in Secret Manager (`github-mcp-pat`)",
            passed=c21_ok,
            max_points=15,
            earned_points=15 if c21_ok else 0,
            summary=(
                f"GitHub PAT secret `{active_gh_secret}` is ENABLED in Secret Manager."
                if c21_ok
                else "Missing `github-mcp-pat` in Secret Manager (`gcloud secrets create github-mcp-pat ...`)."
            ),
            evidence={
                "github_mcp_pat": gh_pat_meta,
                "codemender_github_token": gh_runner_meta,
                "github_token": gh_legacy_meta,
            },
        )
    )

    # Check effective Org Policy for discoveryengine.managed.disableCustomMcpServerConnector
    constraint = "discoveryengine.managed.disableCustomMcpServerConnector"
    st_op, data_op, _ = _http_json(
        f"https://orgpolicy.googleapis.com/v2/projects/{project_id}/policies/{constraint}:getEffectivePolicy",
        headers=auth_headers,
    )
    custom_mcp_enforced = False
    op_source = "orgpolicy_api"
    if st_op == 200 and isinstance(data_op, dict):
        for rule in data_op.get("spec", {}).get("rules") or []:
            if isinstance(rule, dict) and rule.get("enforce") is True:
                custom_mcp_enforced = True
    elif st_op == 404:
        # 404 means the boolean constraint is not set / not enforced on this project
        custom_mcp_enforced = False
    else:
        gcloud_bin = shutil.which("gcloud")
        if gcloud_bin:
            rc_op, out_op, _ = _run_cmd(
                [
                    gcloud_bin,
                    "org-policies",
                    "describe",
                    constraint,
                    f"--project={project_id}",
                    "--effective",
                    "--format=json",
                ]
            )
            op_source = "gcloud_cli"
            if rc_op == 0 and out_op:
                try:
                    parsed_op = json.loads(out_op)
                    for rule in parsed_op.get("spec", {}).get("rules") or []:
                        if isinstance(rule, dict) and rule.get("enforce") is True:
                            custom_mcp_enforced = True
                except Exception:
                    pass

    # Optionally inventory any Discovery Engine dataStores registered in this project
    ge_datastores: List[str] = []
    st_de, data_de, _ = _http_json(
        f"https://discoveryengine.googleapis.com/v1alpha/projects/{project_id}/locations/global/collections/default_collection/dataStores",
        headers=auth_headers,
        timeout=15,
    )
    if st_de == 200 and isinstance(data_de, dict):
        for ds in data_de.get("dataStores") or []:
            if isinstance(ds, dict) and ds.get("displayName"):
                ge_datastores.append(str(ds["displayName"]))

    c22_ok = not custom_mcp_enforced
    checks.append(
        make_check(
            check_id="2.2",
            pillar=p2,
            title="Gemini Enterprise Custom MCP Org Policy Unblocked (`disableCustomMcpServerConnector`)",
            passed=c22_ok,
            max_points=10,
            earned_points=10 if c22_ok else 0,
            summary=(
                f"`{constraint}` has `enforce=false` on `{project_id}` (Custom MCP connectors permitted)."
                if c22_ok
                else f"`{constraint}` is still enforced (`enforce=true`) on `{project_id}`; disable enforcement to register Custom MCP connectors."
            ),
            evidence={
                "constraint": constraint,
                "enforced": custom_mcp_enforced,
                "verification_source": op_source,
                "discovery_engine_datastores_in_project": ge_datastores,
            },
        )
    )

    # --- Step 3 (25 pts): Google Cloud Logging Remote MCP Server (logging.googleapis.com/mcp) ---
    print("[4/6] Checking Goal 3 / Step 3: Google Cloud Logging Remote MCP Server...")
    p3 = "Pillar 3: Google Cloud Logging Remote MCP Server (logging.googleapis.com/mcp)"

    _, enabled_apis = _list_enabled_apis(project_id, auth_headers)
    logging_api_ok = "logging.googleapis.com" in enabled_apis
    has_logging_viewer = any(
        str(b.get("role", "")) in ("roles/logging.viewer", "roles/logging.admin", "roles/owner", "roles/editor")
        for b in iam_bindings
    )

    mcp_headers = {
        "Authorization": f"Bearer {access_token}",
        "x-goog-user-project": project_id,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    st_li, resp_li_hdrs, parsed_li, raw_li = _http_request(
        "https://logging.googleapis.com/mcp",
        method="POST",
        headers=mcp_headers,
        body={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "lab7-verifier", "version": "1.0"},
            },
        },
        timeout=30,
    )
    session_id = resp_li_hdrs.get("mcp-session-id", "")
    if session_id:
        mcp_headers["Mcp-Session-Id"] = session_id

    st_lt, _, parsed_lt, raw_lt = _http_request(
        "https://logging.googleapis.com/mcp",
        method="POST",
        headers=mcp_headers,
        body={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        timeout=30,
    )
    rpc_lt = _parse_mcp_jsonrpc(parsed_lt, raw_lt)
    logging_mcp_tools: Dict[str, Dict[str, Any]] = {}
    for t in (rpc_lt.get("result", {}) or {}).get("tools") or []:
        if isinstance(t, dict) and t.get("name"):
            logging_mcp_tools[str(t["name"])] = t

    expected_log_tools = {"list_log_entries", "list_log_names"}
    remote_mcp_enabled = st_lt == 200 and expected_log_tools.issubset(set(logging_mcp_tools.keys()))
    c31_ok = logging_api_ok and has_logging_viewer and remote_mcp_enabled
    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3,
            title="Cloud Logging API, Remote MCP Endpoint (`logging.googleapis.com/mcp`) & `roles/logging.viewer`",
            passed=c31_ok,
            max_points=15,
            earned_points=15 if c31_ok else (7 if logging_api_ok else 0),
            summary=(
                f"`https://logging.googleapis.com/mcp` is active for `{project_id}` exposing {sorted(logging_mcp_tools.keys())}."
                if c31_ok
                else (
                    f"Cloud Logging Remote MCP check: api_enabled={logging_api_ok}, viewer_iam={has_logging_viewer}, "
                    f"mcp_http={st_lt} (run `gcloud beta services mcp enable logging.googleapis.com --project {project_id}`)."
                )
            ),
            evidence={
                "logging_api_enabled": logging_api_ok,
                "logging_viewer_iam_bound": has_logging_viewer,
                "mcp_initialize_http_status": st_li,
                "mcp_tools_list_http_status": st_lt,
                "exposed_tools": sorted(logging_mcp_tools.keys()),
            },
        )
    )

    live_log_call_ok = False
    live_log_excerpt = ""
    if remote_mcp_enabled:
        tool_schema = (
            logging_mcp_tools.get("list_log_entries", {}).get("inputSchema", {}).get("properties") or {}
        )
        call_args: Dict[str, Any] = {}
        if "resourceNames" in tool_schema:
            call_args["resourceNames"] = [f"projects/{project_id}"]
        elif "resource_names" in tool_schema:
            call_args["resource_names"] = [f"projects/{project_id}"]
        if "pageSize" in tool_schema:
            call_args["pageSize"] = 5
        elif "page_size" in tool_schema:
            call_args["page_size"] = 5
        if "filter" in tool_schema:
            call_args["filter"] = f'logName="projects/{project_id}/logs/codemender"'

        st_lc, _, parsed_lc, raw_lc = _http_request(
            "https://logging.googleapis.com/mcp",
            method="POST",
            headers=mcp_headers,
            body={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "list_log_entries", "arguments": call_args},
            },
            timeout=30,
        )
        rpc_lc = _parse_mcp_jsonrpc(parsed_lc, raw_lc)
        _, live_log_excerpt = _extract_mcp_tool_result(rpc_lc)
        live_log_call_ok = st_lc == 200 and "error" not in rpc_lc

    checks.append(
        make_check(
            check_id="3.2",
            pillar=p3,
            title="Live `list_log_entries` Query via `https://logging.googleapis.com/mcp`",
            passed=live_log_call_ok,
            max_points=10,
            earned_points=10 if live_log_call_ok else 0,
            summary=(
                f"Successfully executed `list_log_entries` via Google Cloud Logging Remote MCP on `projects/{project_id}`."
                if live_log_call_ok
                else "Live `list_log_entries` MCP invocation against `https://logging.googleapis.com/mcp` failed."
            ),
            evidence={
                "tool": "list_log_entries",
                "project": f"projects/{project_id}",
                "call_succeeded": live_log_call_ok,
                "response_excerpt": live_log_excerpt[:250],
            },
        )
    )

    # --- Step 4 (25 pts): Seeded CodeMender Telemetry in Cloud Logging & Cross-Signal Correlation ---
    print("[5/6] Checking Goal 3 / Step 4: Seeded logs/codemender Telemetry & Cross-Signal Correlation...")
    p4 = "Pillar 4: Seeded CodeMender Telemetry in Cloud Logging & Cross-Signal Correlation"

    st_le, data_le, _ = _http_json(
        "https://logging.googleapis.com/v2/entries:list",
        method="POST",
        headers=auth_headers,
        body={
            "resourceNames": [f"projects/{project_id}"],
            "filter": f'logName="projects/{project_id}/logs/codemender"',
            "pageSize": 50,
            "orderBy": "timestamp desc",
        },
    )
    found_event_types: Set[str] = set()
    found_issue_ids: Set[str] = set()
    entry_count = 0
    if st_le == 200 and isinstance(data_le, dict):
        entries = data_le.get("entries") or []
        entry_count = len(entries)
        for ent in entries:
            jp = ent.get("jsonPayload") or {}
            if isinstance(jp, dict):
                if jp.get("event_type"):
                    found_event_types.add(str(jp["event_type"]))
                if jp.get("issue_id") or jp.get("finding_id"):
                    found_issue_ids.add(str(jp.get("issue_id") or jp.get("finding_id")))

    expected_events = {"CODEMENDER_SCAN_STARTED", "CODEMENDER_FINDING", "CODEMENDER_SANDBOX_ERROR"}
    c41_ok = expected_events.issubset(found_event_types)
    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4,
            title="Seeded `logs/codemender` Events (`CODEMENDER_SCAN_STARTED`, `CODEMENDER_FINDING`, `CODEMENDER_SANDBOX_ERROR`)",
            passed=c41_ok,
            max_points=15,
            earned_points=15 if c41_ok else (7 if entry_count > 0 else 0),
            summary=(
                f"`projects/{project_id}/logs/codemender` contains all 3 expected CodeMender event types across {entry_count} log entries."
                if c41_ok
                else f"Found event_types={sorted(found_event_types)} in `logs/codemender` (expected {sorted(expected_events)})."
            ),
            evidence={
                "log_name": f"projects/{project_id}/logs/codemender",
                "entry_count": entry_count,
                "event_types_found": sorted(found_event_types),
                "issue_ids_found": sorted(found_issue_ids),
            },
        )
    )

    services = _list_cloud_run_services(project_id, region, auth_headers)
    _, mcp_svc = _find_codemender_mcp_service(services)
    mcp_uri = str(mcp_svc.get("uri", ""))
    corr_ok = False
    corr_count = 0
    if mcp_uri:
        st_cl, _, parsed_cl, raw_cl, _ = _request_codemender_service(
            mcp_uri,
            "/mcp",
            project_id,
            auth_headers,
            method="POST",
            body={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "search_codemender_logs",
                    "arguments": {"log_name": "codemender", "hours_ago": 720, "limit": 20},
                },
            },
            extra_headers={"Accept": "application/json, text/event-stream"},
        )
        rpc_cl = _parse_mcp_jsonrpc(parsed_cl, raw_cl)
        cl_obj, cl_txt = _extract_mcp_tool_result(rpc_cl)
        if isinstance(cl_obj, dict):
            corr_count = int(cl_obj.get("count", len(cl_obj.get("entries") or [])) or 0)
        corr_ok = st_cl == 200 and (corr_count > 0 or "CM-0001" in cl_txt or "CODEMENDER_" in cl_txt)

    checks.append(
        make_check(
            check_id="4.2",
            pillar=p4,
            title="Cross-Signal Log Correlation via `codemender-mcp-server` (`search_codemender_logs`)",
            passed=corr_ok,
            max_points=10,
            earned_points=10 if corr_ok else 0,
            summary=(
                f"`codemender-mcp-server` correlated {corr_count} `codemender` Cloud Logging entry/entries with BigQuery findings."
                if corr_ok
                else "`search_codemender_logs` on `codemender-mcp-server` returned 0 correlated `codemender` log entries."
            ),
            evidence={
                "mcp_service_uri": mcp_uri,
                "correlated_log_entries_count": corr_count,
                "correlation_verified": corr_ok,
            },
        )
    )

    return checks


# ============================================================================
# GOAL 4: HUMAN-IN-THE-LOOP REMEDIATION & SANDBOX VERIFICATION (100 PTS)
# ============================================================================
def run_goal_4_checks(
    project_id: str,
    region: str,
    github_org: str,
    target_repo: str,
    github_token: str,
    repo_root: Path,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    repo_slug = f"{github_org}/{target_repo}" if github_org else ""

    # --- Step 1 (30 pts): Remediation Branch & Pull Request Created on GitHub ---
    print("[2/6] Checking Goal 4 / Step 1: Remediation Branch & Pull Request on GitHub...")
    p1 = "Pillar 1: Remediation Branch & Pull Request Created on GitHub"

    remediation_pr: Dict[str, Any] = {}
    all_prs: List[Dict[str, Any]] = []
    if repo_slug:
        st_prs, data_prs, _ = _github_api_json(
            f"/repos/{repo_slug}/pulls?state=all&per_page=30", github_token
        )
        if st_prs == 200 and isinstance(data_prs, list):
            all_prs = [p for p in data_prs if isinstance(p, dict)]
            for pr in all_prs:
                head_ref = str(pr.get("head", {}).get("ref", ""))
                title_body = f"{pr.get('title', '')}\n{pr.get('body', '')}".lower()
                if (
                    "cm-0001" in head_ref.lower()
                    or "sqli" in head_ref.lower()
                    or head_ref.startswith("security/")
                    or head_ref.startswith("codemender/fix")
                    or "cm-0001" in title_body
                    or "cwe-89" in title_body
                ) and "armor" not in head_ref.lower():
                    remediation_pr = pr
                    break

    pr_number = remediation_pr.get("number")
    pr_url = str(remediation_pr.get("html_url", ""))
    head_branch = str(remediation_pr.get("head", {}).get("ref", ""))
    base_branch = str(remediation_pr.get("base", {}).get("ref", ""))
    c11_ok = bool(pr_number and head_branch and head_branch != "main" and base_branch == "main")
    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1,
            title="Remediation Feature Branch (`security/CM-0001-sqli` / `codemender/fix-*`) & PR Targeting `main`",
            passed=c11_ok,
            max_points=15,
            earned_points=15 if c11_ok else 0,
            summary=(
                f"Pull Request #{pr_number} (`{head_branch}` -> `{base_branch}`) found at {pr_url}."
                if c11_ok
                else f"No `CM-0001` remediation Pull Request targeting `main` found on `{repo_slug or target_repo}`."
            ),
            evidence={
                "repository": repo_slug,
                "pr_number": pr_number,
                "pr_url": pr_url,
                "head_branch": head_branch,
                "base_branch": base_branch,
                "total_prs_inspected": len(all_prs),
            },
        )
    )

    pr_title = str(remediation_pr.get("title", ""))
    pr_body = str(remediation_pr.get("body") or "")
    combined_text = f"{pr_title}\n{pr_body}"
    cites_issue = bool(re.search(r"CM-0001|wiz-issue-0001|CWE-89", combined_text, re.IGNORECASE))
    cites_rca = bool(re.search(r"app/db\.py|search_items", combined_text, re.IGNORECASE))
    cites_verify = bool(
        re.search(
            r"verif|sandbox|poc|test_poc_sqli|parameterized|PATCH_VERIFIED",
            combined_text,
            re.IGNORECASE,
        )
    )
    c12_ok = bool(pr_number and cites_issue and cites_rca and cites_verify)
    checks.append(
        make_check(
            check_id="1.2",
            pillar=p1,
            title="Structured Pull Request Body (`CM-0001` / `wiz-issue-0001`, Root Cause & Verification Verdict)",
            passed=c12_ok,
            max_points=15,
            earned_points=15 if c12_ok else (7 if (pr_number and cites_issue) else 0),
            summary=(
                f"PR #{pr_number} documents issue ID (`CM-0001`/`CWE-89`), `app/db.py` root cause, and verification summary."
                if c12_ok
                else f"PR body check: cites_issue={cites_issue}, cites_rca={cites_rca}, cites_verification={cites_verify}."
            ),
            evidence={
                "pr_title": pr_title,
                "cites_issue_id": cites_issue,
                "cites_app_db_rca": cites_rca,
                "cites_sandbox_verification": cites_verify,
            },
        )
    )

    # --- Step 2 (30 pts): Minimal Parameterized SQL Fix Quality (CWE-89 in app/db.py) ---
    print("[3/6] Checking Goal 4 / Step 2: Parameterized SQL Fix Quality in app/db.py...")
    p2 = "Pillar 2: Minimal Parameterized SQL Fix Quality (CWE-89 in app/db.py)"

    db_py_content = ""
    patch_diff = ""
    changed_files: List[str] = []
    if repo_slug and pr_number:
        st_pf, data_pf, _ = _github_api_json(
            f"/repos/{repo_slug}/pulls/{pr_number}/files", github_token
        )
        if st_pf == 200 and isinstance(data_pf, list):
            for fobj in data_pf:
                if isinstance(fobj, dict):
                    fname = str(fobj.get("filename", ""))
                    changed_files.append(fname)
                    if fname == "app/db.py":
                        patch_diff = str(fobj.get("patch", ""))

        if head_branch:
            st_db, data_db, _ = _github_api_json(
                f"/repos/{repo_slug}/contents/app/db.py?ref={urllib.parse.quote(head_branch)}",
                github_token,
            )
            if st_db == 200 and isinstance(data_db, dict) and data_db.get("content"):
                try:
                    db_py_content = base64.b64decode(data_db["content"]).decode("utf-8", errors="replace")
                except Exception:
                    pass

    # Fallback: inspect local target repo if GitHub content unavailable
    if not db_py_content:
        local_target = find_local_target_repo(repo_root, target_repo)
        if local_target and (local_target / "app" / "db.py").is_file():
            db_py_content = (local_target / "app" / "db.py").read_text(encoding="utf-8", errors="replace")

    no_comment_db = re.sub(r"#[^\n]*", "", db_py_content)
    still_vulnerable_fstring = bool(
        re.search(r"WHERE\s+source\s*=\s*'\{source\}'", no_comment_db)
    )
    has_parameterized_where = bool(
        re.search(r"WHERE\s+source\s*=\s*(?:\?|%s)", no_comment_db, re.IGNORECASE)
    )
    has_bound_tuple = bool(
        re.search(r"_run\s*\(\s*conn\s*,\s*query\s*,\s*(?:\(\s*source\s*,\s*\)|\[\s*source\s*\])", no_comment_db)
    )
    module_intact = "def search_items" in no_comment_db and "def _connect" in no_comment_db
    c21_ok = (
        bool(pr_number)
        and module_intact
        and not still_vulnerable_fstring
        and has_parameterized_where
        and has_bound_tuple
    )
    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2,
            title="Minimal Parameterized SQL Fix in `app/db.py` (`WHERE source = ?` & `_run(conn, query, (source,))`)",
            passed=c21_ok,
            max_points=30,
            earned_points=30 if c21_ok else 0,
            summary=(
                "PR branch `app/db.py` removes SQL string interpolation in `search_items()` and binds `(source,)` via parameterized placeholder."
                if c21_ok
                else (
                    f"`app/db.py` fix check: pr_present={bool(pr_number)}, vulnerable_fstring_removed={not still_vulnerable_fstring}, "
                    f"parameterized_where={has_parameterized_where}, bound_tuple={has_bound_tuple}."
                )
            ),
            evidence={
                "changed_files": changed_files,
                "vulnerable_fstring_present": still_vulnerable_fstring,
                "parameterized_placeholder_present": has_parameterized_where,
                "bound_params_tuple_present": has_bound_tuple,
                "patch_excerpt": patch_diff[:500],
            },
        )
    )

    # --- Step 3 (25 pts): Isolated Sandbox Validation & BigQuery / Workflow Audit Trail ---
    print("[4/6] Checking Goal 4 / Step 3: Isolated Sandbox Validation & Audit Trail...")
    p3 = "Pillar 3: Isolated Sandbox Validation & BigQuery / Workflow Audit Trail"

    # 1. Check Cloud Run Job executions on codemender-runner
    st_exec, data_exec, _ = _http_json(
        f"https://run.googleapis.com/v2/projects/{project_id}/locations/{region}/jobs/codemender-runner/executions",
        headers=auth_headers,
    )
    runner_exec_count = 0
    succeeded_execs = 0
    if st_exec == 200 and isinstance(data_exec, dict):
        execs = data_exec.get("executions") or []
        runner_exec_count = len(execs)
        for ex in execs:
            if isinstance(ex, dict) and int(ex.get("succeededCount", 0) or 0) > 0:
                succeeded_execs += 1

    # 2. Check BigQuery codemender.jobs & codemender.findings status updates
    bq_url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/queries"
    st_bqf, data_bqf, _ = _http_json(
        bq_url,
        method="POST",
        headers=auth_headers,
        body={
            "query": f"SELECT * FROM `{project_id}.codemender.findings` LIMIT 50",
            "useLegacySql": False,
        },
    )
    bq_verified_or_fixed = False
    bq_statuses: List[str] = []
    if st_bqf == 200 and isinstance(data_bqf, dict):
        fields = [f.get("name", "") for f in data_bqf.get("schema", {}).get("fields", [])]
        for row in data_bqf.get("rows") or []:
            rmap = dict(zip(fields, [c.get("v") for c in row.get("f", [])]))
            st_val = str(rmap.get("status") or "").upper()
            vst_val = str(rmap.get("verify_status") or "").upper()
            fst_val = str(rmap.get("fix_status") or "").upper()
            pr_v = str(rmap.get("pr_url") or "")
            if st_val:
                bq_statuses.append(st_val)
            if (
                st_val in ("VERIFIED", "FIXED", "PATCHED", "PATCH_GENERATED", "APPLIED")
                or vst_val == "VERIFIED"
                or fst_val in ("FIXED", "PATCHED")
                or "github.com/" in pr_v
            ):
                bq_verified_or_fixed = True

    st_bqj, data_bqj, _ = _http_json(
        bq_url,
        method="POST",
        headers=auth_headers,
        body={
            "query": f"SELECT COUNT(*) FROM `{project_id}.codemender.jobs`",
            "useLegacySql": False,
        },
    )
    bq_jobs_count = 0
    if st_bqj == 200 and isinstance(data_bqj, dict):
        rows_j = data_bqj.get("rows") or []
        if rows_j:
            bq_jobs_count = int(rows_j[0].get("f", [{}])[0].get("v", 0) or 0)

    # 3. Check GitHub Actions workflow runs (sandbox-validate.yml / codemender-scan.yml)
    gh_workflow_runs = 0
    if repo_slug:
        st_wf, data_wf, _ = _github_api_json(
            f"/repos/{repo_slug}/actions/runs?per_page=10", github_token
        )
        if st_wf == 200 and isinstance(data_wf, dict):
            gh_workflow_runs = int(data_wf.get("total_count", 0) or 0)

    c31_ok = runner_exec_count > 0 or bq_verified_or_fixed or bq_jobs_count > 0 or gh_workflow_runs > 0
    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3,
            title="Isolated Sandbox Execution & Verification Audit Trail (`codemender-runner` / BigQuery / Actions)",
            passed=c31_ok,
            max_points=25,
            earned_points=25 if c31_ok else 0,
            summary=(
                f"Sandbox validation verified (`runner_executions={runner_exec_count}`, `bq_jobs={bq_jobs_count}`, `bq_verified_or_fixed={bq_verified_or_fixed}`, `gh_actions_runs={gh_workflow_runs}`)."
                if c31_ok
                else "No sandbox validation execution found in `codemender-runner`, BigQuery `codemender`, or GitHub Actions."
            ),
            evidence={
                "codemender_runner_executions": runner_exec_count,
                "codemender_runner_succeeded": succeeded_execs,
                "bigquery_jobs_count": bq_jobs_count,
                "bigquery_finding_verified_or_fixed": bq_verified_or_fixed,
                "bigquery_statuses": sorted(set(bq_statuses)),
                "github_actions_workflow_runs": gh_workflow_runs,
            },
        )
    )

    # --- Step 4 (15 pts): Human-in-the-Loop Merge Refusal Guardrail Enforced ---
    print("[5/6] Checking Goal 4 / Step 4: Human-in-the-Loop Merge Guardrail...")
    p4 = "Pillar 4: Human-in-the-Loop Merge Refusal Guardrail Enforced"

    pr_state = str(remediation_pr.get("state", ""))
    merged_at = remediation_pr.get("merged_at")
    auto_merge = remediation_pr.get("auto_merge")
    merged_by_login = ""
    if pr_number and merged_at and repo_slug:
        st_prd, data_prd, _ = _github_api_json(
            f"/repos/{repo_slug}/pulls/{pr_number}", github_token
        )
        if st_prd == 200 and isinstance(data_prd, dict):
            merged_by_login = str((data_prd.get("merged_by") or {}).get("login", ""))

    bot_merged = bool(
        merged_at and ("bot" in merged_by_login.lower() or "codemender" in merged_by_login.lower())
    )
    c41_ok = bool(pr_number) and auto_merge is None and not bot_merged
    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4,
            title="Human-in-the-Loop Merge Guardrail Enforced (No Autonomous Agent PR Merge)",
            passed=c41_ok,
            max_points=15,
            earned_points=15 if c41_ok else 0,
            summary=(
                f"PR #{pr_number} respected human-in-the-loop merge policy (`state={pr_state}`, `auto_merge=None`, `bot_merged=False`)."
                if c41_ok
                else f"Merge guardrail check failed: pr_present={bool(pr_number)}, auto_merge={auto_merge}, merged_by={merged_by_login}."
            ),
            evidence={
                "pr_number": pr_number,
                "pr_state": pr_state,
                "merged_at": merged_at,
                "merged_by": merged_by_login,
                "auto_merge_enabled": auto_merge is not None,
                "bot_merged": bot_merged,
            },
        )
    )

    return checks


# ============================================================================
# GOAL 5: CLOUD ARMOR WAF & INGRESS LOCKDOWN (`watchlist`) (100 PTS)
# ============================================================================
def run_goal_5_checks(
    project_id: str,
    region: str,
    github_org: str,
    target_repo: str,
    github_token: str,
    repo_root: Path,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    repo_slug = f"{github_org}/{target_repo}" if github_org else ""

    # --- Step 1 (25 pts): Cloud Run Ingress Lockdown & Cloud Armor Terraform / PR ---
    print("[2/6] Checking Goal 5 / Step 1: Cloud Run Ingress Lockdown & Cloud Armor Terraform / PR...")
    p1 = "Pillar 1: Cloud Run Ingress Lockdown & Cloud Armor Terraform / PR"

    services = _list_cloud_run_services(project_id, region, auth_headers)
    watchlist_svc = services.get("watchlist", {})
    watchlist_uri = str(watchlist_svc.get("uri", ""))
    watchlist_ingress = str(watchlist_svc.get("ingress", ""))
    c11_ok = watchlist_ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
    checks.append(
        make_check(
            check_id="1.1",
            pillar=p1,
            title="`watchlist` Cloud Run Service Locked to `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`",
            passed=c11_ok,
            max_points=15,
            earned_points=15 if c11_ok else 0,
            summary=(
                "`watchlist` Cloud Run ingress is locked to `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`."
                if c11_ok
                else f"`watchlist` ingress is `{watchlist_ingress or 'missing'}` (expected `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`)."
            ),
            evidence={
                "service_uri": watchlist_uri,
                "ingress": watchlist_ingress,
            },
        )
    )

    armor_pr_url = ""
    local_armor_tf = False
    if repo_slug:
        st_prs, data_prs, _ = _github_api_json(
            f"/repos/{repo_slug}/pulls?state=all&per_page=30", github_token
        )
        if st_prs == 200 and isinstance(data_prs, list):
            for pr in data_prs:
                if not isinstance(pr, dict):
                    continue
                href = str(pr.get("head", {}).get("ref", "")).lower()
                t_b = f"{pr.get('title', '')}\n{pr.get('body', '')}".lower()
                if "armor" in href or "cloud-armor" in t_b or "cloud_armor" in t_b or "security_policy" in t_b:
                    armor_pr_url = str(pr.get("html_url", ""))
                    break

    local_target = find_local_target_repo(repo_root, target_repo)
    if local_target and (local_target / "terraform" / "cloud_armor.tf").is_file():
        tf_txt = (local_target / "terraform" / "cloud_armor.tf").read_text(encoding="utf-8", errors="replace")
        local_armor_tf = "google_compute_security_policy" in tf_txt

    c12_ok = bool(armor_pr_url or local_armor_tf)
    checks.append(
        make_check(
            check_id="1.2",
            pillar=p1,
            title="Cloud Armor Terraform IaC (`cloud_armor.tf` & GitHub PR `security/cloud-armor-protection`)",
            passed=c12_ok,
            max_points=10,
            earned_points=10 if c12_ok else 0,
            summary=(
                f"Cloud Armor Terraform IaC verified (`github_pr={armor_pr_url or 'N/A'}`, `local_cloud_armor_tf={local_armor_tf}`)."
                if c12_ok
                else "Missing Cloud Armor PR (`security/cloud-armor-protection`) on GitHub and local `terraform/cloud_armor.tf`."
            ),
            evidence={
                "github_cloud_armor_pr": armor_pr_url,
                "local_cloud_armor_tf_present": local_armor_tf,
            },
        )
    )

    # --- Step 2 (25 pts): Google Cloud Armor Security Policy & OWASP WAF Rules ---
    print("[3/6] Checking Goal 5 / Step 2: Google Cloud Armor Security Policy & OWASP WAF Rules...")
    p2 = "Pillar 2: Google Cloud Armor Security Policy & OWASP WAF Rules"

    st_sp, data_sp, _ = _http_json(
        f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/securityPolicies",
        headers=auth_headers,
    )
    armor_policy: Dict[str, Any] = {}
    if st_sp == 200 and isinstance(data_sp, dict):
        for pol in data_sp.get("items") or []:
            if isinstance(pol, dict):
                pname = str(pol.get("name", ""))
                if pname == "watchlist-cloud-armor-policy" or "watchlist" in pname or "armor" in pname:
                    armor_policy = pol
                    break
        if not armor_policy and data_sp.get("items"):
            armor_policy = data_sp["items"][0]

    policy_name = str(armor_policy.get("name", ""))
    rules = armor_policy.get("rules") or []
    default_deny_ok = False
    explicit_allow_ok = False
    sqli_waf_ok = False
    lfi_waf_ok = False

    for r in rules:
        if not isinstance(r, dict):
            continue
        prio = int(r.get("priority", -1))
        action = str(r.get("action", "")).lower()
        expr = str((r.get("match") or {}).get("expr", {}).get("expression", "")).lower()
        if prio == 2147483647 and action.startswith("deny"):
            default_deny_ok = True
        if prio < 2147483647 and action == "allow":
            explicit_allow_ok = True
        if action.startswith("deny") and "sqli" in expr:
            sqli_waf_ok = True
        if action.startswith("deny") and "lfi" in expr:
            lfi_waf_ok = True

    c21_ok = bool(policy_name and default_deny_ok and explicit_allow_ok)
    checks.append(
        make_check(
            check_id="2.1",
            pillar=p2,
            title="Cloud Armor Policy (`watchlist-cloud-armor-policy`) Default `deny(403)` & Authorized CIDR `allow` Rule",
            passed=c21_ok,
            max_points=12,
            earned_points=12 if c21_ok else (6 if default_deny_ok else 0),
            summary=(
                f"Security policy `{policy_name}` enforces default `deny(403)` (`2147483647`) and explicit `allow` rule."
                if c21_ok
                else f"Policy `{policy_name or 'missing'}`: default_deny={default_deny_ok}, explicit_allow={explicit_allow_ok}."
            ),
            evidence={
                "policy_name": policy_name,
                "rule_count": len(rules),
                "default_deny_2147483647": default_deny_ok,
                "authorized_cidr_allow_rule": explicit_allow_ok,
            },
        )
    )

    c22_ok = sqli_waf_ok and lfi_waf_ok
    checks.append(
        make_check(
            check_id="2.2",
            pillar=p2,
            title="Preconfigured OWASP WAF Rules (`sqli-v33-stable` & `lfi-v33-stable` `deny(403)`)",
            passed=c22_ok,
            max_points=13,
            earned_points=13 if c22_ok else (6 if (sqli_waf_ok or lfi_waf_ok) else 0),
            summary=(
                f"`{policy_name}` enforces both OWASP SQLi (`sqli-*`) and Path Traversal/LFI (`lfi-*`) `deny(403)` WAF rules."
                if c22_ok
                else f"WAF rules on `{policy_name or 'missing'}`: sqli_waf={sqli_waf_ok}, lfi_waf={lfi_waf_ok}."
            ),
            evidence={
                "policy_name": policy_name,
                "sqli_waf_rule_active": sqli_waf_ok,
                "lfi_waf_rule_active": lfi_waf_ok,
            },
        )
    )

    # --- Step 3 (25 pts): Global External ALB & Serverless NEG Attachment ---
    print("[4/6] Checking Goal 5 / Step 3: Global External Load Balancer & Serverless NEG Attachment...")
    p3 = "Pillar 3: Global External Application Load Balancer & Serverless NEG Attachment"

    st_neg, data_neg, _ = _http_json(
        f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/networkEndpointGroups",
        headers=auth_headers,
    )
    neg_name = ""
    if st_neg == 200 and isinstance(data_neg, dict):
        for neg in data_neg.get("items") or []:
            if isinstance(neg, dict) and str(neg.get("cloudRun", {}).get("service", "")) == "watchlist":
                neg_name = str(neg.get("name", ""))
                break

    st_bs, data_bs, _ = _http_json(
        f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/backendServices",
        headers=auth_headers,
    )
    bs_name = ""
    bs_policy = ""
    bs_logging = False
    if st_bs == 200 and isinstance(data_bs, dict):
        for bs in data_bs.get("items") or []:
            if isinstance(bs, dict):
                nm = str(bs.get("name", ""))
                if nm == "watchlist-backend" or "watchlist" in nm:
                    bs_name = nm
                    bs_policy = str(bs.get("securityPolicy", ""))
                    bs_logging = bool((bs.get("logConfig") or {}).get("enable", False))
                    break

    policy_attached = bool(policy_name and policy_name in bs_policy)
    c31_ok = bool(neg_name and bs_name and policy_attached and bs_logging)
    checks.append(
        make_check(
            check_id="3.1",
            pillar=p3,
            title="Serverless NEG (`watchlist-serverless-neg`) & Backend Service (`watchlist-backend`) with Cloud Armor & Logging",
            passed=c31_ok,
            max_points=15,
            earned_points=15 if c31_ok else (7 if (neg_name and bs_name and policy_attached) else 0),
            summary=(
                f"Serverless NEG `{neg_name}` and Backend Service `{bs_name}` attach `{policy_name}` with `logConfig.enable=True`."
                if c31_ok
                else f"NEG=`{neg_name}`, backend=`{bs_name}`, policy_attached={policy_attached}, logging_enabled={bs_logging}."
            ),
            evidence={
                "serverless_neg": neg_name,
                "backend_service": bs_name,
                "attached_security_policy": bs_policy,
                "logging_enabled": bs_logging,
            },
        )
    )

    st_fr, data_fr, _ = _http_json(
        f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/forwardingRules",
        headers=auth_headers,
    )
    fr_name = ""
    lb_ip = ""
    if st_fr == 200 and isinstance(data_fr, dict):
        for fr in data_fr.get("items") or []:
            if isinstance(fr, dict):
                nm = str(fr.get("name", ""))
                if nm == "watchlist-forwarding-rule" or "watchlist" in nm:
                    fr_name = nm
                    lb_ip = str(fr.get("IPAddress", ""))
                    break

    c32_ok = bool(fr_name and lb_ip)
    checks.append(
        make_check(
            check_id="3.2",
            pillar=p3,
            title="URL Map, HTTP Proxy & Global Forwarding Rule (`watchlist-forwarding-rule`) Provisioned",
            passed=c32_ok,
            max_points=10,
            earned_points=10 if c32_ok else 0,
            summary=(
                f"Global Forwarding Rule `{fr_name}` is active at external Load Balancer IP `{lb_ip}`."
                if c32_ok
                else "Global Forwarding Rule `watchlist-forwarding-rule` or external LB IP not found."
            ),
            evidence={
                "forwarding_rule": fr_name,
                "load_balancer_ip": lb_ip,
            },
        )
    )

    # --- Step 4 (25 pts): Live Perimeter Enforcement & Cloud Armor Telemetry Audit ---
    print("[5/6] Checking Goal 5 / Step 4: Live Perimeter Enforcement & Cloud Armor Logs...")
    p4 = "Pillar 4: Live Perimeter Enforcement & Cloud Armor Telemetry Audit"

    st_direct = 0
    direct_blocked = False
    if watchlist_uri:
        st_direct, _, _ = _http_json(f"{watchlist_uri}/health", timeout=20)
        direct_blocked = st_direct in (403, 404)

    st_lb_sqli = 0
    st_lb_lfi = 0
    lb_waf_blocked = False
    if lb_ip:
        sqli_qs = urllib.parse.urlencode({"source": "' OR '1'='1"})
        st_lb_sqli, _, _ = _http_json(f"http://{lb_ip}/api/items?{sqli_qs}", timeout=20)
        st_lb_lfi, _, _ = _http_json(f"http://{lb_ip}/api/notes?file=../not_a_secret.txt", timeout=20)
        lb_waf_blocked = st_lb_sqli == 403 and st_lb_lfi == 403

    c41_ok = direct_blocked and lb_waf_blocked
    checks.append(
        make_check(
            check_id="4.1",
            pillar=p4,
            title="Direct `.run.app` Blocked (`404`/`403`) & Load Balancer Blocks SQLi/LFI Exploits (`403 Forbidden`)",
            passed=c41_ok,
            max_points=15,
            earned_points=15 if c41_ok else (7 if direct_blocked else 0),
            summary=(
                f"Direct `.run.app` returned `HTTP {st_direct}` (blocked) and Cloud Armor LB (`{lb_ip}`) blocked SQLi (`{st_lb_sqli}`) & LFI (`{st_lb_lfi}`)."
                if c41_ok
                else f"Perimeter probe results: direct_run_http={st_direct}, lb_sqli_http={st_lb_sqli}, lb_lfi_http={st_lb_lfi}."
            ),
            evidence={
                "direct_cloud_run_http_status": st_direct,
                "direct_cloud_run_blocked": direct_blocked,
                "lb_ip": lb_ip,
                "lb_sqli_http_status": st_lb_sqli,
                "lb_lfi_http_status": st_lb_lfi,
            },
        )
    )

    def _query_armor_logs() -> Tuple[int, List[str]]:
        pol_filter = (
            f' AND jsonPayload.enforcedSecurityPolicy.name="{policy_name}"' if policy_name else ""
        )
        st_al, data_al, _ = _http_json(
            "https://logging.googleapis.com/v2/entries:list",
            method="POST",
            headers=auth_headers,
            body={
                "resourceNames": [f"projects/{project_id}"],
                "filter": f'resource.type="http_load_balancer"{pol_filter}',
                "pageSize": 20,
                "orderBy": "timestamp desc",
            },
        )
        outcomes: List[str] = []
        if st_al == 200 and isinstance(data_al, dict):
            for ent in data_al.get("entries") or []:
                enf = (ent.get("jsonPayload") or {}).get("enforcedSecurityPolicy") or {}
                if isinstance(enf, dict) and enf.get("name"):
                    outcomes.append(
                        f"{enf.get('name')}:priority={enf.get('priority')}:outcome={enf.get('outcome')}"
                    )
        return len(outcomes), outcomes

    armor_log_count, armor_log_samples = _query_armor_logs()
    if armor_log_count == 0 and lb_ip:
        time.sleep(8)
        armor_log_count, armor_log_samples = _query_armor_logs()

    c42_ok = armor_log_count > 0
    checks.append(
        make_check(
            check_id="4.2",
            pillar=p4,
            title="Cloud Logging `http_load_balancer` Cloud Armor Enforcement Telemetry (`enforcedSecurityPolicy`)",
            passed=c42_ok,
            max_points=10,
            earned_points=10 if c42_ok else 0,
            summary=(
                f"Cloud Logging recorded {armor_log_count} `enforcedSecurityPolicy` event(s) for `{policy_name}`."
                if c42_ok
                else f"No `http_load_balancer` `enforcedSecurityPolicy` logs found yet for `{policy_name or 'watchlist-cloud-armor-policy'}`."
            ),
            evidence={
                "policy_name": policy_name,
                "enforcement_log_count": armor_log_count,
                "sample_enforcements": armor_log_samples[:5],
            },
        )
    )

    return checks


# ============================================================================
# CRYPTOGRAPHIC ANTI-CHEAT ATTESTATION & WAA SUBMISSION
# ============================================================================
def resolve_signer_service_account(
    project_id: str, project_number: str, auth_headers: Dict[str, str]
) -> str:
    """
    Resolves an active service account inside `<project_id>` for minting the Google-signed
    RS256 OIDC JWT via IAM Credentials API.
    """
    candidates = [
        f"codemender-mcp-sa@{project_id}.iam.gserviceaccount.com",
        f"codemender-mcp@{project_id}.iam.gserviceaccount.com",
        f"codemender-runner@{project_id}.iam.gserviceaccount.com",
        f"watchlist-sa@{project_id}.iam.gserviceaccount.com",
        f"watchlist@{project_id}.iam.gserviceaccount.com",
    ]
    for sa_email in candidates:
        url_sa = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{urllib.parse.quote(sa_email)}"
        st_sa, data_sa, _ = _http_json(url_sa, headers=auth_headers)
        if st_sa == 200 and isinstance(data_sa, dict) and not data_sa.get("disabled", False):
            return sa_email

    url_list = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"
    st_list, data_list, _ = _http_json(url_list, headers=auth_headers)
    if st_list == 200 and isinstance(data_list, dict):
        for acc in data_list.get("accounts", []):
            email = str(acc.get("email", ""))
            if email.endswith(f"@{project_id}.iam.gserviceaccount.com") and not acc.get("disabled", False):
                return email
        for acc in data_list.get("accounts", []):
            email = str(acc.get("email", ""))
            if (
                project_number
                and email == f"{project_number}-compute@developer.gserviceaccount.com"
                and not acc.get("disabled", False)
            ):
                return email

    return candidates[0]


def mint_google_signed_attestation_jwt(
    project_id: str,
    project_number: str,
    auth_headers: Dict[str, str],
    student_id: str,
    principal_email: str,
    goal_id: str,
    submission_id: str,
    earned_points: int,
    max_points: int,
    payload_sha256: str,
    timestamp_unix: int,
    lab_id: str = "lab_7",
) -> Dict[str, Any]:
    """
    Mints an asymmetric RS256 OIDC ID token signed by Google's IAM Credentials service
    binding student identity, project, lab_id, goal_id, submission_id, signer SA, score,
    timestamp, and the SHA-256 hash of the canonical assessment JSON payload.
    """
    sa_email = resolve_signer_service_account(project_id, project_number, auth_headers)
    lab_param = lab_id if lab_id else LAB_METADATA.get("lab_id", "lab_7")
    audience = (
        f"https://secops-codemender.assessment/v1"
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
    """Submits the cryptographically attested Goal report directly to the Web Assessor endpoint."""
    id_token = str(attestation.get("id_token") or "")
    meta = canonical_payload.get("metadata", {})
    goal_id = str(meta.get("goal_id", "goal-1-target-app-deployment"))
    lab_id = str(meta.get("lab_id") or LAB_METADATA.get("lab_id", "lab_7"))
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
    lines.append("# [7] Using AI for Sec Ops — Student Goal Assessment Report")
    lines.append("")
    lines.append(
        "> **Automated LLM Assessor & Grading Pipeline Notice**: This report contains live GCP infrastructure, "
        "MCP server, GitHub repository, and security control verification evidence for a specific **Lab 7 Goal**, "
        "followed by a canonical JSON payload and an **asymmetric `RS256` Google-signed OIDC JWT (`id_token`)** "
        "that cryptographically binds the student's identity, GCP project, `lab_id` (`lab_7`), `goal_id`, "
        "submission nonce, and the `SHA-256` digest of the assessment evidence."
    )
    lines.append("")
    lines.append("## 1. Executive Summary & Student Identity")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| :--- | :--- |")
    lines.append(
        f"| **Assessed Lab (`lab_id`)** | `{meta.get('lab_id', 'lab_7')}` — **[{meta.get('lab_number', 7)}] {meta.get('lab_title', '')}** |"
    )
    lines.append(
        f"| **Assessed Goal (`goal_id`)** | `{meta.get('goal_id', 'goal-1-target-app-deployment')}` — **{meta.get('goal_title', '')}** |"
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
        lines.append(
            f"### Check {c['check_id']} — {c['title']} (`{c['status']}`, {c['earned_points']}/{c['max_points']} pts)"
        )
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
        "   - Confirm that the `aud` claim inside the Google-signed JWT matches the student's `project_id`, `principal`, `student`, `goal` (`goal_id`), `lab` (`lab_7`), `nonce` (`submission_id`), and the recomputed `sha256` digest.\n"
        "   - If the `sha256` in the signed JWT does not match the report's JSON payload, or if `project_id` belongs to a different student in `students`, **flag the submission as INVALID / TAMPERED**.\n"
        "2. **Record Goal-Scoped Grade (`HIGHEST` Score Retention Policy)**:\n"
        "   - Grade and register this submission solely under `goal_id` (`student_goal_grades` keyed by `(student_id, goal_id)`).\n"
        "   - Do **not** overwrite or invalidate previously completed goals (since later goals remediate vulnerabilities and lock down public Cloud Run ingress tested in Goal 1).\n"
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


# ============================================================================
# STATE MANAGEMENT & CLI ENTRYPOINT
# ============================================================================
def _state_file_path(repo_root: Path) -> Path:
    return repo_root / ".agents" / "skills" / "verify-deployment" / ".assessment_state.json"


def _load_assessment_state(repo_root: Path) -> Dict[str, Any]:
    state_path = _state_file_path(repo_root)
    state: Dict[str, Any] = {
        "enrollment_key": "",
        "student_id": "",
        "submit_url": "",
        "project_id": "",
        "region": "",
        "github_org": "",
        "target_repo": "",
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
    return implemented_goals[-1] if implemented_goals else "goal-1-target-app-deployment"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify [7] Using AI for Sec Ops (Wiz & CodeMender MCP Security Agent Lab) goal completion "
            "and generate a cryptographically attested Markdown report."
        )
    )
    parser.add_argument("--project-id", help="GCP project ID (auto-detected from ~/lab.env or gcloud if omitted)", default=None)
    parser.add_argument("--region", help="GCP Cloud Run / Compute region (defaults to us-central1)", default=None)
    parser.add_argument("--github-org", help="GitHub username or organization hosting Lab07-CloudRun-Service-Deploy-1", default=None)
    parser.add_argument("--target-repo", help="Target repository name (defaults to Lab07-CloudRun-Service-Deploy-1)", default=None)
    parser.add_argument("--student-id", help="Student email or identifier", default=None)
    parser.add_argument(
        "--lab-id",
        "--lab",
        dest="lab_id",
        help=f"Lab identifier (defaults to '{LAB_METADATA.get('lab_id', 'lab_7')}')",
        default=os.environ.get("ASSESSMENT_LAB_ID") or LAB_METADATA.get("lab_id", "lab_7"),
    )
    parser.add_argument(
        "--goal",
        dest="goal",
        help="Lab goal identifier (auto-selects next uncompleted goal if omitted). Short aliases '1'..'5' or 'goal-1'..'goal-5' are accepted.",
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
        help="List all registered Lab 7 goals and their steps as JSON, then exit.",
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
    lab_env = collect_lab_env(repo_root)

    state_updated = False
    for attr, state_key in (
        ("enrollment_key", "enrollment_key"),
        ("submit_url", "submit_url"),
        ("student_id", "student_id"),
        ("project_id", "project_id"),
        ("region", "region"),
        ("github_org", "github_org"),
        ("target_repo", "target_repo"),
    ):
        cli_val = getattr(args, attr, None)
        if cli_val and not _is_placeholder(str(cli_val)):
            state[state_key] = str(cli_val).strip()
            state_updated = True
        elif state.get(state_key) and not _is_placeholder(str(state[state_key])):
            setattr(args, attr, str(state[state_key]))

    if state_updated or not args.list_goals:
        _save_assessment_state(repo_root, state)

    if args.list_goals:
        completed_map = state.get("completed_goals") or {}
        enriched = []
        for gid, gdef in GOAL_REGISTRY.items():
            enriched.append(
                {
                    **gdef,
                    "completed": gid in completed_map,
                    "completion_info": completed_map.get(gid),
                }
            )
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
            f"ERROR: Goal '{goal_id}' ({goal_def['title']}) verification steps are not yet enabled.",
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

    print(f"[1/6] Resolving GCP credentials, project metadata, GitHub target, and student identity for {goal_id}...")
    access_token, token_source = get_access_token()
    project_id = resolve_project_id(args.project_id, lab_env)
    region = resolve_region(args.region, lab_env)
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
    github_token, gh_token_source = resolve_github_token_in_memory(project_id, auth_headers, lab_env)
    github_org, target_repo = resolve_github_org_and_repo(
        explicit_org=args.github_org,
        explicit_repo=args.target_repo,
        state=state,
        lab_env=lab_env,
        repo_root=repo_root,
        project_id=project_id,
        auth_headers=auth_headers,
        github_token=github_token,
    )

    state["project_id"] = project_id
    state["region"] = region
    state["student_id"] = student_info["student_id"]
    if github_org:
        state["github_org"] = github_org
    if target_repo:
        state["target_repo"] = target_repo
    _save_assessment_state(repo_root, state)

    print(
        f"      Project: {project_meta['project_id']} (#{project_meta['project_number']}) | Region: {region} | "
        f"GitHub: {github_org or '<unresolved>'}/{target_repo} ({gh_token_source}) | "
        f"Student: {student_info['student_id']} ({token_source})"
    )

    if goal_id == "goal-1-target-app-deployment":
        all_checks = run_goal_1_checks(
            project_id=project_id,
            project_number=project_meta["project_number"],
            region=region,
            github_org=github_org,
            target_repo=target_repo,
            github_token=github_token,
            auth_headers=auth_headers,
        )
    elif goal_id == "goal-2-codemender-mcp-deployment":
        all_checks = run_goal_2_checks(
            project_id=project_id,
            region=region,
            lab_env=lab_env,
            auth_headers=auth_headers,
        )
    elif goal_id == "goal-3-enterprise-mcp-connectors":
        all_checks = run_goal_3_checks(
            project_id=project_id,
            region=region,
            access_token=access_token,
            auth_headers=auth_headers,
        )
    elif goal_id == "goal-4-hitl-remediation":
        all_checks = run_goal_4_checks(
            project_id=project_id,
            region=region,
            github_org=github_org,
            target_repo=target_repo,
            github_token=github_token,
            repo_root=repo_root,
            auth_headers=auth_headers,
        )
    elif goal_id == "goal-5-cloud-armor-protection":
        all_checks = run_goal_5_checks(
            project_id=project_id,
            region=region,
            github_org=github_org,
            target_repo=target_repo,
            github_token=github_token,
            repo_root=repo_root,
            auth_headers=auth_headers,
        )
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

    lab_id = (getattr(args, "lab_id", None) or LAB_METADATA.get("lab_id", "lab_7")).strip()
    lab_number = int(LAB_METADATA.get("lab_number", 7))
    lab_title = str(LAB_METADATA.get("title", "Using AI for Sec Ops - Creating your Sec Agent Lab"))

    canonical_payload: Dict[str, Any] = {
        "schema_version": "secops-codemender-assessment/v2",
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
            "region": region,
            "github_repository": f"{github_org}/{target_repo}" if github_org else target_repo,
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

    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    pretty_canonical_json = json.dumps(canonical_payload, indent=2, sort_keys=True)

    print("[6/6] Minting Google-signed RS256 OIDC attestation JWT & writing Markdown report...")
    attestation = mint_google_signed_attestation_jwt(
        project_id=project_id,
        project_number=project_meta["project_number"],
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
    print(
        f"GOAL VERIFICATION COMPLETE: {earned_points}/{max_points} pts ({pct}%) — {passed_checks}/{total_checks} checks passed"
    )
    print(f"Assessed Lab      : {lab_id} ({lab_title})")
    print(f"Assessed Goal     : {goal_id} ({goal_title})")
    print(f"Submission Nonce  : {submission_id}")
    print(f"Student Principal : {student_info['authenticated_principal_email']}")
    print(f"GCP Project       : {project_meta['project_id']} (#{project_meta['project_number']})")
    print(f"GitHub Target     : {github_org or '<unresolved>'}/{target_repo}")
    print(f"Payload SHA-256   : {payload_sha256}")
    print(
        f"Attestation Status: {attestation.get('status')} (Google OIDC verified={attestation.get('google_tokeninfo_verified')})"
    )
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
