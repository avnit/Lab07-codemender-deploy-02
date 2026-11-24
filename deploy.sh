#!/usr/bin/env bash
# ==============================================================================
# deploy.sh -- single entry point for the Lab 7 CodeMender Cloud Run services.
#
# Deploys, with gcloud only (no Terraform, no Docker, no prompts):
#   1. codemender-runner-mcp  Cloud Run service  (source: codemender-runner-mcp/)
#   2. codemender-mcp         Cloud Run service  (source: codemender-mcp/)
# plus what both of them need to work: Artifact Registry repo, GCS transit
# bucket, BigQuery dataset, least-privilege service accounts and the sandboxed
# `codemender-runner` Cloud Run Job they dispatch to.
#
# No GitHub owner/repository is needed at deploy time: the target repository is
# an argument of the MCP tools. A GitHub token is optional (GITHUB_TOKEN); it is
# only required to clone private repos and push fix branches / PRs.
#
#   ./deploy.sh                          # deploy everything
#   ./deploy.sh --only mcp               # only the codemender-mcp service
#   ./deploy.sh --only runner-mcp        # only the codemender-runner-mcp service
#   ./deploy.sh --help
#
# The script is idempotent: re-running it only rebuilds images whose source
# changed and re-applies configuration.
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER_SRC="codemender-runner-mcp"
MCP_SRC="codemender-mcp"

# ------------------------------------------------------------------ helpers
c_bold=$'\033[1m'; c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_off=$'\033[0m'
[[ -t 1 ]] || { c_bold=""; c_red=""; c_grn=""; c_ylw=""; c_off=""; }
step() { printf '\n%s==> %s%s\n' "$c_bold" "$*" "$c_off"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '    %s!%s %s\n' "$c_ylw" "$c_off" "$*" >&2; }
die()  { printf '%sERROR:%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }

# retry CMD... -- IAM is eventually consistent: a binding for a service account
# created seconds ago can fail with "does not exist". Retry before giving up.
retry() {
  local attempt=1 max=6 out
  until out="$("$@" 2>&1)"; do
    if (( attempt >= max )); then
      printf '%s\n' "$out" >&2
      return 1
    fi
    sleep $(( attempt * 5 ))
    attempt=$(( attempt + 1 ))
  done
}

usage() {
  cat <<'EOF'
Usage: ./deploy.sh [options]

Options
  -p, --project ID            GCP project (default: $PROJECT_ID, .env, gcloud config)
  -r, --region REGION         GCP region (default: us-central1)
      --only TARGET           Deploy one service: "runner-mcp" or "mcp" (default: both)
      --skip-runner-job       Do not build/deploy the codemender-runner Cloud Run Job
                              (use when it already exists; the job must be present
                              for cm_find / cm_validate / cm_fix to work)
      --allow-unauthenticated Public URLs. codemender-runner-mcp is then protected by
                              a generated bearer token (Secret Manager);
                              codemender-mcp has NO application-level auth.
                              Default: IAM-only (roles/run.invoker).
  -h, --help                  Show this help

Environment (all optional; also read from codemender-mcp/.env, or $ENV_FILE)
  PROJECT_ID / GCP_PROJECT_ID, REGION
  GITHUB_TOKEN                Stored in Secret Manager, never as a plain env var.
                              Never prompted for. Omit for public-repo scanning.
  WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_ENDPOINT   Enable Wiz tools (codemender-mcp)
  BQ_DATASET (codemender), BQ_TABLE (findings), BQ_LOCATION (US)
  CM_REPORTS_BUCKET           Transit bucket (default: codemender-reports-<project>)
  INVOKER_MEMBERS             Comma-separated IAM members granted roles/run.invoker
                              in IAM-only mode (default: the active gcloud account)
  BUILD_SERVICE_ACCOUNT       Service account e-mail for Cloud Build
  RUNNER_MCP_SERVICE (codemender-runner-mcp), MCP_SERVICE (codemender-mcp),
  RUNNER_JOB (codemender-runner), AR_REPO (codemender-runner)
EOF
}

# load_env_file FILE -- read KEY=VALUE pairs for an allowlist of keys. The file
# is parsed, never sourced, and values already present in the environment win.
ENV_KEYS=" GCP_PROJECT_ID PROJECT_ID REGION BQ_DATASET BQ_TABLE BQ_LOCATION LOG_NAME_FILTER \
CM_RUNNER_JOB_NAME CM_REPORTS_BUCKET CM_DEFAULT_PATCH_MODE GITHUB_TOKEN GITHUB_API_URL \
WIZ_CLIENT_ID WIZ_CLIENT_SECRET WIZ_API_ENDPOINT WIZ_AUTH_URL WIZ_AUDIENCE "
load_env_file() {
  local file="$1" line key val
  [[ -f "$file" ]] || return 0
  info "reading settings from ${file#"${ROOT}/"}"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    key="${BASH_REMATCH[2]}"; val="${BASH_REMATCH[3]}"
    [[ "$ENV_KEYS" == *" ${key} "* ]] || continue
    [[ -z "${!key+x}" ]] || continue
    if [[ "$val" =~ ^\"(.*)\"$ || "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
    printf -v "$key" '%s' "$val"
  done < "$file"
}

# ------------------------------------------------------------------ args
ONLY="all"
SKIP_RUNNER_JOB="${SKIP_RUNNER_JOB:-false}"
ALLOW_UNAUTHENTICATED="${ALLOW_UNAUTHENTICATED:-false}"
CLI_PROJECT=""; CLI_REGION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--project|-r|--region|--only)
      [[ $# -ge 2 ]] || die "$1 needs a value."
      case "$1" in
        -p|--project) CLI_PROJECT="$2" ;;
        -r|--region) CLI_REGION="$2" ;;
        --only) ONLY="$2" ;;
      esac
      shift ;;
    --skip-runner-job) SKIP_RUNNER_JOB=true ;;
    --allow-unauthenticated) ALLOW_UNAUTHENTICATED=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "Unknown option: $1" ;;
  esac
  shift
done
for flag in SKIP_RUNNER_JOB ALLOW_UNAUTHENTICATED; do
  case "${!flag}" in true|false) ;; *) die "${flag} must be 'true' or 'false' (got '${!flag}')." ;; esac
done
case "$ONLY" in
  all) DEPLOY_RUNNER_MCP=true; DEPLOY_MCP=true ;;
  runner-mcp|codemender-runner-mcp) DEPLOY_RUNNER_MCP=true; DEPLOY_MCP=false ;;
  mcp|codemender-mcp) DEPLOY_RUNNER_MCP=false; DEPLOY_MCP=true ;;
  *) die "--only must be 'runner-mcp' or 'mcp' (got '${ONLY}')." ;;
esac

# ------------------------------------------------------------- preflight
step "Checking prerequisites"
for bin in gcloud bq; do
  command -v "$bin" >/dev/null 2>&1 || die "'$bin' is not installed (install the Google Cloud SDK)."
done
for dir in "$RUNNER_SRC" "$MCP_SRC"; do
  [[ -d "${ROOT}/${dir}" ]] || die "Missing source directory: ${dir}/ (run deploy.sh from the repository root checkout)."
done
load_env_file "${ENV_FILE:-${ROOT}/${MCP_SRC}/.env}"

PROJECT_ID="${CLI_PROJECT:-${PROJECT_ID:-${GCP_PROJECT_ID:-}}}"
[[ -n "$PROJECT_ID" ]] || PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
[[ -n "$PROJECT_ID" && "$PROJECT_ID" != "(unset)" ]] \
  || die "No GCP project. Pass --project ID or run: gcloud config set project ID"
REGION="${CLI_REGION:-${REGION:-us-central1}}"

ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
gcloud auth print-access-token >/dev/null 2>&1 || die "gcloud is not logged in. Run: gcloud auth login"
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)' 2>/dev/null || true)"
[[ -n "$PROJECT_NUMBER" ]] || die "Project '${PROJECT_ID}' not found or not accessible as ${ACCOUNT:-the current account}."

# ------------------------------------------------------------- settings
RUNNER_MCP_SERVICE="${RUNNER_MCP_SERVICE:-codemender-runner-mcp}"
MCP_SERVICE="${MCP_SERVICE:-codemender-mcp}"
RUNNER_JOB="${RUNNER_JOB:-${CM_RUNNER_JOB_NAME:-codemender-runner}}"
AR_REPO="${AR_REPO:-codemender-runner}"
BUCKET="${CM_REPORTS_BUCKET:-codemender-reports-${PROJECT_ID}}"
BUCKET_TTL_DAYS="${BUCKET_TTL_DAYS:-7}"
BQ_DATASET="${BQ_DATASET:-codemender}"
BQ_TABLE="${BQ_TABLE:-findings}"
BQ_LOCATION="${BQ_LOCATION:-US}"
LOG_NAME_FILTER="${LOG_NAME_FILTER:-codemender}"
PATCH_MODE="${CM_DEFAULT_PATCH_MODE:-pr}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITHUB_API_URL="${GITHUB_API_URL:-https://api.github.com}"
GITHUB_SECRET="${GITHUB_SECRET:-codemender-github-token}"
AUTH_SECRET="${AUTH_SECRET:-codemender-mcp-auth-token}"
WIZ_CLIENT_ID="${WIZ_CLIENT_ID:-}"
WIZ_CLIENT_SECRET="${WIZ_CLIENT_SECRET:-}"
WIZ_API_ENDPOINT="${WIZ_API_ENDPOINT:-}"
WIZ_AUTH_URL="${WIZ_AUTH_URL:-https://auth.app.wiz.io/oauth/token}"
WIZ_AUDIENCE="${WIZ_AUDIENCE:-wiz-api}"
WIZ_SECRET="${WIZ_SECRET:-wiz-client-secret}"
RUNNER_TIMEOUT="${RUNNER_TIMEOUT:-10800s}"
RUNNER_CPU="${RUNNER_CPU:-2}"
RUNNER_MEMORY="${RUNNER_MEMORY:-8Gi}"
# The runner MCP watches multi-hour jobs from background threads, so it keeps
# one warm instance by default (same as its Terraform module).
RUNNER_MCP_MIN_INSTANCES="${RUNNER_MCP_MIN_INSTANCES:-1}"
RUNNER_MCP_MAX_INSTANCES="${RUNNER_MCP_MAX_INSTANCES:-3}"
MCP_MIN_INSTANCES="${MCP_MIN_INSTANCES:-0}"
MCP_MAX_INSTANCES="${MCP_MAX_INSTANCES:-10}"

case "$PATCH_MODE" in pr|branch|none) ;; *) die "CM_DEFAULT_PATCH_MODE must be pr, branch or none (got '${PATCH_MODE}')." ;; esac

sa_email() { printf '%s@%s.iam.gserviceaccount.com' "$1" "$PROJECT_ID"; }
RUNNER_SA="$(sa_email codemender-runner-sa)"
RUNNER_MCP_SA="$(sa_email codemender-runner-mcp-sa)"
MCP_SA="$(sa_email codemender-mcp-sa)"

AR_HOST="${REGION}-docker.pkg.dev"
AR_PATH="${AR_HOST}/${PROJECT_ID}/${AR_REPO}"

# src_tag DIR -- content-addressed image tag: the git tree hash of DIR when it is
# committed and clean (unchanged source => same tag => no rebuild), otherwise a
# timestamp so uncommitted changes are always built.
src_tag() {
  local dir="$1" tag
  if tag="$(git -C "$ROOT" rev-parse --short=12 "HEAD:${dir}" 2>/dev/null)" \
     && [[ -z "$(git -C "$ROOT" status --porcelain -- "$dir" 2>/dev/null)" ]]; then
    printf '%s' "$tag"
  else
    date -u +%Y%m%d%H%M%S
  fi
}
RUNNER_SRC_TAG="$(src_tag "$RUNNER_SRC")"
RUNNER_IMAGE="${AR_PATH}/codemender-runner:${RUNNER_SRC_TAG}"
RUNNER_MCP_IMAGE="${AR_PATH}/codemender-mcp:${RUNNER_SRC_TAG}"       # name fixed by cloudbuild.mcp.yaml
MCP_IMAGE="${AR_PATH}/codemender-mcp-server:$(src_tag "$MCP_SRC")"

info "project=${PROJECT_ID}  region=${REGION}  account=${ACCOUNT:-unknown}"
info "services: $($DEPLOY_RUNNER_MCP && printf '%s ' "$RUNNER_MCP_SERVICE")$($DEPLOY_MCP && printf '%s' "$MCP_SERVICE")"
info "runner job: ${RUNNER_JOB}$($SKIP_RUNNER_JOB && printf ' (skipped)')"
info "access: $([[ "$ALLOW_UNAUTHENTICATED" == true ]] && printf 'public URL' || printf 'IAM-only (roles/run.invoker)')"
ok "prerequisites satisfied"

# ------------------------------------------------------------------ APIs
step "Enabling required APIs"
gcloud services enable \
  run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  bigquery.googleapis.com storage.googleapis.com logging.googleapis.com \
  secretmanager.googleapis.com iam.googleapis.com aiplatform.googleapis.com \
  --project "$PROJECT_ID" --quiet
ok "APIs enabled"

# ------------------------------------------------------- shared resources
step "Shared resources (Artifact Registry, GCS bucket, BigQuery dataset)"
if gcloud artifacts repositories describe "$AR_REPO" --location "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; then
  ok "Artifact Registry repo ${AR_REPO} exists"
else
  gcloud artifacts repositories create "$AR_REPO" --repository-format=docker --location "$REGION" \
    --description="CodeMender runner and MCP server images" --project "$PROJECT_ID" --quiet >/dev/null
  ok "created Artifact Registry repo ${AR_REPO}"
fi

if gcloud storage buckets describe "gs://${BUCKET}" --project "$PROJECT_ID" >/dev/null 2>&1; then
  ok "bucket gs://${BUCKET} exists"
else
  gcloud storage buckets create "gs://${BUCKET}" --project "$PROJECT_ID" --location "$REGION" \
    --uniform-bucket-level-access --public-access-prevention --soft-delete-duration=0 --quiet >/dev/null
  LIFECYCLE_FILE="$(mktemp)"
  printf '{"rule":[{"action":{"type":"Delete"},"condition":{"age":%d}},{"action":{"type":"AbortIncompleteMultipartUpload"},"condition":{"age":1}}]}\n' \
    "$BUCKET_TTL_DAYS" > "$LIFECYCLE_FILE"
  gcloud storage buckets update "gs://${BUCKET}" --lifecycle-file="$LIFECYCLE_FILE" --project "$PROJECT_ID" --quiet >/dev/null
  rm -f "$LIFECYCLE_FILE"
  ok "created bucket gs://${BUCKET} (private, objects deleted after ${BUCKET_TTL_DAYS} days)"
fi

if bq --project_id="$PROJECT_ID" show --dataset "${PROJECT_ID}:${BQ_DATASET}" >/dev/null 2>&1; then
  ok "BigQuery dataset ${BQ_DATASET} exists"
else
  bq --project_id="$PROJECT_ID" --location="$BQ_LOCATION" mk --dataset \
    --description="CodeMender findings, verification verdicts and patches" "${PROJECT_ID}:${BQ_DATASET}" >/dev/null
  ok "created BigQuery dataset ${BQ_DATASET} (${BQ_LOCATION})"
fi

# Ensure the unified findings table schema exists (supports both live cm_find
# SARIF ingestion and Lab 7 mock-findings.json bq load --autodetect seeding).
bq --project_id="$PROJECT_ID" --location="$BQ_LOCATION" query --use_legacy_sql=false --quiet >/dev/null <<EOSQL
CREATE TABLE IF NOT EXISTS \`${PROJECT_ID}.${BQ_DATASET}.${BQ_TABLE}\` (
  finding_id STRING,
  issue_id STRING,
  event_type STRING,
  session_id STRING,
  scan_job_id STRING,
  repo STRING,
  repository STRING,
  ref STRING,
  commit_sha STRING,
  payload_uri STRING,
  fingerprint STRING,
  rule_id STRING,
  cwe_id STRING,
  vulnerability_type STRING,
  severity STRING,
  title STRING,
  description STRING,
  message STRING,
  file_path STRING,
  line_number INT64,
  start_line INT64,
  end_line INT64,
  status STRING,
  verify_status STRING,
  dismiss_reason STRING,
  fix_status STRING,
  sarif STRING,
  verified_sarif STRING,
  patch STRING,
  patch_ref STRING,
  patch_branch STRING,
  patch_commit STRING,
  pr_url STRING,
  wiz_issue_id STRING,
  last_job_id STRING,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
)
PARTITION BY DATE(created_at);

ALTER TABLE \`${PROJECT_ID}.${BQ_DATASET}.${BQ_TABLE}\`
  ADD COLUMN IF NOT EXISTS finding_id STRING,
  ADD COLUMN IF NOT EXISTS issue_id STRING,
  ADD COLUMN IF NOT EXISTS event_type STRING,
  ADD COLUMN IF NOT EXISTS session_id STRING,
  ADD COLUMN IF NOT EXISTS scan_job_id STRING,
  ADD COLUMN IF NOT EXISTS repo STRING,
  ADD COLUMN IF NOT EXISTS repository STRING,
  ADD COLUMN IF NOT EXISTS ref STRING,
  ADD COLUMN IF NOT EXISTS commit_sha STRING,
  ADD COLUMN IF NOT EXISTS payload_uri STRING,
  ADD COLUMN IF NOT EXISTS fingerprint STRING,
  ADD COLUMN IF NOT EXISTS rule_id STRING,
  ADD COLUMN IF NOT EXISTS cwe_id STRING,
  ADD COLUMN IF NOT EXISTS vulnerability_type STRING,
  ADD COLUMN IF NOT EXISTS severity STRING,
  ADD COLUMN IF NOT EXISTS title STRING,
  ADD COLUMN IF NOT EXISTS description STRING,
  ADD COLUMN IF NOT EXISTS message STRING,
  ADD COLUMN IF NOT EXISTS file_path STRING,
  ADD COLUMN IF NOT EXISTS line_number INT64,
  ADD COLUMN IF NOT EXISTS start_line INT64,
  ADD COLUMN IF NOT EXISTS end_line INT64,
  ADD COLUMN IF NOT EXISTS status STRING,
  ADD COLUMN IF NOT EXISTS verify_status STRING,
  ADD COLUMN IF NOT EXISTS dismiss_reason STRING,
  ADD COLUMN IF NOT EXISTS fix_status STRING,
  ADD COLUMN IF NOT EXISTS sarif STRING,
  ADD COLUMN IF NOT EXISTS verified_sarif STRING,
  ADD COLUMN IF NOT EXISTS patch STRING,
  ADD COLUMN IF NOT EXISTS patch_ref STRING,
  ADD COLUMN IF NOT EXISTS patch_branch STRING,
  ADD COLUMN IF NOT EXISTS patch_commit STRING,
  ADD COLUMN IF NOT EXISTS pr_url STRING,
  ADD COLUMN IF NOT EXISTS wiz_issue_id STRING,
  ADD COLUMN IF NOT EXISTS last_job_id STRING,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;
EOSQL
ok "BigQuery table ${BQ_DATASET}.${BQ_TABLE} schema reconciled"

# ------------------------------------------------- service accounts + IAM
ensure_sa() {  # ensure_sa EMAIL DISPLAY_NAME
  local email="$1" name="${1%%@*}"
  if gcloud iam service-accounts describe "$email" --project "$PROJECT_ID" >/dev/null 2>&1; then
    ok "service account ${name} exists"
  else
    gcloud iam service-accounts create "$name" --display-name="$2" --project "$PROJECT_ID" --quiet >/dev/null
    ok "created service account ${name}"
  fi
}
grant_project() {  # grant_project MEMBER ROLE
  retry gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="$1" --role="$2" --condition=None --quiet \
    || die "Could not grant $2 to $1 on project ${PROJECT_ID}."
}
grant_bucket() {  # grant_bucket SA_EMAIL
  retry gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" --member="serviceAccount:$1" \
    --role=roles/storage.objectUser --project "$PROJECT_ID" --quiet \
    || die "Could not grant roles/storage.objectUser on gs://${BUCKET} to $1."
}
grant_dataset() {  # grant_dataset SA_EMAIL -- dataset-scoped, not project-wide
  retry bq --project_id="$PROJECT_ID" --location="$BQ_LOCATION" query --use_legacy_sql=false --quiet \
    "GRANT \`roles/bigquery.dataEditor\` ON SCHEMA \`${PROJECT_ID}.${BQ_DATASET}\` TO \"serviceAccount:$1\"" \
    || die "Could not grant roles/bigquery.dataEditor on dataset ${BQ_DATASET} to $1."
}
grant_secret() {  # grant_secret SA_EMAIL SECRET
  retry gcloud secrets add-iam-policy-binding "$2" --member="serviceAccount:$1" \
    --role=roles/secretmanager.secretAccessor --project "$PROJECT_ID" --quiet \
    || die "Could not grant access to secret $2 to $1."
}
# Roles shared by both MCP services: write findings, stage code snapshots,
# read job executions and write logs.
grant_mcp_base() {  # grant_mcp_base SA_EMAIL
  grant_dataset "$1"
  grant_bucket "$1"
  grant_project "serviceAccount:$1" roles/bigquery.jobUser
  grant_project "serviceAccount:$1" roles/run.viewer
  grant_project "serviceAccount:$1" roles/logging.logWriter
}

step "Service accounts and IAM (least privilege)"
if ! $SKIP_RUNNER_JOB; then
  ensure_sa "$RUNNER_SA" "CodeMender runner sandbox job"
  grant_bucket "$RUNNER_SA"
  grant_project "serviceAccount:${RUNNER_SA}" roles/logging.logWriter
  grant_project "serviceAccount:${RUNNER_SA}" roles/aiplatform.user
  ok "runner job identity configured"
fi
if $DEPLOY_RUNNER_MCP; then
  ensure_sa "$RUNNER_MCP_SA" "CodeMender runner MCP server"
  grant_mcp_base "$RUNNER_MCP_SA"
  ok "${RUNNER_MCP_SERVICE} identity configured"
fi
if $DEPLOY_MCP; then
  ensure_sa "$MCP_SA" "CodeMender MCP server"
  grant_mcp_base "$MCP_SA"
  grant_project "serviceAccount:${MCP_SA}" roles/logging.viewer   # search_codemender_logs
  ok "${MCP_SERVICE} identity configured"
fi

# Cloud Build identity: push to this repo and write build logs.
BUILD_SA="${BUILD_SERVICE_ACCOUNT:-}"
BUILD_SA="${BUILD_SA##*/}"
BUILD_SA_ARGS=()
if [[ -n "$BUILD_SA" ]]; then
  BUILD_SA_ARGS=(--service-account="projects/${PROJECT_ID}/serviceAccounts/${BUILD_SA}")
else
  BUILD_SA="$(gcloud builds get-default-service-account --project "$PROJECT_ID" \
    --format='value(serviceAccountEmail)' 2>/dev/null || true)"
  BUILD_SA="${BUILD_SA##*/}"
  BUILD_SA="${BUILD_SA:-${PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"
fi
retry gcloud artifacts repositories add-iam-policy-binding "$AR_REPO" --location "$REGION" --project "$PROJECT_ID" \
  --member="serviceAccount:${BUILD_SA}" --role=roles/artifactregistry.writer --quiet \
  || die "Could not grant roles/artifactregistry.writer on ${AR_REPO} to ${BUILD_SA}."
grant_project "serviceAccount:${BUILD_SA}" roles/logging.logWriter
grant_project "serviceAccount:${BUILD_SA}" roles/storage.objectViewer   # read the uploaded source tarball
ok "Cloud Build identity: ${BUILD_SA}"

# --------------------------------------------------------------- secrets
secret_exists() { gcloud secrets describe "$1" --project "$PROJECT_ID" >/dev/null 2>&1; }
put_secret() {  # put_secret NAME VALUE -- create, or add a version only if the value changed
  local name="$1" value="$2" current
  if ! secret_exists "$name"; then
    printf '%s' "$value" | gcloud secrets create "$name" --data-file=- --replication-policy=automatic \
      --project "$PROJECT_ID" --quiet >/dev/null
    ok "created secret ${name}"
    return
  fi
  current="$(gcloud secrets versions access latest --secret "$name" --project "$PROJECT_ID" 2>/dev/null || true)"
  if [[ "$current" == "$value" ]]; then
    ok "secret ${name} is up to date"
  else
    printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- --project "$PROJECT_ID" --quiet >/dev/null
    ok "added a new version to secret ${name}"
  fi
}

step "Secrets"
RUNNER_MCP_SECRETS=()
MCP_SECRETS=()

if [[ -z "$GITHUB_TOKEN" ]] && ! secret_exists "$GITHUB_SECRET" && secret_exists "github-token"; then
  GITHUB_SECRET="github-token"
fi
if [[ -n "$GITHUB_TOKEN" ]]; then
  put_secret "$GITHUB_SECRET" "$GITHUB_TOKEN"
fi
if secret_exists "$GITHUB_SECRET"; then
  if $DEPLOY_RUNNER_MCP; then grant_secret "$RUNNER_MCP_SA" "$GITHUB_SECRET"; RUNNER_MCP_SECRETS+=("GITHUB_TOKEN=${GITHUB_SECRET}:latest"); fi
  if $DEPLOY_MCP; then grant_secret "$MCP_SA" "$GITHUB_SECRET"; MCP_SECRETS+=("GITHUB_TOKEN=${GITHUB_SECRET}:latest"); fi
  ok "GitHub token mounted from secret ${GITHUB_SECRET}"
else
  warn "No GitHub token (GITHUB_TOKEN unset, secret ${GITHUB_SECRET} absent): public repos can be scanned;"
  warn "private repos and fix branches/PRs need one. Re-run with GITHUB_TOKEN=... to add it."
fi

WIZ_ENABLED=false
if $DEPLOY_MCP; then
  if [[ -n "$WIZ_CLIENT_ID" && -n "$WIZ_CLIENT_SECRET" && -n "$WIZ_API_ENDPOINT" ]]; then
    put_secret "$WIZ_SECRET" "$WIZ_CLIENT_SECRET"
    grant_secret "$MCP_SA" "$WIZ_SECRET"
    MCP_SECRETS+=("WIZ_CLIENT_SECRET=${WIZ_SECRET}:latest")
    WIZ_ENABLED=true
    ok "Wiz integration enabled (${WIZ_API_ENDPOINT})"
  else
    info "Wiz integration not configured (set WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_ENDPOINT to enable)"
  fi
fi

# The runner MCP's static bearer token replaces IAM in public mode only: behind
# IAM the Authorization header carries the caller's identity token instead.
if $DEPLOY_RUNNER_MCP && [[ "$ALLOW_UNAUTHENTICATED" == true ]]; then
  if ! secret_exists "$AUTH_SECRET"; then
    put_secret "$AUTH_SECRET" "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
  grant_secret "$RUNNER_MCP_SA" "$AUTH_SECRET"
  RUNNER_MCP_SECRETS+=("CM_MCP_AUTH_TOKEN=${AUTH_SECRET}:latest")
  ok "bearer token for ${RUNNER_MCP_SERVICE} in secret ${AUTH_SECRET}"
fi

# ----------------------------------------------------------------- images
image_exists() { gcloud artifacts docker images describe "$1" --project "$PROJECT_ID" >/dev/null 2>&1; }
TMP_BUILD_CONFIG=""
trap '[[ -z "$TMP_BUILD_CONFIG" ]] || rm -f "$TMP_BUILD_CONFIG"' EXIT

build_with_config() {  # build_with_config LABEL IMAGE SOURCE_DIR CONFIG SUBSTITUTIONS
  if image_exists "$2"; then
    ok "$1 image up to date (${2##*:})"
    return
  fi
  info "building $1 image with Cloud Build -> ${2}"
  (cd "${ROOT}/$3" && gcloud builds submit . --config="$4" --substitutions="$5" \
    --project "$PROJECT_ID" ${BUILD_SA_ARGS[@]+"${BUILD_SA_ARGS[@]}"} --quiet) \
    || die "Cloud Build failed for the $1 image."
  ok "$1 image pushed"
}

step "Container images"
if ! $SKIP_RUNNER_JOB; then
  info "the runner image is large; its first build takes ~10-15 minutes"
  build_with_config "runner job" "$RUNNER_IMAGE" "$RUNNER_SRC" cloudbuild.yaml \
    "_REGION=${REGION},_REPO_NAME=${AR_REPO},_IMAGE_TAG=${RUNNER_IMAGE##*:}"
fi
if $DEPLOY_RUNNER_MCP; then
  build_with_config "$RUNNER_MCP_SERVICE" "$RUNNER_MCP_IMAGE" "$RUNNER_SRC" cloudbuild.mcp.yaml \
    "_REGION=${REGION},_REPO_NAME=${AR_REPO},_IMAGE_TAG=${RUNNER_MCP_IMAGE##*:}"
fi
if $DEPLOY_MCP; then
  # codemender-mcp/cloudbuild.yaml also deploys and needs $COMMIT_SHA (trigger
  # builds only), so build its Dockerfile with a minimal build-and-push config.
  TMP_BUILD_CONFIG="$(mktemp)"
  cat > "$TMP_BUILD_CONFIG" <<'EOF'
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${_IMAGE}', '.']
images: ['${_IMAGE}']
options:
  logging: CLOUD_LOGGING_ONLY
EOF
  build_with_config "$MCP_SERVICE" "$MCP_IMAGE" "$MCP_SRC" "$TMP_BUILD_CONFIG" "_IMAGE=${MCP_IMAGE}"
fi

# ------------------------------------------------------------- runner job
if ! $SKIP_RUNNER_JOB; then
  step "Cloud Run Job ${RUNNER_JOB}"
  gcloud run jobs deploy "$RUNNER_JOB" --image "$RUNNER_IMAGE" --region "$REGION" --project "$PROJECT_ID" \
    --service-account "$RUNNER_SA" --cpu "$RUNNER_CPU" --memory "$RUNNER_MEMORY" \
    --task-timeout "$RUNNER_TIMEOUT" --max-retries 0 --tasks 1 \
    --set-env-vars "EPHEMERAL_SCRATCH_DIR=/workspace" --quiet >/dev/null
  ok "job ${RUNNER_JOB} deployed"
elif ! gcloud run jobs describe "$RUNNER_JOB" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; then
  die "--skip-runner-job was given but job ${RUNNER_JOB} does not exist in ${REGION}. Re-run without it."
fi

# Each MCP service may execute this one job (with overrides), nothing else.
grant_job_executor() {  # grant_job_executor SA_EMAIL
  retry gcloud run jobs add-iam-policy-binding "$RUNNER_JOB" --region "$REGION" --project "$PROJECT_ID" \
    --member="serviceAccount:$1" --role=roles/run.jobsExecutorWithOverrides --quiet \
    || die "Could not grant roles/run.jobsExecutorWithOverrides on job ${RUNNER_JOB} to $1."
}

# --------------------------------------------------------------- services
AUTH_FLAG="--no-allow-unauthenticated"
[[ "$ALLOW_UNAUTHENTICATED" != true ]] || AUTH_FLAG="--allow-unauthenticated"

# INVOKERS: who may call the services in IAM-only mode.
INVOKERS=()
if [[ "$ALLOW_UNAUTHENTICATED" != true ]]; then
  if [[ -n "${INVOKER_MEMBERS:-}" ]]; then
    IFS=',' read -r -a INVOKERS <<< "$INVOKER_MEMBERS"
  else
    if [[ "$ACCOUNT" == *.gserviceaccount.com ]]; then
      INVOKERS+=("serviceAccount:${ACCOUNT}")
    elif [[ -n "$ACCOUNT" ]]; then
      INVOKERS+=("user:${ACCOUNT}")
    fi
    # Include Gemini Enterprise (Discovery Engine), Vertex AI Agent Engine,
    # and project IAM users already provisioned in this project so GE custom
    # MCP calls do not fail with 403 run.routes.invoke denied.
    PROJECT_IAM_JSON="$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json 2>/dev/null || true)"
    for candidate in \
      "serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com" \
      "serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
      "serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-aiplatform.iam.gserviceaccount.com" \
      "serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-dialogflow.iam.gserviceaccount.com" \
      "serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"; do
      if [[ "$PROJECT_IAM_JSON" == *"\"${candidate}\""* ]]; then
        INVOKERS+=("$candidate")
      fi
    done
    while IFS= read -r proj_user; do
      [[ -z "$proj_user" || "$proj_user" == "user:${ACCOUNT}" ]] && continue
      INVOKERS+=("$proj_user")
    done < <(grep -oE '"user:[^"]+"' <<< "$PROJECT_IAM_JSON" | tr -d '"' | sort -u || true)
  fi
fi

join_by_comma() { local IFS=','; printf '%s' "$*"; }

# deploy_service NAME IMAGE SA ENV_VARS SECRETS_CSV [extra gcloud flags...]
deploy_service() {
  local name="$1" image="$2" sa="$3" env_vars="$4" secrets="$5"; shift 5
  local secret_flag="--clear-secrets" member
  [[ -z "$secrets" ]] || secret_flag="--set-secrets=${secrets}"
  step "Cloud Run service ${name}"
  gcloud run deploy "$name" --image "$image" --region "$REGION" --project "$PROJECT_ID" \
    --service-account "$sa" --port 8080 --ingress all "$AUTH_FLAG" \
    --set-env-vars "$env_vars" "$secret_flag" \
    --startup-probe "httpGet.path=/healthz,periodSeconds=5,failureThreshold=12" \
    "$@" --quiet || die "Deployment of ${name} failed."
  for member in ${INVOKERS[@]+"${INVOKERS[@]}"}; do
    retry gcloud run services add-iam-policy-binding "$name" --region "$REGION" --project "$PROJECT_ID" \
      --member="$member" --role=roles/run.invoker --quiet \
      || warn "could not grant roles/run.invoker on ${name} to ${member}"
  done
  ok "service ${name} deployed"
}
service_url() {
  gcloud run services describe "$1" --region "$REGION" --project "$PROJECT_ID" --format='value(status.url)' 2>/dev/null || true
}

RUNNER_MCP_URL=""; MCP_URL=""

if $DEPLOY_RUNNER_MCP; then
  grant_job_executor "$RUNNER_MCP_SA"
  # CPU stays allocated (no throttling): job watchers and repo staging run in
  # background threads after the tool call has returned.
  deploy_service "$RUNNER_MCP_SERVICE" "$RUNNER_MCP_IMAGE" "$RUNNER_MCP_SA" \
    "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},CLOUD_RUN_REGION=${REGION},CLOUD_RUN_JOB_NAME=${RUNNER_JOB},GCS_TRANSIT_BUCKET=${BUCKET},BQ_DATASET=${BQ_DATASET},BQ_LOCATION=${BQ_LOCATION},CM_MCP_DEFAULT_PATCH_MODE=${PATCH_MODE},GITHUB_API_URL=${GITHUB_API_URL}" \
    "$(join_by_comma ${RUNNER_MCP_SECRETS[@]+"${RUNNER_MCP_SECRETS[@]}"})" \
    --cpu 1 --memory 2Gi --no-cpu-throttling --cpu-boost --timeout 3600 --concurrency 40 \
    --min-instances "$RUNNER_MCP_MIN_INSTANCES" --max-instances "$RUNNER_MCP_MAX_INSTANCES"
  RUNNER_MCP_URL="$(service_url "$RUNNER_MCP_SERVICE")"
fi

if $DEPLOY_MCP; then
  grant_job_executor "$MCP_SA"
  MCP_ENV="GCP_PROJECT_ID=${PROJECT_ID},GCP_REGION=${REGION},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE},BQ_LOCATION=${BQ_LOCATION},LOG_NAME_FILTER=${LOG_NAME_FILTER},CM_RUNNER_JOB_NAME=${RUNNER_JOB},CM_REPORTS_BUCKET=${BUCKET},CM_DEFAULT_PATCH_MODE=${PATCH_MODE},GITHUB_API_URL=${GITHUB_API_URL}"
  if $WIZ_ENABLED; then
    MCP_ENV="${MCP_ENV},WIZ_CLIENT_ID=${WIZ_CLIENT_ID},WIZ_API_ENDPOINT=${WIZ_API_ENDPOINT},WIZ_AUTH_URL=${WIZ_AUTH_URL},WIZ_AUDIENCE=${WIZ_AUDIENCE}"
  fi
  # Session affinity keeps an SSE client on the instance holding its session.
  deploy_service "$MCP_SERVICE" "$MCP_IMAGE" "$MCP_SA" "$MCP_ENV" \
    "$(join_by_comma ${MCP_SECRETS[@]+"${MCP_SECRETS[@]}"})" \
    --cpu 1 --memory 1Gi --no-cpu-throttling --cpu-boost --timeout 3600 --concurrency 80 --session-affinity \
    --min-instances "$MCP_MIN_INSTANCES" --max-instances "$MCP_MAX_INSTANCES"
  MCP_URL="$(service_url "$MCP_SERVICE")"
fi

# ---------------------------------------------------------------- summary
health() {  # health URL -- best effort; never fails the deploy
  local url="$1" token=""
  command -v curl >/dev/null 2>&1 || return 0
  [[ "$ALLOW_UNAUTHENTICATED" == true ]] || token="$(gcloud auth print-identity-token 2>/dev/null || true)"
  if curl -fsS --max-time 20 ${token:+-H "Authorization: Bearer ${token}"} "${url}/healthz" >/dev/null 2>&1; then
    ok "health check passed: ${url}/healthz"
  else
    warn "health check did not pass yet: ${url}/healthz (the service may still be starting, or your account lacks roles/run.invoker)"
  fi
}

step "Done"
if [[ -n "$RUNNER_MCP_URL" ]]; then
  ok "${RUNNER_MCP_SERVICE}: ${RUNNER_MCP_URL}/mcp  (streamable HTTP)"
  health "$RUNNER_MCP_URL"
fi
if [[ -n "$MCP_URL" ]]; then
  ok "${MCP_SERVICE}: ${MCP_URL}/mcp  (streamable HTTP), ${MCP_URL}/sse  (SSE)"
  health "$MCP_URL"
fi

if [[ "$ALLOW_UNAUTHENTICATED" == true ]]; then
  if [[ -n "$RUNNER_MCP_URL" ]]; then
    cat <<EOF

    ${RUNNER_MCP_SERVICE} requires a bearer token:
      Authorization: Bearer \$(gcloud secrets versions access latest --secret ${AUTH_SECRET} --project ${PROJECT_ID})
EOF
  fi
  if [[ -n "$MCP_URL" ]]; then
    warn "${MCP_SERVICE} is PUBLIC with no application-level auth: anyone with the URL can call its tools."
    warn "Re-run without --allow-unauthenticated to restrict it to roles/run.invoker."
  fi
else
  cat <<EOF

    Both services require IAM auth (roles/run.invoker). Call them with:
      Authorization: Bearer \$(gcloud auth print-identity-token)
    or open a local authenticated tunnel:
      gcloud run services proxy <service> --region ${REGION} --project ${PROJECT_ID} --port 8080
EOF
fi
