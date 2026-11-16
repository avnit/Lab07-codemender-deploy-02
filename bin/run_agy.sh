#!/usr/bin/env bash
#
# run_agy.sh - Authenticate Antigravity (AGY) via gcloud Application Default Credentials (ADC)
#              backed by a Google Cloud Workforce Identity Pool login configuration (auth.json),
#              then launch the Antigravity CLI (agy).
#

set -euo pipefail

# --- Resolve Script Directory ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Color Helpers for Logging ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { printf '%b[INFO]%b %s\n' "$BLUE" "$NC" "$*"; }
log_success() { printf '%b[SUCCESS]%b %s\n' "$GREEN" "$NC" "$*"; }
log_warn()    { printf '%b[WARN]%b %s\n' "$YELLOW" "$NC" "$*"; }
log_error()   { printf '%b[ERROR]%b %s\n' "$RED" "$NC" "$*" >&2; }

# --- Configuration Defaults ---
LOGIN_CONFIG="${LOGIN_CONFIG:-$SCRIPT_DIR/auth.json}"
WORKFORCE_POOL_ID="${WORKFORCE_POOL_ID:-XXXXXX}"
WORKFORCE_PROVIDER_ID="${WORKFORCE_PROVIDER_ID:-YYYYYY}"
PROJECT_ID="${PROJECT_ID:-}"
TEMP_DIR="${TEMP_DIR:-}"
SKIP_LOGIN=false
NO_LAUNCH_BROWSER=true
AGY_ARGS=()

MARKER_FILE=""
cleanup() {
    if [[ -n "${MARKER_FILE:-}" && -f "$MARKER_FILE" ]]; then
        rm -f "$MARKER_FILE" 2>/dev/null || true
    fi
}
trap cleanup EXIT

show_help() {
    cat <<EOF
Usage: $(basename "$0") [options] [-- <agy_args>...]

Authenticates Antigravity through gcloud Application Default Credentials (ADC)
backed by a Workforce Identity Pool login configuration (auth.json) and launches agy.

Options:
  --pool-id <ID>         Workforce Pool ID (replaces XXXXXX in auth.json)
  --provider-id <ID>     Workforce Provider ID (replaces YYYYYY in auth.json)
  --project <PROJECT_ID> Target Google Cloud Project ID for ADC quota/billing
  --login-config <FILE>  Path to login config file (default: $SCRIPT_DIR/auth.json)
  --temp-dir <TEMP_DIR>  Optional <TEMP_DIR> name under /tmp/<TEMP_DIR> (or full path) for Step 2c copy
  --launch-browser       Allow gcloud to launch a local browser instead of auth-code paste mode
  --no-launch-browser    Print sign-in URL and prompt for authorization code (default)
  --skip-login           Skip gcloud login if ADC is already configured and launch agy
  -h, --help             Show this help message

Environment Variables:
  WORKFORCE_POOL_ID      Workforce Pool ID
  WORKFORCE_PROVIDER_ID  Workforce Provider ID
  PROJECT_ID             Google Cloud Project ID
  LOGIN_CONFIG           Path to auth.json (default: $SCRIPT_DIR/auth.json)
EOF
}

require_arg() {
    local flag="$1"
    local count="$2"
    local val="${3:-}"
    if [[ "$count" -lt 2 || -z "$val" ]]; then
        log_error "Missing value for $flag"
        exit 1
    fi
}

# --- Parse Command-Line Arguments ---
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pool-id)
                require_arg "$1" "$#" "${2:-}"
                WORKFORCE_POOL_ID="$2"
                shift 2
                ;;
            --pool-id=*)
                WORKFORCE_POOL_ID="${1#*=}"
                require_arg "--pool-id" 2 "$WORKFORCE_POOL_ID"
                shift
                ;;
            --provider-id)
                require_arg "$1" "$#" "${2:-}"
                WORKFORCE_PROVIDER_ID="$2"
                shift 2
                ;;
            --provider-id=*)
                WORKFORCE_PROVIDER_ID="${1#*=}"
                require_arg "--provider-id" 2 "$WORKFORCE_PROVIDER_ID"
                shift
                ;;
            --project)
                require_arg "$1" "$#" "${2:-}"
                PROJECT_ID="$2"
                shift 2
                ;;
            --project=*)
                PROJECT_ID="${1#*=}"
                require_arg "--project" 2 "$PROJECT_ID"
                shift
                ;;
            --login-config)
                require_arg "$1" "$#" "${2:-}"
                LOGIN_CONFIG="$2"
                shift 2
                ;;
            --login-config=*)
                LOGIN_CONFIG="${1#*=}"
                require_arg "--login-config" 2 "$LOGIN_CONFIG"
                shift
                ;;
            --temp-dir)
                require_arg "$1" "$#" "${2:-}"
                TEMP_DIR="$2"
                shift 2
                ;;
            --temp-dir=*)
                TEMP_DIR="${1#*=}"
                require_arg "--temp-dir" 2 "$TEMP_DIR"
                shift
                ;;
            --launch-browser)
                NO_LAUNCH_BROWSER=false
                shift
                ;;
            --no-launch-browser)
                NO_LAUNCH_BROWSER=true
                shift
                ;;
            --skip-login)
                SKIP_LOGIN=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --)
                shift
                while [[ $# -gt 0 ]]; do
                    AGY_ARGS+=("$1")
                    shift
                done
                break
                ;;
            *)
                AGY_ARGS+=("$1")
                shift
                ;;
        esac
    done
}

write_login_config() {
    local target="$1"
    local pool="$2"
    local provider="$3"

    mkdir -p "$(dirname "$target")"
    cat > "$target" <<EOF
{
  "universe_domain": "googleapis.com",
  "universe_cloud_web_domain": "cloud.google",
  "type": "external_account_authorized_user_login_config",
  "audience": "//iam.googleapis.com/locations/global/workforcePools/${pool}/providers/${provider}",
  "auth_url": "https://auth.cloud.google/authorize",
  "token_url": "https://sts.googleapis.com/v1/oauthtoken",
  "token_info_url": "https://sts.googleapis.com/v1/introspect"
}
EOF
}

# --- Step 1: Create or Validate Login Configuration File (auth.json) ---
setup_login_config() {
    log_info "Step 1: Preparing Workforce Identity Pool login configuration ($LOGIN_CONFIG)..."

    local file_existed=false
    local existing_pool=""
    local existing_provider=""
    local needs_write=false

    if [[ -f "$LOGIN_CONFIG" ]]; then
        file_existed=true
        local existing_aud
        existing_aud=$(grep -o '"audience":[[:space:]]*"[^"]*"' "$LOGIN_CONFIG" || true)
        if [[ "$existing_aud" =~ workforcePools/([^/]+)/providers/ ]]; then
            existing_pool="${BASH_REMATCH[1]}"
        fi
        if [[ "$existing_aud" =~ providers/([^/\"]+) ]]; then
            existing_provider="${BASH_REMATCH[1]}"
        fi
    else
        needs_write=true
    fi

    # Merge CLI/env overrides with existing config values so neither gets clobbered
    if [[ "$WORKFORCE_POOL_ID" != "XXXXXX" ]]; then
        if [[ "$WORKFORCE_POOL_ID" != "$existing_pool" ]]; then
            needs_write=true
        fi
    elif [[ -n "$existing_pool" ]]; then
        WORKFORCE_POOL_ID="$existing_pool"
    fi

    if [[ "$WORKFORCE_PROVIDER_ID" != "YYYYYY" ]]; then
        if [[ "$WORKFORCE_PROVIDER_ID" != "$existing_provider" ]]; then
            needs_write=true
        fi
    elif [[ -n "$existing_provider" ]]; then
        WORKFORCE_PROVIDER_ID="$existing_provider"
    fi

    # Prompt interactively if placeholders XXXXXX or YYYYYY are still present
    if [[ -z "$WORKFORCE_POOL_ID" || "$WORKFORCE_POOL_ID" == "XXXXXX" ]] && [[ -t 0 ]]; then
        read -rp "Enter your Workforce Pool ID (replaces XXXXXX): " input_pool
        if [[ -n "$input_pool" ]]; then
            WORKFORCE_POOL_ID="$input_pool"
            needs_write=true
        fi
    fi

    if [[ -z "$WORKFORCE_PROVIDER_ID" || "$WORKFORCE_PROVIDER_ID" == "YYYYYY" ]] && [[ -t 0 ]]; then
        read -rp "Enter your Workforce Provider ID (replaces YYYYYY): " input_provider
        if [[ -n "$input_provider" ]]; then
            WORKFORCE_PROVIDER_ID="$input_provider"
            needs_write=true
        fi
    fi

    if [[ "$needs_write" == true ]]; then
        write_login_config "$LOGIN_CONFIG" "${WORKFORCE_POOL_ID:-XXXXXX}" "${WORKFORCE_PROVIDER_ID:-YYYYYY}"
        if [[ "$file_existed" == true ]]; then
            log_info "Updated login configuration file: $LOGIN_CONFIG"
        else
            log_info "Created login configuration file: $LOGIN_CONFIG"
        fi
    fi

    if grep -Eq "XXXXXX|YYYYYY" "$LOGIN_CONFIG"; then
        log_error "$LOGIN_CONFIG still contains placeholder values (XXXXXX or YYYYYY)."
        log_error "Pass --pool-id <POOL_ID> and --provider-id <PROVIDER_ID>, or edit $LOGIN_CONFIG directly."
        exit 1
    fi

    if ! grep -q '"external_account_authorized_user_login_config"' "$LOGIN_CONFIG"; then
        log_error "$LOGIN_CONFIG is missing type 'external_account_authorized_user_login_config'."
        exit 1
    fi

    log_success "Login configuration ready at $LOGIN_CONFIG"
}

copy_adc_if_needed() {
    local default_adc_dir="$HOME/.config/gcloud"
    local default_adc_file="$default_adc_dir/application_default_credentials.json"
    mkdir -p "$default_adc_dir"

    local source_adc=""
    if [[ -n "$TEMP_DIR" ]]; then
        if [[ -f "$TEMP_DIR" ]]; then
            source_adc="$TEMP_DIR"
        elif [[ -f "$TEMP_DIR/application_default_credentials.json" ]]; then
            source_adc="$TEMP_DIR/application_default_credentials.json"
        elif [[ -f "/tmp/$TEMP_DIR/application_default_credentials.json" ]]; then
            source_adc="/tmp/$TEMP_DIR/application_default_credentials.json"
        else
            log_error "Could not find credentials under --temp-dir '$TEMP_DIR'."
            exit 1
        fi
    elif [[ -n "${CLOUDSDK_CONFIG:-}" && "$CLOUDSDK_CONFIG" != "$default_adc_dir" && -f "$CLOUDSDK_CONFIG/application_default_credentials.json" ]]; then
        source_adc="$CLOUDSDK_CONFIG/application_default_credentials.json"
    elif [[ -n "${MARKER_FILE:-}" && -f "$default_adc_file" && ! "$MARKER_FILE" -nt "$default_adc_file" ]]; then
        # gcloud wrote directly to ~/.config/gcloud/application_default_credentials.json during this run
        source_adc="$default_adc_file"
    elif [[ -n "${MARKER_FILE:-}" ]]; then
        # Check if gcloud wrote a new ADC file owned by the current user under /tmp/<TEMP_DIR>/ (e.g. Cloud Shell)
        # Note trailing slash '/tmp/' so macOS (/tmp -> private/tmp symlink) is traversed properly.
        local latest_tmp_adc=""
        latest_tmp_adc=$(find /tmp/ -maxdepth 2 -user "$(id -un)" -name "application_default_credentials.json" -newer "$MARKER_FILE" -print -quit 2>/dev/null || true)
        if [[ -n "$latest_tmp_adc" && -f "$latest_tmp_adc" ]]; then
            source_adc="$latest_tmp_adc"
        fi
    fi

    if [[ -n "$source_adc" && "$source_adc" != "$default_adc_file" ]]; then
        log_info "Step 2c: Copying credentials from $source_adc to $default_adc_file..."
        cp "$source_adc" "$default_adc_file"
        chmod 600 "$default_adc_file"
        log_success "Copied ADC credentials to $default_adc_file"
    elif [[ -s "$default_adc_file" ]]; then
        chmod 600 "$default_adc_file"
        log_success "Step 2c: ADC credentials verified at $default_adc_file"
    else
        log_warn "ADC file was not automatically found at $default_adc_file."
        if [[ -t 0 ]]; then
            read -rp "If gcloud saved credentials to /tmp/<TEMP_DIR>/application_default_credentials.json, enter <TEMP_DIR> (or full path): " user_temp
            if [[ -n "$user_temp" ]]; then
                if [[ -f "$user_temp" ]]; then
                    cp "$user_temp" "$default_adc_file"
                elif [[ -f "$user_temp/application_default_credentials.json" ]]; then
                    cp "$user_temp/application_default_credentials.json" "$default_adc_file"
                elif [[ -f "/tmp/$user_temp/application_default_credentials.json" ]]; then
                    cp "/tmp/$user_temp/application_default_credentials.json" "$default_adc_file"
                else
                    log_error "Could not find credentials file at '$user_temp' or '/tmp/$user_temp/application_default_credentials.json'."
                    exit 1
                fi
                chmod 600 "$default_adc_file"
                log_success "Copied ADC credentials to $default_adc_file"
            fi
        fi
        if [[ ! -s "$default_adc_file" ]]; then
            log_error "Application Default Credentials not found at $default_adc_file."
            exit 1
        fi
    fi
}

# --- Step 2: Generate Application Default Credentials ---
generate_adc() {
    # Unset GOOGLE_APPLICATION_CREDENTIALS before gcloud runs so gcloud doesn't warn/prompt about it
    unset GOOGLE_APPLICATION_CREDENTIALS || true

    local default_adc_file="$HOME/.config/gcloud/application_default_credentials.json"

    if [[ "$SKIP_LOGIN" == true ]]; then
        log_info "Skipping gcloud ADC login (--skip-login specified)."
        copy_adc_if_needed
        return 0
    fi

    if ! command -v gcloud &>/dev/null; then
        export PATH="$HOME/google-cloud-sdk/bin:$PATH:/opt/homebrew/bin:/usr/local/bin:/usr/bin"
    fi
    if ! command -v gcloud &>/dev/null; then
        log_error "'gcloud' CLI is not installed or not in PATH."
        exit 1
    fi

    # Resolve PROJECT_ID if not set (check gcloud config, then existing ADC quota_project_id)
    if [[ -z "$PROJECT_ID" ]]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null || true)
        if [[ "$PROJECT_ID" == "(unset)" ]]; then
            PROJECT_ID=""
        fi
    fi
    if [[ -z "$PROJECT_ID" && -f "$default_adc_file" ]]; then
        PROJECT_ID=$(sed -n 's/.*"quota_project_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$default_adc_file" | head -n 1 || true)
    fi

    if [[ -z "$PROJECT_ID" && -t 0 ]]; then
        read -rp "Enter your target Google Cloud Project ID (<PROJECT_ID>): " PROJECT_ID
    fi

    if [[ -z "$PROJECT_ID" ]]; then
        log_error "Target Google Cloud Project ID is required. Use --project <PROJECT_ID> or set PROJECT_ID."
        exit 1
    fi

    log_info "Step 2: Generating Application Default Credentials for project '$PROJECT_ID'..."
    echo ""
    if [[ "$NO_LAUNCH_BROWSER" == true ]]; then
        log_info "Step 2a (Authenticate with Okta):"
        echo "  1. Open the sign-in URL printed below in your browser (Google Chrome recommended)."
        echo "  2. Sign in on your Okta sign-in page with your corporate credentials and complete MFA."
        log_info "Step 2b (Paste the Authorization Code into the CLI):"
        echo "  3. Copy the authorization code from the Google Cloud confirmation page,"
        echo "     paste it at the prompt below, and press Enter."
    else
        log_info "Step 2a (Authenticate with Okta in Browser):"
        echo "  1. Complete sign-in and MFA in the browser window opened by gcloud."
    fi
    echo ""

    MARKER_FILE=$(mktemp /tmp/run_agy_adc.XXXXXX)

    local gcloud_flags=(
        "--login-config=$LOGIN_CONFIG"
        "--project=$PROJECT_ID"
        "--billing-project=$PROJECT_ID"
    )
    if [[ "$NO_LAUNCH_BROWSER" == true ]]; then
        gcloud_flags+=("--no-launch-browser")
    fi

    gcloud auth application-default login "${gcloud_flags[@]}"

    # --- Step 2c: Copy or Verify Credentials at Default ADC Location ---
    copy_adc_if_needed
}

# --- Step 3 & Step 4: Enable ADC Auth and Launch Antigravity ---
launch_agy() {
    log_info "Step 3: Enabling ADC Authentication for Antigravity..."
    unset GOOGLE_APPLICATION_CREDENTIALS || true
    export AGY_ADC_AUTH=true
    log_success "Exported AGY_ADC_AUTH=true"

    export PATH="$SCRIPT_DIR:$HOME/.local/bin:$PATH"
    if ! command -v agy &>/dev/null; then
        log_error "'agy' CLI not found in PATH. Run '$SCRIPT_DIR/install.sh' to install it first."
        exit 1
    fi

    log_info "Step 4: Launching Antigravity CLI (agy)..."
    exec agy ${AGY_ARGS[@]+"${AGY_ARGS[@]}"}
}

main() {
    parse_args "$@"
    setup_login_config
    generate_adc
    launch_agy
}

main "$@"

