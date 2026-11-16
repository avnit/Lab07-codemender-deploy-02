#!/usr/bin/env bash
#
# Antigravity CLI - Unix Bootstrapper Script (Bash/Zsh)
#
# Downloads, staging-verifies, and installs the Antigravity CLI flat native build.
#

set -euo pipefail

# 1. Default Setup & Constants
DOWNLOAD_BASE_URL="https://antigravity-cli-auto-updater-974169037036.us-central1.run.app"
TARGET_DIR="$HOME/.local/bin"
CUSTOM_DIR=""
FORCE_INSTALL=false

# Helper: Display usage instructions
show_usage() {
    echo "Usage: $(basename "$0") [options]"
    echo ""
    echo "Options:"
    echo "  -d, --dir <path>    Specify a custom directory to install the binary"
    echo "  -f, --force         Reinstall even if 'agy' is already present"
    echo "  -h, --help          Display this help menu"
    echo ""
}

# Parse Arguments
while [ "$#" -gt 0 ]; do
    case "$1" in
        -d|--dir)
            if [ "$#" -lt 2 ] || [ -z "${2:-}" ] || [ "${2#-}" != "$2" ]; then
                echo "[ERROR] Missing path for --dir parameter" >&2
                exit 1
            fi
            CUSTOM_DIR="$2"
            shift 2
            ;;
        --dir=*)
            CUSTOM_DIR="${1#*=}"
            if [ -z "$CUSTOM_DIR" ]; then
                echo "[ERROR] Missing path for --dir parameter" >&2
                exit 1
            fi
            shift
            ;;
        -f|--force)
            FORCE_INSTALL=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown parameter: $1" >&2
            show_usage
            exit 1
            ;;
    esac
done

# Resolve dynamic installation target directory
if [ -n "$CUSTOM_DIR" ]; then
    # Expand leading ~/ if passed literally
    case "$CUSTOM_DIR" in
        "~") CUSTOM_DIR="$HOME" ;;
        "~/"*) CUSTOM_DIR="$HOME/${CUSTOM_DIR#\~/}" ;;
    esac
    TARGET_DIR="$CUSTOM_DIR"
fi

# Resolve TARGET_DIR to an absolute path if it already exists
if [ -d "$TARGET_DIR" ]; then
    TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
fi

BINARY_PATH="$TARGET_DIR/agy"

# 2. STEP 1: Pre-existence & Dynamic Path Check
if [ -f "$BINARY_PATH" ] && [ "$FORCE_INSTALL" != true ]; then
    echo "Notice: 'agy' is already installed at $BINARY_PATH."
    echo "The Antigravity CLI automatically self-updates in the background during regular runs."
    echo ""
    echo "If you want to perform a fresh installation, pass --force or delete the binary first:"
    echo "  $(basename "$0") --force"
    echo "  rm \"$BINARY_PATH\""
    exit 0
fi

echo "⠋ Detecting system environment..."

# 3. Detect Platform
case "$(uname -s)" in
    Darwin) os="darwin" ;;
    # Termux needs the Bionic build: Android's linker rejects glibc/musl ones.
    # uname -o names the userland, so a proot distro inside Termux (e.g. Ubuntu,
    # "GNU/Linux") still gets the regular Linux build.
    Linux)
        if [ "$(uname -o 2>/dev/null || true)" = "Android" ]; then
            os="android"
        else
            os="linux"
        fi
        ;;
    *)
        echo "Fatal: Unsupported operating system: $(uname -s). Antigravity CLI currently supports 64-bit Windows, macOS, and Linux." >&2
        exit 1
        ;;
esac

case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *)
        echo "Fatal: Unsupported architecture: $(uname -m). Antigravity CLI currently supports 64-bit Windows, macOS, and Linux." >&2
        exit 1
        ;;
esac

# musl libc detection on Linux
platform=""
if [ "$os" = "linux" ]; then
    if [ -f /lib/libc.musl-x86_64.so.1 ] || [ -f /lib/libc.musl-aarch64.so.1 ] || { command -v ldd >/dev/null 2>&1 && ldd /bin/ls 2>&1 | grep -q musl; }; then
        platform="linux_${arch}_musl"
    else
        platform="linux_${arch}"
    fi
else
    platform="${os}_${arch}"
fi

echo "✓ Platform detected: $platform"

# 4. Manifest Query & JSON Parsing (POSIX-Compliant)
echo "⠋ Querying release repository..."

# Construct Platform JSON Manifest URL
MANIFEST_URL="$DOWNLOAD_BASE_URL/manifests/$platform.json"

DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    echo "Fatal: Either curl or wget is required but neither is installed." >&2
    exit 1
fi

fetch_manifest() {
    if [ "$DOWNLOADER" = "curl" ]; then
        curl -fsSL "$1"
    else
        wget -q -O - "$1"
    fi
}

manifest_json=$(fetch_manifest "$MANIFEST_URL" 2>/dev/null || true)
if [ -z "$manifest_json" ]; then
    echo "Fatal: Could not connect to the release server to download the manifest. Please check your internet connection or firewall settings." >&2
    exit 1
fi

# JSON string parser without jq dependency; matches exact key name (not suffix)
parse_json_key() {
    local payload="$1"
    local key="$2"
    local lines
    lines=$(printf '%s\n' "$payload" | tr '{,}' '\n\n\n')
    printf '%s\n' "$lines" | sed -n '/^[[:space:]]*"'"$key"'"[[:space:]]*:/{
        s/^[[:space:]]*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p
        q
    }'
}

version=$(parse_json_key "$manifest_json" "version")
url=$(parse_json_key "$manifest_json" "url")
sha512=$(parse_json_key "$manifest_json" "sha512" | tr '[:upper:]' '[:lower:]')

if [ -z "$url" ] || [ -z "$sha512" ]; then
    echo "Fatal: Failed to parse release manifest. The manifest may be corrupted or malformed." >&2
    exit 1
fi

echo "✓ Latest available version: ${version:-unknown}"

# 5. Download & SHA512 Checksum Verification
STAGING_BASE="$HOME/.cache/antigravity/staging"
if ! mkdir -p "$STAGING_BASE" 2>/dev/null; then
    echo "Error: Failed to create staging directory at $STAGING_BASE. Please check your home directory write permissions." >&2
    exit 1
fi

WORK_DIR=$(mktemp -d "$STAGING_BASE/install.XXXXXX")
chmod 700 "$WORK_DIR" 2>/dev/null || true

# Cleanup trap to ensure temporary staging directory and temp binary are reaped on any exit
tmp_binary=""
cleanup() {
    if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR" 2>/dev/null || true
    fi
    if [ -n "${tmp_binary:-}" ] && [ -f "$tmp_binary" ]; then
        rm -f "$tmp_binary" 2>/dev/null || true
    fi
}
trap cleanup EXIT

is_tar_gz=false
case "$url" in
    *.tar.gz|*.tar.gz\?*) is_tar_gz=true ;;
esac

if [ "$is_tar_gz" = true ]; then
    staging_payload="$WORK_DIR/agy.tar.gz"
else
    staging_payload="$WORK_DIR/agy"
fi

download_file() {
    local src="$1"
    local dst="$2"
    if [ "$DOWNLOADER" = "curl" ]; then
        curl -fsSL -o "$dst" "$src"
    else
        wget -q -O "$dst" "$src"
    fi
}

echo "⠋ Downloading release package..."
if ! download_file "$url" "$staging_payload"; then
    echo "Fatal: Failed to download release package from $url. Please check your internet connection or firewall settings." >&2
    exit 1
fi

# Compute SHA512 Checksum portably across macOS, Linux, BSD, and minimal environments
compute_sha512() {
    local file="$1"
    if command -v sha512sum >/dev/null 2>&1; then
        sha512sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 512 "$file" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha512 "$file" | awk '{print $NF}'
    else
        echo "Fatal: Cannot verify SHA-512 checksum (neither sha512sum, shasum, nor openssl is installed)." >&2
        return 1
    fi
}

actual_hash=$(compute_sha512 "$staging_payload" | tr '[:upper:]' '[:lower:]')

if [ -z "$actual_hash" ] || [ "$actual_hash" != "$sha512" ]; then
    echo "Security Halt: The downloaded payload checksum does not match the manifest. The file may be corrupted or compromised. Installation aborted." >&2
    exit 1
fi
echo "✓ Download complete and checksum verified."

# 6. Direct Binary Extraction & Atomic Write Permission Validation
if ! mkdir -p "$TARGET_DIR" 2>/dev/null; then
    echo "Write Error: Permission denied when attempting to create $TARGET_DIR. Please re-run the installer using the '--dir' flag to specify a writable custom directory." >&2
    exit 1
fi

# Canonicalize TARGET_DIR now that it exists so `agy install --dir` receives an absolute path
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
BINARY_PATH="$TARGET_DIR/agy"

extracted_binary=""
if [ "$is_tar_gz" = true ]; then
    echo "⠋ Extracting binary from archive..."
    if ! tar -xzf "$staging_payload" -C "$WORK_DIR" 2>/dev/null; then
        echo "Extraction Error: Failed to extract binary from archive." >&2
        exit 1
    fi
    if [ -f "$WORK_DIR/antigravity" ]; then
        extracted_binary="$WORK_DIR/antigravity"
    elif [ -f "$WORK_DIR/agy" ]; then
        extracted_binary="$WORK_DIR/agy"
    else
        echo "Extraction Error: Expected binary ('antigravity' or 'agy') not found in archive." >&2
        exit 1
    fi
else
    echo "⠋ Staging binary for installation..."
    extracted_binary="$staging_payload"
fi

# Stage into target directory and atomically rename to avoid ETXTBSY if 'agy' is currently running
tmp_binary="$TARGET_DIR/.agy.tmp.$$"
if ! cp "$extracted_binary" "$tmp_binary" 2>/dev/null; then
    echo "Write Error: Permission denied when attempting to write binary to $TARGET_DIR. Please re-run the installer using the '--dir' flag to specify a writable custom directory." >&2
    exit 1
fi

# Ensure Executable Permission Bit (soft fallback if filesystem doesn't support chmod)
chmod +x "$tmp_binary" || echo "Warning: Could not set executable permission bit on $BINARY_PATH. You may need to ensure the partition supports execution." >&2

# Clear macOS Gatekeeper Quarantine attribute to prevent unidentified developer blocks
if [ "$os" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$tmp_binary" 2>/dev/null || true
fi

if ! mv -f "$tmp_binary" "$BINARY_PATH" 2>/dev/null; then
    echo "Write Error: Failed to move binary into place at $BINARY_PATH." >&2
    exit 1
fi
tmp_binary=""

# 7. Native Setup Handoff (Go-Native Setup Trigger)
echo "⠋ Configuring shell environment..."

if [ -n "$CUSTOM_DIR" ]; then
    # Run with canonical custom directory and absorb non-fatal soft warning exits
    "$BINARY_PATH" install --dir "$TARGET_DIR" || true
else
    # Run standard configuration and absorb non-fatal soft warning exits
    "$BINARY_PATH" install || true
fi

echo "✓ Antigravity CLI installed at $BINARY_PATH"

