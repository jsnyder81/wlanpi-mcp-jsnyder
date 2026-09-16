#!/bin/bash
#
# Install the wlanpi-mcp UFW application profiles and open the HTTPS port.
#
# Mirrors the wlanpi-core UFW setup pattern: the app profile is staged under
# /etc/wlanpi-mcp/ufw and copied into /etc/ufw/applications.d here, then
# enabled with `ufw allow`. A version marker keeps this idempotent so it only
# re-applies when the shipped rules version changes.
#
# Clients reach the MCP server through the nginx HTTPS front-end on 8767
# (profile wlanpi-mcp-tls). The daemon itself binds to loopback, so its
# cleartext port 8766 (profile wlanpi-mcp) is closed here, including on
# upgrade from rules version 1 which had opened it.
#
# Paths are overridable through the environment for tests;
# WLANPI_MCP_UFW_NO_ROOT_CHECK=1 skips the root check.

set -o errexit
set -o nounset
set -o pipefail

readonly RULES_DIR="${WLANPI_MCP_UFW_RULES_DIR:-/etc/wlanpi-mcp/ufw}"
readonly CURRENT_VERSION_FILE="${RULES_DIR}/current-rules-version"
readonly INSTALLED_VERSION_FILE="${WLANPI_MCP_UFW_INSTALLED_VERSION_FILE:-/etc/wlanpi-mcp/installed-rules-version}"
readonly UFW_APPS_DIR="${WLANPI_MCP_UFW_APPS_DIR:-/etc/ufw/applications.d}"
readonly RULES_FILE="${RULES_DIR}/wlanpi-mcp.rules"
readonly UFW_APP_FILE="${UFW_APPS_DIR}/wlanpi-mcp"
readonly LOGFILE="${WLANPI_MCP_UFW_LOGFILE:-/var/log/wlanpi-mcp-firstboot.log}"
readonly NO_ROOT_CHECK="${WLANPI_MCP_UFW_NO_ROOT_CHECK:-0}"

mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null || true
exec > >(tee -a "$LOGFILE") 2>&1

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_info() {
    log "INFO: $1"
}

if ischroot; then
    log_info "Running in chroot environment, skipping wlanpi-mcp UFW setup"
    exit 0
fi

log_error() {
    log "ERROR: $1" >&2
}

error() {
    log_error "$1"
    exit 1
}

cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Script failed with exit code: ${exit_code}"
    fi
    exit $exit_code
}

check_root() {
    [ "$NO_ROOT_CHECK" != "1" ] || return 0
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (current uid=$(id -u))"
    fi
}

check_file_readable() {
    local file="$1"
    local desc="$2"

    if [ ! -f "$file" ]; then
        error "${desc} not found at ${file}"
    fi

    if [ ! -r "$file" ]; then
        error "Cannot read ${desc} at ${file} (permission denied)"
    fi
}

check_dir_writable() {
    local dir="$1"
    local desc="$2"

    if [ ! -d "$dir" ]; then
        if ! mkdir -p "$dir" 2>/dev/null; then
            error "Failed to create ${desc} at ${dir} (permission denied)"
        fi
    elif [ ! -w "$dir" ]; then
        error "Cannot write to ${desc} at ${dir} (permission denied)"
    fi
}

check_prerequisites() {
    check_file_readable "$CURRENT_VERSION_FILE" "Rules version file"
    check_file_readable "$RULES_FILE" "UFW rules file"

    if ! command -v ufw >/dev/null 2>&1; then
        error "ufw is not installed"
    fi
}

apply_ufw_rules() {
    local current_version
    local installed_version

    if ! current_version=$(cat "$CURRENT_VERSION_FILE" 2>/dev/null); then
        error "Failed to read current version from ${CURRENT_VERSION_FILE}"
    fi

    if [ -f "$INSTALLED_VERSION_FILE" ] && [ -r "$INSTALLED_VERSION_FILE" ]; then
        if ! installed_version=$(cat "$INSTALLED_VERSION_FILE" 2>/dev/null); then
            error "Failed to read installed version from ${INSTALLED_VERSION_FILE}"
        fi
        if [ "$current_version" = "$installed_version" ]; then
            log_info "UFW rules are up to date (version: ${current_version})"
            return 0
        fi
    fi

    check_dir_writable "$UFW_APPS_DIR" "UFW applications directory"

    log_info "Updating UFW application profile..."
    if ! cp "$RULES_FILE" "$UFW_APP_FILE"; then
        error "Failed to copy rules file to ${UFW_APP_FILE}"
    fi

    # Close the cleartext daemon port: the literal-port rule from pre-0.3.3
    # packages and the wlanpi-mcp profile rule from rules version 1. The
    # daemon now binds to loopback behind the nginx HTTPS front-end.
    ufw delete allow 8766/tcp >/dev/null 2>&1 || true
    ufw delete allow wlanpi-mcp >/dev/null 2>&1 || true

    log_info "Applying UFW rules..."
    if ! ufw allow wlanpi-mcp-tls >/dev/null 2>&1; then
        error "Failed to allow wlanpi-mcp-tls in UFW"
    fi
    if ! ufw reload >/dev/null 2>&1; then
        error "Failed to reload UFW"
    fi

    log_info "Updating installed version..."
    if ! cp "$CURRENT_VERSION_FILE" "$INSTALLED_VERSION_FILE"; then
        error "Failed to update installed version file at ${INSTALLED_VERSION_FILE}"
    fi
    log_info "UFW rules applied successfully (version: ${current_version})"
}

main() {
    trap cleanup EXIT
    check_root
    check_prerequisites
    apply_ufw_rules
}

main
