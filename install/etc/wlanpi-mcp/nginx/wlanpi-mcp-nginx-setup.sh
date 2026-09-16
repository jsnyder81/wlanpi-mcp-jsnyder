#!/bin/bash
#
# Link or unlink the wlanpi-mcp HTTPS front-end (nginx site) and reload nginx.
#
#   wlanpi-mcp-nginx-setup.sh apply    # link the site, validate, reload nginx
#   wlanpi-mcp-nginx-setup.sh remove   # unlink the site, reload nginx
#
# Called by the package maintainer scripts; it is not an operator command.
# The site terminates TLS on 8767 with the device certificate that wlanpi-core
# generates and proxies to the MCP daemon on 127.0.0.1:8766.
#
# apply never leaves nginx broken: if the configuration test fails with our
# site linked, the link is removed again (a bad site would also take the
# wlanpi-core API, served by the same nginx, off the air).
#
# Paths are overridable through the environment for tests. Set
# WLANPI_MCP_NGINX_NO_SYSTEM=1 to skip the nginx test/reload (tests, chroot).

set -o errexit
set -o nounset
set -o pipefail

SITE_SRC="${WLANPI_MCP_NGINX_SITE_SRC:-/etc/wlanpi-mcp/nginx/wlanpi_mcp_tls.conf}"
SITES_ENABLED="${WLANPI_MCP_NGINX_SITES_ENABLED:-/etc/nginx/sites-enabled}"
CERT="${WLANPI_MCP_NGINX_CERT:-/etc/nginx/ssl/self-signed-wlanpi.cert}"
KEY="${WLANPI_MCP_NGINX_KEY:-/etc/nginx/ssl/self-signed-wlanpi.key}"
NO_SYSTEM="${WLANPI_MCP_NGINX_NO_SYSTEM:-0}"

LINK="${SITES_ENABLED}/$(basename "$SITE_SRC")"

usage() {
    echo "usage: $0 apply|remove" >&2
    exit 2
}

system_available() {
    [ "$NO_SYSTEM" != "1" ] || return 1
    command -v nginx >/dev/null 2>&1 || return 1
    if command -v ischroot >/dev/null 2>&1 && ischroot; then
        return 1
    fi
    return 0
}

service_invoke() {
    if command -v deb-systemd-invoke >/dev/null 2>&1; then
        deb-systemd-invoke "$@"
    else
        systemctl "$@"
    fi
}

nginx_test() {
    system_available || return 0
    if ! nginx -t >/dev/null 2>&1; then
        echo "error: nginx configuration test failed:" >&2
        nginx -t >&2 || true
        return 1
    fi
}

nginx_reload() {
    system_available || return 0
    service_invoke reload nginx.service >/dev/null 2>&1 \
        || service_invoke restart nginx.service >/dev/null 2>&1 \
        || echo "warning: could not reload nginx; the HTTPS front-end takes effect at the next nginx restart" >&2
}

apply() {
    if [ ! -f "$SITE_SRC" ]; then
        echo "error: ${SITE_SRC} missing; cannot enable the HTTPS front-end" >&2
        exit 1
    fi
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "error: device certificate ${CERT} / ${KEY} not found (wlanpi-core's postinst generates it); not enabling the HTTPS front-end" >&2
        exit 1
    fi

    mkdir -p "$SITES_ENABLED"
    if [ ! -L "$LINK" ] || [ "$(readlink "$LINK")" != "$SITE_SRC" ]; then
        ln -sfn "$SITE_SRC" "$LINK"
        echo "Linked ${LINK} -> ${SITE_SRC}"
    fi

    if ! nginx_test; then
        rm -f "$LINK"
        echo "error: unlinked ${LINK} so nginx keeps serving; wlanpi-mcp is not reachable over HTTPS until this is fixed" >&2
        exit 1
    fi
    nginx_reload
}

remove() {
    if [ -L "$LINK" ] || [ -e "$LINK" ]; then
        rm -f "$LINK"
        echo "Unlinked ${LINK}"
        nginx_test || true
        nginx_reload
    fi
}

case "${1:-}" in
    apply)  apply ;;
    remove) remove ;;
    *)      usage ;;
esac
