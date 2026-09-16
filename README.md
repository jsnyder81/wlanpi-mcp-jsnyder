# wlanpi-mcp

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes [WLAN Pi](https://wlanpi.com) capabilities - device info, service management, Wi-Fi scanning, profiler control, Bluetooth, and VLANs - to AI assistants like Claude.

It is a thin bridge to the `wlanpi-core` REST API on the device (`http://localhost:31415`); every tool call goes through that API.

## How it runs

Two transports:

- **SSE (daemon mode)** - how the Debian package runs it under systemd. Remote MCP clients connect to `https://<wlanpi>:8767/sse`: an nginx front-end installed by the package terminates TLS on port `8767` and proxies to the daemon, which listens in cleartext on `127.0.0.1:8766` only. Every connection **must** present a wlanpi-core JWT (see [Authentication](#authentication)). See [TLS](#tls) for the certificate.
- **stdio** - the MCP client launches the server as a subprocess. Only useful when the client runs on the WLAN Pi itself.

## Installation on the WLAN Pi

Install the Debian package (depends on `wlanpi-core`):

```bash
sudo apt install ./wlanpi-mcp_*.deb
```

This installs to `/opt/wlanpi-mcp`, enables the `wlanpi-mcp` systemd service (SSE mode, HTTPS on port 8767), and reads configuration from `/etc/wlanpi-mcp/config.env` (see `install/etc/wlanpi-mcp/config.env.example`).

The package also installs an nginx site (`/etc/wlanpi-mcp/nginx/wlanpi_mcp_tls.conf`, linked into `/etc/nginx/sites-enabled`) and a UFW application profile that opens `8767/tcp`. The daemon's own port `8766` is bound to loopback and closed in the firewall.

## TLS

nginx serves `https://<wlanpi>:8767` with the **self-signed device certificate** that wlanpi-core generates at install time (`/etc/nginx/ssl/self-signed-wlanpi.cert`). Its subject alternative names are `localhost`, `wlanpi.local`, `127.0.0.1` and `198.18.42.1` (the USB/OTG address), so a client that trusts the cert still gets a hostname mismatch when it connects by LAN IP. You have two options:

1. **Trust the cert and connect by a name it covers** - copy the cert off the device (`scp wlanpi@<wlanpi>:/etc/nginx/ssl/self-signed-wlanpi.cert .`) and connect to `https://wlanpi.local:8767/sse` or `https://198.18.42.1:8767/sse`. Claude Code and `mcp-remote` are Node programs, so point them at the cert with `NODE_EXTRA_CA_CERTS=/path/to/self-signed-wlanpi.cert`.
2. **Skip verification** - set `NODE_TLS_REJECT_UNAUTHORIZED=0` for the client. The connection is still encrypted but not authenticated, so do this only on a network you trust.

Either way the JWT never travels in cleartext on the LAN any more.

To use your own certificate, edit the `ssl_certificate`/`ssl_certificate_key` lines in `/etc/wlanpi-mcp/nginx/wlanpi_mcp_tls.conf` (a dpkg conffile, so upgrades won't clobber it) and `sudo systemctl reload nginx`.

To build the package from source: `dpkg-buildpackage -us -uc`.

## Authentication

This server implements **no authentication of its own** - by design. Your MCP client presents a JWT issued by wlanpi-core as `Authorization: Bearer <token>`, and that same token is forwarded on every wlanpi-core API call, where it is validated (signature, expiry, revocation). The MCP server never mints, verifies, or refreshes tokens; if the token expires mid-session, tool calls fail with 401 until the client reconnects with a fresh one.

### Generating a token with `getjwt`

The easiest way to get a token is the `getjwt` helper that ships with wlanpi-core. SSH to the WLAN Pi and run:

```bash
sudo getjwt claude-desktop --no-color
```

The positional argument is a device ID - an arbitrary name identifying the client the token is for (e.g. `claude-desktop`, `claude-code`). `sudo` is needed because `getjwt` signs the request with wlanpi-core's local HMAC shared secret, which unprivileged users can't read. `--no-color` gives clean output for copy/paste or scripting.

It prints the token response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

Use the `access_token` value as your Bearer token in the client configs below. Tokens expire (7 days by default in wlanpi-core) - when tool calls start failing with 401, generate a fresh token and update your client config.

Alternatively, call `POST /api/v1/auth/token` yourself - see the wlanpi-core API docs (Swagger UI at `http://<wlanpi>:31415/docs`) for the HMAC signing details.

The full flow, including the nginx `X-Real-IP` handling that makes on-box calls take core's JWT validation path, is documented in [docs/auth-flow.md](docs/auth-flow.md).

## Connecting Claude Code

On any machine that can reach the WLAN Pi:

```bash
claude mcp add --transport sse wlanpi https://<wlanpi>:8767/sse \
  --header "Authorization: Bearer <your-wlanpi-core-jwt>"
```

Then launch Claude Code with the device cert trusted (or verification disabled, see [TLS](#tls)):

```bash
NODE_EXTRA_CA_CERTS=/path/to/self-signed-wlanpi.cert claude
# or, on a trusted network only:
NODE_TLS_REJECT_UNAUTHORIZED=0 claude
```

Verify with `/mcp` inside Claude Code - the `wlanpi` server should show as connected, with its tools and resources listed.

To share the config with your whole project (checked into `.mcp.json`) add `--scope project`; the default scope is local to you.

### Claude Code running on the WLAN Pi itself (stdio)

If Claude Code runs on the device, you can skip the HTTP hop and launch the server over stdio. There are no HTTP headers in stdio mode, so the token comes from the `WLANPI_CORE_TOKEN` environment variable instead:

```bash
claude mcp add wlanpi \
  --env WLANPI_CORE_TOKEN=<your-wlanpi-core-jwt> \
  -- /opt/wlanpi-mcp/bin/python -m wlanpi_mcp --transport stdio
```

(Use your own interpreter path instead of `/opt/wlanpi-mcp/bin/python` if you installed from source with pip.)

## Connecting Claude Desktop

Claude Desktop launches stdio servers, so a remote SSE server is bridged with the [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) proxy (requires Node.js on your desktop machine).

Edit your Claude Desktop config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wlanpi": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "https://<wlanpi>:8767/sse",
        "--transport", "sse-only",
        "--header", "Authorization: Bearer ${WLANPI_TOKEN}"
      ],
      "env": {
        "WLANPI_TOKEN": "<your-wlanpi-core-jwt>",
        "NODE_EXTRA_CA_CERTS": "/path/to/self-signed-wlanpi.cert"
      }
    }
  }
}
```

Notes:

- `NODE_EXTRA_CA_CERTS` makes Node trust the device's self-signed cert; connect by a name the cert covers (see [TLS](#tls)). To skip verification instead, replace it with `"NODE_TLS_REJECT_UNAUTHORIZED": "0"`.
- `--transport sse-only` skips mcp-remote's streamable-HTTP probe; this server speaks SSE.
- The token is passed via the `env` block and interpolated into the header (`${WLANPI_TOKEN}`) - this sidesteps a known mcp-remote issue with spaces in `args` values on some platforms.

Restart Claude Desktop after editing the file. The WLAN Pi tools appear under the tools (🔨) menu.

## Configuration

Settings load from the environment or `/etc/wlanpi-mcp/config.env`:

| Variable | Default | Purpose |
|---|---|---|
| `WLANPI_CORE_URL` | `http://localhost:31415` | wlanpi-core API base URL |
| `WLANPI_CORE_TOKEN` | *(empty)* | Fallback JWT for **stdio mode only**; leave empty in SSE mode |
| `WLANPI_MCP_HOST` | `127.0.0.1` | SSE bind host (loopback: nginx proxies to it) |
| `WLANPI_MCP_PORT` | `8766` | SSE bind port (must match `proxy_pass` in the nginx site) |
| `ALLOW_POWER_CONTROL` | `true` | Set `false` to disable the `reboot_device`/`shutdown_device` tools |
| `LOG_LEVEL` | `INFO` | Logging level |

Service management tools (`start_service`, `stop_service`, `restart_service`) are restricted to the allowlist in `wlanpi_mcp/config.py` (`ALLOWED_SERVICES`).

## What's exposed

- **Tools** - system/power control, network interface queries, WLAN/Wi-Fi scanning, VLAN config, profiler control, Bluetooth, network config profiles, regulatory domain, device mode, and diagnostics utilities.
- **Resources** - read-oriented views of device info, network state, services, Bluetooth, profiler results, network configs, and device mode.
- **Prompts** - guided diagnostics workflows.

Connect a client and list tools/resources for the full, current inventory.

## Development

Requires Python ≥ 3.13.

```bash
pip install -e ".[testing]"
pytest                                    # run tests
python -m wlanpi_mcp --transport stdio    # run locally (stdio)
python -m wlanpi_mcp --transport sse      # run locally (cleartext SSE on 127.0.0.1:8766; --host 0.0.0.0 to expose it)
```

## License

BSD-3-Clause
