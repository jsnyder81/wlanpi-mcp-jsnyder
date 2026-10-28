# wlanpi-mcp

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes [WLAN Pi](https://wlanpi.com) capabilities - device info, service management, Wi-Fi scanning, profiler control, Bluetooth, and VLANs - to AI assistants like Claude.

It is a thin bridge to the `wlanpi-core` REST API on the device (`https://localhost:31415`); every tool call goes through that API.

## How it runs

Two transports:

- **Streamable HTTP (daemon mode)** - how the Debian package runs it under systemd: the uvicorn daemon binds loopback-only and an nginx site fronts it. `https://<wlanpi>:8767/mcp` terminates the device's self-signed TLS and is the only endpoint (the plaintext 8766 fallback was removed, #17). Every request **must** present a wlanpi-core JWT (see [Authentication](#authentication)). The transport is stateless: each request is a complete exchange with no server-side session, so a client that reconnects after a daemon restart or an idle gap keeps working. Releases before 0.6.12 served `/sse` instead; see the upgrade note under [Connecting Claude Code](#connecting-claude-code).
- **stdio** - the MCP client launches the server as a subprocess. Only useful when the client runs on the WLAN Pi itself.

## Installation on the WLAN Pi

Install the Debian package (depends on `wlanpi-core`):

```bash
sudo apt install ./wlanpi-mcp_*.deb
```

This installs to `/opt/wlanpi-mcp`, enables the `wlanpi-mcp` systemd service (streamable HTTP, fronted by nginx with TLS on 8767), and reads configuration from `/etc/wlanpi-mcp/config.env` (see `install/etc/wlanpi-mcp/config.env.example`).

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

Alternatively, call `POST /api/v1/auth/token` yourself - see the wlanpi-core API docs (Swagger UI at `https://<wlanpi>:31415/docs`) for the HMAC signing details.

The full flow, from the MCP client through nginx to wlanpi-core, is documented in [docs/auth-flow.md](docs/auth-flow.md).

## Connecting Claude Code

On any machine that can reach the WLAN Pi:

```bash
claude mcp add --transport http wlanpi https://<wlanpi-ip>:8767/mcp \
  --header "Authorization: Bearer <your-wlanpi-core-jwt>"
```

Then verify with `/mcp` inside Claude Code - the `wlanpi` server should show as connected, with its tools and resources listed.

To share the config with your whole project (checked into `.mcp.json`) add `--scope project`; the default scope is local to you.

Upgrading from a release that served `/sse`? Remove the old entry (`claude mcp remove wlanpi`) and add it again as above: the transport is now `http` and the path is `/mcp`.

### Claude Code running on the WLAN Pi itself (stdio)

If Claude Code runs on the device, you can skip the HTTP hop and launch the server over stdio. There are no HTTP headers in stdio mode, so the token comes from the `WLANPI_CORE_TOKEN` environment variable instead:

```bash
claude mcp add wlanpi \
  --env WLANPI_CORE_TOKEN=<your-wlanpi-core-jwt> \
  -- /opt/wlanpi-mcp/bin/python -m wlanpi_mcp --transport stdio
```

(Use your own interpreter path instead of `/opt/wlanpi-mcp/bin/python` if you installed from source with pip.)

## Connecting Claude Desktop

Claude Desktop launches stdio servers, so a remote HTTP server is bridged with the [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) proxy (requires Node.js on your desktop machine).

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
        "https://<wlanpi-ip>:8767/mcp",
        "--transport", "http-only",
        "--header", "Authorization: Bearer ${WLANPI_TOKEN}"
      ],
      "env": {
        "WLANPI_TOKEN": "<your-wlanpi-core-jwt>"
      }
    }
  }
}
```

Notes:

- The TLS endpoint (8767) uses the same self-signed certificate as wlanpi-core, so your client must trust it (`/etc/nginx/ssl/self-signed-wlanpi.cert` on the device), or accept the cert warning. The JWT is encrypted in transit.
- The daemon relies on the Bearer JWT gate, not on the MCP SDK's Host/Origin (DNS rebinding) check, which is disabled because nginx forwards the client's real Host header to the loopback-only daemon. A `421 Misdirected Request` on `/mcp` means that check is on again.
- There is no plaintext endpoint: 8767 is the only one, so a harness that cannot be pointed at a CA file (e.g. goose) needs `self-signed-wlanpi.cert` added to the OS trust store it uses. The plaintext `http://<wlanpi>:8766/mcp` fallback was removed (#17): nothing listens on 8766 and UFW no longer opens it, so a client still configured for it times out (or gets connection refused on-box). Point it at `https://<wlanpi>:8767/mcp` instead.
- `--transport http-only` skips mcp-remote's SSE fallback; this server speaks streamable HTTP only.
- The token is passed via the `env` block and interpolated into the header (`${WLANPI_TOKEN}`) - this sidesteps a known mcp-remote issue with spaces in `args` values on some platforms.

Restart Claude Desktop after editing the file. The WLAN Pi tools appear under the tools (🔨) menu.

## Configuration

Settings load from the environment or `/etc/wlanpi-mcp/config.env`:

| Variable | Default | Purpose |
|---|---|---|
| `WLANPI_CORE_URL` | `https://localhost:31415` | wlanpi-core API base URL |
| `WLANPI_CORE_CA` | `/etc/nginx/ssl/self-signed-wlanpi.cert` | CA bundle for verifying wlanpi-core's TLS listener |
| `WLANPI_CORE_TOKEN` | *(empty)* | Fallback JWT for **stdio mode only**; leave empty in daemon mode |
| `WLANPI_MCP_HOST` | `127.0.0.1` | Daemon bind host (loopback-only; nginx fronts the public 8767) |
| `WLANPI_MCP_PORT` | `8768` | Daemon bind port (loopback-only upstream) |
| `ALLOW_POWER_CONTROL` | `true` | Set `false` to disable the `reboot_device`/`shutdown_device` tools |
| `LOG_LEVEL` | `INFO` | Logging level |

Service management tools (`start_service`, `stop_service`, `restart_service`) are restricted to wlanpi-core's service allowlist, which `list_allowed_services` reads from `GET /api/v1/system/services`.

## What's exposed

- **Tools** - system/power control, network interface queries, WLAN/Wi-Fi scanning, VLAN config, profiler control, Bluetooth, network config profiles, regulatory domain, device mode, and diagnostics utilities.
- **Resources** - read-oriented views of device info, network state, services, Bluetooth, profiler results, network configs, and device mode.
- **Prompts** - guided diagnostics workflows.

Connect a client and list tools/resources for the full, current inventory.

### Confirmations and background tasks

On requests that use MCP protocol revision 2026-07-28, the server uses two client features when the client declares them. Clients without them, such as Claude Desktop or `claude -p`, get the same tools without these features.

- **Elicitation.** The server asks you directly instead of relying on the model to ask:
  - It confirms before destructive actions: `reboot_device`, `shutdown_device`, `purge_profiler_data`, `set_regulatory_domain`, `reset_network_namespaces`, `delete_network_config` with `force`, and the override cases of `activate_network_config` and `deactivate_network_config`.
  - It lets you pick the adapter when `scan_wlan` finds several.
  - For `create_network_config`, it opens a page on the WLAN Pi where you type each Wi-Fi passphrase, so the passphrase never passes through the conversation. The page uses the WLAN Pi's own certificate, so your browser may warn about it the first time.
- **MCP Tasks** (`io.modelcontextprotocol/tasks`). `start_pcap_file`, `capture_scan`, `capture_observe`, `run_speedtest` and `profile_clients` run in the background with live progress. That keeps them clear of the client's per-request timeout. `profile_clients` requires task support.

Task state and pending confirmations live in the daemon's memory. A restart drops them, and the client starts the call again.

## Development

Requires Python ≥ 3.13.

```bash
pip install -e ".[testing]"
pytest                                    # run tests
python -m wlanpi_mcp --transport stdio    # run locally (stdio)
python -m wlanpi_mcp --transport streamable-http   # run locally (127.0.0.1:8768/mcp; front with nginx for 8767)
```

## License

BSD-3-Clause
