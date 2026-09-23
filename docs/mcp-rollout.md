# MCP rollout

Action-oriented companion to the design in [`mcp-auth-plan.md`](./mcp-auth-plan.md).
It records what has landed, what remains for on-box MCP, and what is left for
external/remote MCP.

Capture contract:
[`capture-ws-mcp-handover.md`](https://github.com/WLAN-Pi/wlanpi-core/blob/dev/docs/capture-ws-mcp-handover.md).

## 1. Landed

| Change | Repo | Delivers |
|---|---|---|
| Auth hardening (#159) | wlanpi-core | Immediate revocation, boot-bound monotonic token lifetime, credential-based dispatch |
| Credential dispatch (#160) | wlanpi-core | Auth selected by the credential presented; `X-Wlanpi-Client` sentinel removed; route-auth guard test |
| TLS-only API | wlanpi-core | Production `:31415` is HTTPS-only with the self-signed cert; dev HTTP stays on loopback `:8000` |
| Capture WebSocket (#165) | wlanpi-core | First-message auth (`4401`), `did`-owned sessions, read-only subscribers, pcapng framing, bounded subscriber queues |
| Root-only secret (#179) | wlanpi-core | `shared_secret.bin` is `0600 root:root`; on-device clients use JWTs |
| WebUI bearer migration (#120) | wlanpi-webui | The WebUI mints its own JWT and never reads the secret |
| `getjwt --export` (#217) | wlanpi-core | Token export for client scripts |
| Capture tools | wlanpi-mcp | Owner capture and subscribe, backed by the core capture WebSocket |
| P5 (#4) | wlanpi-mcp | No `X-Wlanpi-Client` header; one CA-pinned TLS context for REST and the capture WebSocket; `WLANPI_CORE_TOKEN` env-only; `TOOL_PROFILE=classroom` / `TOOL_ALLOWLIST` |

## 2. On-box MCP

On-box MCP (stdio, or loopback HTTP) reaches core over `https://localhost:31415`
with the canonical CA. This path is complete: Bearer authentication, token
lifetime and revocation, and capture (owner or subscriber) all work.

## 3. External / remote MCP

Remote MCP is the same capture protocol plus transport and trust.

| Item | Owner | Status |
|---|---|---|
| Clients trust the device certificate | client | SANs cover `localhost`, `wlanpi.local`, and loopback; connect by `wlanpi.local` or distribute the cert |
| MCP daemon binds loopback by default | wlanpi-mcp packaging | Binds `0.0.0.0` today; loopback is a manual step |
| One-page setup guide | docs | Not started |
| Certificate SAN regeneration / pairing | wlanpi-core | The real external gap; PKI, not nginx |

## 4. Beyond

Only needed for multi-party or multi-tenant deployments:

- Streamable HTTP (`POST /mcp`, stateless) for wlanpi-mcp.
- `aud` claims (issue now, enforce later).
- Core introspection endpoint.
- MCP service identity to core (ends JWT passthrough).
- Busy/interference detection and a capture-sources endpoint.

## 5. Notes

- The old feature-flagged TLS front-ends (`:31416` API, `:8767` MCP, `:8443`
  dev) were abandoned in favour of TLS-only `:31415`.
- `TOKEN_LIFETIME_MODE` was dropped; the token lifetime model is fixed.
