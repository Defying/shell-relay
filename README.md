# Shell Relay 🔌

A lightweight, hardened WebSocket daemon that provides AI agents with direct zsh shell access to a macOS machine — no SSH required.

## Overview

Shell Relay runs as a macOS LaunchAgent and exposes a JSON-over-WebSocket API for authenticated command execution. Designed for AI agent ↔ host machine communication with security-first defaults.

```
┌────────────────────┐       wss:// (TLS)       ┌──────────────────┐
│                    │ ──────────────────────── │   macOS Host     │
│   AI Agent / VM    │      JSON messages       │   shell-relay    │
│                    │ ◀──────────────────────  │   daemon         │
└────────────────────┘                          └──────────────────┘
                                                           │
                                                           ▼
                                                 ┌─────────────────┐
                                                 │   zsh session   │
                                                 │   (per client)  │
                                                 └─────────────────┘
```

## Features

- **TLS by default** — `wss://` with configurable cert/key
- **Token authentication** — 256-bit shared secret, constant-time comparison
- **Command filtering** — allowlist + blocklist with regex patterns
- **Rate limiting** — per-IP connection limits, per-session command throttling
- **Auth throttling** — brute-force protection with temporary IP bans
- **Output caps** — configurable stdout/stderr byte limits
- **Payload limits** — max WebSocket message size enforcement
- **Redacted logging** — command hashes only, no raw command text in logs
- **Health check** — `GET /healthz` endpoint
- **LaunchAgent** — auto-start on boot, auto-restart on crash

## Requirements

- Node.js 18+
- macOS (LaunchAgent support)
- `ws` npm package

## Installation

```bash
# Create install directory
sudo mkdir -p /usr/local/opt/shell-relay
sudo chown $(whoami) /usr/local/opt/shell-relay

# Clone and install
cd /usr/local/opt/shell-relay
git clone git@github.com:Defying/shell-relay.git .
npm install

# Generate TLS certs (self-signed)
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj '/CN=localhost'

# Generate auth token
openssl rand -hex 32 > /dev/null  # copy output to config.json

# Configure
cp config.example.json config.json
# Edit config.json: set your token, adjust allowlist/blocklist as needed
```

## Configuration

Copy `config.example.json` to `config.json` and customize:

| Key | Default | Description |
|-----|---------|-------------|
| `port` | `8765` | WebSocket server port |
| `host` | `127.0.0.1` | Bind address (loopback recommended) |
| `token` | — | 256-bit hex auth token |
| `shell` | `/bin/zsh` | Shell to spawn |
| `maxSessions` | `10` | Max concurrent sessions |
| `idleTimeoutMs` | `300000` | Idle session timeout (5 min) |
| `maxPayloadBytes` | `16384` | Max inbound WS message size |
| `tls.enabled` | `true` | Require TLS |
| `tls.cert` | — | Path to TLS certificate |
| `tls.key` | — | Path to TLS private key |
| `commandAllowlist` | `[...]` | Regex patterns for allowed commands |
| `commandBlocklist` | `[...]` | Regex patterns for blocked commands |
| `rateLimit.*` | — | Per-IP and per-session rate limits |
| `authThrottle.*` | — | Brute-force protection settings |
| `outputCaps.*` | — | Max stdout/stderr bytes per command |

## Protocol

JSON messages over WebSocket (`wss://`).

### Authentication
```json
→ {"type": "auth", "token": "<your-token>"}
← {"type": "auth_ok", "sessionId": "uuid"}
```

### Command Execution
```json
→ {"type": "exec", "command": "hostname"}
← {"type": "stdout", "data": "omens\n", "id": "cmd-uuid"}
← {"type": "exit", "code": 0, "id": "cmd-uuid"}
```

### Error Responses
```json
← {"type": "auth_fail"}
← {"type": "error", "message": "command blocked by policy"}
← {"type": "error", "message": "rate limit exceeded"}
```

## LaunchAgent Setup

```bash
# Copy plist
cp com.openclaw.shell-relay.plist ~/Library/LaunchAgents/

# Load (starts immediately)
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.openclaw.shell-relay.plist

# Check status
launchctl print gui/$(id -u)/com.openclaw.shell-relay

# Stop
launchctl bootout gui/$(id -u)/com.openclaw.shell-relay
```

## Remote Access via SSH Tunnel

Since the relay binds to `127.0.0.1`, access from other machines requires an SSH tunnel:

```bash
# On the remote machine
ssh -N -L 8765:127.0.0.1:8765 user@host

# Then connect to wss://127.0.0.1:8765 locally
```

## Security Notes

- **Always use TLS** — never run with `tls.enabled: false` on a network
- **Loopback binding** — bind to `127.0.0.1` and use SSH tunnels for remote access
- **Token rotation** — generate new tokens regularly with `openssl rand -hex 32`
- **Command filtering** — allowlist is checked first, then blocklist. Both use regex.
- **Logs** — stored at `logs/relay.log`, commands are hashed (not logged in plain text)
- **Never commit `config.json`** — it contains your auth token

## License

MIT
