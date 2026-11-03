# Crucible v2.2

Unified Penetration Testing Platform — orchestrate, execute, and manage penetration testing engagements across 12 integrated tools from a single interface.

Crucible v2.0 merges three previously separate Flask applications:
- **Vantage** (network recon) — Scattershot3 + OSift + Trawler
- **Crucible v1** (web/API) — Fracture + Siphon + Auger + AuthProbe
- **Spectre** (wireless) — Aether + Aether-B + Aether-Z + Aether-U

Plus Nessus vulnerability scanner integration and worker delegation for distributed execution.

## Requirements

- Python 3.10+
- Linux (Kali recommended) or macOS
- pr0t31n shared modules at `/opt/pr0t31n/shared/` (optional, degrades gracefully)
- Tool scripts installed at `/opt/pr0t31n/<ToolName>/` (see tool registry below)

## Installation

```bash
cd /opt/pr0t31n/Crucible
python3 install.py
```

The installer:
1. Creates required directories (static, templates, routes, models, services, adapters, sockets)
2. Installs Python dependencies from `requirements.txt`
3. Vendors shared modules (`_auth.py`, `pr0t31n_system_info.py`, `pr0t31n_v11_enrichment.js`) from `/opt/pr0t31n/shared/`
4. Downloads `socket.io.min.js` from CDN
5. Initializes session-based authentication via `_auth.py`

## Quick Start

```bash
python3 app.py
```

Crucible starts on **https://0.0.0.0:5100** with self-signed TLS. On first launch, `_auth.py` generates credentials and prints them to the console.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Flask 3.x + Flask-SocketIO 5.x (threading async_mode)   │
├─────────────────────────────────────────────────────────┤
│ 15 Blueprints (routes/)    │ 4 SocketIO modules          │
│ 12 Tool Adapters (adapters/)                             │
├─────────────────────────────────────────────────────────┤
│ ProcessManager │ QueueManager │ WorkerDelegate           │
│ FindingsEngine │ ActionEngine │ IntelService             │
│ ScopeManager   │ TokenParser  │ NessusClient             │
├─────────────────────────────────────────────────────────┤
│ JSON file storage (no SQL)  │ SocketIO rooms per project │
└─────────────────────────────────────────────────────────┘
```

### Tool Adapter Pattern

Each tool has an adapter class (`adapters/<tool>.py`) implementing the `ToolAdapter` ABC. Adapters define:
- Command-line argument construction
- Environment variables
- Settings schema and defaults
- Protocol token family (Crucible/Vantage/Spectre)
- Test connection support

Adapters are lazy-loaded via `adapters/__init__.py` registry.

### Protocol Token IPC

Tools communicate with Crucible through stdout protocol tokens parsed by `services/token_parser.py`:

| Token Family | Tools | Delimiter |
|---|---|---|
| `__CRUCIBLE_*__:` | Fracture, Siphon, Auger | Colon |
| `__VANTAGE_*__:` | Scattershot3, OSift, Trawler | Colon |
| `__SPECTRE_*__ ` | Aether family | Space |

Token types: LOG, ERR, STATUS, PROMPT, FINDING, ACTION_ITEM, TARGET, PORT

### Parallelism Groups

| Group | Tools | Execution |
|---|---|---|
| recon | Scattershot3, OSift | Parallel |
| attack | Fracture, Siphon | Serial |
| wireless | Aether, Aether-B, Aether-Z, Aether-U | Serial |
| any | Trawler, Auger, AuthProbe, Nessus | Unrestricted |

## Tool Registry

| ID | Tool | Key | Domain | Sudo |
|---|---|---|---|---|
| `ss3` | Scattershot3 | SS | Recon | Yes |
| `osift` | OSift | OS | Recon | Yes |
| `trawler` | Trawler | TR | Traffic | No |
| `fracture` | Fracture | FR | Web App | No |
| `siphon` | Siphon | SI | API | No |
| `auger` | Auger | AU | Database | No |
| `aether` | Aether (WiFi) | AE | Wireless | Yes |
| `aether_b` | Aether-B (BT) | AB | Wireless | Yes |
| `aether_z` | Aether-Z (Zigbee) | AZ | Wireless | Yes |
| `aether_u` | Aether-U (UWB) | AW | Wireless | Yes |
| `authprobe` | AuthProbe | AP | Recon | No |
| `nessus` | Nessus | NE | Vuln Scan | No |

## Features

### Project Management
- 4-step creation wizard (Engagement → Tools → Scope → Review)
- Edit existing projects
- Download/export project data
- Clear results or delete projects

### Console
- Real-time tool output via SocketIO
- Per-tool sidebar with activity indicators
- stdin input for interactive prompts
- 5000-line ring buffer per tool
- Auto-scroll toggle

### Findings
- Universal finding schema v1.1 (`pr0t31n_schema`)
- Dedup key: `(title_lower, ip, port, scope, hostname)`
- Filter by tool, risk level, keyword search
- False positive management with recovery
- Risk statistics (Critical/High/Medium/Low/Info)
- Bulk operations: accept, suppress, risk override

### Action Items
- 8 categories: port discovery, target expansion, URL discovery, wireless targets, PCAP analysis, DB targets, retest, scope expansion
- 2 approval tiers: AUTO (in-scope, low-risk) and CONFIRM (tool launches, scope expansion)
- Lifecycle: created → queued → running → complete/dismissed
- Bulk operations: dismiss, queue

### Intelligence
- Per-tool intelligence aggregation
- Cross-tool correlation
- Technology stack, credential, certificate intelligence

### Worker Delegation
- Register remote Crucible instances as workers
- Delegate tool runs to workers via WebSocket
- Real-time console/finding/log streaming from workers
- Automatic reconnection (30 attempts, 10s interval)

### Nessus Integration
- API client for Nessus Professional/Expert
- Scan creation, launch, status polling, export
- .nessus XML file upload and parsing
- Finding extraction with severity mapping

### Wireless
- Interface detection (Linux + macOS)
- SSID scanning
- Monitor/managed mode switching
- Radio cleanup (straggler process termination)

### Web Shell
- Interactive terminal in the browser via xterm.js
- PTY-based subprocess (zsh/bash) per SocketIO session
- Terminal resize support
- Reconnect and clear scrollback controls

### UI
- 10 curated CSS palettes (Tuxedo, Blueprint, Forge, Bloom, Ember, Coruscant, Neuromancer, Synthwave, Espresso, Sage)
- Dark/light mode toggle
- Session timeout with warning overlay
- Responsive layout

## File Structure

```
Crucible/
├── app.py                  # Flask app factory + SocketIO init
├── config.py               # Constants, tool registry, palettes
├── _auth.py                # Session-based auth (vendored)
├── install.py              # Multi-platform installer
├── requirements.txt        # Python dependencies
├── VERSION                 # Version file (2.3.1)
├── adapters/               # 12 tool adapter classes + shared base + registry
│   ├── base.py             # ToolAdapter ABC
│   ├── aether_base.py      # Shared Aether-family base (build_command, load_findings)
├── models/                 # JSON file storage layer
│   ├── project.py          # Project CRUD
│   ├── findings.py         # Findings storage + dedup
│   ├── action_items.py     # Action item lifecycle
│   ├── logs.py             # Log/error storage + time filtering
│   ├── targets.py          # Target aggregation
│   └── settings.py         # Per-tool settings schemas
├── routes/                 # 16 Flask blueprints + shared helpers
│   ├── _helpers.py         # require_project, get_ext, resolve_project_file
│   ├── auth.py             # Login/logout/session
│   ├── home.py             # Index + wizard
│   ├── project.py          # Project view
│   ├── console.py          # Console buffer API
│   ├── findings.py         # Findings CRUD + FP
│   ├── action_items.py     # Action item API
│   ├── settings.py         # Tool settings + AuthProbe + WiFi
│   ├── logs.py             # Logs/errors with time-range filter
│   ├── targets.py          # Target/port API
│   ├── intelligence.py     # Intel aggregation
│   ├── nessus.py           # Nessus API proxy
│   ├── traffic.py          # Trawler/pcap management
│   ├── export.py           # Project export/download
│   ├── worker.py           # Worker delegation API
│   ├── integration.py      # Nexus integration
│   └── shell.py            # Web shell page
├── services/               # Business logic
│   ├── process_manager.py  # Subprocess lifecycle + SocketIO events
│   ├── queue_manager.py    # Execution queue with disk persistence
│   ├── token_parser.py     # Protocol token IPC parser
│   ├── findings_engine.py  # Live finding processing
│   ├── action_engine.py    # Action item generation
│   ├── scope_manager.py    # CIDR/URL scope enforcement
│   ├── intel.py            # Intelligence aggregation
│   ├── nessus_client.py    # Nessus REST API client
│   ├── wireless.py         # WiFi interface management
│   └── worker_delegate.py  # Remote worker WebSocket client
├── sockets/                # SocketIO event handlers
│   ├── connection.py       # Join/leave project rooms
│   ├── tools.py            # Tool start/kill/input/status
│   ├── prompts.py          # Interactive prompt resolution
│   ├── workers.py          # Worker delegation events
│   └── shell.py            # Web shell PTY subprocess
├── templates/              # Jinja2 templates
│   ├── base.html           # Layout, nav, palette picker, session timeout
│   ├── index.html          # Home page with engagement sidebar
│   ├── wizard.html         # 4-step project creation/edit wizard
│   ├── project.html        # 9-tab project view (monolithic JS)
│   ├── shell.html           # Interactive web terminal (xterm.js)
│   └── login.html          # Auth login page
├── static/
│   ├── css/style.css       # 10 palettes × dark/light, all component styles
│   ├── js/main.js          # Palette, theme, session, toast utilities
│   ├── js/socket.io.min.js # SocketIO client library
│   └── img/logo.svg        # Crucible logo
└── projects.json           # Project registry (created at runtime)
```

## SocketIO Events

### Client → Server
| Event | Purpose |
|---|---|
| `tool_start` | Start a tool subprocess |
| `tool_kill` | Kill a running tool |
| `tool_input` | Send stdin to a tool |
| `get_console` | Request console buffer |
| `get_status` | Request all tool statuses |
| `join_project` | Join a project's SocketIO room |
| `leave_project` | Leave a project's SocketIO room |
| `shell_open` | Open a PTY shell session |
| `shell_input` | Send keystrokes to shell |
| `shell_resize` | Resize terminal dimensions |
| `shell_close` | Close shell session |

### Server → Client
| Event | Purpose |
|---|---|
| `tool_status` | Tool state change |
| `tool_started` | Tool process launched |
| `tool_done` | Tool process exited |
| `console_line` | Console output line |
| `tool_finding` | New finding discovered |
| `tool_action_item` | New action item |
| `tool_target` | New target discovered |
| `tool_port` | New port discovered |
| `tool_log` | Log entry |
| `tool_error` | Error entry |
| `tool_prompt` | Interactive prompt |
| `prompt_resolved` | Prompt answered |
| `tool_queued` | Tool queued for execution |
| `tool_killed` | Tool killed |
| `all_status` | All tool statuses |
| `console_buffer` | Full console buffer |
| `checkpoint_status` | Checkpoint data |
| `shell_output` | Shell stdout/stderr data |
| `shell_exit` | Shell session ended |

## Port

Crucible v2.0 runs on port **5100** (inherits from Vantage, which previously held this port).

## Integration Points

- **Nexus** — central hub status reporting via `/api/nexus-status`
- **Shared Catalogue** — findings catalogue enrichment via `pr0t31n_catalogue.py`
- **Prometheus** — report generation from universal findings

## License

Internal pr0t31n toolkit. Not for distribution.
