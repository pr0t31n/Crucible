# Crucible

**Web & API Assessment Platform** — Flask/SocketIO orchestrator for [Fracture](https://github.com/pr0t31n/Fracture) (web app pentest) and [Siphon](https://github.com/pr0t31n/Siphon) (API security testing).

Crucible is the operational frontend for running web application and API penetration tests. It manages engagements, launches tools as supervised subprocesses, streams real-time output to your browser, aggregates findings, and handles interactive prompts (including sudo password masking).

---

## Architecture

```
Browser  ←── HTTPS/WebSocket ──→  Crucible (Flask/SocketIO :5500)
                                        │
                                 ┌──────┴──────┐
                                 │             │
                           fracture.py    siphon.py
                           (web app)      (API)
                                 │             │
                           fracture_output/ siphon_output/
                           findings.json    findings.json
```

Crucible uses a protocol token architecture for subprocess communication:

| Token | Description |
|-------|-------------|
| `__CRUCIBLE_LOG__:` | Structured log entry (JSON) |
| `__CRUCIBLE_ERR__:` | Structured error entry (JSON) |
| `__CRUCIBLE_PROMPT__:` | Interactive prompt (modal dialog) |
| `__CRUCIBLE_STATUS__:` | Phase/step status update |

---

## Features

- **Dual-tool console** — side-by-side streaming output for Fracture and Siphon
- **Real-time findings** — findings.json polled every 5 s during scans, pushed via SocketIO
- **Interactive prompt handling** — password fields masked in browser, never logged in plaintext
- **Sudo credential handling** — browser modal for sudo prompts with auto-masking
- **Phase status tracking** — live phase progress from CRUCIBLE_STATUS tokens
- **Findings table** — filterable by risk, tool; sortable; CSV export
- **Structured logs & errors** — categorised, filterable, paginated
- **Settings editor** — in-browser JSON editor for fr_settings.json and si_settings.json
- **Checkpoint viewer** — inspect resume state from checkpoint.json
- **Per-engagement project directories** — `~/clients/<client>/<client>_<scope>_<year>/`
- **HTTPS** — self-signed TLS cert generated on first run
- **Auth with mandatory password change** — default credentials must be replaced on first login
- **CSRF protection** — server-side synchronizer tokens on all POST forms

---

## Installation

```bash
cd /Users/pr0t31n/Crucible
python3 install.py
```

Options:
```
--skip-system    Skip OS package installation
--skip-pip       Skip Python package installation
--skip-service   Skip systemd/launchd service installation
--check          Verify installation only (no changes)
```

Dependencies are installed automatically:
- `flask >= 3.0.0`
- `flask-socketio >= 5.3.0`
- `eventlet >= 0.35.0`
- `psutil >= 5.9.0`

Fracture and Siphon must be installed separately:
```bash
python3 /Users/pr0t31n/Fracture/install.py
python3 /Users/pr0t31n/Siphon/install.py
```

---

## Quick Start

```bash
cd /Users/pr0t31n/Crucible
python3 app.py
```

Then open: **https://localhost:5500**

1. Accept the self-signed TLS certificate warning
2. Log in with default credentials: `admin` / `t3mpPas$w0rd`
3. **You will be immediately prompted to set a new username and strong password**
4. Create a new engagement from the dashboard
5. Select target URL(s) and which tools to run
6. Open the engagement and click Start for Fracture and/or Siphon

---

## Default Credentials

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `t3mpPas$w0rd` |

**These must be changed on first login.** Crucible enforces a mandatory credential rotation — you cannot access any other page until you set a strong, unique username and password.

Password policy: blocked common passwords, username cannot match password, minimum 8 characters.

---

## Project Directory Structure

```
~/clients/<client_short>/<client_short>_<scope>_<year>/
├── fr_settings.json         # Fracture scan configuration
├── si_settings.json         # Siphon scan configuration
├── fracture_output/         # Created by Fracture
│   ├── findings.json
│   ├── summary.json
│   └── checkpoint.json
├── siphon_output/           # Created by Siphon
│   ├── findings.json
│   ├── summary.json
│   └── checkpoint.json
├── crucible_console_fr.jsonl # Fracture console history
├── crucible_console_si.jsonl # Siphon console history
├── crucible_logs.jsonl       # Structured logs
└── crucible_errors.jsonl     # Structured errors
```

---

## Nexus Integration

Crucible exposes an unauthenticated status endpoint for the Nexus hub:

```
GET /api/nexus-status
→ {"app": "crucible", "scanning": false, "version": "1.0.0"}
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Project list |
| GET | `/project/<id>` | Project detail |
| GET | `/new_project` | New project form |
| GET | `/edit_project/<id>` | Edit project form |
| POST | `/api/create_project` | Create project |
| POST | `/api/update_project/<id>` | Update project |
| GET | `/api/project/<id>` | Get project JSON |
| GET | `/api/settings/<id>/fr` | Get Fracture settings |
| POST | `/api/settings/<id>/fr` | Save Fracture settings |
| GET | `/api/settings/<id>/si` | Get Siphon settings |
| POST | `/api/settings/<id>/si` | Save Siphon settings |
| GET | `/api/console/<id>/fr` | Get Fracture console buffer |
| GET | `/api/console/<id>/si` | Get Siphon console buffer |
| GET | `/api/findings/<id>` | Get all findings (aggregated) |
| GET | `/api/logs/<id>` | Get structured logs |
| GET | `/api/errors/<id>` | Get structured errors |
| GET | `/api/status/<id>` | Get phase status cache |
| GET | `/api/checkpoint/<id>/fr` | Get Fracture checkpoint |
| GET | `/api/checkpoint/<id>/si` | Get Siphon checkpoint |
| GET | `/api/summary/<id>` | Get scan summary |
| DELETE | `/api/delete_project/<id>` | Delete project |
| GET | `/api/nexus-status` | Nexus hub probe (unauthenticated) |

---

## SocketIO Events

### Client → Server
| Event | Description |
|-------|-------------|
| `join_project` | Join a project room |
| `leave_project` | Leave a project room |
| `fr_start` | Launch Fracture subprocess |
| `fr_kill` | Kill Fracture |
| `fr_input` | Send answer to Fracture prompt |
| `si_start` | Launch Siphon subprocess |
| `si_kill` | Kill Siphon |
| `si_input` | Send answer to Siphon prompt |
| `crucible_answer` | Generic prompt answer |

### Server → Client
| Event | Description |
|-------|-------------|
| `fr_output` | Fracture console line |
| `si_output` | Siphon console line |
| `fr_started` | Fracture started (PID) |
| `fr_done` | Fracture exited (returncode) |
| `fr_stopped` | Fracture killed |
| `si_started` | Siphon started (PID) |
| `si_done` | Siphon exited (returncode) |
| `si_stopped` | Siphon killed |
| `tool_status` | Tool status update {fr, si} |
| `finding` | New/updated finding |
| `log_entry` | Structured log entry |
| `err_entry` | Structured error entry |
| `crucible_status` | Phase status update |
| `crucible_prompt` | Interactive prompt request |
| `prompt_resolved` | Prompt answered |

---

## Port

Crucible runs on **port 5500** (HTTPS).

Tool ports used by subprocesses (Fracture and Siphon manage their own networking).

---

## Legal Disclaimer

Crucible is designed exclusively for **authorized penetration testing** and **security research**. Use of this software against systems without explicit written authorization from the system owner is **illegal** and may result in criminal prosecution.

The authors of Crucible accept no liability for misuse. Always obtain proper authorization before conducting any security assessment.

**For authorized use only.**
