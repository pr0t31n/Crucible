<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Crucible — Unified Penetration Testing Platform

**Crucible** is the unified orchestration platform for the pr0t31n toolkit. It manages, executes, and correlates penetration testing engagements across 18 integrated tool adapters, 13 standalone quick-action tools, and 9 external CLI tool integrations from a single authenticated HTTPS dashboard. Crucible v2.0 merged three previously separate Flask applications — network recon, web/API testing, and wireless assessment — into one platform with shared findings, unified intelligence, centralized session management, and 49 scope-gated report types.

```
https://localhost:5100
```

---


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/crucible)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

### Project Management

- **4-step creation wizard** — Engagement metadata, tool selection, scope definition, and review/confirm with live validation at each step
- **Per-URL auth configuration** — each Fracture target URL gets independent auth testing via Test Connection, with auto-detect as the default method
- **7 engagement scopes** — External, OSINT, Internal, Wireless, Web Application, API, and Endpoint; each scope gates which tools, settings, and report types are available
- **Edit existing projects** — modify scope, targets, tool settings, and engagement metadata after creation
- **Project export/import** — download project data as ZIP archives; import supports Crucible v2, v1, legacy, raw tool output, and single scanner file formats
- **Engagement clear** — reset results (including FindingsDB) without deleting project configuration
- **Client directory structure** — platform-aware output paths (`/clients` on Linux, `/Users/Shared/clients` on macOS) with per-year, per-tool organization

### Console

- **Real-time tool output** via SocketIO with per-tool sidebar and activity indicators
- **5,000-line ring buffer** per tool with auto-scroll toggle and server-side clear
- **stdin input** for interactive tool prompts with prompt resolution tracking
- **Append-on-restart** — console history preserved across tool restarts rather than cleared
- **Tool status indicators** — running, queued, paused, complete, failed, killed states with color-coded badges

### FindingsDB (SQLite Backend)

- **Server-side pagination** — large finding sets served page-by-page instead of loading thousands of records into the browser
- **Version-aware import engine** — detects export format (v3.0 DB-native, v2.0 JSON, v1.x legacy, raw, file import) and converts to current layout
- **Live finding injection** — new findings from running tools are inserted into the SQLite database in real time
- **DB-aggregate summaries** — risk statistics, tool breakdowns, and intelligence data computed from DB queries rather than JSON file scans
- **DB-first loading** — all legacy JSON endpoints fall through to FindingsDB when available, with atomic JSON-to-DB migration on first access

### Findings

- **Universal finding schema v1.1** with 56 fields (15 required, 41 enrichment) via `pr0t31n_schema`
- **Dedup key**: `(title_lower, ip, port, scope, hostname)` — automatic deduplication across tools
- **Filter by tool, risk level, keyword search** with full-text search via FTS5 rebuild
- **False positive management** with recovery — findings move to `falsePositives.json` and can be restored
- **Risk statistics** — Critical/High/Medium/Low/Info counts with per-tool and per-scope breakdowns
- **Bulk operations** — accept, suppress, risk override across multiple findings
- **Notes** — per-finding analyst notes
- **Evidence file upload** — attach screenshots, PoC scripts, and other evidence files directly to findings
- **Evidence audit** — CRITICAL-level logging for findings that lack evidence files
- **CISA KEV enrichment** — automatic Known Exploited Vulnerabilities catalogue matching with 24-hour refresh cycle and backfill on startup
- **Snapshots** — point-in-time finding state snapshots for comparison

### Action Items

- **9 categories**: port discovery, target expansion, URL discovery, wireless targets, PCAP analysis, DB targets, AD targets, retest, scope expansion, and manual checks
- **2 approval tiers**: AUTO (in-scope, low-risk actions) and CONFIRM (tool launches, scope expansion)
- **Lifecycle**: created, queued, running, complete, dismissed
- **Immediate auto-queue** — mid-execution action items that qualify are auto-queued without waiting for the parent tool to finish
- **Manual testing action items** — catalogue-driven checklists loaded from `manual_checks.json` files shipped with Fracture and Siphon; resolved as findings when a tester confirms a manual check
- **Bulk operations** — dismiss, queue, and scope-filtered views

### Session Manager

- **Centralized auth keepalive** — captures, stores, and proactively refreshes authentication sessions across tools
- **Per-target auth table** — wizard and settings page display per-URL auth status (tested/untested) with truncated auth preview; Test Connection uses a URL selector dropdown for multi-target engagements
- **8 session types**: OAuth2, JWT, Cookie, Basic, API Key, Bearer (static), NTLM, Custom
- **Automatic refresh** — sessions refreshed 120 seconds before expiry with configurable heartbeat (45s interval)
- **Cross-tool sharing** — tools receive live credentials from the session store rather than managing their own tokens
- **Kill/Kill All** — terminate individual sessions or all sessions for a project
- **Session registration from action items** — sessions can be registered directly from tool execution flows

### Intelligence

- **Per-tool intelligence aggregation** — each tool's output parsed into structured intelligence panels
- **Cross-tool correlation** — technology stacks, credentials, certificates, software versions, DNS records, subdomains, emails, and phone numbers aggregated from all tools
- **DB-backed paginated intelligence** (v2) — large intelligence datasets served via FindingsDB queries with filtering
- **Attack surface view** — per-host inventory with port/service/severity breakdown, sortable and filterable by risk
- **Mobile intelligence** — domains, URLs, and email addresses extracted from Quill mobile analysis
- **MITM CA certificate panel** — Intelligence tab displays proxy CA details with keytool installation commands for mobile testing

### Report Generation

- **49 report types** across 10 scope categories, generated as PDF via Playwright/Chromium with full CSS rendering
- **Scope-gated availability** — reports filtered by the project's active scopes; only relevant reports shown
- **Engagement completion check** — warns when tools are still running or queued before generating reports
- **Grouped findings** — findings organized by type within each scope section
- **Compliance matrix** — cross-framework mapping (NIST CSF, PCI DSS, ISO 27001, SOC 2, HIPAA)

| Category | Report Types | Count |
|----------|-------------|-------|
| Universal | Full Pentest, Remediation Prioritization, Compliance Matrix, Unified Executive Summary | 4 |
| External | Vulnerability Assessment, Attack Surface, PCI DSS, Perimeter Firewall, Executive Summary | 5 |
| OSINT | Intelligence, Digital Footprint, Email & Credential Exposure, DNS Security, Executive Summary | 5 |
| Internal | Vulnerability Assessment, Network Segmentation, Active Directory, SMB & File Share, Executive Summary | 5 |
| Wireless | Security Assessment, Wi-Fi Configuration, Rogue AP, Bluetooth/IoT, Executive Summary | 5 |
| Web | Vulnerability, OWASP Top 10, Web Technology, Content Discovery, Executive Summary | 5 |
| API | Security Assessment, OWASP API Top 10, Executive Summary | 3 |
| Endpoint | NIST 800-123, DISA STIG, CIS Benchmark, Disk & Storage, Software & Update, Malicious Activity, Hardware | 7 |
| Cloud | Infrastructure, Pentest Assessment, CIS AWS Benchmark, Compliance, Executive Summary | 5 |
| Cross-Scope | Trawler Traffic, Auger Database, Bastion Firewall, Forge Cloud, Quill Mobile, Isotope File Analysis | 5 |

### Burp XML Import Wizard

- **Upload Burp Suite XML exports** — parse and preview findings before committing to the project
- **Preview/commit workflow** — review parsed findings with risk mapping before import
- **Finding deduplication** — imported Burp findings deduplicated against existing project findings

### GoPhish Campaign Analysis

- **Phish Analyzer** — standalone quick-action tool that analyzes GoPhish campaign exports
- **Email filter artifact stripping** — removes email security product artifacts that inflate click/open rates
- **Corrected metrics** — produces accurate campaign statistics after filtering

### Wireless

- **Interface detection** — discovers wireless adapters on Linux and macOS
- **SSID scanning** — scan visible wireless networks with encryption/channel details
- **Monitor/managed mode switching** — toggle wireless interfaces between modes
- **Radio cleanup** — terminate straggler processes that block wireless operations
- **Active/passive scope modes** — per-SSID scope mode selection in wizard and settings; passive mode gates Aether to monitoring-only operations
- **SSID mutual exclusivity** — SSIDs assigned to one scope mode cannot appear in the other

### Mobile Testing (Quill)

- **Frida device discovery** — Python API-based detection of connected USB devices with Frida server
- **MITM proxy integration** — built-in mitmproxy management with configurable port, upstream proxy, and CA certificate upload
- **HAR-to-Siphon handoff** — MITM-captured HAR traffic automatically queued for Siphon API endpoint analysis
- **Analysis mode selector** — Static, Dynamic, or Full analysis with independent MITM and Frida toggles
- **Multi-file analysis** — per-file output directories with findings merge across analyzed binaries
- **Phase selection UI** — choose which Quill analysis phases to run

### Nessus Integration

- **API client** for Nessus Professional/Expert — scan creation, launch, status polling, and export
- **`.nessus` XML file upload** — parse and import findings from exported scan files
- **Severity mapping** — Nessus severity levels mapped to pr0t31n risk scale
- **Scope-aware** — Nessus scan targets derived from project scope definition

### Beacon Integration

- **Activity-driven status push** — engagement status broadcast to Beacon server every 60 seconds while tools are active
- **5-minute cooldown** — pushes continue after last tool completes, then stop to save bandwidth
- **Automatic wake** — any new tool launch restarts the push loop
- **Risk summary** — finding counts by severity transmitted with each status push
- **Per-project configuration** — Beacon URL and enable/disable toggle in project settings

### Vault Integration

- **Active Directory credential testing** — managed tool with full adapter, settings schema, and auto-queue support
- **AD target auto-detection** — action items generated when AD services (LDAP, Kerberos, SMB signing) are discovered by recon tools
- **Module support** — full Vault module configuration through Crucible settings

### Worker Delegation

- **Register remote Crucible instances** as workers for distributed execution
- **Delegate tool runs** to workers via WebSocket with real-time console/finding/log streaming
- **Automatic reconnection** — 30 attempts at 10-second intervals on connection loss
- **Worker status tracking** — connected, disconnected, delegating states visible in the UI

### File Import System

- **Multi-format import** — supports 30+ scanner output formats including nmap XML, Nessus, Nuclei, Burp, sqlmap, Hydra, Responder, Amass, subfinder, and more
- **Tool auto-detection** — parser registry maps file formats to tool categories automatically
- **Folder import** — import entire directories of scanner output with recursive parsing
- **Concurrent import** — up to 3 parallel import jobs with progress tracking via SocketIO
- **Scope and tool override** — manually assign scope or tool attribution during import

### Standalone Quick-Action Tools

13 tools accessible directly from the homepage without creating an engagement:

| Tool | Description |
|------|-------------|
| Engagement Merger | Merge multiple Crucible engagements and Nessus results |
| AuthProbe | Detect authentication methods and fingerprint software |
| Host Discovery | Quick nmap live-host scan (ICMP + TCP + UDP) |
| Wordlist Generator | Scrape websites and build targeted password-candidate wordlists |
| Port Probe | Lightweight nmap TCP SYN scan with service/version detection |
| SSL/TLS Audit | TLS configuration and cipher suite audit via testssl.sh or sslscan |
| Security Headers | HTTP security header pass/fail scorecard with grade |
| Encode / Decode | Base64, URL, HTML entities, hex, JWT decode, hash identification |
| DNS Resolver | A/AAAA/CNAME/MX/NS/TXT/SOA lookups + reverse DNS + WHOIS |
| WiFi Scanner | Scan visible wireless networks and manage interfaces |
| Traffic Dump | Quick packet capture with tshark/tcpdump and internal IP analysis |
| System Info | Hostname, OS, CPU, memory, GPU, users, interfaces, listeners, disk |
| Phish Analyzer | Analyze GoPhish campaigns with email filter artifact correction |

### Web Shell

- **Interactive terminal** in the browser via xterm.js with PTY-based subprocess (zsh/bash)
- **Per-session process** — each SocketIO connection gets its own PTY
- **Terminal resize** — dimensions follow the browser window
- **Reconnect and clear scrollback** controls

### UI and Theming

- **10 curated CSS palettes** across 4 categories:

| Category | Palettes |
|----------|----------|
| Professional | Tuxedo, Blueprint, Forge |
| Casual | Bloom, Ember |
| Nerdy | Coruscant, Neuromancer, Synthwave |
| Natural | Espresso, Sage |

- **Dark/light mode toggle** with palette-independent mode switching
- **Session timeout** — 30-minute timeout with 5-minute warning overlay
- **Responsive layout** — mobile-aware homepage and project views
- **Toast notifications** — non-blocking status messages for async operations
- **9-tab project view** — Console, Findings, Action Items, Intelligence, Settings, Logs, Targets, Reports, Sessions

---

## Architecture

```
                           +-------------------------------+
                           |         Browser Client        |
                           |  xterm.js · SocketIO · fetch  |
                           +--------------+----------------+
                                          |
                            HTTPS :5100 (self-signed TLS)
                                          |
+-------------------------------------------------------------------------+
|                         Flask 3.x + Flask-SocketIO 5.x                  |
|                          (threading async_mode)                         |
+-------------------------------------------------------------------------+
|                                                                         |
|  +------------------+  +-------------------+  +---------------------+   |
|  | 23 Blueprints    |  | 6 SocketIO modules|  | 18 Tool Adapters    |   |
|  | (routes/)        |  | (sockets/)        |  | (adapters/)         |   |
|  +------------------+  +-------------------+  +---------------------+   |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                       Service Layer                               |  |
|  |                                                                   |  |
|  |  ProcessManager    QueueManager      WorkerDelegate               |  |
|  |  FindingsEngine    ActionEngine      ScopeManager                 |  |
|  |  TokenParser       SessionManager    KEVEnricher                  |  |
|  |  NessusClient      ImporterService   ReportGenerator              |  |
|  |  AttackSurface     BeaconClient      SchedulerService             |  |
|  |  AuditLogger       IntelIngestion    Wireless                     |  |
|  |                                                                   |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                       Data Layer                                  |  |
|  |                                                                   |  |
|  |  FindingsDB (SQLite)  ·  JSON file storage  ·  SocketIO rooms     |  |
|  |  projects.json        ·  workers.json       ·  execute_queue.json |  |
|  |                                                                   |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
                          |                    |
            +-------------+----+        +------+--------+
            | Managed Tools    |        | External      |
            | (subprocess)     |        | Integrations  |
            |                  |        |               |
            | SS3, OSift,      |        | Nessus API    |
            | Fracture, Siphon |        | Beacon push   |
            | Auger, Aether*4  |        | Nexus status  |
            | Bastion, Forge   |        | Worker WS     |
            | Quill, Isotope   |        | Frida USB     |
            | Dredge, Vault    |        |               |
            | Trawler, AuthPrb |        |               |
            | pAIn             |        |               |
            +------------------+        +---------------+
```

### Tool Adapter Pattern

Each managed tool has an adapter class (`adapters/<tool>.py`) extending the `ToolAdapter` ABC defined in `adapters/base.py`. Adapters encapsulate:

- Command-line argument construction from project settings
- Environment variable injection (all managed tools receive `CRUCIBLE_MANAGED=1`)
- Settings schema and defaults for the wizard/settings UI
- Protocol token family declaration
- Test connection support (for tools that verify target reachability)

Adapters are lazy-loaded via the `adapters/__init__.py` registry, so unused tools impose no import cost.

### Protocol Token IPC

Tools communicate with Crucible through stdout protocol tokens parsed by `services/token_parser.py`:

| Token Family | Tools | Notes |
|---|---|---|
| `__CRUCIBLE_*__:` | Fracture, Siphon, Auger, Bastion, Forge, Quill, Isotope, Dredge, Trawler, SS3, OSift, Aether, Aether-B, Aether-Z, Aether-U, pAIn | Primary family for all managed tools |
| `__VAULT_*__:` | Vault | Vault-specific token family |

Token types: `LOG`, `ERR`, `STATUS`, `PROMPT`, `FINDING`, `ACTION_ITEM`, `TARGET`, `PORT`

### Parallelism Groups

Tool execution is governed by parallelism groups to prevent resource conflicts:

| Group | Tools | Behavior |
|---|---|---|
| exclusive | SS3, Fracture, Siphon, Forge, Aether family | Only one exclusive tool at a time (OSift can run alongside SS3) |
| any | Trawler, Auger, AuthProbe, Nessus, Bastion, Quill, Isotope, Dredge, Vault, pAIn, all CLI tools | Independent; can run alongside anything |

### Auto-Queue

When a tool completes, its output is analyzed by the `ActionEngine`, which generates action items. Items tagged AUTO are immediately queued for the recommended follow-up tool. Items tagged CONFIRM require analyst approval. Auto-queue stops on tool failure to prevent cascading errors.

---

## Tool Registry

### Managed Tools (19)

| ID | Tool | Key | Domain | Sudo | Description |
|---|---|---|---|---|---|
| `ss3` | Scattershot3 | SS | Recon | Yes | Network reconnaissance and service enumeration |
| `osift` | OSift | OS | Recon | Yes | OSINT gathering and domain intelligence |
| `trawler` | Trawler | TR | Traffic | No | Network traffic capture and analysis |
| `fracture` | Fracture | FR | Web App | No | Web application vulnerability testing |
| `siphon` | Siphon | SI | API | No | API security testing and endpoint analysis |
| `auger` | Auger | AU | Database | No | Database security auditing |
| `aether` | Aether (Wi-Fi) | AE | Wireless | Yes | Wi-Fi security analysis |
| `aether_b` | Aether-B (Bluetooth) | AB | Wireless | Yes | Bluetooth security analysis |
| `aether_z` | Aether-Z (Zigbee) | AZ | Wireless | Yes | Zigbee protocol analysis |
| `aether_u` | Aether-U (UWB) | AW | Wireless | Yes | Ultra-Wideband security analysis |
| `authprobe` | AuthProbe | AP | Recon | No | Authentication mechanism detection |
| `bastion` | Bastion | BA | Firewall | No | Firewall configuration audit |
| `forge` | Forge | FG | Cloud | No | Cloud infrastructure security audit |
| `quill` | Quill | QU | Mobile | No | Mobile application security analysis |
| `isotope` | Isotope | IS | File | No | Detailed file analysis |
| `dredge` | Dredge | DG | Endpoint | No | Windows endpoint security audit |
| `vault` | Vault | VT | AD | No | Active Directory credential testing |
| `pain` | pAIn | PI | AI | No | AI pipeline prompt-injection red-team testing |
| `nessus` | Nessus | NE | Vuln Scan | No | Vulnerability scanning (external API) |

### External CLI Tools (9)

| ID | Tool | Description |
|---|---|---|
| `nuclei` | Nuclei | Template-based vulnerability scanner |
| `testssl` | testssl.sh | TLS/SSL cipher and protocol testing |
| `sslscan` | sslscan | SSL/TLS cipher enumeration |
| `droopescan` | droopescan | CMS vulnerability scanner |
| `dnstwist` | dnstwist | Domain permutation and typosquatting detection |
| `xurlfind3r` | xurlfind3r | URL and endpoint discovery |
| `emailharvester` | EmailHarvester | Email address harvesting |
| `asnmap` | asnmap | ASN and IP range mapping |
| `webanalyze` | webanalyze | Web technology fingerprinting |

---

## Requirements

- Python 3.10+
- Linux (Kali recommended) or macOS
- Chromium (installed by Playwright, required for PDF report generation)
- pr0t31n shared modules at `/opt/pr0t31n/shared/` (optional; FindingsDB, schema, and enrichment degrade gracefully without them)
- Tool scripts installed at `/opt/pr0t31n/<ToolName>/` (see tool registry above)

---

## Installation

```bash
cd /opt/pr0t31n/Crucible
python3 install.py
```

The installer:

1. Checks Python 3.10+ and platform compatibility
2. Creates required directories (`static/`, `templates/`, `routes/`, `models/`, `services/`, `adapters/`, `sockets/`, `logs/`)
3. Installs Python dependencies from `requirements.txt`
4. Vendors shared modules (`_auth.py`, `pr0t31n_system_info.py`, `pr0t31n_v11_enrichment.js`) from `/opt/pr0t31n/shared/`
5. Downloads `socket.io.min.js` from CDN
6. Installs Playwright and Chromium for PDF report generation
7. Initializes session-based authentication via `_auth.py`

### Python Dependencies

```
Flask>=3.0
Flask-SocketIO>=5.3
requests>=2.31
python-socketio[client]>=5.10
websocket-client>=1.6
openpyxl>=3.1
playwright>=1.40
```

---

## Quick Start

```bash
cd /opt/pr0t31n/Crucible
python3 app.py
```

Crucible starts on **https://0.0.0.0:5100** with self-signed TLS. On first launch, `_auth.py` generates credentials and prints them to the console.

1. Open `https://<host>:5100` in a browser and accept the self-signed certificate
2. Log in with the generated credentials
3. Click **New Engagement** to open the 4-step wizard
4. Configure scope, select tools, and launch

---

## REST API Overview

Crucible exposes a comprehensive REST API. All endpoints require an authenticated session. API endpoints return JSON; page endpoints return HTML.

### Core Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Homepage with engagement sidebar and quick-action tools |
| GET | `/project/<id>` | 9-tab project view |
| POST | `/api/project` | Create new project |
| PUT | `/api/project/<id>` | Update project |
| DELETE | `/api/project/<id>` | Delete project |
| POST | `/api/project/<id>/clear` | Clear engagement results |
| GET | `/api/project/<id>/export` | Export project as ZIP |

### Findings

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/findings/<id>` | Paginated findings (supports `?page=`, `?risk=`, `?tool=`, `?q=`) |
| POST | `/api/finding/mark_fp/<id>` | Mark finding as false positive |
| POST | `/api/finding/recover_fp/<id>` | Recover false positive |
| POST | `/api/finding/risk_override/<id>` | Override finding risk level |
| POST | `/api/finding/note/<id>` | Add/update finding note |
| POST | `/api/finding/attach-evidence/<id>` | Upload evidence file to finding |
| GET | `/api/finding/evidence/<id>/<fid>` | List evidence for a finding |

### Action Items

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/action_items/<id>` | List action items with status filters |
| POST | `/api/action_item/queue/<id>` | Queue an action item for execution |
| POST | `/api/action_item/dismiss/<id>` | Dismiss an action item |
| POST | `/api/action_item/resolve-manual` | Resolve a manual check as a finding |

### Intelligence

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/intelligence/<id>` | Aggregated intelligence data |
| GET | `/api/intelligence/v2/<id>/<panel>` | DB-backed paginated intelligence |
| GET | `/api/attack-surface/<id>` | Host inventory with port/service breakdown |

### Sessions

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/sessions/<id>` | List auth sessions |
| POST | `/api/sessions/<id>/register` | Register a new session |
| POST | `/api/sessions/<id>/kill/<sid>` | Kill a session |
| POST | `/api/sessions/<id>/kill-all` | Kill all sessions |

### Reports

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/report-types/<id>` | Available report types (scope-filtered) |
| POST | `/api/report/<id>` | Generate PDF report |
| GET | `/api/engagement-status/<id>` | Check if tools are still running |

### Logs and Errors

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/logs/<id>` | Structured logs (`?from=`, `?to=`, `?tool=`, `?level=`) |
| GET | `/api/errors/<id>` | Structured errors (`?from=`, `?to=`, `?tool=`, `?level=`) |

### Import

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/import/tools` | List supported import formats |
| POST | `/api/import/<id>/file` | Import a scanner output file |
| POST | `/api/import/burp/<id>/preview` | Preview Burp XML before import |
| POST | `/api/import/burp/<id>/commit` | Commit Burp XML import |

### Standalone Tools

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/standalone_tools` | List available quick-action tools |
| POST | `/api/standalone/<tool>` | Execute a standalone tool |
| GET | `/tools/merger` | Engagement Merger page |
| GET | `/tools/encoder` | Encode/Decode utility page |

### Integration

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/nexus-status` | Nexus hub health check endpoint |
| GET | `/api/frida-devices` | Discover Frida-compatible USB devices |

---

## SocketIO Events

### Client to Server

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

### Server to Client

| Event | Purpose |
|---|---|
| `tool_status` | Tool state change |
| `tool_started` | Tool process launched |
| `tool_done` | Tool process exited |
| `console_line` | Console output line |
| `tool_finding` | New finding discovered |
| `tool_action_item` | New action item generated |
| `tool_target` | New target discovered |
| `tool_port` | New port discovered |
| `tool_log` | Log entry |
| `tool_error` | Error entry |
| `tool_prompt` | Interactive prompt from tool |
| `prompt_resolved` | Prompt answered |
| `tool_queued` | Tool queued for execution |
| `tool_killed` | Tool process killed |
| `all_status` | All tool statuses snapshot |
| `console_buffer` | Full console buffer replay |
| `checkpoint_status` | Tool checkpoint data |
| `shell_output` | Shell stdout/stderr data |
| `shell_exit` | Shell session ended |
| `manual_check_resolved` | Manual check resolved as finding |
| `import_progress` | File import progress update |

---

## File Structure

```
Crucible/
├── app.py                      # Flask app factory + SocketIO init + service wiring
├── config.py                   # Constants, tool registry, palettes, buffer limits
├── _auth.py                    # Session-based auth (vendored from shared)
├── install.py                  # Multi-platform installer
├── requirements.txt            # Python dependencies
├── VERSION                     # Version file (2.219.3)
├── LICENSE                     # GPLv3 license
│
├── adapters/                   # 19 tool adapter classes + shared bases + registry
│   ├── __init__.py             # Lazy-loading adapter registry
│   ├── base.py                 # ToolAdapter ABC
│   ├── aether_base.py          # Shared Aether-family base class
│   ├── deps.py                 # External dependency tool adapter
│   ├── external.py             # CLI tool adapters (nuclei, testssl, etc.)
│   ├── scattershot3.py         # Scattershot3 adapter
│   ├── osift.py                # OSift adapter
│   ├── trawler.py              # Trawler adapter
│   ├── fracture.py             # Fracture adapter
│   ├── siphon.py               # Siphon adapter
│   ├── auger.py                # Auger adapter
│   ├── aether.py               # Aether Wi-Fi adapter
│   ├── aether_b.py             # Aether-B Bluetooth adapter
│   ├── aether_z.py             # Aether-Z Zigbee adapter
│   ├── aether_u.py             # Aether-U UWB adapter
│   ├── authprobe.py            # AuthProbe adapter
│   ├── nessus.py               # Nessus adapter
│   ├── bastion.py              # Bastion adapter
│   ├── forge.py                # Forge adapter
│   ├── quill.py                # Quill adapter
│   ├── isotope.py              # Isotope adapter
│   ├── dredge.py               # Dredge adapter
│   ├── vault.py                # Vault adapter
│   └── pain.py                 # pAIn adapter
│
├── models/                     # Data access layer
│   ├── project.py              # Project CRUD + directory management
│   ├── findings.py             # Findings storage + dedup + FP management
│   ├── action_items.py         # Action item lifecycle + reconciliation
│   ├── logs.py                 # Log/error storage + time filtering
│   ├── targets.py              # Target aggregation
│   ├── settings.py             # Per-tool settings schemas
│   └── evidence.py             # Evidence file storage
│
├── routes/                     # 23 Flask blueprints + helpers
│   ├── _helpers.py             # require_project, get_ext, resolve_project_file
│   ├── auth.py                 # Login/logout/session/password change
│   ├── home.py                 # Homepage + engagement sidebar
│   ├── project.py              # Project wizard, view, CRUD, Frida discovery
│   ├── console.py              # Console buffer API
│   ├── findings.py             # Findings CRUD, FP, evidence, snapshots
│   ├── action_items.py         # Action item API + manual check resolution
│   ├── settings.py             # Tool settings + AuthProbe + WiFi + scope modes
│   ├── logs.py                 # Logs/errors with time-range filter
│   ├── targets.py              # Target/port API
│   ├── intelligence.py         # Intel aggregation (JSON-based)
│   ├── intelligence_v2.py      # Intel aggregation (DB-backed, paginated)
│   ├── nessus.py               # Nessus API proxy
│   ├── traffic.py              # Trawler/pcap management
│   ├── export.py               # Project export/download + evidence file viewer
│   ├── worker.py               # Worker delegation API
│   ├── integration.py          # Nexus integration endpoint
│   ├── shell.py                # Web shell page
│   ├── standalone.py           # 13 standalone quick-action tools
│   ├── report.py               # Report generation + engagement status
│   ├── importer_routes.py      # File/folder import API
│   ├── sessions.py             # Session Manager API
│   ├── attack_surface.py       # Attack surface inventory API
│   └── burp_import.py          # Burp XML import wizard (preview/commit)
│
├── services/                   # Business logic layer
│   ├── process_manager.py      # Subprocess lifecycle, SocketIO events, recovery
│   ├── queue_manager.py        # Execution queue with disk persistence
│   ├── token_parser.py         # Protocol token IPC parser (3 token families)
│   ├── findings_engine.py      # Live finding processing + KEV enrichment
│   ├── action_engine.py        # Action item generation + manual checks
│   ├── scope_manager.py        # CIDR/URL scope enforcement
│   ├── intel.py                # Intelligence aggregation engine
│   ├── intel_ingestion.py      # Intel data ingestion from tool outputs
│   ├── nessus_client.py        # Nessus REST API client
│   ├── wireless.py             # WiFi interface management
│   ├── worker_delegate.py      # Remote worker WebSocket client
│   ├── session_manager.py      # Centralized auth keepalive service
│   ├── kev_enricher.py         # CISA KEV catalogue (24h refresh)
│   ├── report_generator.py     # 49-type PDF report engine (Playwright)
│   ├── import_engine.py        # Version-aware project import engine
│   ├── importer.py             # Multi-format scanner file import service
│   ├── attack_surface.py       # Host/port/service attack surface builder
│   ├── beacon_client.py        # Beacon engagement status push client
│   ├── scheduler.py            # Background task scheduler
│   ├── audit_logger.py         # Audit logging service
│   ├── engagement_log_handler.py # Per-engagement log routing
│   └── utils.py                # Shared utilities (room names, etc.)
│
├── sockets/                    # SocketIO event handlers
│   ├── _helpers.py             # Socket helper utilities
│   ├── connection.py           # Join/leave project rooms
│   ├── tools.py                # Tool start/kill/input/status
│   ├── prompts.py              # Interactive prompt resolution
│   ├── workers.py              # Worker delegation events
│   ├── shell.py                # Web shell PTY subprocess
│   └── importer_events.py      # Import progress events
│
├── templates/                  # Jinja2 templates
│   ├── base.html               # Layout, nav, palette picker, session timeout
│   ├── index.html              # Homepage with engagement sidebar + quick tools
│   ├── wizard.html             # 4-step project creation/edit wizard
│   ├── project.html            # 9-tab project view (monolithic JS)
│   ├── shell.html              # Interactive web terminal (xterm.js)
│   ├── login.html              # Auth login page
│   ├── change_password.html    # Password change page
│   ├── merger.html             # Engagement Merger tool
│   └── encoder.html            # Encode/Decode utility
│
├── static/
│   ├── css/style.css           # 10 palettes x dark/light, all component styles
│   ├── js/
│   │   ├── main.js             # Palette, theme, session, toast utilities
│   │   ├── index.js            # Homepage logic
│   │   ├── project.js          # Project view tab logic (largest JS file)
│   │   ├── wizard.js           # Wizard step logic and validation
│   │   ├── login.js            # Login form handling
│   │   ├── shell.js            # xterm.js terminal logic
│   │   ├── burp_import.js      # Burp XML import wizard UI
│   │   ├── palette-init.js     # Palette initialization (before page paint)
│   │   ├── session-timeout.js  # Session timeout warning overlay
│   │   ├── pr0t31n_v11_enrichment.js  # Schema v1.1 enrichment display
│   │   ├── socket.io.min.js    # SocketIO client library
│   │   ├── xterm.min.js        # xterm.js terminal emulator
│   │   └── xterm-addon-fit.min.js  # xterm.js fit addon
│   └── img/logo.svg            # Crucible logo
│
├── logs/                       # Application log files (created at runtime)
│   └── crucible.log            # Rotating log file
│
├── projects.json               # Project registry (created at runtime)
├── workers.json                # Worker registry (created at runtime)
└── execute_queue.json          # Persistent execution queue
```

---

## Integration Points

| System | Integration | Direction |
|--------|------------|-----------|
| **Nexus** | Fleet hub status reporting via `/api/nexus-status` | Nexus polls Crucible |
| **Beacon** | Engagement status push every 60s while tools active | Crucible pushes to Beacon |
| **Prometheus** | Report generation from universal findings format | Prometheus reads Crucible output |
| **Shared Catalogue** | Findings catalogue enrichment via `pr0t31n_catalogue.py` | Crucible reads catalogue |
| **FindingsDB** | SQLite backend via `pr0t31n_findings_db` shared module | Crucible reads/writes |
| **KEV Catalogue** | CISA Known Exploited Vulnerabilities auto-enrichment | Crucible fetches from CISA |
| **Frida** | USB device discovery for mobile testing | Crucible queries Frida API |
| **Nessus** | Scan management via Nessus REST API | Crucible calls Nessus API |
| **GoPhish** | Campaign analysis via Phish Analyzer | Crucible reads GoPhish exports |
| **Worker Instances** | Distributed tool execution via WebSocket delegation | Crucible delegates to workers |
| **Vault** | AD credential testing as managed tool | Crucible manages Vault subprocess |

---

## Configuration

### Environment

Crucible reads no environment variables for its own configuration. All settings live in `config.py` or in per-project JSON files. Managed tools receive `CRUCIBLE_MANAGED=1` and `PYTHONUNBUFFERED=1` via their environment.

### Key Constants (config.py)

| Constant | Default | Purpose |
|----------|---------|---------|
| `PORT` | 5100 | HTTPS listen port |
| `SESSION_TIMEOUT_MINUTES` | 30 | Session expiry |
| `SESSION_WARNING_MINUTES` | 5 | Warning before expiry |
| `MAX_CONSOLE_LINES` | 5000 | Per-tool console ring buffer |
| `MAX_LOG_ENTRIES` | 2000 | Maximum log entries per project |
| `MAX_ERR_ENTRIES` | 500 | Maximum error entries per project |
| `IMPORT_MAX_CONCURRENT` | 3 | Parallel import jobs |
| `NESSUS_POLL_INTERVAL` | 30 | Seconds between Nessus status polls |
| `DEFAULT_PALETTE` | forge | Initial CSS palette |
| `DEFAULT_MODE` | light | Initial theme mode |

---

## Security

- **HTTPS-only** — self-signed TLS certificate generated on first run
- **Session-based authentication** — `_auth.py` with secure cookie settings (`HttpOnly`, `Secure`, `SameSite=Lax`)
- **Instance-specific cookies** — session cookie name includes a SHA-256 hash of the secret key to prevent cross-instance session confusion
- **Security headers** — applied via `_auth.apply_security_headers()` on every response
- **50 MB upload limit** — `MAX_CONTENT_LENGTH` prevents oversized uploads
- **Path traversal protection** — evidence uploads and file imports validated before writing to disk

---

## Port

Crucible runs on port **5100** (HTTPS).

---

## Codebase

- **~45,000 lines** of Python across routes, services, adapters, models, and sockets
- **~12,800 lines** of HTML templates and CSS/JS frontend code
- **23 Flask blueprints** registered at startup
- **6 SocketIO event modules** for real-time communication
- **18 tool adapter classes** plus shared base classes
- **49 PDF report templates** across 10 scope categories

---

## License

Crucible is licensed under the **GNU General Public License v3.0** (GPLv3).

---

## Version

**2.219.3**
