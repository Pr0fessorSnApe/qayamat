<div align="center">

<h1>QAYAMAT</h1>

<p>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white">
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black">
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge">
  <img src="https://img.shields.io/badge/Use-Authorized%20Testing%20Only-EF4444?style=for-the-badge">
</p>

<p><strong>Autonomous AI-Powered Offensive Security Framework</strong></p>

<p><em>Automated reconnaissance · Vulnerability discovery · OSINT fusion · AI-assisted analysis · Professional reporting</em></p>

</div>

---

## ⚠️ Legal Disclaimer

QAYAMAT is intended **strictly** for:

- Authorized penetration testing engagements
- Security research in controlled environments
- Educational and training purposes
- Defensive security validation

> **You must have explicit written permission before scanning, probing, or testing any target.**
> Unauthorized use against systems you do not own or have authorization to assess may violate local and international laws.
> The author assumes no responsibility for misuse or damages caused by this software.

---

## Complete Usage Guide

**Start here for step-by-step instructions, API keys, pause/resume, and every feature:**

**[docs/USAGE_GUIDE.md](docs/USAGE_GUIDE.md)**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scan Profiles](#scan-profiles)
- [Dashboard](#dashboard)
- [Security & Safety Controls](#security--safety-controls)
- [Development](#development)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

---

## Overview

QAYAMAT is a modular, AI-assisted offensive security framework that orchestrates industry-standard tools into a unified, intelligent workflow. It automates the full engagement lifecycle — from passive reconnaissance and OSINT aggregation to active vulnerability discovery and executive reporting — while enforcing strict scope validation, rate limiting, and ethical testing practices.

Key differentiators:

- **AI-driven orchestration** — Claude/OpenAI models correlate findings, prioritize risks, and generate context-aware recommendations
- **Unified tool chain** — Wraps 20+ best-in-class open-source tools into a single, coherent pipeline
- **Safety-first design** — Scope enforcement, sandbox isolation, and read-only PoC validation baked in from the ground up
- **Production-ready reporting** — HTML, JSON, and dashboard outputs suitable for client deliverables

---

## Features

### Reconnaissance

| Capability | Description |
|---|---|
| Subdomain Enumeration | Multi-source subdomain discovery and validation |
| DNS Resolution | Bulk DNS resolution and record analysis |
| HTTP Probing | Live host detection and response fingerprinting |
| Port Scanning | Fast, configurable TCP/UDP port scanning |
| Technology Fingerprinting | Stack identification (frameworks, servers, CDNs) |
| Screenshot Collection | Automated visual capture of live web assets |
| GitHub Asset Recon | Passive repo/org enumeration for in-scope GitHub targets |
| Historical URL Mining | Archive and crawl-based endpoint harvesting |
| Parameter Extraction | URL and form parameter discovery |
| Endpoint Discovery | Recursive crawling and JS-based path extraction |

### Vulnerability Discovery

| Capability | Description |
|---|---|
| Template-Based Scanning | Nuclei integration with community and custom templates |
| XSS Testing | Reflected, stored, and DOM-based XSS detection |
| SQL Injection | Automated SQLi analysis and parameter fuzzing |
| Open Redirect Detection | External redirect chain identification |
| Misconfiguration Discovery | Cloud, server, and application configuration audits |
| API Fuzzing | REST endpoint fuzzing and response analysis |
| GraphQL Testing | Introspection, injection, and logic flaw testing |
| Secret Exposure Analysis | Hardcoded keys, tokens, and credential detection |

### Intelligence Gathering (OSINT)

QAYAMAT integrates the following threat intelligence and OSINT platforms:

- **Shodan** — Internet-wide device and port intelligence
- **Censys** — Certificate and host scanning data
- **AlienVault OTX** — Community threat indicators
- **SecurityTrails** — DNS and domain history
- **URLScan** — Passive web page scanning records
- **VirusTotal** — Multi-engine file and URL reputation

### AI-Assisted Analysis

- Automated finding correlation and deduplication
- Context-aware risk scoring and prioritization
- Payload generation assistance
- Intelligent workflow orchestration
- Natural language finding enrichment and summarization

### Reporting

- Interactive HTML reports with **full steps to reproduce**, impact, and remediation per finding
- HackerOne / Bugcrowd submission markdown in `reports/submissions/`
- Structured JSON exports for downstream integrations
- Live web dashboard with real-time scan statistics, **cancel scan** button, and triage workflow
- Scan-complete notifications for Discord, Slack, Telegram, and generic webhooks
- Attack chain correlation and risk scoring

### Bug Bounty & Professional Workflow

- **Intelligent exclusions parser** — paste full out-of-scope policy text; auto-extracts domains, wildcards, paths, and prohibited vuln types
- Scope import (HackerOne JSON, Bugcrowd JSON, YAML, `scope.txt`)
- Per-program profiles in `config/programs/`
- Finding deduplication and **strict false-positive validation** (min score 0.65, AI confirmation)
- **Bug bounty modules** including: CT monitor, JS miner, IDOR/BOLA, OAuth, CORS, SSRF, **SSTI auto-verify**, **HTTP smuggling**, **cache poisoning**, **race/business-logic tester**, attack chains
- **One-click HackerOne/Bugcrowd API submit** (`POST /api/findings/{id}/submit`) — requires `.env` tokens
- **CVSS + bounty $ estimator** per program (`bounty_payouts` in program YAML)
- **AI Nuclei template generator** from JS findings → `data/custom-nuclei/`
- OOB callback integration for blind vulnerabilities
- Burp/HAR/ZAP traffic import
- Multi-role authenticated testing (user vs admin)
- Verified subdomain takeover checks
- Continuous monitoring with diff reports
- Nuclei template manager API

**Parse exclusions (API):** `POST /api/bugbounty/parse-exclusions`

**Submit report:** `POST /api/findings/{id}/submit` — body: `{"platform":"hackerone","program_ref":"team-handle","dry_run":true}`

**Bounty estimate:** `GET /api/findings/{id}/bounty-estimate?program=my-program`

### Browser Testing (Playwright)

- Headless Chromium scans for DOM XSS, missing security headers, and screenshots
- Requires: `pip install playwright && python -m playwright install chromium`
- **Windows:** `.\install.ps1` — **Linux/macOS:** `bash install.sh`
- Use **Python 3.11 or 3.12** for best Playwright compatibility (3.14+ may need latest playwright)

### Pause & Resume (emergency / offline)

- **Dashboard:** **Pause** while running — saves checkpoint at end of current step; **Resume** when `status` is `paused`
- **CLI:** `python qayamat.py --resume <scan_id>`
- **API:** `POST /api/scans/{id}/pause` · `POST /api/scans/{id}/resume` · `GET /api/scans/paused`
- Checkpoints: `data/checkpoints/scan_<id>.json` (recon + completed phases preserved)

### Cancel a Running Scan

- **Dashboard:** **Cancel** aborts permanently (no resume)
- **API:** `POST /api/scans/{scan_id}/cancel`
- CLI scans respect cancel/pause signals between phases

---

## Red Team Features (Roadmap — Integrate External Tools)

High-value additions that pair with specialist tools:

| # | Feature | Example tools |
|---|---------|----------------|
| 1 | **C2 framework integration** | Sliver, Havoc, Mythic — tasking from QAYAMAT findings |
| 2 | **Active Directory attack path** | BloodHound, CrackMapExec, Impacket — full AD compromise chains |
| 3 | **Cloud privilege escalation** | Pacu, ScoutSuite, Prowler — AWS/Azure/GCP misconfigs |
| 4 | **Kerberos attacks** | Rubeus, Kerbrute — AS-REP roasting, delegation abuse |
| 5 | **Phishing / payload delivery** | GoPhish, Evilginx — authorized social engineering |
| 6 | **Wireless / network pivoting** | Responder, mitm6, Ligolo — internal lateral movement |
| 7 | **Binary / AV evasion lab** | Donut, Veil — payload generation in sandbox only |
| 8 | **Mobile app testing** | MobSF, Frida — APK/IPA alongside web |
| 9 | **Purple team validation** | Atomic Red Team — map findings to MITRE ATT&CK tests |
| 10 | **Exfiltration simulation** | DNS/HTTPS canaries — prove impact without real exfil |

---

## Architecture

```
qayamat/
├── qayamat.py                  # Main entrypoint
│
├── core/
│   ├── ai_engine.py            # LLM orchestration and prompt management
│   ├── policy_engine.py        # Scope validation and rate limiting
│   ├── payload_engine.py       # Safe PoC and payload generation
│   ├── intelligence_fusion.py  # OSINT aggregation and correlation
│   ├── archive_miner.py        # Historical URL and data mining
│   ├── sandbox.py              # Docker-based payload isolation
│   ├── vault.py                # Encrypted secret storage
│   └── logger.py               # Structured audit logging
│
├── workflows/
│   ├── recon.py                # Reconnaissance pipeline
│   ├── exploitation.py         # Exploitation workflow
│   ├── vuln_scan.py            # Vulnerability scanning pipeline
│   └── reporting.py            # Report generation
│
├── tools/
│   ├── wrappers/               # Tool abstraction layer
│   └── installer.py            # Automated dependency installer
│
├── api/                        # REST API layer
├── frontend/                   # Dashboard UI
├── docker/                     # Sandbox container definitions
├── config/                     # Configuration schemas
├── reports/                    # Generated report output
├── data/                       # Wordlists, templates, signatures
└── tests/                      # Unit and integration tests
```

### Tool Chain

**Reconnaissance**

`subfinder` · `amass` · `dnsx` · `httpx` · `katana` · `naabu` · `gau` · `waybackurls` · `hakrawler` · `gospider` · `gowitness`

**Vulnerability Analysis**

`nuclei` · `dalfox` · `ffuf` · `sqlmap` · `arjun` · `crlfuzz`

---

## Requirements

| Component | Minimum Version |
|---|---|
| Python | 3.11+ |
| Go | 1.21+ |
| Docker | Latest stable |
| Node.js | 18+ |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Pr0fessorSnApe/qayamat.git
cd qayamat
```

### 2. Run the Installer

**Linux / macOS:**

```bash
bash install.sh
# or: bash installer.sh
source venv/bin/activate
python -m playwright install chromium   # if browser step was skipped
cd frontend && npm install && npm run build
```

**Windows (PowerShell):**

```powershell
.\install.ps1
.\venv\Scripts\Activate.ps1
python -m playwright install chromium
cd frontend; npm install; npm run build
```

The installer automatically handles:

- Python virtual environment setup
- Python dependency installation
- Go-based security tool compilation and installation
- Playwright browser installation
- `.env` file generation
- Docker sandbox image build
- Runtime environment configuration

### 3. Activate the Environment

```bash
source venv/bin/activate
```

---

## Configuration

Edit the generated `.env` file and populate your API keys:

```env
# AI Engine
OPENAI_API_KEY=your_key_here
GITHUB_TOKEN=your_github_token_here

# Threat Intelligence
SHODAN_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here

# Notifications
DISCORD_WEBHOOK_URL=
SLACK_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

> API keys are optional. Without them, QAYAMAT operates in passive/local mode with reduced intelligence collection capability.

### Docker Sandbox

The installer builds the sandbox image automatically. To rebuild manually:

```bash
docker build -t qayamat-sandbox - <<'EOF'
FROM python:3.11-slim
RUN useradd -m sandbox
USER sandbox
WORKDIR /home/sandbox
CMD ["python3"]
EOF
```

---

## Usage

### Interactive Mode

```bash
python3 qayamat.py
```

### Non-Interactive Mode

```bash
python3 qayamat.py --targets example.com --profile safe
```

### Multiple Targets

```bash
python3 qayamat.py --targets example.com,api.example.com,staging.example.com
```

### Dashboard Only

```bash
python3 qayamat.py --dashboard-only
```

---

## Scan Profiles

| Profile | Description | Use Case |
|---|---|---|
| `passive` | Passive OSINT only, no active probing | Initial scope mapping, sensitive environments |
| `safe` | Low-risk, non-invasive active testing | Bug bounty programs, production systems |
| `balanced` | Standard assessment intensity | General penetration tests |
| `aggressive` | High-intensity scanning and fuzzing | Internal assessments with full authorization |
| `red_team` | Advanced multi-stage techniques | Full red team engagements |

### Example Workflows

**Passive Reconnaissance**
```bash
python3 qayamat.py --targets example.com --profile passive
```

**Bug Bounty Assessment**
```bash
python3 qayamat.py --targets example.com --profile safe
```

**Authorized Internal Assessment**
```bash
python3 qayamat.py --targets internal.corp --profile aggressive
```

---

## Dashboard

The web dashboard provides real-time visibility into active and completed engagements.

**Default URL:** `http://localhost:8000`

| Feature | Description |
|---|---|
| Live Scan Monitoring | Real-time tool output and pipeline status |
| Asset Tracking | Discovered hosts, endpoints, and services |
| Finding Visualization | Severity-bucketed vulnerability overview |
| Attack Graph | Visual representation of attack paths |
| Report Downloads | One-click HTML and JSON export |
| Statistics Panel | Scan metrics and coverage analytics |

---

## Security & Safety Controls

QAYAMAT enforces multiple layers of protection to prevent accidental or unauthorized use:

| Control | Description |
|---|---|
| Scope Enforcement | All targets validated against defined scope before any activity |
| Rate Limiting | Per-tool request throttling to avoid service disruption |
| Safe PoC Generation | Proof-of-concept payloads are read-only and non-destructive |
| Docker Sandbox Isolation | Payload validation runs in an isolated, unprivileged container |
| Encrypted Secret Storage | API keys and credentials stored with at-rest encryption |
| Audit Logging | Full structured log of all actions, findings, and tool invocations |

---

## Development

### Install Development Dependencies

```bash
pip install pytest pytest-asyncio
```

### Run Tests

```bash
pytest
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev
```

---

## Contributing

Contributions are welcome. Please follow the standard GitHub flow:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m "feat: describe your change"`
4. Push the branch: `git push origin feature/your-feature-name`
5. Open a Pull Request with a clear description of the change and its motivation

Please ensure all tests pass and new functionality includes appropriate test coverage.

---

## Author

**Pr0fessor_SnApe**

Offensive Security Researcher · Penetration Tester · Bug Bounty Hunter

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**Use responsibly. Use ethically. Use legally.**

</div>
