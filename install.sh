#!/usr/bin/env bash
# QAYAMAT Installer

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─────────────────────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'
BOLD='\033[1m'

ok()   { echo -e "${GREEN}[+]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
fail() { echo -e "${RED}[-]${RESET} $1"; }
info() { echo -e "${CYAN}[*]${RESET} $1"; }

trap 'fail "Installer interrupted"; exit 1' INT TERM

echo -e "${BOLD}${CYAN}"
echo "======================================================"
echo "                 QAYAMAT INSTALLER"
echo "======================================================"
echo -e "${RESET}"

# ─────────────────────────────────────────────────────────────
# Root warning
# ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Running without root privileges."
    warn "Some packages may fail to install."
fi

# ─────────────────────────────────────────────────────────────
# Required commands
# ─────────────────────────────────────────────────────────────
REQUIRED_CMDS=(python3 git curl)

for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        fail "$cmd is required but not installed."
        exit 1
    fi
done

ok "Required system commands found"

# ─────────────────────────────────────────────────────────────
# Python version
# ─────────────────────────────────────────────────────────────
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')

info "Python version: $PY_VERSION"

# ─────────────────────────────────────────────────────────────
# Virtual environment
# ─────────────────────────────────────────────────────────────
if [[ ! -d venv ]]; then
    info "Creating Python virtual environment..."
    python3 -m venv venv
else
    ok "Virtual environment already exists, skipping"
fi

source venv/bin/activate

ok "Virtual environment activated"

# ─────────────────────────────────────────────────────────────
# Upgrade pip (only if outdated)
# ─────────────────────────────────────────────────────────────
info "Checking pip, wheel, setuptools..."

python -m pip install --upgrade pip wheel setuptools -q --upgrade-strategy only-if-needed

ok "pip, wheel, setuptools up to date"

# ─────────────────────────────────────────────────────────────
# Install requirements (skip already-satisfied packages)
# ─────────────────────────────────────────────────────────────
if [[ -f requirements.txt ]]; then
    info "Checking Python dependencies..."
    pip install -r requirements.txt -q --upgrade-strategy only-if-needed
    ok "Python dependencies satisfied"
else
    warn "requirements.txt not found"
fi

# ─────────────────────────────────────────────────────────────
# Go tools (skip if binary already exists)
# ─────────────────────────────────────────────────────────────
if command -v go &>/dev/null; then

    export GOPATH="${HOME}/go"
    export PATH="$PATH:$GOPATH/bin"

    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/hahwul/dalfox/v2@latest"
    )

    info "Checking Go security tools..."

    for tool in "${GO_TOOLS[@]}"; do
        # Extract the binary name from the module path (strip version and path prefix)
        bin_name=$(basename "${tool%%@*}")

        if command -v "$bin_name" &>/dev/null; then
            ok "$bin_name already installed, skipping"
            continue
        fi

        info "Installing $bin_name..."
        go install "$tool" \
            && ok "$bin_name installed" \
            || warn "$bin_name failed to install"
    done

else
    warn "Go not installed — skipping Go tools"
fi

# ─────────────────────────────────────────────────────────────
# Playwright — always install package + Chromium browser
# ─────────────────────────────────────────────────────────────
info "Installing Playwright (Python package)..."
pip install "playwright>=1.49.0" -q --upgrade-strategy only-if-needed || warn "pip install playwright failed"

if python -c "import playwright" 2>/dev/null; then
    ok "Playwright Python package ready"
    info "Downloading Chromium for Playwright (required for browser testing)..."
    python -m playwright install chromium || warn "playwright install chromium failed — run manually: python -m playwright install chromium"
    if command -v apt-get &>/dev/null; then
        info "Installing Playwright system dependencies (Linux)..."
        python -m playwright install-deps chromium 2>/dev/null || warn "install-deps skipped (may need sudo)"
    fi
    if python -m playwright install --dry-run chromium 2>&1 | grep -qi "already"; then
        ok "Playwright Chromium browser ready"
    else
        python -m playwright install chromium 2>/dev/null && ok "Playwright Chromium installed" || warn "Verify with: python -m playwright install chromium"
    fi
else
    warn "Playwright not available on this Python version — browser testing disabled"
    warn "Use Python 3.11 or 3.12 for full Playwright support"
fi

# ─────────────────────────────────────────────────────────────
# Runtime directories
# ─────────────────────────────────────────────────────────────
mkdir -p data/checkpoints data/scope_snapshots data/custom-nuclei reports screenshots logs
ok "Runtime directories ready (data/, reports/, checkpoints/)"

# ─────────────────────────────────────────────────────────────
# Environment file (only create if missing)
# ─────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
    if [[ -f .env.example ]]; then
        cp .env.example .env
        ok ".env created from .env.example — add your API keys"
    else
cat > .env <<EOF
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GEMINI_API_KEY=
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
OTX_API_KEY=
VIRUSTOTAL_API_KEY=
SECURITYTRAILS_API_KEY=
URLSCAN_API_KEY=
HACKERONE_API_IDENTIFIER=
HACKERONE_API_TOKEN=
BUGCROWD_API_TOKEN=
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=

HOST=0.0.0.0
PORT=8000
DEBUG=false
EOF
        ok ".env file created"
    fi
else
    ok ".env already exists, skipping"
fi

# ─────────────────────────────────────────────────────────────
# Docker sandbox image (skip if image already built)
# ─────────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then

    if docker info &>/dev/null; then

        if docker image inspect qayamat-sandbox &>/dev/null; then
            ok "Sandbox image already exists, skipping"
        else
            info "Building sandbox container..."

docker build -t qayamat-sandbox - <<'EOF'
FROM python:3.11-slim

RUN useradd -m sandbox

USER sandbox
WORKDIR /home/sandbox

CMD ["python3"]
EOF

            ok "Sandbox image ready"
        fi

    else
        warn "Docker installed but daemon not running"
    fi
else
    warn "Docker not installed"
fi

# ─────────────────────────────────────────────────────────────
# Final message
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}QAYAMAT installation completed.${RESET}"
echo ""

echo "Activate environment:"
echo "source venv/bin/activate"
echo ""

echo "Run QAYAMAT:"
echo "  python3 qayamat.py"
echo ""
echo "Full guide (API keys, pause/resume, all features):"
echo "  docs/USAGE_GUIDE.md"
echo ""
echo "Optional dashboard:"
echo "  cd frontend && npm install && npm run build"
echo ""

echo -e "${RED}Authorized security testing only.${RESET}"
