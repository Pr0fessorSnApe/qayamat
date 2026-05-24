#!/usr/bin/env python3
"""
QAYAMAT — Tool Installer
One-shot installer: installs all Go tools, Python packages, and system dependencies.
Run this once before starting qayamat.py.
"""

import os
import platform
import subprocess
import sys
import shutil
from pathlib import Path

GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "github.com/owasp-amass/amass/v4/...@master",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "gowitness": "github.com/sensepost/gowitness@latest",
    "trufflehog": "github.com/trufflesecurity/trufflehog/v3@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
    "anew": "github.com/tomnomnom/anew@latest",
    "qsreplace": "github.com/tomnomnom/qsreplace@latest",
    "unfurl": "github.com/tomnomnom/unfurl@latest",
    "gospider": "github.com/jaeles-project/gospider@latest",
    "hakrawler": "github.com/hakluke/hakrawler@latest",
    "crlfuzz": "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    "jsluice": "github.com/BishopFox/jsluice/cmd/jsluice@latest",
}

PYTHON_PACKAGES = [
    "arjun",
    "sqlmap",
    "scoutsuite",
    "mitmproxy",
]


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def ok(msg):
    print(f"{Colors.GREEN}  ✓{Colors.RESET}  {msg}")


def fail(msg):
    print(f"{Colors.RED}  ✗{Colors.RESET}  {msg}")


def info(msg):
    print(f"{Colors.CYAN}  ➜{Colors.RESET}  {msg}")


def banner(msg):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'═'*60}{Colors.RESET}")


class ToolInstaller:
    def __init__(self, install_dir: str = "/opt/qayamat/tools"):
        self.install_dir = Path(install_dir)
        self.go_path = Path(os.environ.get("GOPATH", Path.home() / "go"))
        self.go_bin = self.go_path / "bin"
        self.errors: list = []

    # ─── Prerequisites ───────────────────────────────────────────────────────

    def check_python(self) -> bool:
        ok_ver = sys.version_info >= (3, 11)
        ver = f"{sys.version_info.major}.{sys.version_info.minor}"
        if ok_ver:
            ok(f"Python {ver}")
        else:
            fail(f"Python {ver} — need 3.11+")
        return ok_ver

    def check_go(self) -> bool:
        result = subprocess.run(["go", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            ok(result.stdout.strip())
            return True
        fail("Go not found — install Go 1.21+ from https://go.dev/dl/")
        return False

    def check_docker(self) -> bool:
        result = subprocess.run(["docker", "info"], capture_output=True)
        if result.returncode == 0:
            ok("Docker running")
            return True
        fail("Docker not running — start Docker daemon")
        return False

    def check_node(self) -> bool:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            ok(f"Node.js {result.stdout.strip()}")
            return True
        fail("Node.js not found — install Node 18+ from https://nodejs.org/")
        return False

    # ─── Directory setup ─────────────────────────────────────────────────────

    def setup_directories(self) -> None:
        dirs = [
            self.install_dir,
            Path("data"),
            Path("reports"),
            Path("logs"),
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
        ok("Directories created")

    # ─── Go tools ────────────────────────────────────────────────────────────

    def install_go_tool(self, name: str, repo: str) -> bool:
        env = {**os.environ, "GO111MODULE": "on", "GOPATH": str(self.go_path)}
        result = subprocess.run(
            ["go", "install", repo],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
        )
        if result.returncode != 0:
            self.errors.append(f"{name}: {result.stderr[:200]}")
            fail(f"{name}")
            return False

        # Symlink to install_dir for easy lookup
        src = self.go_bin / name
        dst = self.install_dir / name
        if src.exists() and not dst.exists():
            try:
                dst.symlink_to(src)
            except OSError:
                shutil.copy2(src, dst)
        ok(name)
        return True

    def install_all_go_tools(self) -> None:
        banner("Installing Go Tools")
        # Ensure go_bin is in PATH for subprocesses
        os.environ["PATH"] = f"{self.go_bin}:{os.environ.get('PATH','')}"
        for name, repo in GO_TOOLS.items():
            try:
                self.install_go_tool(name, repo)
            except subprocess.TimeoutExpired:
                fail(f"{name} (timed out)")
                self.errors.append(f"{name}: timed out")
            except Exception as e:
                fail(f"{name}: {e}")
                self.errors.append(f"{name}: {e}")

    # ─── Python tools ────────────────────────────────────────────────────────

    def install_python_packages(self) -> None:
        banner("Installing Python Packages")
        for pkg in PYTHON_PACKAGES:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", pkg],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                ok(pkg)
            else:
                fail(f"{pkg}: {result.stderr[:100]}")
                self.errors.append(f"pip:{pkg}")

    # ─── Playwright browsers ─────────────────────────────────────────────────

    def install_playwright(self) -> None:
        banner("Installing Playwright")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "playwright>=1.49.0", "-q"],
            capture_output=False,
        )
        for cmd in (
            [sys.executable, "-m", "playwright", "install", "chromium"],
            [sys.executable, "-m", "playwright", "install", "--with-deps", "chromium"],
        ):
            result = subprocess.run(cmd, capture_output=False)
            if result.returncode == 0:
                ok("Playwright chromium installed")
                return
        fail("Playwright install failed — run: python -m playwright install chromium")

    # ─── Nuclei templates ────────────────────────────────────────────────────

    def update_nuclei_templates(self) -> None:
        banner("Updating Nuclei Templates")
        nuclei_bin = shutil.which("nuclei") or str(self.install_dir / "nuclei")
        if not Path(nuclei_bin).exists():
            info("Nuclei not found, skipping template update")
            return
        result = subprocess.run([nuclei_bin, "-update-templates"], capture_output=True)
        ok("Nuclei templates updated") if result.returncode == 0 else fail("Template update failed (non-fatal)")

    # ─── Frontend build ──────────────────────────────────────────────────────

    def build_frontend(self) -> None:
        banner("Building Frontend")
        frontend_dir = Path("frontend")
        if not frontend_dir.exists():
            fail("frontend/ directory not found")
            return
        if not shutil.which("node"):
            fail("Node.js not found — skipping frontend build")
            return
        for cmd in [["npm", "install", "--silent"], ["npm", "run", "build"]]:
            result = subprocess.run(cmd, cwd=frontend_dir, capture_output=True, text=True)
            if result.returncode != 0:
                fail(f"npm {cmd[1]}: {result.stderr[:200]}")
                return
        ok("Frontend built → frontend/dist/")

    # ─── .env setup ──────────────────────────────────────────────────────────

    def setup_env(self) -> None:
        banner("Environment Configuration")
        env_example = Path(".env.example")
        env_file = Path(".env")
        if not env_file.exists() and env_example.exists():
            shutil.copy(env_example, env_file)
            info(".env created from .env.example — edit it and add your API keys")
        elif env_file.exists():
            ok(".env already exists")
        else:
            fail(".env.example not found")

    # ─── Verification ────────────────────────────────────────────────────────

    def verify_tools(self) -> None:
        banner("Verification")
        for name in GO_TOOLS:
            found = shutil.which(name) or (self.install_dir / name).exists()
            ok(name) if found else fail(f"{name} (missing)")

    # ─── Main entry ──────────────────────────────────────────────────────────

    def ensure_tools(self) -> bool:
        """Called programmatically by qayamat.py on startup."""
        self.setup_directories()
        return True  # Full install done via install.py

    def run_full_install(self) -> bool:
        banner("QAYAMAT — Full Installation")
        print(f"Platform: {platform.system()} {platform.machine()}\n")

        # Prerequisites
        banner("Checking Prerequisites")
        py_ok = self.check_python()
        go_ok = self.check_go()
        self.check_docker()
        self.check_node()

        if not py_ok:
            print(f"\n{Colors.RED}Python 3.11+ is required. Aborting.{Colors.RESET}")
            return False

        # Setup
        self.setup_directories()
        self.setup_env()

        # Tools
        if go_ok:
            self.install_all_go_tools()
        else:
            info("Skipping Go tools (Go not installed)")

        self.install_python_packages()
        self.install_playwright()

        if go_ok:
            self.update_nuclei_templates()

        self.build_frontend()
        self.verify_tools()

        # Summary
        banner("Installation Summary")
        if self.errors:
            print(f"{Colors.YELLOW}  {len(self.errors)} tool(s) failed to install:{Colors.RESET}")
            for e in self.errors:
                print(f"    • {e}")
            print()

        print(f"{Colors.GREEN}{Colors.BOLD}  Installation complete!{Colors.RESET}")
        print(f"\n  Next steps:")
        print(f"    1. Edit {Colors.CYAN}.env{Colors.RESET} with your API keys")
        print(f"    2. Start infrastructure: {Colors.CYAN}docker-compose -f docker/docker-compose.yml up -d{Colors.RESET}")
        print(f"    3. Launch QAYAMAT: {Colors.CYAN}python qayamat.py{Colors.RESET}")
        print()
        return True


if __name__ == "__main__":
    installer = ToolInstaller()
    success = installer.run_full_install()
    sys.exit(0 if success else 1)
