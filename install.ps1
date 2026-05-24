# QAYAMAT Windows Installer
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "======================================================"
Write-Host "              QAYAMAT INSTALLER (Windows)"
Write-Host "======================================================"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Python not found. Install Python 3.11+ from python.org" -ForegroundColor Red
    exit 1
}

$pyVer = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "[*] Python $pyVer"

if (-not (Test-Path "venv")) {
    python -m venv venv
}
& .\venv\Scripts\Activate.ps1

python -m pip install --upgrade pip wheel setuptools -q
pip install -r requirements.txt -q

Write-Host "[*] Installing Playwright..."
pip install "playwright>=1.49.0" -q
python -m playwright install chromium
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Playwright browser install failed. Run: python -m playwright install chromium" -ForegroundColor Yellow
} else {
    Write-Host "[+] Playwright Chromium ready" -ForegroundColor Green
}

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env" -ErrorAction SilentlyContinue
    Write-Host "[+] Created .env from .env.example"
}

New-Item -ItemType Directory -Force -Path data, data\checkpoints, data\custom-nuclei, reports, screenshots | Out-Null

Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "Activate:  .\venv\Scripts\Activate.ps1"
Write-Host "Run:       python qayamat.py"
Write-Host "Resume:    python qayamat.py --resume <scan_id>"
Write-Host "Guide:     docs\USAGE_GUIDE.md"
Write-Host "Dashboard: cd frontend; npm install; npm run build"
Write-Host ""
Write-Host "Authorized security testing only." -ForegroundColor Red
