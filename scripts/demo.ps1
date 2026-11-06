# Cursiv Robotics: one-command demo for Windows 11 (PowerShell 5.1 or 7).
#
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1
#
# Needs (all free): Rust from https://rustup.rs and Python 3.10+ from python.org or the Microsoft Store.
# Runs a seeded virtual mission, verifies it, tampers with a copy, and imports the evidence into a
# research workspace. Everything it produces is SYNTHETIC. No network access, accounts or API keys.
# "Continue", not "Stop": Windows PowerShell 5.1 turns any stderr output of a native program
# (cargo's progress, a Python traceback) into a terminating error under "Stop". Every native
# command below is judged by its exit code instead.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$py = $null
foreach ($c in @("py", "python", "python3")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break }
}
if (-not $py) { Write-Host "Python 3 not found. Install it from https://www.python.org/downloads/ and tick 'Add to PATH'."; exit 1 }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Write-Host "Rust not found. Install it from https://rustup.rs, open a new PowerShell, and run this again."; exit 1 }

& $py -c "import cryptography" *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing the one Python dependency (cryptography)..."
    & $py -m pip install --user cryptography
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $py python\cursiv_demo @args
$code = $LASTEXITCODE
if ($code -eq 0) {
    Write-Host ""
    Write-Host "Open the report:  start runs\demo-full\mission\mission-report.html"
}
exit $code
