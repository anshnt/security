<#
.SYNOPSIS
    Build Aegis Security Suite on Windows: venv, dependencies, tests, PyInstaller executables.
.DESCRIPTION
    Produces dist\aegis.exe (console) and dist\aegis-gui.exe (windowed) plus dist\SHA256SUMS.txt.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
    powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1 -SkipTests -Python py
#>
[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$SkipTests,
    [switch]$NoYara,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Run($exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "'$exe $($arguments -join ' ')' failed with exit code $LASTEXITCODE" }
}

if ($Clean) {
    Step "Cleaning previous build output"
    Remove-Item -Recurse -Force build, dist, .venv -ErrorAction SilentlyContinue
}

Step "Creating virtual environment (.venv)"
if (-not (Test-Path ".venv\Scripts\python.exe")) { Run $Python @("-m", "venv", ".venv") }
$py = Join-Path $root ".venv\Scripts\python.exe"

Step "Installing dependencies"
Run $py @("-m", "pip", "install", "--upgrade", "pip", "wheel")
if ($NoYara) {
    Run $py @("-m", "pip", "install", "-e", ".[dev]")
} else {
    & $py -m pip install -e ".[yara,dev]"
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "yara-python could not be installed; building without the native YARA engine."
        Run $py @("-m", "pip", "install", "-e", ".[dev]")
    }
}

if (-not $SkipTests) {
    Step "Running tests"
    Run $py @("-m", "pytest", "-q")
}

Step "Building aegis.exe (console)"
Run $py @("-m", "PyInstaller", "packaging\aegis.spec", "--noconfirm", "--clean", "--distpath", "dist", "--workpath", "build")

Step "Building aegis-gui.exe (windowed)"
Run $py @("-m", "PyInstaller", "packaging\aegis-gui.spec", "--noconfirm", "--clean", "--distpath", "dist", "--workpath", "build")

Step "Smoke test"
Run ".\dist\aegis.exe" @("info")

Step "Writing checksums"
$sums = Get-ChildItem dist\*.exe | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
$sums | Set-Content -Encoding ascii dist\SHA256SUMS.txt
$sums | ForEach-Object { Write-Host $_ }

Write-Host "`nDone. Output in $root\dist" -ForegroundColor Green
