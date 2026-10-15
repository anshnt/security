<#
.SYNOPSIS
    Remove Aegis Security Suite (tasks, shortcut, PATH entry, program files).
.DESCRIPTION
    Quarantine, logs and settings are kept unless -RemoveData is given.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "Aegis"),
    [switch]$RemoveData
)

$ErrorActionPreference = "Continue"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script from an elevated (Administrator) PowerShell."
    exit 1
}

foreach ($name in "Aegis Realtime Protection", "Aegis Daily Quick Scan", "Aegis Signature Update") {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        Write-Host "Removed scheduled task '$name'"
    }
}

Get-Process -Name "aegis", "aegis-gui" -ErrorAction SilentlyContinue | Stop-Process -Force

$lnk = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Aegis Security Suite.lnk"
if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host "Removed Start Menu shortcut" }

$machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machine -and (($machine -split ";") -contains $InstallDir)) {
    $new = (($machine -split ";") | Where-Object { $_ -and $_ -ne $InstallDir }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $new, "Machine")
    Write-Host "Removed $InstallDir from the system PATH"
}

# The running script lives in $InstallDir, so delete the folder from a detached shell after we exit.
if (Test-Path $InstallDir) {
    Start-Process -WindowStyle Hidden -FilePath "cmd.exe" -ArgumentList "/c ping 127.0.0.1 -n 3 >nul & rmdir /s /q `"$InstallDir`""
    Write-Host "Program files in $InstallDir will be deleted in a moment"
}

if ($RemoveData) {
    foreach ($d in (Join-Path $env:ProgramData "Aegis"), (Join-Path $env:LOCALAPPDATA "Aegis")) {
        if (Test-Path $d) { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "Deleted data folder $d" }
    }
} else {
    Write-Host "Kept quarantine, logs and settings (ProgramData\Aegis, %LOCALAPPDATA%\Aegis). Use -RemoveData to delete them."
}
Write-Host "Aegis uninstalled." -ForegroundColor Green
