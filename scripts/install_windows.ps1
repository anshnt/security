<#
.SYNOPSIS
    Install Aegis Security Suite: copy executables, register background tasks, add shortcuts.
.DESCRIPTION
    Must be run from an elevated PowerShell. Creates three Scheduled Tasks:
      Aegis Realtime Protection  - at logon, highest privileges: aegis.exe monitor
      Aegis Daily Quick Scan     - daily 12:30: aegis.exe scan quick --report html
      Aegis Signature Update     - every 6 hours: aegis.exe update
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install_windows.ps1 -AddToPath
#>
[CmdletBinding()]
param(
    [string]$SourceDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "dist"),
    [string]$InstallDir = (Join-Path $env:ProgramFiles "Aegis"),
    [switch]$AddToPath,
    [switch]$NoTasks,
    [switch]$StartNow
)

$ErrorActionPreference = "Stop"

# Release zip layout: the exes sit next to this script. Source tree layout: ..\dist.
if (-not $PSBoundParameters.ContainsKey("SourceDir") -and (Test-Path (Join-Path $PSScriptRoot "aegis.exe"))) {
    $SourceDir = $PSScriptRoot
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script from an elevated (Administrator) PowerShell."
    exit 1
}

$cli = Join-Path $SourceDir "aegis.exe"
$gui = Join-Path $SourceDir "aegis-gui.exe"
if (-not (Test-Path $cli)) { Write-Error "aegis.exe not found in $SourceDir - run scripts\build_windows.ps1 first."; exit 1 }

Write-Host "Installing to $InstallDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
# Stop a running copy so the files can be replaced
Get-Process -Name "aegis", "aegis-gui" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$InstallDir*" } | Stop-Process -Force
Copy-Item $cli (Join-Path $InstallDir "aegis.exe") -Force
if (Test-Path $gui) { Copy-Item $gui (Join-Path $InstallDir "aegis-gui.exe") -Force }
Copy-Item (Join-Path $PSScriptRoot "uninstall_windows.ps1") $InstallDir -Force
$exe = Join-Path $InstallDir "aegis.exe"

if ($AddToPath) {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (($machine -split ";") -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable("Path", ($machine.TrimEnd(";") + ";" + $InstallDir), "Machine")
        Write-Host "Added $InstallDir to the system PATH (open a new terminal to use 'aegis')."
    }
}

if (-not $NoTasks) {
    $user = "$env:USERDOMAIN\$env:USERNAME"
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew

    $tasks = @(
        @{ Name = "Aegis Realtime Protection"; Args = "monitor";
           Trigger = (New-ScheduledTaskTrigger -AtLogOn -User $user);
           Desc = "Aegis real-time protection (file, process, ransomware and persistence guards)." },
        @{ Name = "Aegis Daily Quick Scan"; Args = "scan quick --report html";
           Trigger = (New-ScheduledTaskTrigger -Daily -At "12:30");
           Desc = "Daily Aegis quick scan with an HTML report." },
        @{ Name = "Aegis Signature Update"; Args = "update";
           Trigger = (New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6));
           Desc = "Download fresh Aegis threat-intelligence signatures every 6 hours." }
    )
    foreach ($t in $tasks) {
        if ($t.Args -eq "monitor") {
            # aegis.exe is a console program: run it through a hidden PowerShell so no window sits open after logon
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -WorkingDirectory $InstallDir `
                -Argument ("-NoProfile -NonInteractive -WindowStyle Hidden -Command `"& '" + $exe + "' monitor`"")
        } else {
            $action = New-ScheduledTaskAction -Execute $exe -Argument $t.Args -WorkingDirectory $InstallDir
        }
        Register-ScheduledTask -TaskName $t.Name -Action $action -Trigger $t.Trigger -Principal $principal `
            -Settings $settings -Description $t.Desc -Force | Out-Null
        Write-Host "Registered scheduled task '$($t.Name)'"
    }
    if ($StartNow) { Start-ScheduledTask -TaskName "Aegis Realtime Protection" }
}

$guiExe = Join-Path $InstallDir "aegis-gui.exe"
if (Test-Path $guiExe) {
    $programs = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut((Join-Path $programs "Aegis Security Suite.lnk"))
    $lnk.TargetPath = $guiExe
    $lnk.WorkingDirectory = $InstallDir
    $lnk.Description = "Aegis Security Suite"
    $lnk.Save()
    Write-Host "Created Start Menu shortcut 'Aegis Security Suite'"
}

Write-Host "`nAegis installed. Run 'aegis info' to verify, or open Aegis Security Suite from the Start Menu." -ForegroundColor Green
