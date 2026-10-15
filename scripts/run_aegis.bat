@echo off
rem Run Aegis from a source checkout:  scripts\run_aegis.bat [--admin] <aegis arguments>
rem   --admin   relaunch this window elevated (UAC prompt) so process / service / registry checks are complete
setlocal EnableDelayedExpansion
set "ROOT=%~dp0.."
set "WANT_ADMIN=0"
set "ARGS="

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="--admin" (
    set "WANT_ADMIN=1"
) else (
    set ARGS=!ARGS! %1
)
shift
goto parse
:parsed

where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
if exist "%ROOT%\.venv\Scripts\python.exe" set "PY=%ROOT%\.venv\Scripts\python.exe"

if "%WANT_ADMIN%"=="1" (
    net session >nul 2>nul
    if errorlevel 1 (
        echo Requesting administrator rights...
        powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath cmd.exe -ArgumentList '/k cd /d ""%ROOT%"" && %PY% -m aegis%ARGS%'"
        exit /b 0
    )
)

pushd "%ROOT%"
%PY% -m aegis%ARGS%
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%
