@echo off
setlocal enabledelayedexpansion

:: ============================
:: OnlineInstallAll.cmd (FINAL FIXED)
:: ============================

echo.
echo =========================================================================================================
echo *** Installing essential Windows programs using latest scripts from GitHub ***
echo =========================================================================================================
echo.

:: --- Log ---
set "LOG=%TEMP%\OnlineInstallAll.log"
echo [%date% %time%] ==== Script started ==== > "%LOG%"

:: --- Admin elevation ---
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if not "%errorlevel%"=="0" (
    echo Requesting admin rights...
    echo Elevating... >> "%LOG%"
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

color 03
echo Running elevated.
echo Running elevated. >> "%LOG%"

:: --- Execution Policy ---
echo Setting PowerShell Execution Policy...
reg add "HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d Unrestricted /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d Unrestricted /f >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Bypass -Force" >> "%LOG%" 2>&1

:: --- URLs ---
set "Run_URL=https://raw.githubusercontent.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/refs/heads/main/Run.ps1"
set "Tasks_URL=https://raw.githubusercontent.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/refs/heads/main/Tasks.psm1"

:: --- Files ---
set "Run=%TEMP%\Run.ps1"
set "Tasks=%TEMP%\Tasks.psm1"

echo Deleting old files...
del /f /q "%Run%" >nul 2>&1
del /f /q "%Tasks%" >nul 2>&1

:: --- Ensure BITS ---
echo Ensuring BITS service is running...
sc query bits | find "RUNNING" >nul 2>&1
if not "%errorlevel%"=="0" (
    sc start bits >nul 2>&1
    timeout /t 5 /nobreak >nul
)
echo BITS ready. >> "%LOG%"

:: --- Retry loop ---
set /a RETRIES=0

:RetryLoop
set /a RETRIES+=1
echo Downloading files (attempt !RETRIES!/5)...
echo Attempt !RETRIES! >> "%LOG%"

:: ===== BITS =====
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Start-BitsTransfer -Source '%Run_URL%' -Destination '%Run%' -ErrorAction Stop" >> "%LOG%" 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Start-BitsTransfer -Source '%Tasks_URL%' -Destination '%Tasks%' -ErrorAction Stop" >> "%LOG%" 2>&1

call :Verify
if "%Verify%"=="Success" goto :DownloadOK

:: ===== IWR Fallback =====
echo BITS failed, trying Invoke-WebRequest... >> "%LOG%"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Invoke-WebRequest -Uri '%Run_URL%' -OutFile '%Run%' -UseBasicParsing" >> "%LOG%" 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Invoke-WebRequest -Uri '%Tasks_URL%' -OutFile '%Tasks%' -UseBasicParsing" >> "%LOG%" 2>&1

call :Verify
if "%Verify%"=="Success" goto :DownloadOK

:: --- Retry ---
if !RETRIES! lss 5 (
    echo Retry in 5 seconds... >> "%LOG%"
    timeout /t 5 /nobreak >nul
    goto :RetryLoop
)

echo ERROR: Download failed after 5 attempts. >> "%LOG%"
goto :exit

:DownloadOK
echo Download successful.
echo Download successful. >> "%LOG%"

:: --- Run main script ---
echo Running script...
echo Running %Run% >> "%LOG%"

set "CALLER_SCRIPT=%~f0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%Run%" "%CALLER_SCRIPT%" >> "%LOG%" 2>&1

if not "%errorlevel%"=="0" (
    echo ERROR: Script execution failed >> "%LOG%"
    goto :exit
)

color 8B
echo Completed successfully.
echo ==== SUCCESS ==== >> "%LOG%"
exit /b 0

:exit
echo *** FAILED - check log: %LOG% ***
echo ==== FAILED ==== >> "%LOG%"
exit /b 1

:Verify
set "Verify=Success"

if not exist "%Run%" (
    echo Run.ps1 missing >> "%LOG%"
    set "Verify=Failed"
)

if not exist "%Tasks%" (
    echo Tasks.psm1 missing >> "%LOG%"
    set "Verify=Failed"
)

goto :eof