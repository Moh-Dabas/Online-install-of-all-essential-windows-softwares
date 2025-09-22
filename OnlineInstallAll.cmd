@echo off
setlocal enabledelayedexpansion

:: ============================
:: OnlineInstallAll.cmd
:: Always download latest PSS.ps1 + AllFunctions.psm1, then run PSS.ps1
:: PowerShell elevation, retries, logging.
:: ============================

Echo.
Echo "======================================================================================================================"
Echo "*************************** This file installs essential windows programms and runtimes ***************************"
Echo "************************** Using the code files from github repo for dynamic code update **************************"
Echo "======================================================================================================================"
Echo.

:: --- Log setup ---
set "LOG=%TEMP%\OnlineInstallAll.log"
echo [%date% %time%] ==== Script started ==== > "%LOG%"

:: --- Admin elevation (PowerShell only) ---
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if not "%errorlevel%"=="0" (
    echo Requesting admin rights...
    echo  Elevating via PowerShell... >> "%LOG%"
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

color 03
echo Running elevated.
echo Running elevated. >> "%LOG%"

Echo Setting Powershell Excution Policy...
reg add "HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -nologo -NonInteractive -Command "Set-ExecutionPolicy Bypass -Force"

:: --- File PS1_URLs ---
set PS1_URL='https://raw.githubusercontent.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/refs/heads/main/PSS.ps1'
set PSM1_URL='https://raw.githubusercontent.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/refs/heads/main/AllFunctions.psm1'
set PS1_FILE='%TEMP%\PSS.ps1'
set PSM1_FILE='%TEMP%\AllFunctions.psm1'
set "PS1=!PS1_FILE:~1!"
set "PS1=!PS1:~0,-1!"
set "PSM1=!PSM1_FILE:~1!"
set "PSM1=!PSM1:~0,-1!"

Echo Deleting old files...
del /f /q "%PS1%" >nul 2>&1
del /f /q "%PSM1%" >nul 2>&1

:: --- Ensure BITS is running ---
echo Ensuring BITS service is running...
sc query bits | find "RUNNING" >nul 2>&1
if not "%errorlevel%"=="0" (
    sc start bits >nul 2>&1
    timeout /t 5 /nobreak >nul
)
echo BITS check complete. >> "%LOG%"

:: --- Download with retries ---
set /a RETRIES=0
:RetryLoop
set /a RETRIES+=1

echo Downloading files (attempt !RETRIES! of 5)...
echo Downloading files (attempt !RETRIES! of 5)... >> "%LOG%"

echo Downloading %PS1% from %PS1_URL% using Bits (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Start-BitsTransfer -Source %PS1_URL% -Destination %PS1_FILE%" >> "%LOG%" 2>>&1
echo Downloading %PSM1% from %PSM1_URL% using Bits (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Start-BitsTransfer -Source %PSM1_URL% -Destination %PSM1_FILE%" >> "%LOG%" 2>>&1

call :Verify
if "%Verify%"=="Success" goto :DownloadOK

:IWR
echo Downloading %PS1% from %PS1_URL% using IWR (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Invoke-WebRequest -Uri %PS1_URL% -OutFile %PS1_FILE%" >> "%LOG%" 2>>&1
echo Downloading %PSM1% from %PSM1_FILE% using IWR (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Invoke-WebRequest -Uri %PSM1_URL% -OutFile %PSM1_FILE%" >> "%LOG%" 2>>&1

call :Verify
if "%Verify%"=="Success" goto :DownloadOK

if !RETRIES! lss 5 (
    echo  Download failed. Retrying in 5s... >> "%LOG%"
    timeout /t 5 /nobreak >nul
    goto :RetryLoop
)

echo ERROR: Download failed after 5 attempts. >> "%LOG%"
goto :exit

:DownloadOK
echo  Successfully downloaded >> "%LOG%"

:: --- Run the main script ---
echo Running Script ...
echo Running %PS1%... >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -File "%PS1%"
if not "%errorlevel%"=="0" (
    echo  ERROR: %PS1% execution failed. >> "%LOG%"
    goto :exit
)

color 8B
echo Completed successfully.
echo  ==== Completed successfully ==== >> "%LOG%"
exit /b 0

:exit
echo *** DOWNLOAD or RUN failed. See log at %LOG% ***
echo  ==== FAILED ==== >> "%LOG%"
exit /b 1

:Verify
:: --- Verify files exist ---
if not exist "%PS1%" (
    echo ERROR: %PS1% missing after download.
    echo  ERROR: %PS1% missing. >> "%LOG%"
    Set Verify=Failed
)
if not exist "%PSM1%" (
    echo ERROR: %PSM1% missing after download.
    echo ERROR: %PSM1% missing. >> "%LOG%"
    Set Verify=Failed
)
Set Verify=Success
goto :eof

