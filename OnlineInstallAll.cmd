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

:: --- Files ---
set Run_URL='https://raw.githubusercontent.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/refs/heads/main/Run.ps1'
set Tasks_URL='https://raw.githubusercontent.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/refs/heads/main/Tasks.psm1'
set Common_URL='https://raw.githubusercontent.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/refs/heads/main/Common.psm1'
set Run_FILE='%TEMP%\Run.ps1'
set Tasks_FILE='%TEMP%\Tasks.psm1'
set Common_FILE='%TEMP%\Common.psm1'
set "Run=!Run_FILE:~1!"
set "Run=!PS1:~0,-1!"
set "Tasks=!Tasks_FILE:~1!"
set "Tasks=!PSM1:~0,-1!"
set "Common=!Common_FILE:~1!"
set "Common=!PSM1:~0,-1!"

Echo Deleting old files...
del /f /q "%Run%" >nul 2>&1
del /f /q "%Tasks%" >nul 2>&1
del /f /q "%Common%" >nul 2>&1

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

echo Downloading %Run% from %Run_URL% using Bits (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Start-BitsTransfer -Source %Run_URL% -Destination %Run_FILE%" >> "%LOG%" 2>>&1
echo Downloading %Tasks% from %Tasks_URL% using Bits (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Start-BitsTransfer -Source %Tasks_URL% -Destination %Tasks_FILE%" >> "%LOG%" 2>>&1
echo Downloading %Common% from %Common_URL% using Bits (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Start-BitsTransfer -Source %Common_URL% -Destination %Common_FILE%" >> "%LOG%" 2>>&1

call :Verify
if "%Verify%"=="Success" goto :DownloadOK

:IWR
echo Downloading %Run% from %Run_URL% using IWR (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Invoke-WebRequest -Uri %Run_URL% -OutFile %Run_FILE%" >> "%LOG%" 2>>&1
echo Downloading %Tasks% from %Tasks_FILE% using IWR (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Invoke-WebRequest -Uri %Tasks_URL% -OutFile %Tasks_FILE%" >> "%LOG%" 2>>&1
echo Downloading %Common% from %Common_FILE% using IWR (attempt !RETRIES!) >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -Command "Invoke-WebRequest -Uri %Common_URL% -OutFile %Common_FILE%" >> "%LOG%" 2>>&1

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
echo Running %Run%... >> "%LOG%"
set "CALLER_SCRIPT=%~f0"
powershell -NoProfile -ExecutionPolicy Bypass -nologo -File "%Run%" "%CALLER_SCRIPT%"
if not "%errorlevel%"=="0" (
    echo  ERROR: %Run% execution failed. >> "%LOG%"
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
if not exist "%Run%" (
    echo ERROR: %Run% missing after download.
    echo  ERROR: %Run% missing. >> "%LOG%"
    Set Verify=Failed
)
if not exist "%Tasks%" (
    echo ERROR: %Tasks% missing after download.
    echo ERROR: %Tasks% missing. >> "%LOG%"
    Set Verify=Failed
)
if not exist "%Common%" (
    echo ERROR: %Common% missing after download.
    echo ERROR: %Common% missing. >> "%LOG%"
    Set Verify=Failed
)
Set Verify=Success
goto :eof

