Call :GetAdmin
REM Commands

Echo.
Echo "======================================================================================================================"
Echo "************************** This file installs essential windows programms and runtimes **************************"
Echo "======================================================================================================================"
Echo.

Echo.
Echo Installing Windows default Powershell (incase it's disabled)
Echo.
dism /online /get-featureinfo /featurename:MicrosoftWindowsPowerShellV2Root | findstr /i "State" | find /i "Enabled" >nul 2>nul
if %errorlevel% == 0 (
    echo Windows Feature: MicrosoftWindowsPowerShellV2Root is Enabled
) else (
    dism /online /Enable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root /All /NoRestart
)
dism /online /get-featureinfo /featurename:MicrosoftWindowsPowerShellV2 | findstr /i "State" | find /i "Enabled" >nul 2>nul
if %errorlevel% == 0 (
    echo Windows Feature: MicrosoftWindowsPowerShellV2 is Enabled
) else (
    dism /online /Enable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 /All /NoRestart
)

Echo.
Echo Making sure Powershell is working
Echo.
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /f >nul 2>nul
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /f >nul 2>nul


Echo Setting Powershell Excution Policy to Bypass
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -nologo -NonInteractive -Command "Set-ExecutionPolicy Bypass -Force"
reg add "HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1

cd /d "%~dp0"

Echo.
Echo Start installing programms
Echo.
Powershell -NoProfile -ExecutionPolicy Bypass -nologo -NonInteractive -File "%~dp0PSS.ps1"
start "" wt -p "Windows PowerShell" winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements

REM Commands end
goto :exit
REM ======================================================================================================================
REM Get Admin privileges
:GetAdmin
@Echo off && SetLOCAL EnableDelayedExpansion && pushd %~dp0
Set "params=%*" && cd /d "%~dp0" && (if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs") && fsutil dirty query %systemdrive% >nul 2>nul || (Echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd /d ""%~sdp0"" && ""%~s0"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit)
title Installing All Essential Programs Online
cls
color 0B
echo *** Script is running with Administrator privileges ***
goto :eof
REM ======================================================================================================================
:exit
Echo.& Echo All done!
REM cleanup
del /f /s /q "%tmp%\IA" >nul 2>nul
del /f /s /q "%tmp%\IAGit\*.zip" "%tmp%\IAGit\*.ps1" "%tmp%\IAGit\*.psm1" >nul 2>nul
taskkill /f /im WindowsTerminal.exe  >nul 2>nul
endlocal && TIMEOUT /t 1 >nul 2>nul
start "" cmd /c "del /f /s /q %tmp% >nul 2>nul"
EXIT