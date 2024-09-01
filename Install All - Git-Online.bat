Call :GetAdmin
REM Commands

Echo.
Echo "======================================================================================================================"
Echo "*************************** This file installs essential windows programms and runtimes ***************************"
Echo "************************** Using the code files from github repo for dynamic code update **************************"
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
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -nologo -Command "Set-ExecutionPolicy Bypass -Force"
reg add "HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1

Echo Downloading ^& runing
del /f /s /q "%tmp%\IA" >nul 2>nul
del /f /s /q "%tmp%\IAGit\*.zip" "%tmp%\IAGit\*.ps1" "%tmp%\IAGit\*.psm1" >nul 2>nul
mkdir "%tmp%\IAGit"

reg add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
sc Start "BITS"
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -nologo -Command "Start-Job -Name BITS {Start-Service -Name 'BITS' -ea silentlycontinue | out-null} | Wait-Job -Timeout 999"
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -nologo -Command "Start-BitsTransfer -Source 'https://github.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/archive/refs/heads/main.zip' -Destination '%tmp%\IAGit\IAGit.zip';Expand-Archive -LiteralPath '%tmp%\IAGit\IAGit.zip' -DestinationPath '%tmp%\IAGit' -Force"
REM Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -nologo -Command "Invoke-WebRequest -Uri 'https://github.com/Moh-Dabas/Online-install-of-all-essential-windows-softwares/archive/refs/heads/main.zip' -OutFile '%tmp%\IAGit\IAGit.zip';Expand-Archive -LiteralPath '%tmp%\IAGit\IAGit.zip' -DestinationPath '%tmp%\IAGit' -Force"
Start "" /High "%tmp%\IAGit\Online-install-of-all-essential-windows-softwares-main\Install All.bat"
if %errorlevel% neq 0 (Start "Relunch" "%~f0" & exit)

REM Commands end
goto :exit
REM ======================================================================================================================
REM Get Admin privileges
:GetAdmin
@Echo off & SetLOCAL EnableDelayedExpansion & pushd %~dp0 & Set "params=%*" & cd /d "%~dp0" & (if exist "%temp%\getadmin.vbs" del /f /q "%temp%\getadmin.vbs") & copy "%~f0" "%temp%\R.bat" /Y
fsutil dirty query %systemdrive% >nul 2>nul || (Echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd /d ""%temp%"" & ""R.bat"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" & "%temp%\getadmin.vbs" & exit)
title Installing All Essential Programs Online
cls
goto :eof
REM ======================================================================================================================
:exit
Echo.&Echo All done!
endlocal && TIMEOUT /t 1 >NUL
start "" "cmd.exe" "/c TIMEOUT /t 2 >NUL & del /f /q "%temp%\R.bat"
EXIT