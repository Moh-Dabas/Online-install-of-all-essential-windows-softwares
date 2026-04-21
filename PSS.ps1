# Main commands

# Get Caller CMD
param($RecievedCmdfullPath)
$global:GRCmdfullPath = $RecievedCmdfullPath
$SetCmdfullPath = $env:CALLER_SCRIPT
$global:GSCmdfullPath = $SetCmdfullPath
# Save the path for the ps1
$global:CallerScriptPath = $MyInvocation.MyCommand.Path

# Set global flag for Debug
$global:ScriptDebug = $true

# Show debug for script paths
if ($ScriptDebug) {
	Write-Host "Starting CMD full path we recieved from the CMD: $GRCmdfullPath"
	Write-Host "Starting CMD full path which was set by the CMD: $GSCmdfullPath"
	Write-Host "Caller Script path: $CallerScriptPath"
}

# Powershell variables
if ($ScriptDebug) {
	$global:ErrorActionPreference = 'Continue'
	$global:progressPreference = 'Continue'
} else {
	$global:ErrorActionPreference = 'SilentlyContinue'
	$global:progressPreference = 'SilentlyContinue'
}

$global:ConfirmPreference = 'None'
$global:Force = $true

Set-Location -Path $PSScriptRoot

# Try Importing AllFunctions.psm1
$ScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
If (-not (Test-Path $ScriptDirectory\AllFunctions.psm1 -ea SilentlyContinue)) {Write-Host "Functions file not found at: $ScriptDirectory";$ScriptDirectory = $PSScriptRoot}
if (-not (Test-Path $ScriptDirectory\AllFunctions.psm1 -ea SilentlyContinue)) {Write-Host "Functions file not found at: $ScriptDirectory";Start-Sleep 10; exit}

try {
	Import-Module -Name $ScriptDirectory\AllFunctions.psm1 -DisableNameChecking -Global -Force
} catch { Write-Host "AllFunctions.psm1 file not found or failed to Import it"; Start-Sleep 10; exit }

Check-RunAsAdministrator #Check Script is running with Elevated Privileges
Start-FunctionWindow Registry-Tweaks #Applye Registry Tweaks
Start-FunctionWindow Tweak-schtasks #Disable scheduled tasks that are considered unnecessary
Start-FunctionWindow DeepTweaks
Start-FunctionWindow Disable-DefenderRealtimeProtection
InitializeCommands
Start-FunctionWindow Set-Personalization
Start-FunctionWindow Set-IdleLock # Set Idle look using UIA
Start-FunctionWindow WinWallpaper
Start-FunctionWindow MaxPowerPlan #Activate Max Performance Power Plan
Start-FunctionWindow Ins-WindowsFeatures #Install Windows Features use DISM
Start-FunctionWindow Windows-Update #Start Install Windows Updates
Start-FunctionWindow Ins-arSAlang #Install Arabic-SA language
Start-FunctionWindow Ins-enUSLang #Install en-US language
Start-FunctionWindow Set-en-US-Culture # Make regional format en-GB with AM/PM
Start-FunctionWindow Unins-enGBLang #remove en-GB language
Start-FunctionWindow Tweak-Language
Start-FunctionWindow Fix-Share #Fix Windows file sharing
Start-FunctionWindow Tweak-Edge #Tweak MS Edge
Start-FunctionWindow Dis-BitLocker #Disable BitLocker
Start-FunctionWindow D-ScanFolder #Create Drive D (If not found)& Create shared Scan folder in it
Start-FunctionWindow Adj-Hosts #Adjust Hosts file
Start-FunctionWindow Create-RLMCopyShortcut
Start-FunctionWindow Update-MSStoreApps # Update MS Store apps using UIA
Start-FunctionWindow Clear-PrintQueue

# The Installers
Ins-Nuget #Install Nuget provider
Ins-Choco #Install Chocolatey
Install-WinGet #Install Winget and Scoop & its dependencies

Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Installing programs *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"

Ins-Office24PP #Start Install Office 2024 Pro Plus & remove old versions
#Ins-AcrobatRdr #Install Adobe Acrobat Reader DC
Ins-AcrobatPro #Install Adobe Acrobat Pro DC
#Ins-Foxit #Install Foxit PDF Reader
Ins-WhatsApp #Install WhatsApp
#Pin-WhatsappWebChrome #Pin Chrome whatsapp web to taskbar
Ins-NotepadPP #Install Notepad++
Ins-Chrome #Install Google Chrome
Ins-WinRAR #Install WinRAR
Ins-KLiteMega #Install K-Lite Codec Pack Mega
Ins-VLC #Install VLC Player
Ins-WScan #Install Windows Scan
Ins-HpSmart #Install Hp Smart App
Ins-DotNetRuntime #Install .Net Runtime All versions
Ins-VCPPRuntime #Install Visual C++ Runtime All versions
Ins-JavaRuntime #Install Java Runtime Environment
Ins-XNA #Install Microsoft XNA Framework Redistributable
Ins-AdobeAIRRuntime #Install Adobe AIR Runtime
Ins-LatestPowershell #Install Latest Stable Powershell
Ins-Terminal #Install Windows Terminal
#Ins-PaintDotNet # Install Paint.Net
#Ins-GIMP # Install GIMP
Ins-OpenAl #Install OpenAl
Unins-DropboxPromotion
Unins-Devhome #Uninstall Dev Home
Ins-DirectX #Install DirectX Extra files
Unins-MSTeams #Uninstall Microsoft Teams
Unins-Cortana #Uninstall & disable Cortana & tweak search
Unins-Copilot #Uninstall & disable Copilot
Unins-Xbox #UnInstall Xbox & Game Bar
UpdateAll #Update all Installd applications use Winget
#EnableSMB1Protocol-Client #Old legacy security threat sharing protocol
#Ins-Office21PP #Start Install Office 2021 Pro Plus & remove old versions
Ins-ExtraFonts #Install Extra Fonts
Fix-MSWindows #Fix Windows
Clean-up
Change_computer_name
temp-clean