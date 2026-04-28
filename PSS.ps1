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
Tweak-schtasks #Disable scheduled tasks that are considered unnecessary
Registry-Tweaks #Applye Registry Tweaks
DeepTweaks
Disable-DefenderRealtimeProtection
InitializeCommands
Set-Personalization
Set-IdleLock # Set Idle look using UIA
WinWallpaper
MaxPowerPlan #Activate Max Performance Power Plan
Ins-Nuget #Install Nuget provider
Ins-Choco #Install Chocolatey
Ins-WindowsFeatures #Install Windows Features use DISM
Install-WinGet #Install Winget and its dependencies

Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Installing programs *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
Ins-LatestPowershell #Install Latest Stable Powershell
Ins-Terminal #Install Windows Terminal
Ins-DotNetRuntime #Install .Net Runtime All versions
Ins-VCPPRuntime #Install Visual C++ Runtime All versions
Ins-JavaRuntime #Install Java Runtime Environment
Ins-XNA #Install Microsoft XNA Framework Redistributable
Ins-AdobeAIRRuntime #Install Adobe AIR Runtime
Ins-arSAlang #Install Arabic-SA language
Ins-enUSLang #Install en-US language
Set-en-US-Culture # Make regional format en-GB with AM/PM
Unins-enGBLang #remove en-GB language
Tweak-Language
Fix-Share #Fix Windows file sharing
Ins-WScan #Install Windows Scan
Ins-HpSmart #Install Hp Smart App
Ins-NotepadPP #Install Notepad++
Ins-Chrome #Install Google Chrome
Tweak-Edge #Tweak MS Edge
#Ins-AcrobatRdr #Install Adobe Acrobat Reader DC
Ins-AcrobatPro #Install Adobe Acrobat Pro DC
#Ins-Foxit #Install Foxit PDF Reader
Ins-WinRAR #Install WinRAR
Ins-KLiteMega #Install K-Lite Codec Pack Mega
Ins-VLC #Install VLC Player
#Ins-PaintDotNet # Install Paint.Net
#Ins-GIMP # Install GIMP
Ins-OpenAl #Install OpenAl
Ins-WhatsApp #Install WhatsApp
#Pin-WhatsappWebChrome #Pin Chrome whatsapp web to taskbar
Unins-DropboxPromotion
Unins-Devhome #Uninstall Dev Home
Ins-DirectX #Install DirectX Extra files
Windows-Update #Start Install Windows Updates
Unins-MSTeams #Uninstall Microsoft Teams
Unins-Cortana #Uninstall & disable Cortana & tweak search
Unins-Copilot #Uninstall & disable Copilot
Unins-Xbox #UnInstall Xbox & Game Bar
UpdateAll #Update all Installd applications use Winget
Dis-BitLocker #Disable BitLocker
#EnableSMB1Protocol-Client #Old legacy security threat sharing protocol
D-ScanFolder #Create Drive D (If not found)& Create shared Scan folder in it
Adj-Hosts #Adjust Hosts file
#Ins-Office21PP #Start Install Office 2021 Pro Plus & remove old versions
Ins-Office24PP #Start Install Office 2024 Pro Plus & remove old versions
Ins-ExtraFonts #Install Extra Fonts
Create-RLMCopyShortcut
Update-MSStoreApps # Update MS Store apps using UIA
Fix-MSWindows #Fix Windows
Clear-PrintQueue
Clean-up
Change_computer_name
temp-clean




