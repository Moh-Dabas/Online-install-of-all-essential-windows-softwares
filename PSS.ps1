# Main commands
$ScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
try{Import-Module -Name $ScriptDirectory\AllFunctions.psm1 -DisableNameChecking -Global -Force}
catch{Write-Host "AllFunctions.psm1 file not found";Start-Sleep 5;exit}

Check-RunAsAdministrator #Check Script is runne with Elevated Privileges
InitializeCommands
MaxPowerPlan #Activate Max Performance Power Plan
Ins-WindowsFeatures #Install Windows Features use DISM
Install-Winget #Install Winget and its dependencies

Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Install programs *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
Ins-arSAlang #Install Arabic-SA language
Ins-enUSLang #Install en-US language
Unins-enGBLang #remove en-GB language
Tweak-Language
#Ins-LatestPowershell #Install Latest Stable Powershell
Ins-Terminal #Install Windows Terminal
Ins-DotNetRuntime #Install .Net Runtime All versions
Ins-VCPPRuntime #Install Visual C++ Runtime All versions
Ins-JavaRuntime #Install Java Runtime Environment
Ins-XNA #Install Microsoft XNA Framework Redistributable
Ins-AdobeAIRRuntime #Install Adobe AIR Runtime
Ins-WScan #Install Windows Scan
Ins-NotepadPP #Install Notepad++
Ins-Chrome #Install Google Chrome
Tweak-Edge
Ins-Acrobat #Install Adobe Acrobat Reader DC
Ins-WinRAR #Install WinRAR
Ins-KLiteMega #Install K-Lite Codec Pack Mega
Ins-VLC #Install VLC Player
Ins-OpenAl #Install OpenAl
Ins-WhatsApp #Install WhatsApp
#Pin-WhatsappWebChrome #Pin Chrome whatsapp web to taskbar
Unins-Devhome #Uninstall Dev Home
Winget-UpdateAll #Update all Installd applications use Winget
Ins-DirectX #Install DirectX Extra files
Windows-Update #Start Install Windows Updates
Unins-MSTeams #Uninstall Microsoft Teams
Unins-Cortana #Uninstall & disable Cortana & tweak search
Unins-Copilot #Uninstall & disable Copilot
Unins-Xbox #UnInstall Xbox & Game Bar
Unins-OneDrive #Remove One Drive
DeepTweaks
Dis-BitLocker #Disable BitLocker
#EnableSMB1Protocol-Client #Old legacy security threat sharing protocol
Fix-Share #Fix Windows file sharing
Tweak-schtasks #Disable scheduled tasks that are considered unnecessary
Registry-Tweaks #Applye Registry Tweaks
D-ScanFolder #Create Drive D (If not found)& Create shared Scan folder in it
Adj-Hosts #Adjust Hosts file
Ins-Office21PP #Start Install Office 2021 Pro Plus & remove old versions
Ins-ExtraFonts #Install Extra Fonts
Clean-up