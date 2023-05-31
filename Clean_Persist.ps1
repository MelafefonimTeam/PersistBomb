#
#______             _     _  ______                 _     
#| ___ \           (_)   | | | ___ \               | |    
#| |_/ /__ _ __ ___ _ ___| |_| |_/ / ___  _ __ ___ | |__  
#|  __/ _ \ '__/ __| / __| __| ___ \/ _ \| '_ ` _ \| '_ \ 
#| | |  __/ |  \__ \ \__ \ |_| |_/ / (_) | | | | | | |_) |
#\_|  \___|_|  |___/_|___/\__\____/ \___/|_| |_| |_|_.__/                                                                                                                 
#
#
#Persistence Mechanisms Cleaning Script
#Autor: Avihay Eldad & Sagi Dinar
#
#
# Admin Check 
#----------------------------------------------------------------------------------------------------------------------------------#
function Admin_Check {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
    if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
        Write-Warning "Please run as an Administrator!"
        Break
    }
}
#----------------------------------------------------------------------------------------------------------------------------------#


# CMD AutoRun  
#----------------------------------------------------------------------------------------------------------------------------------#
function CMD_AutoRun_Clean {
Write-host -ForegroundColor Yellow "Remove CMD AutoRun..."
start-sleep 2
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name AutoRun -ErrorAction SilentlyContinue
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# PowerShell Profile 
#----------------------------------------------------------------------------------------------------------------------------------#
function PowerShell_Profile_Clean {
Write-host -ForegroundColor Yellow "Remove PowerShell Profile..."
Start-Sleep 2
Remove-Item C:\Users\$env:USERNAME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Notepad++ Plugin
#----------------------------------------------------------------------------------------------------------------------------------#
function Notepad++_Plugin_Clean{
	Write-Host -ForegroundColor Yellow "Remove Notepad++ Plugin..."
	Start-Sleep 2
	Remove-Item 'C:\Program Files\Notepad++\plugins\MyNppPlugin1' -Recurse -ErrorAction SilentlyContinue
    Remove-Item 'C:\Program Files\Notepad++\plugins\MyNppPlugin1.dll' -ErrorAction SilentlyContinue
	Write-Host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Sticky Keys
#----------------------------------------------------------------------------------------------------------------------------------#
function Sticky_Keys_Clean {
Write-host -ForegroundColor Yellow "Remove Sticky Keys..."
Start-Sleep 2
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Force
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Screen Saver
#----------------------------------------------------------------------------------------------------------------------------------#
function ScreenSaver_Clean {
Write-host -ForegroundColor Yellow "Remove Malicious Screen Saver file..."
Remove-Item "C:\Users\Public\Libraries\calc.scr" -ErrorAction SilentlyContinue
Start-Sleep 2
$ServiceKey = "control panel\desktop"
Remove-ItemProperty -Path "HKCU:$($ServiceKey)" -Name "SCRNSAVE.EXE" -Force
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Set Image File Execution Options (Notepad)
#----------------------------------------------------------------------------------------------------------------------------------#
function Set_Image_File_Execution_Options_Clean {
Write-host -ForegroundColor Yellow "Remove Set Image File Execution Options (Notepad)..."
Start-Sleep 2
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" -Force
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Scheduled Task
#----------------------------------------------------------------------------------------------------------------------------------#
function Scheduled_Task_Clean {
Write-host -ForegroundColor Yellow "Remove Scheduled Task..."
Start-Sleep 2
schtasks /delete /tn "OneDrive Reporting Task-S-1-5-21-672427273-3495726268-953469399-1001" /f
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Event Viewer
#----------------------------------------------------------------------------------------------------------------------------------#
function Event_Viewer_Clean {
Write-host -ForegroundColor Yellow "Remove Event Viewer..."
Start-Sleep 2
Remove-Item -Path 'C:\Users\Public\Libraries\calc.dll' -Force
Remove-Item -Path "HKCU:\Software\Classes\CLSID\{09108e71-974c-4010-89cb-acf471ae9e2c}" -Recurse -Force -ErrorAction Ignore 
Remove-ItemProperty -Path HKCU:\Environment -Name "COR_ENABLE_PROFILING" -Force -ErrorAction Ignore | Out-Null
Remove-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER" -Force -ErrorAction Ignore | Out-Null
Remove-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER_PATH" -Force -ErrorAction Ignore | Out-Null
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Word Template
#----------------------------------------------------------------------------------------------------------------------------------#
function Word_Template_Clean {
Write-host -ForegroundColor Yellow "Remove Word Template..."
Start-Sleep 2
Remove-Item C:\Users\Public\Libraries\N.txt -force
Remove-Item $env:APPDATA\Microsoft\Templates\Normal.dotm -force
Rename-Item $env:APPDATA\Microsoft\Templates\normal2.dotm Normal.dotm 
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# StartUp Folder
#----------------------------------------------------------------------------------------------------------------------------------#
function StartUp_Folder_Clean {
Write-host -ForegroundColor Yellow "Remove StartUp Folder..."
Start-Sleep 2
Remove-Item "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk" -ErrorAction Ignore
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# RecycleBin CLSID
#----------------------------------------------------------------------------------------------------------------------------------#
function RecycleBin_CLSID_Clean {
Write-host -ForegroundColor Yellow "Remove RecycleBin CLSID..."
Start-Sleep 2
Remove-Item -Path 'HKCR:\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open' -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Wordpad (write.exe)
#----------------------------------------------------------------------------------------------------------------------------------#
function Wordpad_Clean {
Write-host -ForegroundColor Yellow "Remove Wordpad (write.exe)..."
Start-Sleep 2
Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wordpad.exe' -Force -ErrorAction SilentlyContinue | Out-Null
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# ControlPanel Add-Ins
#----------------------------------------------------------------------------------------------------------------------------------#
function ControlPanel_Add-Ins_Clean {
Write-host -ForegroundColor Yellow "Remove ControlPanel Add-Ins..."
Start-Sleep 2
Remove-Item C:\Users\Public\Libraries\control.dll
Remove-ItemProperty -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Control Panel\CPLs" -Name "ShockSoc"
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Outlook Home Page
#----------------------------------------------------------------------------------------------------------------------------------#
function Outlook_Home_Page_Clean {
Write-host -ForegroundColor Yellow "Remove Outlook Home Page ..."
Start-Sleep 2
Remove-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\WebView" -Recurse -Force
Remove-Item C:\users\public\Libraries\home.html -Force
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# PowerPointVBAadd-ins
#----------------------------------------------------------------------------------------------------------------------------------#
function PowerPointVBAadd-ins_Clean {
Write-host -ForegroundColor Yellow "Remove PowerPointVBAadd-ins ..."
Start-Sleep 2
$OfficePath="C:\Program Files (x86)\Microsoft Office\"+"Office*" 
    Try  
    {  
        $OfficeVersion=dir -name $OfficePath -ErrorAction Stop  
        $Ver=$OfficeVersion.Substring( $OfficeVersion.LastIndexOf("e")+1 )
    }  
    Catch  
    {  
        return 
    }   
    $filepath = $env:APPDATA+"\Microsoft\AddIns\calc.ppa"
    Remove-Item $filepath -ErrorAction SilentlyContinue -Force
    $ServiceKey = "Software\Microsoft\Office\"+$Ver+".0\PowerPoint\AddIns\calc"
    Remove-Item -Path "HKCU:$($ServiceKey)" -Force
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# vmTools
#----------------------------------------------------------------------------------------------------------------------------------#
function vmTools_Clean {
Write-host -ForegroundColor Yellow "Remove vmTools ..."
Start-Sleep 2
    if (Test-Path "$env:ProgramData\VMware\VMware Tools\tools.conf.bak") {
        $original = Get-Content "$env:ProgramData\VMware\VMware Tools\tools.conf.bak"
        Set-Content -Path "$env:ProgramData\VMware\VMware Tools\tools.conf" -Value $original -Force
        Remove-Item -Path "$env:ProgramData\VMware\VMware Tools\tools.conf.bak" 
    }
    else {
        Remove-Item -Path "$env:ProgramData\VMware\VMware Tools\tools.conf"
    }
    if (Test-Path "C:\Users\Public\Libraries\ShockSOC.bat") {
        Remove-Item "C:\Users\Public\Libraries\ShockSOC.bat" -Force
    }
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Netsh
#----------------------------------------------------------------------------------------------------------------------------------#
function Netsh_Clean {
Write-host -ForegroundColor Yellow "Remove Netsh ..."
Start-Sleep 2
try
    {
   cmd /c netsh delete helper 'C:\Users\Public\Libraries\CalcDLL.dll'
    }
catch { }

   Remove-Item -Path "C:\Users\Public\Libraries\CalcDLL.dll" -Force
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# New Sercvice
#----------------------------------------------------------------------------------------------------------------------------------#
function New_Service_Clean {
Write-host -ForegroundColor Yellow "Remove Netsh ..."
Start-Sleep 2
cmd /c 'sc delete "Microsoft Update ShockSOC Service"'
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# Display Color Calibration
#----------------------------------------------------------------------------------------------------------------------------------#
function Display_Color_Calibration_Clean {
Write-host -ForegroundColor Yellow "Remove Display Color Calibration ..."
Start-Sleep 2
$RegValue = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CTTune.exe"      
Remove-Item -Path $RegValue -Recurse -Force       
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# PowerShell Job
#----------------------------------------------------------------------------------------------------------------------------------#
function PowerShell_Job_Clean {
Write-host -ForegroundColor Yellow "Remove PowerShell Job ..."
Start-Sleep 2
Unregister-ScheduledTask -TaskName "ShockSOC" -Confirm:$False     
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#


# WMI
#----------------------------------------------------------------------------------------------------------------------------------#
function WMI_Clean {
Write-host -ForegroundColor Yellow "Remove WMI ..."
Start-Sleep 2
$EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = 'ShockSOC-WMI'"
$EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = 'ShockSOC-WMI'"
$FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"
$FilterConsumerBindingToCleanup | Remove-WmiObject
$EventConsumerToCleanup | Remove-WmiObject
$EventFilterToCleanup | Remove-WmiObject
Write-host -ForegroundColor Green "Done!"
}
#----------------------------------------------------------------------------------------------------------------------------------#



function Clean
{
#Check for Admininstrator Privilege
Admin_Check

#Clean Payloads
CMD_AutoRun_Clean
PowerShell_Profile_Clean
Notepad++_Plugin_Clean
Sticky_Keys_Clean
ScreenSaver_Clean
Set_Image_File_Execution_Options_Clean
Scheduled_Task_Clean
Event_Viewer_Clean
Word_Template_Clean
StartUp_Folder_Clean
RecycleBin_CLSID_Clean
Wordpad_Clean
ControlPanel_Add-Ins_Clean
Outlook_Home_Page_Clean
PowerPointVBAadd-ins_Clean
#vmTools_Clean
Netsh_Clean
New_Service_Clean
Display_Color_Calibration_Clean
PowerShell_Job_Clean
WMI_Clean
}