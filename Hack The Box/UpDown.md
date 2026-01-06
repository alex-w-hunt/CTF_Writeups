# Key Takeaways
- Don't just assume functionality based, test is thoroughly before continuing. (user.txt)
- Enumeration is key! Not just when initially looking for vulnerabilities, but also when determining the most effective way to use a vulnerability. (user.txt)

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

To start determining if any of these potentially vulnerabilities exist, I began by running ffuf in the background to look for Vhosts. This quickly found the `dev.siteisup.htb` vhost.
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

Before diving down any rabbit holes, I decided to go to finish enumerating the initial webserver, which means looking for files and directories. Using fuff again, I quickly found that there is a `/dev` directory, with a `.git` folder inside, something that often can provide a lot of information.
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
2. Next, the file `$file` variable is created from the filename included in the POST parameter. This filename then has its extension checked to see if it matches a blacklist. **The use of a blacklist is extremely important here. It can be noted that the .phar filetype is NOT blacklisted.**
```
$file = $_FILES['file']['name'];

# Check if extension is allowed.
$ext = getExtension($file);
if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
        die("Extension not allowed!");
}
```


# Solving root.txt
