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

# Solving root.txt
