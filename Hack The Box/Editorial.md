# Key Takeaways
- Keep it simple and don't make assumptions... if something smells like SSRF, then enumerate localhost! (user.txt)
- Go to the documentation ASAP (root.txt)

# Editorial Overview
- Platform: Linux
- HTB Rating: Easy - Not Too Easy

# Solving User.txt
As we are starting off this machine with no information, I began with the typical nmap scans. We are given a pretty common setup, seeing SSH open and a single webserver on port 80.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

As the webserver seems like the juicer initial target, I opened up Burp Suite alongside firefox and began seeing what it would have for us. Due to an initial error when accessing the webserver over just the IP, I first added `editorial.htb` into my /etc/hosts file, allowing us to access the site.
