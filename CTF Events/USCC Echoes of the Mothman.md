# Overview
This web exploit begins with looking for information disclosed in the HTML source, moves on to understand some Python code, and then ends with command injection to view the flag.

# Solving the box
We connect to the website and right away "View Page Source" to look for any interesting tidbits. We notice the following line towards the bottom of the main webpage:
```
<!-- TODO: remove source code at /static/source.zip when deploying to PROD -->
```

We cross our fingers and hope that the source code still exists in that directory which should be easily accessible to us. Thankfully, visiting /static/source.zip downloads the source.zip file. We then move this into our working directory and unzip it.
```
mv ~/Downloads/source.zip .
unzip source.zip
```

From here, we receive 3 files; app.py, db.py, and utils.py. 
We can open up all three files and read through. There are a bunch of important things to take note of. First, in app.py there is a User class that is denoted as "for backwards compatibility".
```
# here for backwards compatilibity
class User:
    def __init__(self, data):
        for k, v in data.items():
            cmd = 'self.%s = "%s"' % (k, v)
            exec(cmd)
        self.creation_date = datetime.now().strftime('%d/%m/%y')

    def set_welcome_msg(self, msg):
        cmd = 'self.welcome = "%s"' % msg
        exec(cmd)
```

Already, this class looks like a juicy target due to those exec() functions. Just from looking at this it seems like we might be able to do some sort of command injection if we are able to control the data that goes into these functions. However,  it's not that simple. The do_register function that is now being imported from the utils.py file is more secure-- the User class there does not contain exec() functions that we can leverage. So... then how do we leverage this old User class?

That brings us to the db.py file. In this file there are two important pieces of info:
1. Pickle is being used to serialize data
2. A filepath

When pickle is used to serialize/deserialize, it generally relies on the object definitions being the same each time. This would be a reason to keep around that old insecure User class, as things that were already serialized using the old class wouldn't be compatible with the new one. So, it would be super helpful if we could get our hands on a user account that was made a long time ago-- as it might get deserialized from the DB with the insecure class.

Thankfully, the other useful thing in that db.py file was another file that we might be able to download!
```
USERS_DB_FILE = './static/db/users'
```

We navigate to /static/db/users and sure enough are able to download the file.  I then ran strings on this file and it has exactly what we are looking for! Scrolling to the top, we notice a whole bunch of users who seem to have been here for a very long time. It also contains their password hashes.
strings users

```
username
admin
password_hash
 29f4419a6a083ab64345e7e2036f3851
creation_date
05/01/1955
```


I decided to use the admin user. You could put this password hash into something like John the Ripper or Hashcat. Since this just appears to be an md5 hash, I put it into https://crackstation.net/ and it got the password right away: aliens4everlove
I then tried logging in with this user (with Burp Suite open), and it worked.

At this point, it seems that we have the necessary tools to inject commands-- a user that will likely be deserialized using the vulnerable class. Due to using the username and password to actually log in, we would be looking to find a way to pass data to the 'set_welcome_msg' function that we looked at earlier.

We can start by pulling our login request over to Burp Repeater. Here, it looks like we have 3 POST parameters to play around with; uname, paswd, and msg. That msg parameter looks like it might be exactly what we need. 

We can start by entering some random information into the msg parameter and logging in.
```
POST /login HTTP/1.1
Host: chals.uscc-east-2025.ctf.institute:3018
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 41

uname=admin&paswd=aliens4everlove&msg=123
```

Sure enough, we can see that on the webpage it displays "123 admin" instead of "Welcome admin", so I would guess this is the welcome message we were looking for. Now, we can see if we are able to inject into the python itself. My usual test here would be to try some special characters and see if it crashes the page. Further, from looking at the original code, it is likely that some quotes will do. As expected, using the following POST parameters with a double quote will return us a 500 INTERNAL SERVER ERROR status code.
`uname=admin&paswd=aliens4everlove&msg="`


At this point, I opened a new tab in VSCode and started testing valid ways to write this injection-- and it took me awhile. I will spare you from having to look at all my iterations of this. Below is the final version of POST data that will satisfy all of the requirements to read the flag:
```
uname=admin&paswd=aliens4everlove&msg=";self.welcome=__import__('os').popen('cat /flag').read()#
```
