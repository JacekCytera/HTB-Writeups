# Recon

All-tcp:

```bash
nmap -p- -oA scans/nmap-alltcp 10.10.10.48
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
1764/tcp  open  landesk-rc
32400/tcp open  plex
32469/tcp open  unknown
```

Detailed scan:

```bash
> nmap -p 22,53,80,1764,32400,32469 -sVC -oA scans/nmap-tcpdetail 10.10.10.48
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey:
|   1024 aaef5ce08e86978247ff4ae5401890c5 (DSA)
|   2048 e8c19dc543abfe61233bd7e4af9b7418 (RSA)
|   256 b6a07838d0c810948b44b2eaa017422b (ECDSA)
|_  256 4d6840f720c4e552807a4438b8a2a752 (ED25519)
53/tcp    open  domain  dnsmasq 2.76
| dns-nsid:
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    lighttpd 1.4.35
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
|_http-server-header: lighttpd/1.4.35
1764/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-favicon: Plex
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
|_http-title: Unauthorized
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Endpoint scan for port 80 http service:

```
200      GET        1l        1w       18c http://10.10.10.48/versions
200      GET      145l     2311w    14164c http://10.10.10.48/admin/LICENSE
200      GET       20l      170w     1085c http://10.10.10.48/admin/scripts/vendor/LICENSE
200      GET       20l      170w     1085c http://10.10.10.48/admin/style/vendor/LICENSE
```

Endpoint scan for port 32400 http service:

```
...SNIP...
200      GET        3l        7w      101c http://10.10.10.48:32400/website2
200      GET        3l        7w      101c http://10.10.10.48:32400/web_editor
200      GET        3l        8w      175c http://10.10.10.48:32400/identity
200      GET        3l        7w      101c http://10.10.10.48:32400/web4
200      GET        3l        7w      101c http://10.10.10.48:32400/web_first
200      GET        3l        7w      101c http://10.10.10.48:32400/webcontrols
200      GET        3l        7w      101c http://10.10.10.48:32400/webaccess
...SNIP...
```

Visiting [http://10.10.10.48:32400/identity](http://10.10.10.48:32400/identity)
gave us following data, which differed from other discovered endpoints:

```xml
This XML file does not appear to have any style information associated with it. 
The document tree is shown below.
<MediaContainer 
    size="0" 
    machineIdentifier="5c27a36a5b4f7104cb9be08579964da1c5de5949" 
    version="1.7.5.4035-313f93718"> 
</MediaContainer>
```

We were able to get machineIdentifier, which might or might not come in handy later.

# Shell as pi

We were able to connect to /admin page on 80 port, which reveals Pi-Hole software
in use. Also, in headers to that site, was X-Pi-hole header which reveals the
software even without discovering admin dashboard page.

Since Pi-Hole software is installed, we can suspect, that the server runs
on Raspberry Pi. Google search reveals that default credentials for 
Raspberry Pi are:

```
pi:raspberry
```

We try them via ssh and are able to log in as user pi.

# Root flag

Since user pi can run any command as root without password, we immediately
gain root access. But, inside /root directory there is no flag:

```bash
cat /root/root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
```

Lsblk shows, that there is indeed an USB stick mounted on the filesystem:

```bash
lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   10G  0 disk
|-sda1   8:1    0  1.3G  0 part /lib/live/mount/persistence/sda1
`-sda2   8:2    0  8.7G  0 part /lib/live/mount/persistence/sda2
sdb      8:16   0   10M  0 disk /media/usbstick
sr0     11:0    1 1024M  0 rom
loop0    7:0    0  1.2G  1 loop /lib/live/mount/rootfs/filesystem.squashfs
```

Heading to the /media/usbstick yields another disappointment:
```bash
ls -al /media/usbstick/
total 18
drwxr-xr-x 3 root root  1024 Aug 14  2017 .
drwxr-xr-x 3 root root  4096 Aug 14  2017 ..
-rw-r--r-- 1 root root   129 Aug 14  2017 damnit.txt
drwx------ 2 root root 12288 Aug 14  2017 lost+found

cat /media/usbstick/damnit.txt
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

Since running "rm" only removes metadata without actually overwriting
existing data, we should be able to recover the flag by taking memory image
and analyzing it:

```bash
dcfldd if=/dev/sdb of=/home/pi/usb.dd
strings /home/pi/usb.dd

>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
/media/usbstick
2]8^
lost+found
root.txt
damnit.txt
>r &
3d3**************************20b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```

Inside, we have found root flag.
