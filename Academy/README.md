![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/2a748ba16aab6f45a2cf2a0664e8bc42e4e2bf81/Academy/images/logo.png)
# Academy

This is the third box which i tried to get root !

So let's start by find the IP Address of the machine , i can easily guess what ip it's going to be since every box ip is incrementing by 1 in **Virtual Box.**


Anyway lets make sure of it !

You can use **netdiscover** to identify the target ip or you can also get the credentials in the zip file they provide and check for the ip using **"ip a"** command
```
netdiscover -r [your ip ]/24
```
## Scanning

let's do the usual scan :

```
nmap -p- -T4 -A [Target IP here]

-p-: Scans all ports.
-T4: Sets the timing template to aggressive, meaning Nmap will send packets more quickly to speed up the scan.
-A: Enables OS detection, version detection, and traceroute.

```
We are performing a SYN > SYN_ACK > RST

- SYN packet: Nmap sends a SYN packet to the target host, initiating a connection attempt.

- SYN-ACK packet: If the target port is open, it responds with a SYN-ACK packet, indicating its willingness to establish a connection.

- RST packet: Nmap immediately sends a RST (reset) packet to terminate the connection attempt, as it's only interested in determining whether the port is open or closed.


## Results of the scan

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-13 08:49 UTC
Nmap scan report for 192.xxx.xxx.xx
Host is up (0.0075s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.xxx.xxx.xx
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)
|   256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)
|_  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.46 seconds

```
Okay so we have 3 ports **open** which are
- FTP [21]
- SSH [22]
- HTTP [80]

Also there is **Anonymous login** allowed

And we did find a **note.txt** in the scan
```
-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
```
Interesting...! 

Now Check out the webserver 
```
http://192.xxx.xxx.xx
```
It's just a **default Apache2 Page**
There is nothing in it

Since **Anonymous Login** possbile we can try to login with username : **anonymous** & password : **anonymous**

```
──(kali㉿kali)-[~/Desktop/academy]
└─$ ftp 192.xxx.xx.xxx
Connected to 192.xxx.xx.xx
220 (vsFTPd 3.0.3)
Name (192.xxx.xxx.xxx:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```
Let's list the files and find the **note.txt** file

```
ftp> ls
229 Entering Extended Passive Mode (|||60850|)
150 Here comes the directory listing.
-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
226 Directory send OK.
ftp> 

```
To get the file type :

```
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||50715|)
150 Opening BINARY mode data connection for note.txt (776 bytes).
100% |*******************************************************************************|   776       36.03 KiB/s    00:00 ETA
226 Transfer complete.
776 bytes received in 00:00 (24.60 KiB/s)
ftp> exit
221 Goodbye.

```
 Now we got the **note.txt** file in our folder

let's **cat** that

```
┌──(kali㉿kali)-[~/Desktop/academy]
└─$ ls
nmap.txt  note.txt
                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/academy]
└─$ cat note.txt
Hello Heath !
Grimmie has setup the test website for the new academy.
I told him not to use the same password everywhere, he will change it ASAP.


I couldn't create a user via the admin panel, so instead I inserted directly into the database with the following command:

INSERT INTO `students` (`StudentRegno`, `studentPhoto`, `password`, `studentName`, `pincode`, `session`, `department`, `semester`, `cgpa`, `creationdate`, `updationDate`) VALUES
('10201321', '', 'cd73502828457d15655bbd7a63fb0bc8', 'Rum Ham', '777777', '', '', '', '7.60', '2021-05-29 14:36:56', '');

The StudentRegno number is what you use for login.


Le me know what you think of this open-source project, it's from 2020 so it should be secure... right ?
We can always adapt it to our needs.

-jdelta


```
Okay we got some database information's like

- `StudentRegno`, `studentPhoto`, `password`, `studentName`, `pincode`, `session`, `department`, `semester`, `cgpa`, `creationdate`, `updationDate`

Save this information somewhere ! it's useful
this might be useful for some kind of **login** page right.

## Directory Busting
Now lets try to perform some directory hunting you can do this many ways and there are lot of tools available to do this.
- dirb
- ffuf
- dirbuster
- GoBuster
- dirSearch

let's use **fuff** 
```
ffuf -w /usr/share/wordlist/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://[target ip]/FUZZ

```
Result :

```
──(kali㉿kali)-[~/Desktop/academy]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt:FUZZ -u http://192.xxx.xxx.xxx/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.xxx.x.x./FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# Copyright 2007 James Fisher [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 20ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 27ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 28ms]
#                       [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 28ms]
# directory-list-2.3-small.txt [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 20ms]
#                       [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 20ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 33ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 34ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 50ms]
#                       [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 935ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 1573ms]
# on atleast 3 different hosts [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 1612ms]
#                       [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 1682ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 1709ms]
academy                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 73ms]
phpmyadmin              [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 45ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 15ms]
:: Progress: [87664/87664] :: Job [1/1] :: 634 req/sec :: Duration: [0:01:43] :: Errors: 0 ::
                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/academy]
└─$ 

```

Okay we found 2 Directory

- academy
- phpmyadmin


let's check those 

```
http://192.xxx.xx.xx/academy/

http://192.xxx.xxx.xx/phpmyadmin/
```

Now **phpmyadmin** doesn't have anything Interesting in it but **academy** is a login page .

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/33ad39a43e125e216c7e24162c9fbf44035a05f6/Academy/images/loginpage.png)

This looks good it's asking for a **Regno** and **password**


Now remember the **note.txt** file we found during **ftp enumeration**

We can try to login with that info.

We have the **Regno** & also a password **hash**
most likely an **md5** hash.
```
cd73502828457d15655bbd7a63fb0bc8

```
Copy the hash.

Let's identify the password hash using **hash-identifier**  and paste the hash

```
$ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: cd73502828457d15655bbd7a63fb0bc8

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
[+] Haval-128
[+] Haval-128(HMAC)
[+] RipeMD-128
[+] RipeMD-128(HMAC)
[+] SNEFRU-128
[+] SNEFRU-128(HMAC)
[+] Tiger-128
[+] Tiger-128(HMAC)
[+] md5($pass.$salt)
[+] md5($salt.$pass)
[+] md5($salt.$pass.$salt)
[+] md5($salt.$pass.$username)
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($salt.$pass))
[+] md5($salt.md5(md5($pass).$salt))
[+] md5($username.0.$pass)
[+] md5($username.LF.$pass)
[+] md5($username.md5($pass).$salt)
[+] md5(md5($pass))
[+] md5(md5($pass).$salt)
[+] md5(md5($pass).md5($salt))
[+] md5(md5($salt).$pass)
[+] md5(md5($salt).md5($pass))
[+] md5(md5($username.$pass).$salt)
[+] md5(md5(md5($pass)))
[+] md5(md5(md5(md5($pass))))
[+] md5(md5(md5(md5(md5($pass)))))
[+] md5(sha1($pass))
[+] md5(sha1(md5($pass)))
[+] md5(sha1(md5(sha1($pass))))
[+] md5(strtoupper(md5($pass)))
--------------------------------------------------
 HASH: ^C

        Bye!
                                    

```

Writing.....!