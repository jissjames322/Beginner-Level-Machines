
# Kioptrix
 Beginner Level Box For Pentest - Kioptrix Level 1
 
 This is my first box !

 If you find my words idiotic ,well im an idiot : 0 


- You can find this Box in here or you can find in the resources on the youtube video description

``` 
https://www.vulnhub.com/entry/kioptrix-level-1-1,22/
```
- The Main Objective is to achieve root access to this machine.


- This is a basic machine for learning about the tools for vulnerability assessment & exploitation

## Setup

- I have installed virtual box from here 

```
https://www.virtualbox.org/wiki/Downloads

```

    Run virtual box
    File > Import Appliance > Browse > Select the (Kioptrix.ova)
    Also setup your attack box 
    
Configure the Machine Settings

    Ram : 256MB
    Network : Nat Network
If you haven't setup a NAT network you can do that by 

```
preferences > NAT network > Create One
```
- Run the Box

## For Finding the IP of Kioptrix

You can do that by running an arp scan 

    netdiscover -r [ip]/24

```
netdiscover - a simple ARP scanner designed for scanning large networks

-r -  This option specifies the range of IP addresses to scan

[ip]-  This is the base IP Address you want to scan. 

    [Replace with your IP]

/24 - This specifies the subnet mask in CIDR notation, where /24 represents a subnet mask of 255.255.255.0. This means you're scanning all 256 IP addresses in the range, from 192.168.1.0 to 192.168.1.255.
```
You can find the IP if you find any IP is matching to VM


## Recon

Let's scan with nmap 

```
nmap -p- -A -T4  [Target Ip]
```
    nmap - Is a Network Scanner tool used for finding vulnerability and open ports in a machine

    -p - this option tells 'nmap' to scan upto 1000 ports

    -p-  - this option tells 'nmap' to scan all the possible ports which can be upto 65535 ports !

    -A  - Is used for identifying the OS,Version,Script Scan,trace route

    -T4 - -T4: This option sets the timing template to level 4, which is considered "Aggressive". Timing templates control how quickly nmap sends packets.

    -T0-T1 - Very slow scans (useful for evading detection).
    -T2-T3 - Normal speed scans.
    -T4 - Aggressive, faster scan (default for many nmap scans).
    -T5 - Very fast scan (may be detected or cause network issues).


## Good Practices

Always keep notes of  your findings of scan or any operation it might be helpful while your doing pentesting

    These are things i learned from watching 1000 of videos and its true !!

## Scan Result

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-11 07:09 UTC
Nmap scan report for 192.168.57.4
Host is up (0.0079s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey: 
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| http-methods: 
|_  Potentially risky methods: TRACE
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
|_ssl-date: 2024-08-11T11:11:18+00:00; +4h00m03s from scanner time.
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
32768/tcp open  status      1 (RPC #100024)

Host script results:
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: 4h00m02s
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.76 seconds

```

 we can see that there is a Apache running on port 80 check it out 

    http://192.168.57.4

It doesn't have  much information on it.

## Scanning
 Let's use nikto
```
nikto is a web vulnerability scanner
```
Scan result :

```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.57.4
+ Target Hostname:    192.168.57.4
+ Target Port:        80
+ Start Time:         2024-08-11 09:14:56 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ /: Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Thu Sep  6 03:12:46 2001. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Apache is vulnerable to XSS via the Expect header. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3918
+ OpenSSL/0.9.6b appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.9.6) (may depend on server version).
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution.
+ Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system.
+ Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell.
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS). See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0835
+ /manual/: Directory indexing found.
+ /manual/: Web server manual found.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /test.php: This might be interesting.
+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpress/wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpress/wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpress/wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
+ /shell?cat+/etc/hosts: A backdoor was identified.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8908 requests: 0 error(s) and 30 item(s) reported on remote host
+ End Time:           2024-08-11 09:15:56 (GMT0) (60 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

 



