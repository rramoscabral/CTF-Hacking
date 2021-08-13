# CTF Hacking
Capture The Flag (CTF)


CTFs are information security competitions in conferences or events.



## Types of Challenges

There are several different challenges:
 - **Cryptography** Can be "real world" scenarios about encryption (base64, roman cypher, RSA, etc) ransomware and others.
 - **Exploitation** Basicly using exploit like SQL injection, buffer overflow, string format, etc.
 - **Penetration Testing Labs/Pwn** - Exploiting a servers.
 - **Programming** Require some sort of programming like PHP, C#, Java, ect.
 - **Reverse Engineering/Binary** - Reverse engineering or exploiting a binary file.
 - **Steganography** Finding information hidden in files or image.
 - **Web** Exploiting web pages


## Operation Systems


| Operating System | Distro | Description |
|---|---|---|
| [Android Tamer](https://androidtamer.com/) | Debian | For Android Security professionals to work on large array of android security related task’s ranging from Malware Analysis, Penetration Testing and Reverse Engineering.|
| [BackBox](https://backbox.org/) | Ubuntu| It is for penetration testers and security researchers.  It is a Free Open Source Community Project with the aim of promoting the culture of security in IT environment and give its contribution to make it better and safer.|
| [BlackArch Linux](https://blackarch.org/) | Arch Linux | It is for penetration testers and security researchers.|
| [Fedora Security Lab](https://labs.fedoraproject.org/security/) | Fedora | Provides a safe test environment to work on security auditing, forensics, system rescue and teaching security testing methodologies. |
| [Kali Linux](https://www.kali.org/)| Debian | It is an open-source Linux distribution geared towards various information security tasks, such as Penetration Testing, Security Research, Computer Forensics and Reverse Engineering. |
| [Parrot Security OS](https://www.parrotsec.org/) | Debian| Parrot is a worldwide community of developers and security specialists that work together to build a shared framework of tools to make their job easier, standardized and more reliable and secure. |
| [Pentoo](http://www.pentoo.ch/) | Gentoo | It is designed for penetration testing and security assessment.|
| [URIX OS](http://urix.us/) | openSUSE | It is the sucessor of NetSecL OS also know as ISlack. |
| [Wifislax](http://www.wifislax.com/) | Slackware | It is alinux live cd designed by www.seguridadwireless.net and is adapted for wireless. |

<br>

## Tools


### Files

| Tool | Description |
|--|--|
|[binwalk](https://github.com/ReFirmLabs/binwalk) | Analyze and extract files |

<br>

### Forensics

| Tool | Description |
|--|--|
|[Dnscat2](https://github.com/iagox86/dnscat2) | Hosts communication through DNS.|
|[Kroll Artifact Parser and Extractor (KAPE)](https://learn.duffandphelps.com/kape) |Triage program.|
|[Magnet AXIOM](https://www.magnetforensics.com/downloadaxiom) | Artifact-centric DFIR tool.|
|[Registry Dumper](http://www.kahusecurity.com/posts/registry_dumper_find_and_dump_hidden_registry_keys.html) | Dump your registry.|

<br>

### Crypto

| Tool | Type | Description |
|--|--|--|
|[CyberChef](https://gchq.github.io/CyberChef) |  | Web app for analysing and decoding data.|
|[FeatherDuster](https://github.com/nccgroup/featherduster) |  | An automated, modular cryptanalysis tool.|
|[Hash Extender](https://github.com/iagox86/hash_extender) |  | A utility tool for performing hash length extension attacks.|
|[padding-oracle-attacker](https://github.com/KishanBagaria/padding-oracle-attackerl) |  | A CLI tool to execute padding oracle attacks.|
|[PkCrack](https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html) |  | A tool for Breaking PkZip-encryption.|
|[QuipQuip](https://quipqiup.com/) |  | An online tool for breaking substitution ciphers or vigenere ciphers (without key).|
|[RSACTFTool](https://github.com/Ganapati/RsaCtfTool) |  | A tool for recovering RSA private key with various attack.|
|[RSATool](https://github.com/ius/rsatool) |  | Generate private key with knowledge of p and q.|
|[XORToo](https://github.com/hellman/xortool) |  | A tool to analyze multi-byte xor cipher.|

<br>

### Binary

| Tool | Description |
|--|--|
|[GDB](https://www.gnu.org/software/gdb/) - Binary debugger |

<br>

### Passwords

| Tool | Type | Description |
|--|--|--|
|[Hashcat](https://hashcat.net/hashcat/) | Bruteforce |Password Cracker.|
|[Hydra](https://tools.kali.org/password-attacks/hydra) | Bruteforce |A parallelized login cracker which supports numerous protocols to attack.|
|[John The Jumbo](https://github.com/magnumripper/JohnTheRipper) | Bruteforce |Community enhanced version of John the Ripper.|
|[John The Ripper](http://www.openwall.com/john/) | Bruteforce |Password Cracker.|
|[Nozzlr](https://github.com/intrd/nozzlr) | Bruteforce |Nozzlr is a bruteforce framework, trully modular and script-friendly.|
|[Ophcrack](http://ophcrack.sourceforge.net/) | Bruteforce |Windows password cracker based on rainbow tables.|
|[Patator](https://github.com/lanjelot/patator) | Bruteforce |Patator is a multi-purpose brute-forcer, with a modular design.|
|[Turbo Intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack) | Bruteforce |Burp Suite extension for sending large numbers of HTTP requests.|

<br>

### Penetration Testing/Pwn

| Tool | Type |Description |
|--|--|--|  
|[Bettercap](https://github.com/bettercap/bettercap) | Man in the Middle |Framework to perform MITM (Man in the Middle) attacks.|
|[burp suite](https://portswigger.net/burp) | | Feature packed web penetration testing framework |
| [Masscan](https://github.com/robertdavidgraham/masscan) | Network scanner | Mass IP port scanner, TCP port scanner.|
| [Monit](https://linoxide.com/monitoring-2/monit-linux/) |Network  | A linux tool to check a host on the network (and other non-network activities).|
| [Nipe](https://github.com/GouveaHeitor/nipe) | Tor Network | Nipe is a script to make Tor Network your default gateway.|
| [Nmap](https://nmap.org/)| Network auditing | An open source utility for network discovery and security auditing.|
| [Wireshark](https://www.wireshark.org/) | Network dumps | Analyze the network dumps. `(apt-get install wireshark)`|
| [Yersinia](https://github.com/tomac/yersinia)| Network layer 2 | Attack various protocols on layer 2.|
| [Zeek](https://www.zeek.org) | Network monitor | An open-source network security monitor.|
| [Zmap](https://zmap.io/) | Network auditing | An open-source network scanner.|

<br>

### Reverse Engineering

| Tool | Type | Description |
|--|--|--|  
|[Flare VM](https://github.com/fireeye/flare-vm/) | Malware analysts | Based on Windows.|
|[REMnux](https://remnux.org/) | Malware analysts | Based on Debian.|

<br>

### Steganography

| Tool | Description |
|--|--|
|[stegsolve](http://www.caesum.com/handbook/Stegsolve.jar) | Pass various filters over images to look for hidden text |

<br>

### WEB

| Tool | Type | Description |
|--|--|--|
|[Detox](http://relentless-coding.org/projects/jsdetox/install) | JavaScript Deobfuscators | A Javascript malware analysis tool.
|[Metasploit JavaScript Obfuscator](https://github.com/rapid7/metasploit-framework/wiki/How-to-obfuscate-JavaScript-in-Metasploit) | JavaScript Obfustcators | |
|[Revelo](http://www.kahusecurity.com/posts/revelo_javascript_deobfuscator.html) | JavaScript Deobfuscators | Analyze obfuscated Javascript cod
|[Uglify](https://github.com/mishoo/UglifyJS) | JavaScript Obfustcators | |

<br>




