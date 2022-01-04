# OSCP-Cheat-Sheets
Preparation OSCP

## Recon
```bash
nmap -Pn -sT -sV -n <IP> -p- --min-rate 1000 --max-retries 2
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
```
```bash
curl -s -i -k https://<IP>
curl -L <URL>
```
```bash
nikto -h http://192.168.106.11 -C all
```

## Fuzzer directory
```bash
dirb <URL>
python3 /opt/dirsearch/dirsearch.py -u <URL> -e php,txt -x 403
python3 /opt/dirsearch/dirsearch.py -u <URL> -w /usr/share/dirb/wordlists/big.txt -e php,txt
python3 /opt/dirsearch/dirsearch.py -u <URL> -e php,txt -x 403 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

## Explotation

### Interactive shell
```bash
script /dev/null -c bash
ctrl + ^Z
stty raw -echo
fg
reset
xterm
export TERM=xterm-256color
export SHELL=bash
stty rows 26 columns 211
```
stty -a # get rows and colummns



 
## Privilege escalation
https://gtfobins.github.io
```bash
sudo -l
```
### SUID
```bash
find / -perm -u=s -type f 2>/dev/null
$ zsh
```

