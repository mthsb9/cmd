# ICMP

## OS Detection using ICMP-TTL

### Windows Host TTL (32/128)

```
ping 192.168.86.39 
PING 192.168.86.39 (192.168.86.39): 56 data bytes
64 bytes from 192.168.86.39: icmp_seq=0 ttl=128 time=102.920 ms
64 bytes from 192.168.86.39: icmp_seq=1 ttl=128 time=9.164 ms
64 bytes from 192.168.86.39: icmp_seq=2 ttl=128 time=14.223 ms
64 bytes from 192.168.86.39: icmp_seq=3 ttl=128 time=11.265 ms
```
# FTP

Port 21 - Control Channel
Port 20 - Data Transmission (active mode only)
## Using FTP Client

```bash
ftp <IP_Address or DOMAIN_NAME> 
```
## CLI Commands

```bash
get <REMOTE_FILE> <LOCAL_FILE>     : Download a file from the FTP Server.
put <LOCAL_FILE> <REMOTE_FILE>     : Upload a file to the FTP Server.
delete <REMOTE_FILE>               : Delete a file. 
bye/quit                           : Quit FTP Server
```

## Anonymous Login

```bash
User:       anonymous
password:
```

## Download All Available Files

```bash
wget -m --no-passive [ftp://<USERNAME>:<PASSWORD>@](ftp://anonymous:anonymous@10.129.14.136/)<IP_Adress>
```

## TLS/SSL Encryption FTP

```bash
openssl s_client -connect <IP_Address>:<PORT> -starttls ftp
```

## TFTP

Port 69 (UDP)

### Using TFTP Client

```bash
tftp <IP_Address or DOMAIN_NAME> 
```

### CLI Commands

```bash
connect 	                        : Sets the remote host, and optionally the port, for file transfers.
get 	                            : Transfers a file or set of files from the remote host to the local host.
put 	                            : Transfers a file or set of files from the local host onto the remote host.
quit 	                            : Exits tftp.
status                            :	Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on.
verbose 	                        : Turns verbose mode, which displays additional information during file transfer, on or off.
```

# SMB

**NetBIOS implementation (Old Version)**

Port 137/TCP (NetBIOS Name)

Port 138/TCP (NetBIOS Datagrams)

Port 139/TCP (NetBIOS Sessions) 

**SMB over TCP/IP**

Port 445/TCP

## smbclient Commands (Linux)

### List Shares

```bash
smbclient -N -L [//](https://10.129.14.128/)<IP_ADDRESS>

-L              : List Shares of a given Domain
-N              : Null Session (anonymous login)
```

### Connecting to a share

```bash
smbclient [//<IP_ADDRESS>/](https://10.129.14.128/notes)<SHARE>
```

### Useful commands

```bash
get <file_name>  : Download a file from the Server
!<cmd>           : Execute a local command

Example:
!ls              : List current directory (local)
```

## SMB Server

Execute these commands from the server-side. 

```bash
smbstatus         :    Check SMB Connections
```

## SMB Enumeration using rpcclient

```bash
rpcclient -U "" 10.129.14.128
```

### rpcclient Querys

```bash
srvinfo 	                   : Server information.
enumdomains 	               : Enumerate all domains that are deployed in the network.
querydominfo 	               : Provides domain, server, and user information of deployed domains.
netshareenumall 	           : Enumerates all available shares.
netsharegetinfo <share>      : Provides information about a specific share.
enumdomusers 	               : Enumerates all domain users.
queryuser <USER_RID> 	       : Provides information about a specific user.
querygroup <GROUP_RID>       : Provides information about a specific group
```

### **Brute Forcing User RIDs**

```bash
Bash One-Liner

for i in $(seq 500 1100);do rpcclient -N -U "" <IP_ADDRESS> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

Impacket 

samrdump.py <IP_ADDRESS>
```

## SMB Enumeration using CrackMapExec

```bash
crackmapexec smb <IP_ADDRESS> --shares -u '' -p ''
```

## SMB Enumeration with **Enum4Linux-ng**

Installation

```bash
$ git clone [https://github.com/cddmp/enum4linux-ng.git](https://github.com/cddmp/enum4linux-ng.git)
$ cd enum4linux-ng
$ pip3 install -r requirements.txt
```

Enumeration

```
./enum4linux-ng.py <IP_ADDRESS> -A
```

# NFS

Port 111 (TCP/UDP)

Port 2049 (TCP/UDP)

## Using NSE (nmap)

```bash
sudo nmap --script nfs* <IP_ADDRESS> -sV -p111,2049
```

## **Show Available NFS Shares**

```
showmount -e <IP_ADDRESS>
```

## **Mounting NFS Share**

```
$ mkdir target-NFS
$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
$ cd target-NFS
$ tree .
.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share
```

## **List Contents with UIDs & GUIDs**

```bash
ls -n <PATH_TO_THE_SHARE>
```

It is important to note that if the `root_squash` option is set, we cannot edit the `backup.sh` file even as `root`.

## NFS Privilege Escalation

If we have access to the system via SSH and want to read files from 
another folder that a specific user can read, we would need to upload a 
shell to the NFS share that has the `SUID` of that user and then run the shell via the SSH user.

## **Unmounting**

```bash
sudo umount ./target-NFS
```

# DNS

Port 53 (TCP/UDP)

## dig -  Check Name Servers

```bash
dig <DOMAIN_NAME> NS              
```

## dig - Version Query

```bash
dig CH TXT version.bind @<DNS_SERVER>
```

## dig -  ANY Query

```bash
dig any <DOMAIN_NAME> @<NAME_SERVER>
```

## dig - Make a Transfer Zone

```bash
dig @<NAME_SERVER> <DOMAIN_NAME> axfr 
```

## dnsenum - Brute Force Subdomain Enumeration

```bash
dnsenum --dnsserver <DNS_SERVER> --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt <DOMAIN_NAME>
```

# SMTP

Port 25 (TCP) - Standard Version

Port 587 (TCP) - Newer Versions

Port 465 (TCP) - Encrypted Connection

## SMTP Commands

| **Command** | **Description** |
| --- | --- |
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client. |
| `HELO` | The client logs in with its computer name and thus starts the session. |
| `MAIL FROM` | The client names the email sender. |
| `RCPT TO` | The client names the email recipient. |
| `DATA` | The client initiates the transmission of the email. |
| `RSET` | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY` | The client checks if a mailbox is available for message transfer. |
| `EXPN` | The client also checks if a mailbox is available for messaging with this command. |
| `NOOP` | The client requests a response from the server to prevent disconnection due to time-out. |
| `QUIT` | The client terminates the session. |

## Telnet - HELO/EHLO

```bash
> telnet <IP_ADDRESS> <PORT(25)>

HELO mail1.inlanefreight.htb

EHLO mail1
```

## Enumerating Users - VRFY

```
VRFY root

252 2.0.0 root

VRFY cry0l1t3

252 2.0.0 cry0l1t3

```

SMTP Response Codes: [https://serversmtp.com/smtp-error/](https://serversmtp.com/smtp-error/)

## Send an Email

```
> telnet 10.129.14.128 25
Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server

> EHLO inlanefreight.htb

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING

> MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok

> RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok

DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work.
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB

QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

## Nmap - Open Relay Scan

```bash
sudo nmap <IP_ADDRESS> -p25 --script smtp-open-relay -v
```

## smtp-user-enum Tool

```jsx
smtp-user-enum -w <QUERY_TIMEOUT> -t <IP_ADRESS> -M <METHOD> -U <WORDLIST> -m <WORKER_PROCESS>

Example
smtp-user-enum -w 15 -t 10.129.28.199  -M VRFY -U footprinting-wordlist.txt -m 1

This example was used for VERY silent
```

## Send mail using sendmail

```bash
echo -e "Subject: Prueba de enlace\n\nEste es un correo de prueba. Puedes acceder al siguiente enlace: http://localhost:3000/axel/TEST.git" |sendmail jobert@localhost
```

# IMAP/POP3

IMAP 

Port 143 - TCP

Port 993 - TCP/alternative Port

## IMAP Commands

| **Command** | **Description** |
| --- | --- |
| `1 LOGIN username password` | User's login. |
| `1 LIST "" *` | Lists all directories. |
| `1 CREATE "INBOX"` | Creates a mailbox with a specified name. |
| `1 DELETE "INBOX"` | Deletes a mailbox. |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox. |
| `1 LSUB "" *` | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX` | Selects a mailbox so that messages in the mailbox can be accessed. |
| `1 UNSELECT INBOX` | Exits the selected mailbox. |
| `1 FETCH <ID> all` | Retrieves data associated with a message in the mailbox.  (just Headers |
| `1 CLOSE` | Removes all messages with the `Deleted` flag set. |
| `1 LOGOUT` | Closes the connection with the IMAP server. |
| `1 FETCH <ID> BODY[]` | Retrieves data associated with a message in the mailbox (all content) |

## POP3 Commands

| **Command** | **Description** |
| --- | --- |
| `USER username` | Identifies the user. |
| `PASS password` | Authentication of the user using its password. |
| `STAT` | Requests the number of saved emails from the server. |
| `LIST` | Requests from the server the number and size of all emails. |
| `RETR id` | Requests the server to deliver the requested email by ID. |
| `DELE id` | Requests the server to delete the requested email by ID. |
| `CAPA` | Requests the server to display the server capabilities. |
| `RSET` | Requests the server to reset the transmitted information. |
| `QUIT` | Closes the connection with the POP3 server. |

## **cURL**

```bash
curl -k 'imaps://10.129.14.128' --user <USERNAME>:<PASSWORD> -v
```

## **OpenSSL - TLS Encrypted Interaction POP3**

```bash
openssl s_client -connect <IP_ADDRESS>:pop3
```

## **OpenSSL - TLS Encrypted Interaction IMAP**

```bash
openssl s_client -connect <IP_ADDRESS>:imaps
```

# SNMP

Port 161 - UDP

Port 162 - UDP (traps)

## SNMPwalk

```bash
snmpwalk -v2c -c public <IP_ADDRESS>
```

## **OneSixtyOne - Bruteforce Community Strings**

```bash
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
```

## braa - Bruteforcing OIDs

```bash
braa <community string>@<IP>:.1.3.6.*

:.1.3.6.*: OIDs Range
```

# MySQL

Port 3306 - TCP

## MySQL - Interaction

```bash
mysql -u <USER> -h <IP_ADDRESS>
mysql -u <USER> -p<PASSWORD> -h <IP_ADDRESS>   
```

## MySQL - CLI Commands

```
show databases;                                        : Show all databases.
select version(); 
use <DB_NAME>;                                         : Select one of the existing databases.
show tables;                                           : Show all available tables in the selected database.
show columns from <TABLE>; 	                           : Show all columns in the selected database.
select * from <TABLE>; 	                               : Show everything in the desired table.
select * from <TABLE> where <COLUMN> = "<STRING>"; 	   : Search for needed string in the desired table.
```

# MSSQL

Port 1433 - TCP

## NSE for MSSQL

```
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=<PORT>,mssql.username=<USERNAME>,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

## mssql_ping - Metasploit

```
msf6 auxiliary(scanner/mssql/mssql_ping)
```

## **Connecting with mssqlclient.py**

```
python3 mssqlclient.py <USERNAME>@<IP_ADDRESS> -windows-auth
```

# Oracle TNS

Port 1521 - TCP

## **Nmap - SID Bruteforcing**

Used for discover a Oracle database instance (SID)

```jsx
sudo nmap -p1521 -sV <IP_ADDRESS> --open --script oracle-sid-brute
```

## Metasploit - SID Bruteforcing

```
msf6 auxiliary(**scanner/oracle/sid_brute**)
```

## ODAT (Oracle Database Attacking Tool)

```jsx
./odat.py all -s <IP_ADDRESS>
```

## SQLPlus - Log In

```
sqlplus <USERNAME>/<PASSWORD>@<IP_ADDRESS>/<SID>
```

## **Oracle RDBMS - Interaction**

```
SQL> select table_name from all_tables;
SQL> select * from user_role_privs;
```

## SQLPlus - Log In as sysdba

```
sqlplus <USERNAME>/<PASSWORD>@<IP_ADDRESS>/<SID> as sysdba
```

## **Oracle RDBMS - Extract Password Hashes**

```
SQL> select name, password from sys.user$;
```

## **Oracle RDBMS - File Upload**

### Web Servers Default Path

```
/var/html/www           : Linux
C:\inetpub\wwwroot      : Windows

C:\\inetpub\\wwwroot    : Fixed Windows 
```

### Using ODAT

```
./odat.py utlfile -s <IP_ADDRESS> -d <SID> -U <USERNAME> -P <PASSWORD> --sysdba --putFile <WEB_SERVER_PATH> <FileName> ./<FileName>
```

### Accessing the file using cURL

```
curl -X GET http://<IP_ADDRESS>/<FileName>
```

# IPMI

Port 623 - UDP

## NSE for IPMI

```
sudo nmap -sU --script ipmi-version -p 623 <IP_ADDRESS>
```

## IPMI Information Discovery - Metasploit

```
msf6 auxiliary(scanner/ipmi/ipmi_version)
```

IPMI - Default Passwords

| Product | Username | Password |
| --- | --- | --- |
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN | ADMIN |

## Cracking IPMI2 RAKP HMAC-SHA Hash with Hashcat

```
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u

-m 7300            :   Mode IPMI2 RAKP HMAC-SHA
ipmi.txt           :   Hash list file
-a 3               :   Brute Force attack
?1?1?1?1?1?1?1?1   :   '?1' Place to bruteforce
-1 ?d?u            :   Digit 0-9, and A-Z Uppercase
```

## Metasploit Dumping Hashes

```html
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)
```

# SSH

Port 22 - TCP

## Basic Syntax

```bash
ssh <USERNAME>@<IP_ADDRESS>
```

## Using Key Pair

```bash
ssh <USERNAME>@<IP_ADDRESS> -i <privatekey>

first you need to give it the right permissions
> chmod 600 id_rsa
```

## ssh-audit

```html
./ssh-audit.py <IP_ADDRESS>
```

## Change Authentication Method

Using this command allow you to use a preferred method. Useful for Brute Force Attack

```bash
ssh -v <USERNAME>@<IP_ADDRESS> -o PreferredAuthentications=password
```

# Rsync

Port 873 -TCP

## **Probing for Accessible Shares (Example)**

```
> nc -nv <IP_ADDRESS> 873

(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
dev            	Dev Tools
@RSYNCD: EXIT
```

## **Enumerating an Open Share (Example)**

Following the previous example, we can see a share called `dev`, and we can enumerate it further

```
> rsync -av --list-only rsync://<IP_ADDRESS>/dev

receiving incremental file list
drwxr-xr-x             48 2022/09/19 09:43:10 .
-rw-r--r--              0 2022/09/19 09:34:50 build.sh
-rw-r--r--              0 2022/09/19 09:36:02 secrets.yaml
drwx------             54 2022/09/19 09:43:10 .ssh

sent 25 bytes  received 221 bytes  492.00 bytes/sec
total size is 0  speedup is 0.00
```

## Sync Files to the Attacking Machine

```bash
rsync -avz -e ssh <USERNAME>@<IP_ADDRESS>:/remote/path /local/path
```

## Guide - Rsync Abuse

[https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync)

## Guide - Rsync Transfer Files

[https://phoenixnap.com/kb/how-to-rsync-over-ssh](https://phoenixnap.com/kb/how-to-rsync-over-ssh)

# R-Services

Port 512, 513, 514 - TCP

## r-commands

```bash
Command | Service Daemon | Port |
rcp 	  | rshd    	     | 514  |	
rsh 	  | rshd 	         | 514  |
rexec 	| rexecd 	       | 512 	|
rlogin 	| rlogind 	     | 513 	|
```

## Logging-in Using rlogin

```bash
rlogin <IP_ADDRESS> -l <ACCOUNT_NAME>
```

### **Listing Authenticated Users Using Rwho**

Use these commands inside a rlogin session

```bash
rwho
```

 `rwho` daemon periodically broadcasts information about logged-on users, so it might be beneficial to watch the network traffic.

### **Listing Authenticated Users Using rusers**

```bash
rusers -al <IP_ADDRESS>
```

# RDP

Port 3389 - TCP

## **RDP Security Check**

*on GitClone Folder*

```bash
./rdp-sec-check.pl <IP_ADDRESS>
```

## **Initiate an RDP Session**

```bash
xfreerdp /u:<USERNAME> /p:"<PASSWORD>" /v:<IP_ADDRESS>
```

# WinRM

Port 5985 - TCP (using HTTP)

Port 5986 - TCP (using HTTPS)

## evil-winrm

```bash
evil-winrm -i <IP_ADDRESS> -u <USERNAME> -p <PASSWORD>
```

## **WinRM Session from Windows**

```bash
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```

# WMI

Port 135 - TCP

## WMIexec.py

```bash
> /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
```
