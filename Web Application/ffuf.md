# ffuf
## Directory Fuzzing
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```
"FUZZ" is a placeholder used to specify where the wordlist values will be inserted.

## Pages Fuzzing
### Extension Fuzzing
```
ffuf -w /<SNIP>/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```
##### NOTE
Check if the chosen wordlist already contains a dot (.), so it doesn’t have to add the dot after "index" in fuzzing.

### Page Fuzzing
```
ffuf -w /<SNIP>/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```
### Double Fuzzing
```
ffuf -w wls.txt:FUZZ -w wls2.txt:FUZZ_2 -u http://83.136.251.117:57774/blog/FUZZ_2FUZZ -mc 200,302,301 -ic 
```

## Recursive Scanning
```
ffuf -w ~/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v

-e                  : extension
-recursion          : Enable recursion
-recursion-depth    : Set the recursion depth (ex. 1, /home/blog, if there is any directory over
                      blog, it won't be scanned.
```
## Domain Fuzzing
### Add a DNS Record 
```
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```
### Sub-Domain Fuzzing
```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb
```
##### NOTE
if the Fuzzed domain is not public, ffuf won’t get any results. This means that there are no public sub-domains under academy.htb,
as it does not have a public DNS record, as previously mentioned. Even though we did add academy.htb to our /etc/hosts file, 
we only added the main domain, so when ffuf is looking for other sub-domains, it will not find them in /etc/hosts, and will ask the public DNS,
which obviously will not have them.
### VHost Fuzzing

The key difference between VHosts and sub-domains is that a VHost is basically a 'sub-domain' served on the same server and has the same IP,
such that a single IP could be serving two or more different websites.

```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```
##### NOTE
If the VHost does exist and we send a correct sub-domain in the header, we should get a different response size. It is possible to 
filter by response size using the *-fs* flag

## Parameter Fuzzing
### GET
```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```
### POST
```
ffuf -w burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
##### NOTE
In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'"

### Retrieving Response using POST with cUrl
```
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```
### Value Fuzzing
Example: ids.txt is a wordlist containing all numbers from 1-1000.

```
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
## OPTIONS

### Filter Response by Status Code
```
ffuf -w ~/Tools/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://83.136.251.117:57774/blog/FUZZ.php -mc 200,301,302

-mc (match code)
```

### Output name and format (Default JSON)
```
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -t 200 -o directories_found -of html
```

### Increase Threads 
```
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -t 200
```
