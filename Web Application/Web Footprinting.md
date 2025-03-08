# Whois
The WHOIS protocol is a query and response protocol used to retrieve information about the registration details of domain names, IP addresses, and autonomous systems.
It allows users to access data about the owner of a domain, including contact information, registration dates, and domain status.
```
whois <DOMAIN_NAME>
```
# crt.sh Look Up
```
curl -s "https://crt.sh/?q=<DOMAIN_NAME>&output=json" | jq -r '.[] | select(.name_value | contains("<DOMAIN>")) | .name_value' | sort -u
```
# DNS
## Hosts file
The hosts file is a local system file used to map hostnames to IP addresses. It allows a computer to resolve domain names to IP addresses before querying external DNS servers.
### Windows
```
C:\Windows\System32\drivers\etc\hosts 
```
### Linux and MacOS
```
/etc/hosts
```
## dig command
```
dig example.com                   : Default A record lookup for the domain.
dig example.com <RecordType>      : Retrieves specific DNS Record type for the domain
dig @1.1.1.1 domain.com           : Specifies a specific name server to query; in this case 1.1.1.1
dig +trace domain.com             : Shows the full path of DNS resolution.
dig -x 192.168.1.1                : Reverse lookup for a given IP. It needs to specify a Name Server
dig +short domain.com             : Provides a short, concise answer to the query.
dig +noall +answer domain.com     : Displays only the answer section of the query output.
dig domain.com ANY                : Retrieves all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse)
dig axfr @<nameserver> domain.com : Exploiting Trasnfer zone
```
# Sub-Domains Brute Forcing
## DNSEnum
```
dnsenum --enum <DOMAIN_NAME> -f <WORDLIST_PATH> -r
```
# VHost Enumeration
The key difference between VHosts and sub-domains is that a VHost is basically a 'sub-domain' served on the same server and has the same IP, such that a single IP could be serving two or more different websites.
## Gobuster
```
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain


-t     : Increase the number of threads for faster scanning.
-k     : Ignore SSL/TLS certificate errors.
-o     : Output file.
```
Note: You need to modify your host file with your target domain
## ffuf 
```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://example.com:PORT/ -H 'Host: FUZZ.example.com'
```
# WAF Detection
## Wafw00f
```
wafw00f <DomainNameOrURL> 
```
# Automated Web Footprinting Scanner
## Nikto
```
nikto -h <DOMAIN_NAME> -Tuning b

-h        : Specify a Domain Name
-Tuning b : Only run the Software Identification modules
```
# Web Crawler
## Recon Spider
```
python3 ReconSpider.py http://<START_URL>/
```

