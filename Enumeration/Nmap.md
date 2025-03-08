# Nmap
Basic and Advanced Commands for Using Nmap CLI Version
## Enumerating Targets
### Specifying targets using:
```
list:              MACHINE_IP scanme.nmap.org example.com
range:             10.11.12.15-20
subnet:            MACHINE_IP/30
file as input:     nmap -iL nameofthefile.txt
```
### Fine-Tuning Scope
```
single port:            -p20
port list:              -p22,89,443
port range:             -p1-200
scan all port:          -p- (65535 ports)
scan the x top ports:   --top-ports x (x=10,100,1000)
scan timming:           -T<0-5>
use -T0 or -T1 to avoid IDS

0 - Paranoid
1 - Sneaky (used in real engagements, takes TOO MUCH time)
2 - Polite
3 - Normal (nmap default)
4 - Aggressive (used for CTF)
5 - Insane (could loss packets)
```
## Host Discovery
```
-sn  : Ping scan (default) and disabled port-scan
-PR  : ARP scan only
-PE  : ICMP echo request (ICMP type 8, default ICMP echo request, usually blocked by firewall)
-PP  : ICMP timestamp request (ICMP type 13) expecting timestamp request (ICMP type 14)
-PM  : ICMP address mask queries (ICMP type 17) expecting address mask reply (ICMP type 18)
-PS  : TCP SYN ping (port 80, by default, you should specify ports. Privileged users can not complete the 3-way handshake)
-PA  : TCP ACK ping (port 80, by default, you should specify ports. you should receive a TCP RST) <- privileged user
-n   : Avoid reverse-DNS online host (Nmap’s default behaviour).The hostnames can reveal a lot, this can be a helpful step.
-R   : Query DNS server for offline host and specify the DNS server ussing --dns-server DNS_SERVER_IP
-Pn  : Disable ping scan, threat all host as online
```
## Port Scan
### Basic Port Scan
```
-sT : TCP Connect Scan (Complete 3-way handshake for open ports, RST/ACK to respond SYN for closed ports)
-sS : TCP SYN Scan (Incomplete 3-way, after the host receives the SYN/ACK from the server, thi tears down the connection with RST,ACK flag)
-sU : UDP Scan, if the port is open it won't send any message back, but if it is close, the victim machin will show ICMP Type 3 (HosUnreachable)
-F : Enable Fast Mode
-r : don't Random order
-v : verbose
```
### Advanced Port Scan
In these types of scan, nmap cannot be sure if the port is open or filtered by firewall, because in both cases, there won't be a RST, ACK and it will show open|filtered state on the port
```
-sN : NULL Scan, all six flags are set to zero, it's not accurate
-sF : FIN Scan, FIN flag set, not accurate
-sX : Xmas Scan, used to avoid stateless firewall.
-sM : Maimon Scan, OBSOLETE due to change in RFC 793 (TCP) that won't be sure if the port is open or close
```
### Custom Flags Scan
```
-scanflags: custom your TCP Header
```
```
Example:
 nmap --scanflags SYNRSTURG
```
Flags:
- URG
- ACK
- PSH
- RST
- SYN
- FIN

## Post-Port Scan
```
-sV                       : Service detection (necessary to stablish 3-way handshake connection)
--version-intensity LEVEL : Set the intensity of the scan (0-9)
--version-light           : intensity 2
--version-all             : intensity 9
-O                        : OS detection, not accurate, but make good guesses
--traceroute
```
## Nmap Script Engine (NSE)
### Scripts Default Path:
```
/usr/share/nmap/scripts
```
### Scripts Execution
```
-sC : run the scripts in the default category
```
#### Execute a specific category of scripts
```
--script=default : execute a specific category of scripts
```
- auth
- broadcast
- brute
- discovery
- dos
- exploit
- fuzzer
- intrusive
- malware
- safe
- version
- vuln

#### Specific Script or Pattern
```
--script=SCRIPT-NAME : run a specific script
--script='pattern' : run script that match with that pattern
```

example:
```
--script=ftp*
```

## Performance
### Timeouts
```
--initial-rtt-timeout <value>ms :	  Sets the specified time value as initial RTT timeout
--max-rtt-timeout <value>ms     :   Sets the specified time value as maximum RTT timeout.
--min-rtt-timeout 
```
### Retries
```
default value           : 10
--max-retries <retries> : specify the retry rate of the sent packets
```
### Timing
```
-T 0 or -T paranoid
-T 1 or -T sneaky
-T 2 or -T polite
-T 3 or -T normal
-T 4 or -T aggressive
-T 5 or -T insane
```
###  Parallelism
```
--min-parallelism <number>
--max-parallelism <number>
```

## Evasion
### Firewall Evasion
```
-sA : TCP ACK Scan won't tell us the state of the port, just if the port is blocked or not by the firewall. Very usefull to check the firewall's rules.
-sW : Window Scan, similar to TCP ACK Scan, but it will show us much information against a server behind a Firewall.
-f  : Fragment packets
```
### Spoofing and Decoy (IPS/IDS Detection)
#### Spoofing
```
-S SPOOFED_IP              
--spoof-mac SPOOFED_MAC
```
#### Decoy
```
-D DECOY_IP1, DECOY_IP2, DECOY_IP3 . . . ., DECOY_IPn, ME : Make the scan appear to be incoming from many ip addresses
```
example:
```
nmap -D 10.10.2.3, ME, 10.10.2.68, RND, RND 'Target_IP'
```
or
```
nmap -D RND:5 'Target_IP'
```
ME : The turn to scan with my own ip
RND: generate a random source ip
#### Zombie
Requires an idle system connected to the network that you can communicate with. Nmap will make each probe appear as if incoming from the zombie host. Then it will check for indicator whether the zombie host receive any response to the spoofed probe.
```
-sI ZOMBIE_IP 
```
#### Source Port
``` 
--source-port 53 : DNS Proxying (Used to bypass IDS/IPS and firewalls)
```
## Getting More Details
```
--reason         : Provide more details about the scan
-v               : Detailed output
-vv              : Even more detailed output
-d               : Debugging details
-dd              : Even more debug details
--packet-trace   : Trace Packets
```






