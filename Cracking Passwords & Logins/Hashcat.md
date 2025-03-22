# Mutation Rules

| **Function** | **Description** |
| --- | --- |
| `:` | Do nothing. |
| `l` | Lowercase all letters. |
| `u` | Uppercase all letters. |
| `c` | Capitalize the first letter and lowercase others. |
| `sXY` | Replace all instances of X with Y. |
| `$!` | Add the exclamation character at the end. |

More info:
[https://hashcat.net/wiki/doku.php?id=rule_based_attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

## Generating a Rule-based Wordlist

```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

# Cracking Hashes

## **Running Hashcat against NT Hashes**

```bash
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

## **Hashcat - Cracking Unshadowed Hashes**

```bash
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

## Hashcat - Cracking MD5 Hashes

```bash
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

## Hashcat - Cracking Bitlocker Encryption

```bash
hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
```

## Cracking the TGS offline with Hashcat

```jsx
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```
