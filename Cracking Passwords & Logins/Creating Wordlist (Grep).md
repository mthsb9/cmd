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
