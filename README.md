# RCE in ATutor 2.1.1

## Chained vulnerabilities in ATutor 2.1.1 lead to unauthenticated remote code execution (RCE).

I developed a Python script to exploit multiple vulnerabilities and achieve RCE.

## The vulnerabilities are:
1. Unauthenticated Blind SQL Injection: Allows dumping of hashed passwords for the teacher user.
2. Authentication Bypass: Enables login with any account using the hashed password (no need to crack the password).
3. Arbitrary File Upload: Leads to remote code execution (RCE) via the ZipSlip vulnerability.
4. With my Python script, you can exploit all vulnerabilities without needing to target them individually.

using the code
```bash
git clone https://github.com/x6vrn/rce_atutor_2.1.1.git && cd rce_atutor_2.1.1
```
```bash
python3 atutor_RCE.py <target>
```
**example:**
```bash
python3 atutor_RCE.py http://127.0.0.1:8000
```

*Made by Anas Almizani*
