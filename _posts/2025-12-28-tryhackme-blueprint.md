---
title: "TryHackMe: Blueprint"
date: 2025-12-28 23:45:00 +0100
categories: [TryHackMe]
tags:
  - windows
  - web
  - oscommerce
  - rce
  - cve-2018-7204
  - credential-dumping
  - ntlm
  - sam
  - privilege-escalation
description: >-
  Blueprint demonstrates how an exposed legacy osCommerce installation can
  provide unauthenticated remote code execution as SYSTEM and lead directly to
  credential compromise and full administrative control.
author: lenovolegion7
media_subpath: /images/tryhackme_blueprint
image:
  path: room_image.webp
  alt: "Original TryHackMe Blueprint room artwork"
toc: true
comments: false
---

Blueprint is a Windows exploitation challenge centered on an outdated osCommerce installation exposed on TCP/8080. The validated path used an unauthenticated installation-script weakness to obtain command execution with `NT AUTHORITY\SYSTEM` privileges, then demonstrated credential compromise through local SAM/NTLM extraction and recovery of a local-user password.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Blueprint room card](room_card.webp){: w="298" h="272" .shadow }](https://tryhackme.com/room/blueprint){: .center }

## Executive Summary

The target exposed multiple Windows services, including:

```text
80/tcp    HTTP
135/tcp   MSRPC
139/tcp   NetBIOS
443/tcp   HTTPS
445/tcp   SMB
3306/tcp  MySQL
8080/tcp  HTTP / osCommerce
```

The validated attack path was:

1. enumerate the exposed Windows services;
2. identify the legacy osCommerce deployment on TCP/8080;
3. locate the accessible installation workflow under the catalog install path;
4. exploit the unauthenticated osCommerce 2.3.4.1 remote-code-execution condition;
5. obtain operating-system command execution;
6. confirm the web application context was already running as `NT AUTHORITY\SYSTEM`;
7. establish a stable native Windows session for post-exploitation;
8. dump local SAM credential material;
9. recover the password of the local `Lab` account from its NTLM hash;
10. access the final Administrator-level objective from the Administrator profile.

> **Result:** An unauthenticated remote attacker could move directly from exposed web access to SYSTEM-level command execution and complete local credential compromise.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Blueprint laboratory target.

Testing was limited to the assigned host and challenge objective. The public writeup does not publish target/attacker addresses, recovered NTLM hashes, plaintext passwords, or challenge proof values.

## Initial Enumeration

Representative service discovery:

```console
$ nmap \
  -p80,135,139,443,445,3306,8080 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

The HTTP/HTTPS services on standard ports did not expose the primary attack surface.

TCP/8080 hosted the relevant application:

```text
osCommerce 2.3.4.1
```

## Legacy osCommerce Installation Exposure

The application exposed an installation path beneath the osCommerce catalog:

```text
/oscommerce-2.3.4/catalog/install/
```

The legacy installation workflow remained reachable after deployment.

The vulnerable deployment was associated with:

```text
CVE-2018-7204
```

and allowed an unauthenticated attacker to modify application configuration in a way that resulted in arbitrary command execution.

## Unauthenticated Remote Code Execution

The exposed installer was abused to inject executable PHP behavior into the application configuration.

After exploitation, a harmless identity check returned:

```text
nt authority\system
```

This was especially severe because the Apache/osCommerce stack was already executing with SYSTEM-level privileges.

No separate local privilege-escalation exploit was required to reach the highest local Windows privilege.

## Stable Windows Session

The initial web-execution primitive was sufficient for command execution, but a native Windows session provided a more reliable post-exploitation context.

A controlled x86 Windows payload was transferred to the target and executed under the already-compromised SYSTEM context.

The public report omits operator callback addresses, payload binaries, and transport-specific details.

## Credential Harvesting

With SYSTEM-level access, local credential material was extracted from the Windows Security Account Manager.

Relevant local accounts included:

```text
Administrator
Lab
```

The raw NTLM hashes are not published:

```text
Administrator : [REDACTED]
Lab           : [REDACTED]
```

The `Lab` NTLM material was recoverable to a plaintext password, demonstrating full compromise of local account confidentiality.

The recovered password is intentionally redacted:

```text
Lab : [REDACTED]
```

## Administrator Objective

Because the exploitation path already provided `NT AUTHORITY\SYSTEM`, the host's administrative files were directly accessible.

The final challenge objective was located in the Administrator desktop context.

Its value is published only as:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Unauthenticated osCommerce Remote Code Execution

- **Severity:** Critical
- **Affected application:** osCommerce 2.3.4.1
- **Affected service:** HTTP on TCP/8080
- **CVE:** CVE-2018-7204
- **Impact:** unauthenticated SYSTEM-level command execution

The deployed osCommerce installation retained a vulnerable installation workflow that could be abused without authentication to introduce executable application configuration.

**Remediation:**

- remove all installation and setup files immediately after deployment;
- upgrade osCommerce to a currently supported release;
- prevent unauthenticated access to setup or administrative deployment routes;
- monitor application directories for unauthorized configuration changes;
- perform dependency and legacy-application inventory reviews.

### F-02 - Web Application Running with SYSTEM Privileges

- **Severity:** Critical
- **Affected component:** Apache/osCommerce service context
- **Impact:** web RCE immediately became full host compromise

The vulnerable application was running under a highly privileged Windows context. As a result, exploitation immediately returned `NT AUTHORITY\SYSTEM`.

**Remediation:**

- run web services under dedicated low-privilege service accounts;
- remove unnecessary local privileges and token rights;
- isolate web applications from administrative file locations;
- apply Windows service hardening and least privilege.

### F-03 - Local SAM Credential Exposure After SYSTEM Compromise

- **Severity:** High
- **Affected data:** local Windows account hashes
- **Impact:** compromise of Administrator and local-user credential material

SYSTEM access allowed the attacker to extract local SAM/NTLM material.

**Remediation:**

- treat SYSTEM compromise as credential compromise;
- rotate all local credentials after remediation;
- deploy Windows Defender Credential Guard where applicable;
- monitor credential-dumping behavior and suspicious access to SAM/LSA material;
- use unique managed local administrator passwords.

### F-04 - Recoverable Local User Password

- **Severity:** High
- **Affected account:** `Lab`
- **Impact:** plaintext local credential recovery

The recovered NTLM material for the `Lab` account was weak enough to be converted back into a plaintext password.

**Remediation:**

- require long, unique, high-entropy local passwords;
- prohibit weak and reused passwords;
- use Windows LAPS or another managed local-password solution;
- rotate all exposed credentials.

### F-05 - Unsupported Legacy Windows / Application Stack

- **Severity:** High
- **Affected platform:** legacy Windows and osCommerce stack
- **Impact:** increased exposure to known vulnerabilities and unsupported software risk

The environment combined an end-of-life operating-system generation with an obsolete e-commerce application.

**Remediation:**

- migrate the host to a supported Windows release;
- replace or upgrade the legacy osCommerce application;
- remove obsolete software and installers;
- establish lifecycle and patch-management controls.

## Security Impact

The validated weakness resulted in immediate complete host compromise.

An attacker with equivalent access could:

- execute arbitrary commands without authentication;
- operate directly as `NT AUTHORITY\SYSTEM`;
- access all local files and registry data;
- extract local account hashes;
- recover weak local passwords;
- access Administrator-owned content;
- deploy persistent tooling or modify system configuration.

The decisive failure was the combination of unauthenticated legacy application RCE and an unnecessarily privileged web-service identity.

## Detection Opportunities

Useful monitoring controls include:

- alert on requests to osCommerce installation paths after deployment;
- monitor modifications to `configure.php` and application configuration;
- detect web-server processes spawning `cmd.exe`, PowerShell, or unexpected binaries;
- alert on credential-dumping tooling and SAM/LSA access;
- detect downloads of post-exploitation executables through `certutil` or similar utilities;
- monitor unexpected SYSTEM-level child processes from Apache;
- alert on access to Administrator profile data by web-server processes.

## Remediation Priorities

1. Remove the exposed osCommerce installation directory.
2. Upgrade or replace the obsolete osCommerce deployment.
3. Reconfigure the web service to use a dedicated low-privileged identity.
4. Migrate the legacy Windows host to a supported operating system.
5. Rotate all local credentials.
6. Deploy managed unique local administrator passwords.
7. Add monitoring for web-to-process execution and credential dumping.
8. Restrict TCP/8080 to only required networks if the service must remain available.
9. Review SMB/MySQL and other exposed services for unnecessary network reachability.

## Retest Plan

1. Confirm the osCommerce installation directory is no longer reachable.
2. Verify the previous unauthenticated RCE path no longer executes commands.
3. Confirm the web service does not run as SYSTEM.
4. Verify application configuration cannot be modified by unauthenticated users.
5. Confirm previously exposed local credential material has been rotated.
6. Verify the previous `Lab` password no longer authenticates.
7. Confirm SAM/LSA credential dumping is blocked or detected.
8. Verify the final Administrator objective is no longer reachable through the prior web exploit path.

## Lessons Learned

Blueprint demonstrates how legacy web software can turn a single application flaw into immediate operating-system compromise when service privilege boundaries are weak.

The exposed osCommerce installer supplied unauthenticated code execution, the web stack's SYSTEM context eliminated the need for a separate privilege-escalation stage, and post-exploitation access enabled full local credential compromise.

The strongest defensive response is to combine secure deployment hygiene, software lifecycle management, least-privilege service identities, and credential protection rather than treating the vulnerable application as an isolated issue.
