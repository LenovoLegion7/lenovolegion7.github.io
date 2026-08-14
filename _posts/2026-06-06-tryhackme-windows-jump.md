---
title: "TryHackMe: Windows Jump"
date: 2026-06-06 23:45:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - smb
  - rdp
  - winlogon
  - autoadminlogon
  - service-hijacking
  - scheduled-tasks
  - privilege-escalation
description: >-
  Windows Jump chains guest-readable SMB credentials, Winlogon AutoAdminLogon
  secrets, writable service binaries, and a modifiable SYSTEM task script into
  complete NT AUTHORITY\SYSTEM compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_windows_jump
image:
  path: room_image.webp
  alt: "Original TryHackMe Windows Jump room artwork"
toc: true
comments: false
---

Windows Jump is a Windows privilege-escalation challenge built around weak credential handling and unsafe file permissions. The validated path progressed from guest SMB access through `thmuser`, `notadmin`, and `svcadmin`, then reached `NT AUTHORITY\SYSTEM` through a writable task script executed by SYSTEM.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Windows Jump room card](room_card.webp){: w="290" h="267" .shadow }](https://tryhackme.com/room/windowsjump){: .center }

## Executive Summary

The host exposed standard Windows management and file-sharing services:

```text
135/tcp    MSRPC
139/tcp    NetBIOS-SSN
445/tcp    SMB
3389/tcp   RDP
5985/tcp   WinRM
47001/tcp  HTTPAPI
```

The validated privilege-escalation path was:

1. enumerate SMB as Guest;
2. read the public share and recover the `thmuser` onboarding credential;
3. authenticate to RDP as `thmuser`;
4. enumerate Winlogon registry values;
5. recover the AutoAdminLogon plaintext credential for `notadmin`;
6. move into the `notadmin` account context;
7. identify the `THMSvc` service running as `svcadmin`;
8. confirm weak ACLs allowed replacement of `C:\Windows\THMSVC\svc.exe`;
9. start the service and obtain execution as `svcadmin`;
10. identify `C:\Windows\Tasks\cleanup.bat` as modifiable by `svcadmin`;
11. replace the task script contents with a controlled payload launcher;
12. wait for the SYSTEM task to execute the modified script;
13. obtain `NT AUTHORITY\SYSTEM`;
14. retrieve the final objective.

> **Result:** Guest-level access was converted into complete SYSTEM compromise through exposed credentials, weak service permissions, and a writable SYSTEM-executed task script.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Windows Jump lab.

Testing was limited to the assigned host and challenge objectives. Persistence outside the lab objective, destructive actions, and denial-of-service testing were excluded.

## Initial Enumeration

Representative service discovery:

```console
$ nmap \
  -p135,139,445,3389,5985,47001 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed attack surface included SMB, RDP, WinRM, RPC, and HTTPAPI services.

## Guest SMB Access and thmuser Credential Exposure

SMB accepted Guest access and exposed a readable public share:

```console
$ nxc smb TARGET_IP \
  -u guest \
  -p '' \
  --shares
```

The public share contained a welcome document with default credentials for:

```text
thmuser
```

The password is intentionally redacted:

```text
thmuser : [REDACTED]
```

Those credentials authenticated successfully to RDP.

## thmuser RDP Foothold

The recovered account was used for an interactive desktop session:

```text
PRIVESC\thmuser
```

The first authorized objective was accessible in the user profile and is published only as:

```text
THM{[REDACTED]}
```

The account did not provide the final privilege level, but it gave the local interactive access needed for registry and service enumeration.

## Winlogon AutoAdminLogon Credential Exposure

Local enumeration identified plaintext AutoAdminLogon values under:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

The registry disclosed:

```text
DefaultUserName: notadmin
DefaultPassword: [REDACTED]
```

The recovered credential allowed progression into:

```text
PRIVESC\notadmin
```

The corresponding challenge objective is redacted:

```text
THM{[REDACTED]}
```

## THMSvc Service Binary Hijacking

Service enumeration identified:

```text
Service: THMSvc
Binary:  C:\Windows\THMSVC\svc.exe
Account: .\svcadmin
```

The service directory and executable had unsafe write permissions. The `notadmin` context could replace the service binary:

```text
C:\Windows\THMSVC\svc.exe
```

After replacing the service executable with a controlled service payload and starting `THMSvc`, execution occurred as:

```text
PRIVESC\svcadmin
```

The `svcadmin` proof is redacted:

```text
THM{[REDACTED]}
```

## Writable SYSTEM Task Script

The final privilege boundary was a task script:

```text
C:\Windows\Tasks\cleanup.bat
```

ACL review showed that `svcadmin` had modify access while the task executed under SYSTEM.

The task script was changed to launch a controlled executable placed at:

```text
C:\Windows\Tasks\shell.exe
```

When the scheduled task executed, the callback identity was:

```text
nt authority\system
```

The final objective was located at:

```text
C:\flag4.txt
```

and is redacted:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Public SMB Share Exposed Default Credentials

- **Severity:** High
- **Affected component:** `\\PRIVESC\Public`
- **Impact:** Guest access yielded a valid local-user credential

A guest-readable SMB share contained onboarding material with reusable credentials.

**Remediation:**

- disable Guest access unless explicitly required;
- remove credentials from shared folders and documentation;
- use unique temporary onboarding credentials with mandatory rotation;
- review share permissions regularly;
- alert on world-readable credential files.

### F-02 - Winlogon AutoAdminLogon Exposed Plaintext Credentials

- **Severity:** High
- **Affected component:** Winlogon AutoAdminLogon registry values
- **Impact:** direct progression from `thmuser` to `notadmin`

The Winlogon registry stored a reusable plaintext password.

**Remediation:**

- disable AutoAdminLogon;
- remove `DefaultPassword`;
- use managed service identities, LAPS, or secure vaulting;
- rotate the exposed account;
- audit endpoints for plaintext Winlogon secrets.

### F-03 - Service Binary Hijacking via Weak File Permissions

- **Severity:** High
- **Affected service:** `THMSvc`
- **Affected binary:** `C:\Windows\THMSVC\svc.exe`
- **Impact:** code execution as `svcadmin`

The lower-privileged account could replace a binary executed by a more privileged service identity.

**Remediation:**

- restrict service directories and executables to Administrators and SYSTEM;
- remove broad full-control ACLs;
- deploy file-integrity monitoring;
- review privileged services for writable binary paths.

### F-04 - Writable SYSTEM-Executed Task Script

- **Severity:** Critical
- **Affected component:** `C:\Windows\Tasks\cleanup.bat`
- **Impact:** arbitrary command execution as `NT AUTHORITY\SYSTEM`

A non-administrative service account could modify a batch file executed by a SYSTEM scheduled task.

**Remediation:**

- restrict write and modify permissions on task scripts to Administrators and SYSTEM;
- place task content in explicitly controlled directories;
- avoid inherited low-privilege modify rights;
- execute only trusted and signed task actions where practical;
- monitor scheduled-task scripts for unauthorized changes.

## Security Impact

The validated chain resulted in complete host compromise.

An attacker with equivalent access could:

- recover credentials from public shares;
- obtain interactive user access;
- recover plaintext credentials from the registry;
- replace a service binary executed by a more privileged account;
- modify a task script executed by SYSTEM;
- execute arbitrary commands as `NT AUTHORITY\SYSTEM`;
- access all data and security controls available to the local operating system.

The decisive issue was cumulative trust: each account could influence credentials, binaries, or scripts used by the next higher-privileged context.

## Detection Opportunities

Useful monitoring controls include:

- monitor Guest and anonymous SMB access;
- alert on credential-like files in public shares;
- detect reads of Winlogon AutoAdminLogon values;
- monitor changes to `C:\Windows\THMSVC\svc.exe`;
- alert on service binary replacement or unexpected service restarts;
- monitor modifications to `C:\Windows\Tasks\cleanup.bat`;
- detect executable creation in `C:\Windows\Tasks`;
- alert on child processes spawned by SYSTEM task actions;
- monitor suspicious transitions between local accounts during the same session window.

## Remediation Priorities

1. Remove plaintext credentials from SMB shares.
2. Disable Guest access where unnecessary.
3. Disable AutoAdminLogon and rotate exposed credentials.
4. Correct ACLs on `C:\Windows\THMSVC` and `svc.exe`.
5. Review all privileged service binary paths for lower-user write access.
6. Restrict `cleanup.bat` and task directories to Administrators and SYSTEM.
7. Review scheduled tasks for writable action paths.
8. Add monitoring for credential files, Winlogon secrets, service-binary changes, and task-script modification.
9. Rotate credentials for all accounts involved in the chain.

## Retest Plan

1. Confirm Guest cannot read the public credential material.
2. Verify `thmuser` onboarding credentials are no longer exposed or reusable.
3. Confirm Winlogon contains no plaintext `DefaultPassword`.
4. Verify the previous `notadmin` credential is invalid.
5. Confirm `notadmin` cannot modify `C:\Windows\THMSVC` or `svc.exe`.
6. Verify service-binary replacement cannot produce `svcadmin` execution.
7. Confirm `svcadmin` cannot modify `C:\Windows\Tasks\cleanup.bat`.
8. Verify the SYSTEM task action references only protected content.
9. Confirm the previous chain no longer reaches SYSTEM.

## Lessons Learned

Windows Jump demonstrates how a Windows host can be fully compromised through ordinary configuration and permission weaknesses without a kernel exploit.

A public share leaked the first credential, AutoAdminLogon exposed the next, weak service ACLs crossed another account boundary, and a writable task script finally collapsed the SYSTEM boundary.

The strongest defensive response is to treat credential storage, SMB access, service ACLs, and scheduled-task file permissions as one connected privilege-escalation surface.
