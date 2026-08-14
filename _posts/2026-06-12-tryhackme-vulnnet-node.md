---
title: "TryHackMe: VulnNet: Node"
date: 2026-06-12 23:55:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - nodejs
  - express
  - insecure-deserialization
  - cve-2017-5941
  - node-serialize
  - sudo
  - npm
  - systemd
  - privilege-escalation
description: >-
  VulnNet: Node chains unauthenticated Node.js insecure deserialization,
  sudo npm abuse, and writable systemd service files into complete root compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_vulnnet_node
image:
  path: room_image.webp
  alt: "Original TryHackMe VulnNet Node room artwork"
toc: true
comments: false
---

VulnNet: Node is a Linux web-to-root challenge built around unsafe Node.js deserialization and weak privilege boundaries. The validated path began with a malicious serialized session cookie, produced remote code execution as the web user, escalated to `serv-manage` through passwordless `npm`, and ended with root access by modifying a writable systemd service and reloading it through delegated `systemctl`.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe VulnNet Node room card](room_card.webp){: w="292" h="266" .shadow }](https://tryhackme.com/room/vulnnetnode){: .center }

## Executive Summary

The target exposed a Node.js/Express web application on TCP/8080 and an SSH service:

```text
22/tcp    SSH
8080/tcp  HTTP / Node.js / Express
```

The validated attack path was:

1. enumerate the web application on TCP/8080;
2. inspect the session cookie issued to a Guest user;
3. decode the Base64 cookie and identify the `node-serialize` object format;
4. exploit CVE-2017-5941 through a serialized IIFE payload;
5. obtain command execution as `www`;
6. enumerate sudo privileges;
7. identify passwordless execution of `/usr/bin/npm` as `serv-manage`;
8. abuse an npm lifecycle hook to execute a shell as `serv-manage`;
9. retrieve the user objective;
10. identify writable systemd unit files owned by group `serv-manage`;
11. confirm delegated `systemctl daemon-reload` and timer start/stop privileges;
12. replace the service definition with a controlled root command;
13. reload systemd and start the timer;
14. obtain a root shell;
15. retrieve the final root objective.

> **Result:** An unauthenticated web user was able to progress to full root compromise through insecure deserialization, unsafe sudo delegation, and writable privileged service definitions.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe VulnNet: Node laboratory target.

Testing was limited to the single assigned host. No denial-of-service testing was performed, and data access was limited to the challenge objectives required to prove compromise.

## Initial Enumeration

Representative service discovery:

```console
$ nmap \
  -p22,8080 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

The web application on TCP/8080 used Node.js/Express and issued a serialized session cookie to unauthenticated visitors.

## Session Cookie Analysis

The application returned a Base64-encoded session value representing a Guest object.

Decoded structure:

```json
{
  "username": "Guest",
  "isGuest": true,
  "encoding": "utf-8"
}
```

The object format was handled by the vulnerable `node-serialize` package.

## Insecure Deserialization RCE

The application used `node-serialize` version `<= 0.0.4`, which is vulnerable to CVE-2017-5941 when user-controlled serialized data is passed to `unserialize()`.

The package supports serialized functions using a special function marker. An Immediately Invoked Function Expression can therefore execute as soon as the server deserializes the attacker-controlled object.

The public writeup intentionally omits the complete callback payload, but the technique was equivalent to:

```text
session = Base64(
  serialized object containing an immediately invoked function
)
```

The malicious cookie produced a reverse shell as:

```text
uid=1001(www)
gid=1001(www)
```

This established the initial host foothold without authentication.

## sudo npm Escalation to serv-manage

Local sudo enumeration showed:

```text
(serv-manage) NOPASSWD: /usr/bin/npm
```

Because npm executes lifecycle scripts from `package.json`, this rule was equivalent to arbitrary command execution as `serv-manage`.

Representative lab workflow:

```console
$ TF="$(mktemp -d)"

$ cat > "$TF/package.json" <<'EOF'
{
  "scripts": {
    "preinstall": "/bin/bash -c 'COMMAND_PLACEHOLDER'"
  }
}
EOF

$ sudo -u serv-manage \
  /usr/bin/npm \
  -C "$TF" \
  --unsafe-perm \
  i
```

Execution succeeded as:

```text
uid=1000(serv-manage)
gid=1000(serv-manage)
```

The user-level objective was located at:

```text
/home/serv-manage/user.txt
```

Its value is published only as:

```text
THM{[REDACTED]}
```

## Writable systemd Unit Files

Further enumeration showed that `serv-manage` could modify:

```text
/etc/systemd/system/vulnnet-auto.timer
/etc/systemd/system/vulnnet-job.service
```

The files were root-owned but group-writable by `serv-manage`.

The account also had passwordless sudo permission to execute:

```text
/bin/systemctl daemon-reload
/bin/systemctl start vulnnet-auto.timer
/bin/systemctl stop vulnnet-auto.timer
```

This combination created a direct root escalation path.

## Root Escalation Through systemd

The original service definition was replaced with a controlled `ExecStart` action.

Representative service concept:

```ini
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'COMMAND_PLACEHOLDER'
```

After modifying:

```text
/etc/systemd/system/vulnnet-job.service
```

the new unit definition was loaded and activated:

```console
$ sudo /bin/systemctl daemon-reload

$ sudo /bin/systemctl start vulnnet-auto.timer
```

The privileged service executed as root:

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

### VN-001 - Insecure Deserialization in node-serialize

- **Severity:** Critical
- **Affected service:** Node.js / Express application on TCP/8080
- **CVE:** CVE-2017-5941
- **CWE:** CWE-502
- **Impact:** unauthenticated remote code execution

The application trusted attacker-controlled serialized session data and processed it using the unsafe `node-serialize` package.

**Remediation:**

- remove `node-serialize`;
- use safe data serialization such as `JSON.parse()` / `JSON.stringify()`;
- move session state server-side;
- use opaque session identifiers;
- never deserialize executable object formats from client-controlled data;
- audit Node.js dependencies for known vulnerabilities.

### VN-002 - Passwordless sudo npm Privilege Escalation

- **Severity:** High
- **Affected account:** `www`
- **Target account:** `serv-manage`
- **Sudo rule:** `(serv-manage) NOPASSWD: /usr/bin/npm`
- **Impact:** arbitrary code execution as a more privileged user

npm lifecycle hooks allowed attacker-controlled script execution under the delegated `serv-manage` identity.

**Remediation:**

- remove the sudo rule;
- never delegate general-purpose package managers through sudo;
- if operationally required, use a root-owned wrapper with strict allow-listed arguments;
- reduce privileges of the web service account;
- isolate web workloads through containers or other process boundaries.

### VN-003 - Writable systemd Service Enabling Root Escalation

- **Severity:** High
- **Affected files:** `vulnnet-auto.timer`, `vulnnet-job.service`
- **Impact:** arbitrary root command execution

The `serv-manage` account could modify systemd unit files and then use delegated `systemctl` privileges to reload and activate them.

**Remediation:**

- ensure systemd units are owned by `root:root`;
- use mode `0644` or stricter;
- remove non-root write access;
- revoke passwordless `systemctl daemon-reload`;
- revoke non-root timer/service control unless strictly required;
- deploy filesystem-integrity monitoring for systemd unit files.

## Security Impact

The validated chain resulted in complete root compromise from an unauthenticated remote starting position.

An attacker with equivalent access could:

- execute arbitrary Node.js code through a crafted session cookie;
- obtain an interactive shell as the web application user;
- execute arbitrary commands as `serv-manage`;
- modify privileged systemd unit definitions;
- trigger root execution through delegated service-management commands;
- access or alter any file, process, and system configuration available to root.

The compromise required no valid application or SSH credential.

## Detection Opportunities

Useful monitoring controls include:

- alert on unusual Base64 session-cookie structures;
- detect `_$$ND_FUNC$$_`-style serialized function markers;
- monitor Node.js application processes spawning shells;
- alert on sudo execution of npm by web-service accounts;
- monitor creation of temporary package manifests used by privileged npm;
- alert on writes to `/etc/systemd/system/*.service` and `*.timer`;
- monitor `systemctl daemon-reload` by non-root principals;
- detect unexpected timer activation;
- alert on systemd services spawning interactive shells or outbound callbacks.

## Remediation Priorities

1. Remove `node-serialize` immediately.
2. Replace client-controlled serialized sessions with secure server-side sessions.
3. Remove the `www → serv-manage` sudo npm rule.
4. Correct ownership and permissions on all systemd unit files.
5. Revoke delegated systemctl daemon-reload and timer-control privileges.
6. Rotate any secrets accessible after compromise.
7. Add dependency scanning to CI/CD.
8. Add filesystem-integrity monitoring for systemd unit files.
9. Apply process isolation to the Node.js application.

## Retest Plan

1. Confirm malicious serialized session objects are rejected.
2. Verify the application no longer uses `node-serialize`.
3. Confirm the web account cannot execute npm as `serv-manage`.
4. Verify npm lifecycle hooks cannot create a `serv-manage` shell through sudo.
5. Confirm systemd unit files are not writable by `serv-manage`.
6. Verify `serv-manage` cannot reload the systemd daemon through sudo.
7. Confirm `serv-manage` cannot start the privileged timer through the previous path.
8. Verify modified unit definitions cannot execute as root.
9. Confirm the previous exploitation chain no longer reaches root.

## Lessons Learned

VulnNet: Node demonstrates how application-layer code execution can become complete system compromise when local privilege boundaries are also weak.

Unsafe client-side serialization provided unauthenticated RCE. A package manager delegated through sudo converted the web account into a more trusted local identity, and writable systemd service definitions combined with delegated `systemctl` control collapsed the final root boundary.

The strongest defensive response is to treat dependency safety, session design, sudo rules, file ownership, and privileged service management as one connected trust chain.
