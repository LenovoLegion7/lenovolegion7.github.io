---
title: "TryHackMe: Voyage"
date: 2026-06-27 23:50:00 +0200
categories: [TryHackMe]
tags:
  - joomla
  - api
  - credential-disclosure
  - ssh
  - docker
  - pivoting
  - pickle
  - deserialization
  - cap-sys-module
  - container-escape
description: >-
  Voyage chained an unauthenticated Joomla configuration disclosure,
  credential reuse, internal Docker pivoting, insecure Python pickle
  deserialization, and CAP_SYS_MODULE abuse into full host compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_voyage
image:
  path: room_image.webp
  alt: "Original TryHackMe Voyage room artwork"
toc: true
comments: false
---

Voyage is a multi-stage web-to-host compromise focused on exposed application secrets, credential reuse, container pivoting, insecure deserialization, and a dangerous Linux capability. The validated chain moved from an unauthenticated Joomla API configuration disclosure to root access in one container, lateral movement to an internal Flask finance application, root command execution through a client-controlled pickle session, and finally host compromise through `CAP_SYS_MODULE`.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Voyage room card](room_card.webp){: w="303" h="272" .shadow }](https://tryhackme.com/room/voyage){: .center }

## Executive Summary

The target exposed:

```text
22/tcp    SSH
80/tcp    HTTP / Joomla
2222/tcp  alternate SSH service
```

The initial Joomla web application exposed a public configuration API endpoint. That endpoint returned database credentials and Joomla metadata without authentication.

The leaked password was reused for root SSH access on port `2222`, which placed the attacker inside a Docker container. Internal network enumeration from that container discovered a second Flask-based finance service. The finance application stored client-controlled `session_data` as a hex-encoded Python pickle, enabling arbitrary command execution as root inside the second container.

The second container also possessed the dangerous `CAP_SYS_MODULE` capability. Container root could therefore load a kernel module into the host kernel and execute commands in the host context.

> **Result:** Root access was obtained in two containers, followed by host-level root code execution and recovery of both TryHackMe objectives.
{: .prompt-danger }

## External Enumeration

The external target can be represented without publishing the lab address:

```console
$ nmap -p22,80,2222 -sV -sC -T4 -Pn TARGET_IP
```

The scan identified Joomla on port `80` and two separate SSH services.

The different SSH versions suggested that port `2222` might represent a containerized or alternate environment rather than the host itself.

## Attack Path Overview

1. **External enumeration** — identified Joomla and SSH on ports `22` and `2222`.
2. **Joomla API disclosure** — queried a public configuration endpoint and recovered database credentials and Joomla metadata.
3. **Credential reuse** — reused the disclosed password for root SSH access on port `2222`.
4. **Container confirmation** — confirmed the shell was running inside the first Docker container.
5. **Internal discovery** — enumerated the Docker network and identified a second Flask application.
6. **Port forwarding** — tunneled the internal finance service back to the attacker system.
7. **Pickle deserialization** — forged a malicious `session_data` pickle and executed commands as root in the second container.
8. **Container escape** — abused `CAP_SYS_MODULE` to load a kernel module and execute code in the host context.

## Unauthenticated Joomla API Configuration Disclosure

The Joomla API exposed application configuration without authentication:

```text
/api/index.php/v1/config/application?public=true
```

A request to the endpoint returned high-value settings including:

```text
user=root
password=[REDACTED]
db=joomla_db
dbprefix=ecsjh_
```

The disclosed credential was reusable outside the database context, which greatly increased the impact.

### VYG-01 - Unauthenticated Joomla API Configuration Disclosure

- **Severity:** Critical
- **Impact:** Credential and application-secret disclosure

Anyone able to reach the web application could retrieve sensitive configuration data.

**Remediation:**

- require authentication and authorization for configuration API routes;
- rotate all exposed credentials;
- restrict sensitive API endpoints at the web-server and application layers;
- monitor access to Joomla configuration routes.

## Root Credential Reuse on Container SSH

The disclosed password was accepted for SSH login as root on port `2222`:

```console
$ ssh -p 2222 root@TARGET_IP
Password: [REDACTED]
```

The resulting shell was root but not yet host root.

Container context was confirmed through:

```console
# hostname -I
INTERNAL_CONTAINER_IP

# ls -la /.dockerenv
-rwxr-xr-x 1 root root 0 ... /.dockerenv
```

### VYG-02 - Root Credential Reuse on Exposed Container SSH

- **Severity:** Critical
- **Impact:** Immediate root access to the first container

Credential reuse converted the Joomla information disclosure directly into an administrative shell.

**Remediation:**

- use unique secrets for databases, applications, and operating-system access;
- disable direct root SSH login;
- prefer named accounts and key-based authentication;
- remove unnecessary SSH daemons from containers;
- restrict container SSH to management networks.

## Internal Network Pivoting

The first container could reach additional Docker-network services.

Internal discovery identified a second service:

```text
INTERNAL_SERVICE_IP:5000
Werkzeug / Python
Tourism Secret Finance Panel
```

A representative discovery sequence was:

```console
# nmap -sn INTERNAL_DOCKER_SUBNET
# nmap -sV -sC -Pn -p5000 INTERNAL_SERVICE_IP
```

The service was not directly exposed externally, but the compromised container provided a pivot point.

An SSH local forward exposed it on the attacker system:

```console
$ ssh \
  -N \
  -L 5001:INTERNAL_SERVICE_IP:5000 \
  -p 2222 \
  root@TARGET_IP
```

### VYG-03 - Internal Network Pivoting from a Compromised Container

- **Severity:** High
- **Impact:** Lateral movement to an internal privileged application

The container network permitted unnecessary east-west reachability.

**Remediation:**

- segment containers based on application need;
- apply deny-by-default east-west policies;
- use dedicated Docker networks and host firewall rules;
- avoid placing sensitive services on networks reachable from unrelated containers.

## Insecure Python Pickle Deserialization

The finance application stored session state in a client-side cookie:

```text
session_data=[REDACTED]
```

The data was hex-encoded Python pickle content.

Because the application deserialized attacker-controlled pickle data, a malicious object could trigger arbitrary command execution.

The source report confirms execution as root in the second container:

```text
uid=0(root) gid=0(root) groups=0(root)
```

The user-level objective was recovered from:

```text
/root/user.txt
THM{[REDACTED]}
```

### VYG-04 - Insecure Python Pickle Deserialization

- **Severity:** Critical
- **Impact:** Arbitrary command execution as root in the second container

Client-controlled pickle deserialization is equivalent to remote code execution.

**Remediation:**

- never deserialize untrusted pickle data;
- use safe formats such as JSON with strict validation;
- keep sessions server-side where possible;
- cryptographically protect client-side session data if unavoidable;
- run web applications as non-root users;
- detect suspicious pickle magic bytes in cookies.

## Dangerous `CAP_SYS_MODULE` Capability

Privilege inspection inside the second container revealed:

```console
# capsh --print
Current: ... cap_sys_module ... =ep
```

`CAP_SYS_MODULE` allows loading kernel modules into the host kernel. This effectively breaks the container security boundary for container root.

The running kernel was:

```text
6.8.0-1031-aws
```

The source report documents compiling a custom module against available AWS headers, adjusting the module `vermagic` for the running kernel, and loading it successfully.

A representative sequence was:

```console
# uname -r
6.8.0-1031-aws

# strings revwrite-1031.ko | grep '6.8.0-103'
vermagic=6.8.0-1031-aws SMP mod_unload modversions

# insmod ./revwrite-1031.ko

# cat /proc/modules | grep revwrite
revwrite ... Live ...
```

The module executed a host-context helper and wrote host evidence back into a location reachable from the container.

The resulting context showed:

```text
uid=0(root) gid=0(root) groups=0(root)
host context confirmed
THM{[REDACTED]}
```

### VYG-05 - `CAP_SYS_MODULE` Enables Host Compromise

- **Severity:** Critical
- **Impact:** Container escape and host root code execution

This capability allows container root to modify the host kernel and should be considered equivalent to host compromise.

**Remediation:**

- remove `CAP_SYS_MODULE` from all containers;
- avoid privileged containers and broad capability sets;
- explicitly add only capabilities that are required;
- apply AppArmor, SELinux, seccomp, and `no-new-privileges`;
- audit for `cap_add: SYS_MODULE`, host namespace sharing, Docker socket mounts, and privileged mode;
- monitor unexpected `insmod`, `modprobe`, and `/proc/modules` changes.

## Security Impact

Voyage demonstrates how multiple weaknesses compound into a complete infrastructure compromise:

```text
Joomla configuration disclosure
-> credential reuse
-> root SSH into first container
-> internal Docker pivot
-> malicious pickle deserialization
-> root in second container
-> CAP_SYS_MODULE
-> host root
```

The most serious issues were the unauthenticated configuration disclosure, reuse of root credentials, unsafe deserialization, and the presence of `CAP_SYS_MODULE`.

## Remediation Priorities

1. Rotate all credentials exposed by the Joomla API.
2. Remove public access to sensitive Joomla configuration API routes.
3. Disable direct root SSH and remove unnecessary SSH from containers.
4. Remove `CAP_SYS_MODULE` and any privileged container settings.
5. Replace pickle-based client-side sessions with safe server-side session storage.
6. Run the finance application as a non-root account.
7. Segment container networks and enforce deny-by-default east-west access.
8. Add CI/CD checks for dangerous Docker capabilities and exposed secrets.
9. Monitor suspicious configuration API access, SSH logins, pickle-like cookies, and kernel module loading.

## Retest Plan

1. Confirm the Joomla configuration endpoint no longer exposes sensitive data anonymously.
2. Verify all disclosed credentials have been rotated and are not reused across services.
3. Confirm root SSH access is disabled.
4. Verify unrelated containers cannot reach the internal finance application.
5. Confirm malformed or crafted `session_data` values are rejected without deserialization.
6. Verify the finance service runs as a non-root user.
7. Confirm the finance container no longer has `CAP_SYS_MODULE`.
8. Verify kernel module loading from container context is blocked.
9. Confirm both user and root objectives are no longer obtainable through the documented chain.

## Lessons Learned

Voyage is a strong example of why container security depends on the entire trust chain, not just application isolation.

A public configuration leak became root container access because the same password was reused. That container then provided network reachability to a vulnerable internal service. Root access in the second container became host root because a dangerous kernel capability had been granted.

The most effective defense is layered: protect secrets, prevent credential reuse, segment internal networks, never deserialize attacker-controlled pickle data, and keep privileged Linux capabilities out of application containers.
