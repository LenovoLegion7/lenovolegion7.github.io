---
title: "TryHackMe: HealthGPT"
date: 2026-08-14 12:30:00 +0200
categories: [TryHackMe]
tags:
  - ai
  - llm
  - ollama
  - api
  - information-disclosure
  - secret-management
  - werkzeug
  - web
description: >-
  HealthGPT demonstrates how an unauthenticated Ollama management/runtime API
  can bypass a safety-focused chat interface and expose sensitive model
  configuration material.
author: lenovolegion7
media_subpath: /images/tryhackme_healthgpt
image:
  path: room_image.webp
  alt: "Original TryHackMe HealthGPT room artwork"
toc: true
comments: false
---

HealthGPT is an AI application security challenge focused on the difference between model-level safety instructions and real access control. The validated path did not require prompt injection or brute force: direct network access to an exposed Ollama API allowed model enumeration and configuration inspection, bypassing the intended HealthGPT chat interface.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe HealthGPT room card](room_card.webp){: w="295" h="268" .shadow }](https://tryhackme.com/room/healthgpt){: .center }

## Executive Summary

The target exposed the following relevant services:

```text
22/tcp     SSH
80/tcp     HTTP
5000/tcp   HTTP
11434/tcp  Ollama API
```

The validated attack path was:

1. enumerate open TCP services;
2. review the public HealthGPT chat interface;
3. identify TCP/11434 as an exposed Ollama runtime/management API;
4. access the API without authentication;
5. enumerate local models through `/api/tags`;
6. identify HealthGPT-related models;
7. inspect model configuration through `/api/show`;
8. recover sensitive policy material from the model configuration/system-prompt content;
9. validate the disclosed value against the TryHackMe answer format.

> **Result:** The web chat guardrails were bypassed entirely because the backend LLM API was directly reachable and unauthenticated.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe HealthGPT laboratory target.

Testing focused on discovery, web/API analysis, and read-only proof-of-concept verification where possible. Password attacks, SSH brute force, denial-of-service testing, persistence, destructive activity, lateral movement, and testing outside the assigned target were excluded.

## Initial Enumeration

Representative service discovery:

```console
$ nmap \
  -p22,80,5000,11434 \
  -sV -sC -T4 -Pn \
  TARGET_IP
```

Observed services:

```text
22/tcp     SSH   OpenSSH
80/tcp     HTTP  Werkzeug / Python
5000/tcp   HTTP  Werkzeug / Python
11434/tcp  HTTP  Ollama / Golang net/http
```

The main web application presented a chat-based AI assistant interface.

## Exposed Ollama Backend

Direct access to TCP/11434 returned the Ollama service banner:

```text
Ollama is running
```

The backend accepted API requests without authentication. This meant the attacker did not need to interact with the intended HealthGPT frontend or its safety/compliance controls.

## Model Enumeration

The Ollama model inventory was available through:

```console
$ curl -s \
  http://TARGET_IP:11434/api/tags
```

Relevant models included:

```text
healthgpt3:latest
healthgpt2:latest
healthgpt:latest
```

This exposed internal model naming and confirmed that the backend hosted multiple HealthGPT-related model variants.

## Model Configuration Inspection

The `/api/show` endpoint returned model metadata and configuration material.

Representative read-only request:

```console
$ curl -s \
  http://TARGET_IP:11434/api/show \
  -H "Content-Type: application/json" \
  -d '{"model":"healthgpt3:latest","verbose":true}'
```

Searching the returned strings for sensitive terms exposed policy material embedded in the model configuration/system-prompt content.

The sensitive challenge value is intentionally redacted:

```text
Secret policy flag: [REDACTED]
```

The final TryHackMe answer is also redacted:

```text
THM{[REDACTED]}
```

## Why the Chat Guardrails Failed

The frontend attempted to constrain what the assistant would reveal, but the exposed Ollama API bypassed that interaction layer completely.

This demonstrates an important security boundary:

```text
LLM safety instructions != authentication
LLM safety instructions != authorization
LLM safety instructions != secret storage
```

Secrets placed in model prompts, Modelfiles, system instructions, or retrievable model configuration should be assumed recoverable by any principal that can access the relevant management/runtime interfaces.

## Findings

### F-01 - Unauthenticated Ollama API Exposed on TCP/11434

- **Severity:** Critical
- **Affected service:** Ollama API on TCP/11434
- **Impact:** unauthenticated model enumeration and configuration retrieval

The Ollama management/runtime interface was reachable directly from the attacker network and accepted API requests without authentication.

**Remediation:**

- bind Ollama to localhost or a backend-only interface;
- block TCP/11434 from untrusted networks;
- require authenticated service-to-service access where remote access is necessary;
- add logging and rate limiting;
- apply least-privilege network controls.

### F-02 - Sensitive Policy Material Stored in Model Configuration

- **Severity:** Critical
- **Affected component:** HealthGPT model configuration / system-prompt material
- **Impact:** unauthorized disclosure of secret-like policy content

Sensitive material was stored in a location retrievable through the Ollama management API.

**Remediation:**

- remove secrets from prompts, Modelfiles, model configuration, and system instructions;
- store credentials and confidential values only in managed secret stores;
- rotate any exposed values;
- scan model configuration automatically for sensitive strings;
- include LLM configuration in CI/CD secret scanning.

### F-03 - Development-Grade Werkzeug HTTP Services Exposed

- **Severity:** Medium
- **Affected services:** TCP/80 and TCP/5000
- **Observed stack:** Werkzeug / Python
- **Impact:** unnecessary development-service exposure and information disclosure

The environment exposed Werkzeug-backed HTTP services directly.

**Remediation:**

- deploy behind a hardened production WSGI/ASGI server and reverse proxy;
- suppress unnecessary server banners;
- restrict backend-only services such as TCP/5000;
- separate public frontend and internal application components.

## Additional Observation

### O-01 - SSH Service Exposed

SSH was reachable on TCP/22. No SSH authentication testing was performed because it was unnecessary after the room objective was achieved.

This is therefore an **observed exposure**, not an exploited finding.

## Security Impact

The demonstrated issue allowed an unauthenticated network user to bypass the intended HealthGPT chat interface and directly inspect backend model information.

An attacker with equivalent access could:

- enumerate installed model inventory;
- inspect model metadata and configuration;
- retrieve system-prompt or policy material;
- discover internal operational instructions;
- bypass frontend monitoring and safety controls;
- potentially consume inference/runtime resources without authorization.

In a real healthcare environment, the same design could expose API keys, internal workflows, confidential operational material, or patient-adjacent context.

## Detection Opportunities

Useful monitoring controls include:

- alert on direct access to TCP/11434 from non-backend networks;
- monitor `/api/tags` and `/api/show` access;
- detect model metadata enumeration;
- alert on requests for verbose model configuration;
- correlate direct backend API use with absence of a normal frontend session;
- monitor unusual inference/runtime request volume;
- detect external access to development-grade TCP/5000 services;
- scan model configurations for secret-like strings.

## Remediation Priorities

1. Block TCP/11434 from untrusted networks.
2. Bind Ollama to localhost or a backend-only subnet.
3. Remove sensitive policy and secret-like values from model configuration.
4. Rotate any real secret exposed through model context or configuration.
5. Put required model API access behind authenticated service-to-service controls.
6. Restrict externally exposed TCP/5000.
7. Replace development-grade web serving with a production deployment pattern.
8. Add monitoring for direct LLM API and metadata access.
9. Add AI configuration and prompt secret scanning to CI/CD.

## Retest Plan

1. Confirm TCP/11434 is closed, filtered, or accessible only from approved backend hosts.
2. Verify unauthenticated `/api/tags` requests are rejected.
3. Verify unauthenticated `/api/show` requests are rejected.
4. Confirm HealthGPT model configuration contains no flags, credentials, or confidential policy values.
5. Verify any previously exposed real values have been rotated or invalidated.
6. Confirm TCP/5000 is not externally reachable unless explicitly required and protected.
7. Verify application logs capture and alert on unexpected direct Ollama API access.
8. Confirm the previous attack path can no longer recover sensitive configuration material.

## Lessons Learned

HealthGPT demonstrates that LLM guardrails are not a replacement for conventional application and infrastructure security.

The frontend attempted to enforce safety rules, but a directly exposed backend API made those controls irrelevant. Once model-management endpoints were reachable without authentication, the attacker could inspect the model inventory and retrieve configuration material directly.

The strongest defensive response is to treat model runtimes like any other sensitive backend service: isolate them, authenticate access, authorize every operation, log usage, and never store secrets inside prompts or model configuration.
