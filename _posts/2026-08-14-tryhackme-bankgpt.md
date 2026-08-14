---
title: "TryHackMe: BankGPT"
date: 2026-08-14 13:00:00 +0200
categories: [TryHackMe]
tags:
  - ai
  - llm
  - ollama
  - api
  - information-disclosure
  - secret-management
  - werkzeug
  - banking
  - web
description: >-
  BankGPT demonstrates how an unauthenticated Ollama management/runtime API
  can bypass a banking chat interface and expose sensitive model configuration
  containing a secret support API key.
author: lenovolegion7
media_subpath: /images/tryhackme_bankgpt
image:
  path: room_image.webp
  alt: "Original TryHackMe BankGPT room artwork"
toc: true
comments: false
---

BankGPT is an AI application security challenge focused on backend exposure and secret handling. The validated path did not require prompt injection, password attacks, or SSH access: direct network access to an exposed Ollama API allowed model enumeration and configuration inspection, bypassing the intended BankGPT chat interface and disclosing a secret key stored in model context.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe BankGPT room card](room_card.webp){: w="301" h="273" .shadow }](https://tryhackme.com/room/bankgpt){: .center }

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
2. review the public BankGPT chat interface;
3. identify TCP/11434 as an exposed Ollama runtime/management API;
4. access the API without authentication;
5. enumerate local models through `/api/tags`;
6. identify the `bankgpt:latest` model;
7. inspect model configuration through `/api/show`;
8. recover a sensitive support API key from the model configuration/system-prompt content;
9. validate the disclosed value against the TryHackMe answer format.

> **Result:** The BankGPT web guardrails were bypassed entirely because the backend LLM API was directly reachable and unauthenticated.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe BankGPT laboratory target.

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

The main web application presented a customer-service AI assistant interface.

## Exposed Ollama Backend

Direct access to TCP/11434 returned the Ollama service banner:

```text
Ollama is running
```

The backend accepted API requests without authentication. This bypassed the BankGPT frontend and any interaction controls implemented there.

## Model Enumeration

The Ollama model inventory was exposed through:

```console
$ curl -s \
  http://TARGET_IP:11434/api/tags
```

The relevant BankGPT model was:

```text
bankgpt:latest
```

Model metadata also identified the model family and runtime characteristics, demonstrating broader backend inventory disclosure.

## Model Configuration Inspection

The `/api/show` endpoint returned BankGPT model configuration and system-prompt material.

Representative read-only request:

```console
$ curl -s \
  http://TARGET_IP:11434/api/show \
  -H "Content-Type: application/json" \
  -d '{"model":"bankgpt:latest"}'
```

Searching the returned content for sensitive terms exposed a support API key stored inside the model configuration.

The secret value itself is intentionally redacted:

```text
Support API key: [REDACTED]
```

The TryHackMe answer is also redacted:

```text
THM{[REDACTED]}
```

## Why the Chat Guardrails Failed

The frontend attempted to constrain user interaction with the model, but the exposed Ollama backend bypassed that control layer completely.

This demonstrates an important boundary:

```text
LLM safety instructions != authentication
LLM safety instructions != authorization
LLM prompts/configuration != secret storage
```

A secret embedded in model context should be treated as exposed to any principal that can query model-management or configuration endpoints.

## Findings

### F-01 - Unauthenticated Ollama API Exposed on TCP/11434

- **Severity:** Critical
- **Affected service:** Ollama API on TCP/11434
- **Impact:** unauthenticated model enumeration and configuration retrieval

The Ollama management/runtime API was directly reachable from the attacker network without authentication.

**Remediation:**

- bind Ollama to localhost or a backend-only interface;
- block TCP/11434 from untrusted networks;
- put required access behind authenticated service-to-service controls;
- use network ACLs, API-gateway policy, or mTLS where appropriate;
- log and rate-limit direct LLM API requests.

### F-02 - Sensitive Secret Stored in BankGPT Model Configuration

- **Severity:** Critical
- **Affected model:** `bankgpt:latest`
- **Affected data:** support API key
- **Impact:** unauthenticated disclosure of credential-like material

The BankGPT model configuration stored a support API key in content retrievable through the Ollama API.

**Remediation:**

- remove all secrets from prompts, Modelfiles, system instructions, and model configuration;
- store secrets only in a managed secret store;
- inject secrets server-side only when strictly required by authorized tools;
- rotate exposed values;
- scan prompts/configuration automatically for secret-like strings;
- add AI configuration secret scanning to CI/CD.

### F-03 - Development-Grade Werkzeug HTTP Services Exposed

- **Severity:** Medium
- **Affected services:** TCP/80 and TCP/5000
- **Observed stack:** Werkzeug / Python
- **Impact:** unnecessary development-service exposure and information disclosure

Werkzeug-backed HTTP services were exposed directly.

**Remediation:**

- deploy behind a production WSGI/ASGI server and hardened reverse proxy;
- disable Flask debug mode;
- suppress detailed server banners;
- restrict backend-only services such as TCP/5000;
- apply standard HTTP hardening controls.

## Additional Observation

### O-01 - SSH Service Exposed

SSH was reachable on TCP/22. No authentication testing was performed because it was not necessary to complete the challenge objective.

This is therefore an **observed exposure**, not an exploited finding.

## Security Impact

The demonstrated weakness allowed an unauthenticated network user to bypass the intended BankGPT frontend and directly inspect the underlying model configuration.

An attacker with equivalent access could:

- enumerate installed model inventory;
- inspect model metadata and system-prompt content;
- recover secret-like values embedded in model configuration;
- bypass frontend monitoring and guardrails;
- potentially invoke model/runtime functions without authorization;
- consume backend inference resources.

In a real banking environment, an exposed key could provide access to downstream support services, internal workflows, or privileged banking data depending on its permissions.

## Detection Opportunities

Useful monitoring controls include:

- alert on direct TCP/11434 access from non-backend networks;
- monitor `/api/tags`, `/api/show`, `/api/chat`, and related endpoints;
- detect model inventory enumeration;
- alert on verbose model-configuration requests;
- correlate backend API use with absence of an expected frontend session;
- monitor unusual inference/request volume;
- detect external access to TCP/5000;
- scan model configuration for API-key and credential patterns.

## Remediation Priorities

1. Block TCP/11434 from untrusted networks.
2. Bind Ollama to localhost or a backend-only subnet.
3. Rotate the exposed support API key.
4. Remove secrets from BankGPT model configuration and prompts.
5. Place required model APIs behind authenticated service-to-service controls.
6. Restrict externally exposed TCP/5000.
7. Replace development-grade web serving with a production deployment pattern.
8. Add monitoring for direct LLM API and model-metadata access.
9. Add prompt/configuration secret scanning to CI/CD.

## Retest Plan

1. Confirm TCP/11434 is closed, filtered, or reachable only from approved backend hosts.
2. Verify unauthenticated `/api/tags` requests are rejected.
3. Verify unauthenticated `/api/show` requests are rejected.
4. Confirm BankGPT model configuration contains no API keys or secret-like values.
5. Verify the previously exposed support API key has been rotated or invalidated.
6. Confirm TCP/5000 is not externally reachable unless explicitly required and protected.
7. Verify logs capture and alert on direct Ollama API access.
8. Confirm the previous attack path can no longer recover sensitive model configuration.

## Lessons Learned

BankGPT demonstrates that LLM guardrails are not a replacement for conventional backend security.

The frontend could attempt to control model behavior, but an unauthenticated backend management API made those controls irrelevant. Once the model runtime was reachable directly, model inventory and configuration became accessible without passing through the intended application boundary.

The strongest defensive response is to isolate model runtimes, authenticate and authorize API access, keep secrets outside model context, and monitor backend model-management interfaces like any other sensitive production service.
