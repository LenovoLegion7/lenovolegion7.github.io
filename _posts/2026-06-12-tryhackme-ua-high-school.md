---
title: "TryHackMe: U.A. High School"
date: 2026-06-12 23:40:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - web
  - command-injection
  - php
  - credential-exposure
  - steganography
  - ssh
  - sudo
  - eval
  - privilege-escalation
description: >-
  U.A. High School chains an unauthenticated PHP command backdoor, hidden
  credential material, steganography, and an eval-based sudo script into
  complete root compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_ua_high_school
image:
  path: room_image.webp
  alt: "Original TryHackMe U.A. High School room artwork"
toc: true
comments: false
---

U.A. High School is a Linux web-to-root challenge built around a deliberately exposed command-execution backdoor, insecure credential storage, and unsafe privileged shell scripting. The validated path progressed from unauthenticated command execution as `www-data` to SSH access as `deku`, then reached root by abusing a passwordless sudo script that passed attacker-controlled input through `eval()`.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe U.A. High School room card](room_card.webp){: w="295" h="269" .shadow }](https://tryhackme.com/room/yueiua){: .center }

## Executive Summary

The target exposed SSH and Apache HTTP:

```text
22/tcp  SSH
80/tcp  HTTP
```

The validated attack path was:

1. enumerate the web service and hidden directories;
2. identify `/assets/` and its PHP entry point;
3. discover the unauthenticated `cmd` parameter;
4. execute operating-system commands through `shell_exec()`;
5. obtain a reverse shell as `www-data`;
6. discover `/Hidden_Content/passphrase.txt`;
7. decode the hidden passphrase;
8. repair the intentionally malformed image header of `oneforall.jpg`;
9. extract embedded credentials through steganography;
10. authenticate to SSH as `deku`;
11. retrieve the user objective;
12. identify passwordless sudo access to `/opt/NewComponent/feedback.sh`;
13. review its deny-list and unsafe use of `eval()`;
14. bypass the filter with output redirection;
15. write an authorized SSH key into root's profile;
16. authenticate as root through the injected key;
17. retrieve the final root objective.

> **Result:** Unauthenticated web access was converted into full root compromise through a command-execution backdoor, exposed credential material, steganography, and unsafe sudo/eval logic.
{: .prompt-danger }

## Scope and Safety Context

This assessment was performed only against the authorized TryHackMe U.A. High School laboratory target.

Testing was limited to the assigned host and challenge objectives. No denial-of-service testing was performed, and data access was limited to the minimum required to demonstrate compromise.

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
22/tcp  SSH   OpenSSH
80/tcp  HTTP  Apache
```

The web application exposed the U.A. High School site over HTTP.

## Hidden Assets Directory

Directory enumeration identified:

```text
/assets/
```

The directory contained a hidden PHP entry point whose `cmd` parameter was processed server-side.

The relevant logic was equivalent to:

```php
if (isset($_GET['cmd'])) {
    $value = shell_exec($_GET['cmd']);
    echo base64_encode($value);
}
```

This created unauthenticated operating-system command execution.

## Unauthenticated Command Execution

A harmless identity check confirmed code execution:

```console
$ curl -s \
  "http://TARGET_IP/assets/?cmd=whoami" \
  | base64 -d
```

The result was:

```text
www-data
```

The same primitive was then used to establish an interactive shell as:

```text
www-data
```

The public report intentionally omits attacker-specific callback addresses.

## Hidden Passphrase Recovery

Post-exploitation enumeration identified:

```text
/var/www/Hidden_Content/passphrase.txt
```

The file contained a Base64-encoded passphrase. The decoded value is intentionally not published:

```text
[REDACTED]
```

This passphrase became the first half of a two-step credential-recovery path.

## Steganographic Credential Recovery

The web server contained:

```text
/var/www/html/assets/images/oneforall.jpg
```

The image had inconsistent magic bytes and required header repair before steganographic extraction.

After restoring the expected image format and using the recovered passphrase, the embedded data disclosed valid credentials for:

```text
deku
```

The password is redacted:

```text
deku : [REDACTED]
```

## SSH Foothold as deku

The recovered credential authenticated successfully over SSH:

```console
$ ssh deku@TARGET_IP
```

The user-level objective was retrieved from the authorized challenge environment and is published only as:

```text
THM{[REDACTED]}
```

## Sudo feedback.sh Privilege Boundary

Local sudo enumeration showed:

```text
(ALL) /opt/NewComponent/feedback.sh
```

The script attempted to sanitize user input using a deny-list, but still passed attacker-controlled input into:

```text
eval()
```

Several metacharacters were blocked, but output redirection operators remained usable.

This meant input that appeared to be data could still cause privileged file writes when the script was executed through sudo.

## Root Escalation Through Output Redirection

The validated escalation used output redirection to write an authorized SSH public key into:

```text
/root/.ssh/authorized_keys
```

Conceptually, the privileged input was:

```text
AUTHORIZED_PUBLIC_KEY > /root/.ssh/authorized_keys
```

The exact public key is not published.

Because `feedback.sh` was running with sudo privileges and used `eval()`, the shell processed the redirection as root.

The attacker then authenticated to the host as:

```text
root
```

The final objective was retrieved from the root context and is redacted:

```text
THM{[REDACTED]}
```

## Findings

### F-01 - Unauthenticated OS Command Injection in assets/index.php

- **Severity:** Critical
- **Affected path:** `/assets/index.php`
- **CWE:** CWE-78
- **Impact:** unauthenticated remote code execution

The hidden PHP endpoint accepted a `cmd` parameter and passed it directly to `shell_exec()` without validation.

**Remediation:**

- remove the backdoor endpoint completely;
- never pass user input directly to shell execution functions;
- replace shell calls with safe parameterized APIs;
- apply strict allow-list validation;
- run the web service under a least-privileged account.

### F-02 - Sudo Privilege Escalation via feedback.sh

- **Severity:** Critical
- **Affected script:** `/opt/NewComponent/feedback.sh`
- **CWE:** CWE-250
- **Impact:** arbitrary root-level file writes and full root compromise

The `deku` account could run the script through sudo, while the script processed attacker-controlled data with `eval()`.

**Remediation:**

- remove the sudo permission for `feedback.sh`;
- eliminate `eval()` entirely;
- implement a fixed set of explicit operations;
- use strict allow-list parsing rather than a deny-list;
- do not permit shell metacharacters or redirection in privileged input.

### F-03 - Hardcoded Credentials in Steganographic Image

- **Severity:** High
- **Affected artifact:** `/var/www/html/assets/images/oneforall.jpg`
- **CWE:** CWE-798
- **Impact:** recovery of valid SSH credentials

Credentials were embedded inside a web-accessible image and protected only by a passphrase stored separately on the same server.

**Remediation:**

- remove credentials from images and application assets;
- rotate the exposed account credential;
- store secrets in a managed vault;
- scan application assets for embedded secret material.

### F-04 - Weak Input Sanitization in feedback.sh

- **Severity:** High
- **Affected script:** `/opt/NewComponent/feedback.sh`
- **Impact:** deny-list bypass and privileged shell interpretation

The script attempted to block selected special characters but did not safely separate user input from shell syntax.

**Remediation:**

- remove `eval()`;
- accept only explicitly valid characters and data formats;
- never depend on blacklist filtering for shell safety;
- separate command logic from user-provided data.

### F-05 - Hidden Directory Information Disclosure

- **Severity:** Medium
- **Affected path:** `/Hidden_Content/`
- **CWE:** CWE-548
- **Impact:** disclosure of the steganographic passphrase

A hidden web-server directory exposed sensitive material needed for credential recovery.

**Remediation:**

- remove non-production hidden content from web-accessible locations;
- disable unnecessary directory listing;
- enforce access controls on non-public resources;
- maintain deployment checks for sensitive files.

## Security Impact

The validated chain resulted in complete root compromise from an unauthenticated remote starting position.

An attacker with equivalent access could:

- execute arbitrary commands through the web application;
- obtain an interactive shell as `www-data`;
- recover hidden credential material;
- authenticate as a valid local user;
- abuse privileged shell scripting;
- write files into the root account;
- authenticate directly as root;
- access or modify all data and system configuration.

The decisive failures were the exposed command backdoor, insecure secret storage, and privileged use of `eval()`.

## Detection Opportunities

Useful monitoring controls include:

- alert on requests containing the `/assets/?cmd=` pattern;
- detect Apache/PHP child processes spawning shells;
- monitor access to `/Hidden_Content/`;
- scan web assets for embedded or encoded credential material;
- monitor SSH logins for newly exposed credentials;
- alert on execution of `/opt/NewComponent/feedback.sh` through sudo;
- detect privileged writes to `/root/.ssh/authorized_keys`;
- monitor new root SSH sessions following sudo script execution.

## Remediation Priorities

1. Remove the command-execution backdoor from `/assets/index.php`.
2. Remove `eval()` from `feedback.sh`.
3. Revoke `deku`'s sudo permission for the script.
4. Rotate the exposed `deku` credential.
5. Remove credential material from `oneforall.jpg`.
6. Remove the hidden passphrase file from the web server.
7. Review web content for additional hidden or test artifacts.
8. Monitor root SSH key changes and privileged sudo script execution.
9. Perform a broader application code review for shell execution primitives.

## Retest Plan

1. Confirm `/assets/` no longer accepts arbitrary `cmd` execution.
2. Verify the web application cannot execute OS commands through user input.
3. Confirm `/Hidden_Content/passphrase.txt` is no longer accessible.
4. Verify the previous steganographic credential material has been removed.
5. Confirm the old `deku` credential no longer authenticates.
6. Verify `deku` cannot execute `feedback.sh` through sudo.
7. Confirm the script no longer uses `eval()`.
8. Verify output redirection cannot write privileged files.
9. Confirm unauthorized SSH keys cannot be added to root's profile.
10. Verify the previous attack chain no longer reaches root.

## Lessons Learned

U.A. High School demonstrates how multiple intentionally weak trust boundaries can turn a simple web exposure into complete system compromise.

The web layer provided unauthenticated command execution, hidden application content exposed the material needed to recover a real account, and a privileged `eval()` script turned a normal user into root.

The strongest defensive response is to treat web command execution, secret storage, local account credentials, sudo rules, and shell parsing as one connected privilege boundary.
