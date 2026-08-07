---
title: "TryHackMe: Capture Returns"
date: 2026-07-04 23:56:00 +0200
categories: [TryHackMe]
tags:
  - web
  - authentication
  - brute-force
  - captcha
  - python
  - opencv
  - tesseract
description: >-
  Capture Returns demonstrated that weak administrator credentials remained
  recoverable even after login errors were normalized and CAPTCHA challenges
  were introduced, because both credential testing and the image challenges
  could still be automated.
author: lenovolegion7
media_subpath: /images/tryhackme_capture_returns
image:
  path: room_image.webp
  alt: "Original TryHackMe Capture Returns room artwork"
toc: true
comments: false
---

Capture Returns revisits an administrator login workflow that attempts to resist automated credential attacks with generic errors and image-based CAPTCHA challenges. The validated path showed that the control raised the cost of brute-force attempts but did not stop them: a session-aware Python client extracted the embedded CAPTCHA images, solved shape and arithmetic challenges locally, and continued testing the supplied candidate lists until a valid administrator account was recovered.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Capture Returns room card](room_card.webp){: w="305" h="270" .shadow }](https://tryhackme.com/room/capturereturns){: .center }

## Initial Enumeration

Service discovery identified SSH on TCP/22 and a Gunicorn-backed HTTP application on TCP/80. The application redirected users to `/login`, which presented an administrator login form with `username` and `password` fields.

```console
$ nmap -Pn -sC -sV -T4 TARGET_IP
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu
80/tcp open  http  Gunicorn 20.0.4
```

A manual baseline request confirmed the login workflow:

```console
$ curl -i http://TARGET_IP/login
HTTP/1.1 200 OK
...
```

The assessment used the candidate username and password material supplied by the room rather than attempting unrestricted password generation.

## Validated Attack Path

1. **Service discovery** — identified the SSH service and the Gunicorn HTTP application.
2. **Login workflow review** — confirmed `/login` as the administrator authentication endpoint and observed generic failure responses.
3. **Candidate-list preparation** — built the supplied room material into local username and password lists.
4. **CAPTCHA analysis** — repeated attempts triggered base64-embedded image challenges that could be extracted directly from the HTTP response.
5. **Challenge automation** — OpenCV contour analysis handled geometric shapes, while Tesseract OCR handled arithmetic expressions.
6. **Credential testing** — a persistent `requests.Session` preserved cookies and retried each credential pair after solving the challenge.
7. **Objective validation** — the administrator account `bart` authenticated with password `[REDACTED]`, and the application returned `THM{[REDACTED]}`.

> **Result:** The authentication control was bypassed and protected application access was obtained with a weak administrator credential.
{: .prompt-danger }

## CAPTCHA Workflow Analysis

After enough failed attempts, the response contained an image CAPTCHA encoded as a data URI. The solver extracted the base64 payload, decoded it locally, and classified the challenge before resubmitting the credential pair.

```python
match = B64_RE.search(response.text)
base64_data = match.group(1)
raw = base64.b64decode(base64_data)
image = Image.open(BytesIO(raw)).convert("RGB")
```

Two challenge families were observed:

- **Math expressions** — processed with OCR and evaluated after validation.
- **Geometric shapes** — classified using contour analysis as circle, square, or triangle.

The workflow did not require bypassing the CAPTCHA endpoint itself. Instead, the CAPTCHA was solved as intended but automatically, allowing credential attempts to continue.

## Authentication Automation

The script retained HTTP state with a persistent session, attempted the current credential pair, detected whether a CAPTCHA was present, solved it, and resubmitted the same pair.

```python
session = requests.Session()

# Submit credential pair.
# If the response contains a CAPTCHA:
#   1. decode the embedded image
#   2. solve the challenge locally
#   3. resubmit the same credential pair with the answer
```

The supplied candidate lists contained 29 usernames and 108 passwords. The successful result was:

```console
[*] Users: 29 | Passwords: 108
[+] Credentials: bart:[REDACTED]
[+] Flag: THM{[REDACTED]}
```

## Findings

### CR-01 — Credential brute force remained practical

**Severity:** High

The login endpoint accepted repeated credential attempts without a lockout, rate limit, or progressive delay strong enough to make the supplied search space impractical. CAPTCHA challenges appeared after repeated failures but could be solved automatically.

**Impact:** An attacker with a realistic candidate list could recover a valid administrator account and access protected content.

**Remediation:**

- Apply server-side rate limiting by account, source, and session.
- Introduce lockout or step-up verification after repeated failures.
- Require MFA for administrator accounts.
- Alert on repeated failed authentication and CAPTCHA events.

### CR-02 — CAPTCHA challenge was automatable

**Severity:** High

CAPTCHA images were embedded directly in the HTML response and consisted of machine-readable geometric or arithmetic challenges. Local image processing and OCR solved them reliably enough to continue the attack.

**Impact:** The CAPTCHA delayed automated attempts but did not materially prevent them.

**Remediation:**

- Do not treat CAPTCHA as the primary brute-force defense.
- Pair any CAPTCHA with effective throttling and account protections.
- Prefer risk-based challenges or a hardened provider where CAPTCHA is required.
- Monitor challenge issuance and repeated solve attempts.

### CR-03 — Weak administrator credentials

**Severity:** High

The administrator account `bart` used a common dictionary-style password present in the supplied candidate list.

```text
username: bart
password: [REDACTED]
```

**Impact:** Weak credential hygiene allowed direct authentication without exploiting a server-side code defect.

**Remediation:**

- Require long, unique passwords.
- Block common and breached passwords.
- Require MFA for privileged accounts.
- Review existing administrator credentials for reuse and weak values.

### CR-04 — Enumeration mitigation was incomplete

**Severity:** Medium

Generic login errors reduced direct username enumeration compared with the earlier challenge, but this control did not prevent credential testing against a finite candidate list.

**Impact:** The application reduced one information-disclosure vector without breaking the overall authentication attack path.

**Remediation:**

- Keep generic authentication errors.
- Combine them with throttling, lockouts, MFA, credential hygiene, and telemetry.
- Detect credential-stuffing patterns across accounts and sessions.

## Security Impact

The demonstrated chain resulted in authenticated administrator access to the protected application. In a production environment, the same weaknesses could enable unauthorized access to administrative functions and any data exposed to that account.

The primary issue was not a single CAPTCHA implementation defect in isolation. The compromise depended on several controls failing together: a feasible credential search space, a weak privileged password, insufficient login throttling, and a CAPTCHA that was inexpensive to automate.

## Remediation Priorities

1. Reset the affected administrator password and review all privileged credentials.
2. Require MFA for administrator accounts.
3. Implement account-, IP-, and session-aware rate limits and lockouts.
4. Block common and breached passwords.
5. Replace simple CAPTCHA-only defenses with risk-based controls.
6. Alert on repeated failed logins and repeated CAPTCHA issuance.

## Lessons Learned

Capture Returns demonstrates that uniform authentication errors are useful but insufficient by themselves. A defense against credential attacks must reduce the attacker's ability to make attempts, not merely reduce the information revealed by each individual failure.

CAPTCHA also should not be treated as an authentication boundary. If a challenge can be downloaded and solved locally, a determined automated client can incorporate it into the same credential-testing loop. Rate limiting, MFA, credential quality, and detection remain the more important controls.
