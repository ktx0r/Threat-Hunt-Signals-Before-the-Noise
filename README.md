# Signals Before the Noise

| Field | Detail |
|---|---|
| **Threat Category** | Initial Access · Credential Abuse · Payload Delivery · C2 · Defense Evasion |
| **Client Environment** | PHTG (Healthcare) |
| **Device Investigated** | `azwks-phtg-02` |
| **Hunt Window** | 2025-12-09 to 2025-12-23 |
| **Analyst** | Katie aka ktx0r |

## 1. Executive Summary

I have been requested to investigate anomalous activity on endpoint `azwks-phtg-02` within client environment PHTG, a healthcare organization operating exclusively within the United States. The investigation confirmed a multi-stage intrusion beginning with sustained RDP brute force activity from external IPs, progressing to successful unauthorized authentication from an unexpected geographic region, payload staging and delivery via a double-extension evasion technique, Windows Defender passive mode bypass, and Meterpreter C2 establishment to attacker infrastructure in Uruguay.

The attacker demonstrated patience and operational awareness — leveraging a legitimate internal service directory for payload concealment and abusing an existing scheduled launch mechanism for persistence. No data exfiltration was confirmed, however sensitive internal files were accessed during the operator session.

## 2. Attack Chain Overview

```
RDP Brute Force (External IPs)
        │
        ▼
Successful RDP Logon — Uruguay (173.244.55.131 / .130)
Account: vmadminusername
        │
        ▼
Interactive Session — notepad.exe (Operator Activity Begins)
Sensitive file accessed: notes_sarah.txt
        │
        ▼
Payload Staged: Sarah_Chen_Notes.Txt
  → Renamed: Sarah_Chen_Notes.exe.Txt   (double-extension evasion)
  → Renamed: Sarah_Chen_Notes.exe
  → Defender quarantines (3x, 14:11–14:17)
        │
        ▼
Defender switched to Passive Mode
  → Payload executes without blocking
        │
        ▼
C2 Established: 173.244.55.130:4444 (Meterpreter / Uruguay)
        │
        ▼
Payload renamed: PHTG.exe
Moved to: C:\ProgramData\PHTG\HealthCloud\
Persistence via: Launch.bat (legitimate service wrapper)
```

## 3. Technical Findings

### 3.1 Initial Access — RDP Brute Force

Sustained RDP brute force activity was identified against `azwks-phtg-02` over the hunt window, originating from two primary external sources.

| Metric | Value |
|---|---|
| Total failed logon attempts | 693 |
| Unique source IPs observed | 2 |
| Protocol targeted | RDP (port 3389) |
| Logon failure type | `InvalidUserNameOrPassword` |
| Peak failure count (single IP) | 675 |

### 3.2 Unauthorized Authentication — Uruguay

Despite PHTG operating exclusively within the United States, successful RDP authentications were identified originating from Uruguay — outside the organization's expected operating region.

| Field | Value |
|---|---|
| Account compromised | `vmadminusername` |
| Unexpected country | Uruguay |
| First successful logon (UY) | 2025-12-12 05:47:45 UTC |
| Source IPs (Uruguay) | `173.244.55.131`, `173.244.55.130` |
| Total successful logons (UY) | 23 |

**KQL — Successful Logons by Country:**
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| distinct country_name
```

### 3.3 Operator Activity — Interactive Session

Following the first successful Uruguay logon, routine session startup processes ran for approximately 7.5 hours before an interactive desktop session was established. The first notable indicator of purposeful operator activity was the launch of `notepad.exe` via PowerShell at 13:35 UTC.

During the session, two internal documents were accessed via Notepad:

| File | Path | Assessment |
|---|---|---|
| `Notes 12122025.txt` | `C:\Users\vmAdminUsername\Documents\PHTG\` | General session notes |
| `notes_sarah.txt` | `C:\Users\vmAdminUsername\Documents\PHTG\` | Internal personnel notes — security-relevant content |

### 3.4 Payload Staging — Double Extension Evasion

The attacker staged a payload disguised as an internal document, employing a double-extension technique to evade casual inspection. The full rename chain was reconstructed via `DeviceFileEvents`:

| Timestamp (UTC) | Filename | Action |
|---|---|---|
| 2025-12-12 14:11 | `Sarah_Chen_Notes.Txt` | File exists / baseline |
| 2025-12-12 14:02 | `Sarah_Chen_Notes.exe.Txt` | Renamed — double extension evasion |
| 2025-12-12 14:18 | `Sarah_Chen_Notes.exe` | Renamed — executable form |
| 2025-12-13 10:14 | `Sarah_Chen_Notes.exe` | Moved to HealthCloud directory |
| 2025-12-13 10:22 | `PHTG.exe` | Final rename — masquerades as legitimate service |

**File Hash (SHA256):**
```
224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695
```

### 3.5 Defense Evasion — Defender Passive Mode

Windows Defender detected and quarantined the payload three times between 14:11 and 14:17 on 2025-12-12, classifying it as:

- `Trojan:Win32/Meterpreter.RPZ!MTB`
- `Trojan:Win32/Meterpreter.gen!E`

Following repeated quarantine, Defender was switched to **Passive Mode**, disabling active blocking. The payload subsequently executed without interference.

**DeviceEvents evidence:**
```
"ThreatName":"Trojan:Win32/Meterpreter.RPZ!MTB","ReportSource":"Windows Defender Antivirus passive mode"
```

### 3.6 C2 Communication — Meterpreter over Port 4444

Following execution, the payload established an outbound C2 connection consistent with a Meterpreter reverse shell.

| Field | Value |
|---|---|
| Initiating process | `sarah_chen_notes.exe` |
| Destination IP | `173.244.55.130` |
| Destination port | `4444` |
| Protocol | TCP |
| C2 geography | Uruguay, South America |

Port 4444 is the Metasploit/Meterpreter default listener port. The C2 IP shares a subnet with the initial unauthorized RDP logon source, indicating the same threat actor controlled both the access point and the C2 infrastructure.

### 3.7 Persistence — Legitimate Service Hijack

The final payload was placed inside a directory belonging to a legitimate internal service (`HealthCloud`) rolled out the same week, providing cover for the malicious binary.

| Field | Value |
|---|---|
| Final payload name | `PHTG.exe` |
| Final payload path | `C:\ProgramData\PHTG\HealthCloud\PHTG.exe` |
| Launch mechanism | `C:\ProgramData\PHTG\HealthCloud\Launch.bat` |
| Initiating process | `cmd.exe` |

The batch file was invoked twice on 2025-12-13 (10:21 and 10:22 UTC), suggesting manual re-execution or a scheduled trigger.

## 4. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| IP | `173.244.55.131` | First RDP logon from Uruguay |
| IP | `173.244.55.128` | Secondary RDP source (Uruguay per GeoIP) |
| IP | `173.244.55.130` | Meterpreter C2 |
| SHA256 | `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` | Meterpreter payload |
| File | `Sarah_Chen_Notes.exe` | Payload — phase 1 name |
| File | `Sarah_Chen_Notes.exe.Txt` | Payload — double extension evasion |
| File | `PHTG.exe` | Payload — final masqueraded name |
| File | `Launch.bat` | Persistence mechanism |
| Path | `C:\ProgramData\PHTG\HealthCloud\` | Payload staging directory |
| Account | `vmadminusername` | Compromised credential |
| Port | `4444` | Meterpreter C2 listener |

## 5. MITRE ATT&CK Mapping

| Technique ID | Name | Observed Behavior |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | 693 failed RDP attempts |
| T1078 | Valid Accounts | `vmadminusername` used for unauthorized access |
| T1036.007 | Masquerading: Double File Extension | `Sarah_Chen_Notes.exe.Txt` |
| T1036.005 | Masquerading: Match Legitimate Name | `PHTG.exe` in HealthCloud directory |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defender switched to Passive Mode |
| T1055 | Process Injection | Meterpreter in-memory execution |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over TCP 4444 |
| T1543 | Create or Modify System Process | `Launch.bat` persistence wrapper |

## 6. Recommendations

**Immediate:**
- Isolate `azwks-phtg-02` and reimage
- Rotate all credentials for `vmadminusername` and audit for lateral movement
- Block `173.244.55.128/29` subnet at perimeter firewall
- Block SHA256 hash across all endpoints
- Investigate how Defender was switched to Passive Mode and by what account

**Short Term:**
- Enforce geographic-based Conditional Access — block RDP from outside the US
- Implement account lockout policy after failed RDP attempts
- Enable Defender tamper protection to prevent mode switching
- Audit `C:\ProgramData\` for unexpected executables and batch files
- Review HealthCloud service rollout — determine if other endpoints received similar directory structure

**Long Term:**
- Deploy MFA on all privileged accounts
- Implement Just-In-Time (JIT) RDP access via Azure Bastion
- Establish baseline for normal process behavior on clinical workstations
- Build detection rule: alert on Defender mode changes outside change management windows

## 7. Hunt Methodology

All investigation was conducted using Microsoft Sentinel Log Analytics Workspace (KQL) against the following tables:

- `DeviceLogonEvents` — authentication analysis, brute force identification, geographic correlation
- `DeviceProcessEvents` — process tree analysis, operator activity reconstruction
- `DeviceFileEvents` — payload rename chain, file access, SHA256 correlation
- `DeviceNetworkEvents` — C2 identification, outbound connection analysis
- `DeviceEvents` — Defender telemetry, malware classification, passive mode evidence

Geographic correlation performed via `ipv4_lookup` against the MaxMind GeoIP2 dataset loaded as `externaldata` within KQL.
