> **Classification:** `TLP:RED — CONFIDENTIAL`
> **Report ID:** `IR-2025-007`
> **Analyst:** `Michael Kirby`
> **Date:** `2026-05-XX`
> **Version:** `1.0`

---

# 🛡️ Threat Hunt Report — Signals After the Noise

---

## 📌 Executive Summary

Following confirmation in a prior hunt that an attacker had established a Meterpreter foothold on `azwks-phtg-02`, this investigation reconstructs what the operator did once inside. Over a seven-hour window on 13 December 2025, the operator returned using previously stolen credentials (not a fresh brute force), moved laterally to a second workstation (`azwks-phtg-01`), and built a fully operational presence across both hosts. This included redundant persistence mechanisms, a masquerading service binary, two parallel command-and-control channels to `health-cloud.cc`, deliberate and layered Windows Defender evasion, and — at the end of the session — a confirmed credential dump from LSASS memory on `azwks-phtg-01`. The operator's tradecraft throughout was deliberate, redundant, and methodical, consistent with a mature, hands-on adversary rather than automated malware.

### 🔑 Key Findings at a Glance

| Category | Detail |
|----------|--------|
| 🔴 **Risk Rating** | `CRITICAL` |
| ⏱️ **Attacker Dwell Time** | `~7 hours confirmed interactive operator activity within this hunt's window (2025-12-13 09:48–18:00 UTC); builds on persistence established in a prior session` |
| 🖥️ **Systems Compromised** | `2 — azwks-phtg-01 (primary operator workspace), azwks-phtg-02 (re-entry point, pre-existing persistence)` |
| 👤 **Users Affected** | `vmadminusername (compromised administrative account, reused from prior compromise)` |
| 📦 **Data Exfiltrated** | `LSASS memory contents read via PROCESS_ALL_ACCESS — confirmed credential dump; downstream use/exfiltration of harvested credentials not confirmed in this hunt's window` |
| 🔑 **Credentials Exposed** | `vmadminusername (reused); LSASS memory contents on azwks-phtg-01 (cached credential material)` |
| 🌐 **Exfil Destination** | `Not confirmed in this hunt — active two-channel C2 to health-cloud.cc represents the likely path for any future exfiltration` |
| 🕵️ **Attacker Infrastructure** | `health-cloud.cc (updates.health-cloud.cc, status.health-cloud.cc) — C2 domain; operator RDP from Uruguay (173.244.55.131)` |
| 📋 **Breach Notification Required** | `PENDING ASSESSMENT — confirmed LSASS credential dump on a second host; scope of harvested credentials and any use of them requires further investigation` |

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Reconstruct the full attack chain from initial access to exfiltration
- Correlate attacker behaviour to MITRE ATT&CK techniques
- Determine the full scope of compromise for breach notification
- Document evidence, detection gaps, and remediation requirements

---

## 🧭 Scope & Environment

| Field | Detail |
|-------|--------|
| **Platform** | `Microsoft Sentinel / Microsoft Defender for Endpoint` |
| **Workspace / Table** | `LAW-Cyber-Range — DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents, DeviceNetworkEvents` |
| **Domain** | `PHTG HealthCloud — internal Azure workstation fleet` |
| **Hosts In Scope** | `azwks-phtg-01 (newly compromised via lateral movement), azwks-phtg-02 (re-entry point, prior persistence)` |
| **Data Sources** | `Microsoft Defender for Endpoint telemetry — logon, process, file, registry, antivirus/detection, and network events` |
| **Investigation Window** | `2025-12-13 09:00 → 2025-12-13 18:00 UTC` |
| **Hunt Triggered By** | `Continuation of prior hunt ("Signals Before the Noise") — confirmed Meterpreter foothold on azwks-phtg-02 required follow-on investigation of post-access operator activity` |

---

## 📚 Table of Contents

- [📌 Executive Summary](#-executive-summary)
- [🎯 Hunt Objectives](#-hunt-objectives)
- [🧭 Scope & Environment](#-scope--environment)
- [🧠 Hunt Overview](#-hunt-overview)
- [⏱️ Attack Timeline](#️-attack-timeline)
- [👤 Attacker Profile](#-attacker-profile)
- [🔴 IOC Summary](#-ioc-summary)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🛠️ Remediation & Containment Checklist](#️-remediation--containment-checklist)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The investigation opened by challenging an assumption. A sequence of failed logons followed by a success on `vmadminusername` looked like brute force at first glance — but comparing failures and successes side-by-side by IP, account, and logon type revealed they didn't match on any dimension. The failures were unrelated internet background noise targeting generic accounts. The `vmadminusername` success was a `Batch` logon with no `RemoteIP` — automated, local execution, not an interactive credential-guessing session. A scheduled task (`PHTG User Baseline Report`), planted in a prior session, was cycling on `azwks-phtg-02` and had fired before the operator even logged in. The access vector was **credential reuse**, not brute force.

That scheduled task did more than just run — it performed lateral movement automatically. At 09:48, before the operator's manual RDP session from Uruguay arrived at 09:52, a `RemoteInteractive` logon landed on `azwks-phtg-01`, sourced from `azwks-phtg-02`'s internal IP (`10.0.0.152`). The operator's persistence had already opened the door to a second host before they sat down. A check for further pivoting from `azwks-phtg-01` returned nothing — the lateral movement stopped at one additional host.

Once on `azwks-phtg-01`, process telemetry revealed the operator's toolkit. The first script executed was a deliberately inconspicuous `_.ps1`, launched with `-WindowStyle Hidden -ExecutionPolicy Bypass` — concealment flags that recurred throughout the session. The command line also exposed the operator's staging directory: `C:\ProgramData\PHTG\HealthCloud`, nested inside a legitimate internal application's folder structure. Files in the `Cache` and `TempCache` subdirectories were hidden using `attrib +h +s`. A binary named `PHTGHealthCloudSvc.exe`, running from this staging directory, was found to falsely claim — via its compiled version metadata — to be `bitsadmin.exe`, a Windows LOLBin masquerade.

Persistence was redundant by design. A registry Run key entry (`PHTGHealthCloudTray`) was written to both hosts, launching a hidden PowerShell script (`HealthCloudTray.ps1`) at every interactive logon. A `.lnk` file (`PHTG HealthCloud.lnk`) was independently dropped into the Startup folder on `azwks-phtg-01` — a second, registry-independent persistence mechanism. A third registry change registered the operator's tooling as a custom Windows Application Event Log source, granting it the ability to blend malicious telemetry into a high-volume log that receives far less scrutiny than the Security log. Validation confirmed the Run key on `azwks-phtg-02` fired twice within the window.

The operator's command-and-control was equally redundant. The masquerading `PHTGHealthCloudSvc.exe` beaconed continuously — 22 `/healthcheck` executions recorded. In parallel, two base64-encoded PowerShell commands decoded to `Invoke-WebRequest` calls against `updates.health-cloud.cc` (task retrieval) and `status.health-cloud.cc` (status reporting) — two independent channels under one parent domain, providing redundancy against detection of either. A consistent one-second download-and-execute pattern was observed repeatedly: an outbound request, followed one second later by local execution of the retrieved payload. After establishing outbound connectivity, the operator ran `amsi_probe.ps1` — a self-describing pre-execution check against Windows' Antimalware Scan Interface. `cmd.exe` was twice used as a deliberate intermediary to break process lineage between PowerShell and follow-on payloads.

Windows Defender was handled in layers. Permanent exclusions were added for the `Cache` staging directory and the `PHTGHealthCloudSvc.exe` masquerade binary. Defender did generate two `AntivirusReport` events against the `PHTG HealthCloud.lnk` artifact, but `WasExecutingWhileDetected: false` meant the file was flagged at rest, not blocked, and persistence remained. Most surgically, a transient Defender exclusion was added for `C:\Users\vmAdminUsername\Documents\PHTG` at the exact timestamp `_.ps1` executed — and removed seconds later, leaving only a timestamp correlation as evidence.

The session ended with credential access. Of 139 `OpenProcessApiCall` events against `lsass.exe`, all but one were attributable to known security tooling or system context. The remaining event — `powershell.exe` under `vmadminusername`, spawned by `task_FLAG-13.ps1` — opened a handle to LSASS with a limited access mask (`5136`), then one second later escalated to `PROCESS_ALL_ACCESS` (`2047999` / `0x1FFFFF`). Three minutes later, a `ReadProcessMemoryApiCall` against `lsass.exe` confirmed the full MITRE T1003.001 credential dump chain: open handle, escalate access, read memory.

---

## ⏱️ Attack Timeline

| Timestamp (UTC) | Host | Action | MITRE Technique |
|----------------|------|--------|----------------|
| 2025-12-13 09:38:02 | azwks-phtg-02 | `PHTGHealthCloudTray` Run key written (pre-anchor, prior persistence) | T1547.001 |
| 2025-12-13 09:48:00 | azwks-phtg-02 | Hunt anchor — `PHTG User Baseline Report` scheduled task fires automatically | T1053.005, T1078 |
| 2025-12-13 09:48:40 | azwks-phtg-01 | Lateral movement — `RemoteInteractive` logon from `10.0.0.152` (azwks-phtg-02) | T1021.001 |
| 2025-12-13 09:52:00 | azwks-phtg-02 | Operator RDPs interactively from Uruguay (`173.244.55.131`) | T1021.001 |
| 2025-12-13 10:11:42 | azwks-phtg-01 | `_.ps1` executes (hidden, bypass); transient Defender exclusion added for `Documents\PHTG` | T1059.001, T1562.001 |
| 2025-12-13 10:12:13 | azwks-phtg-01 | `task_FLAG-01.ps1` begins cycling — download-and-execute loop starts | T1105 |
| 2025-12-13 10:12:17 | azwks-phtg-01 | `PHTGHealthCloudSvc.exe` first `/healthcheck` beacon fires | T1071.001 |
| 2025-12-13 10:12:59 | azwks-phtg-01 | `PHTGHealthCloudTray` Run key written | T1547.001 |
| 2025-12-13 10:13:00 | azwks-phtg-01 | `PHTG HealthCloud.lnk` dropped to Startup folder | T1547.001 |
| 2025-12-13 10:13:43 | azwks-phtg-01 | First encoded PowerShell beacon — `updates.health-cloud.cc` (checkin) | T1027, T1071.001 |
| 2025-12-13 10:13:44 | azwks-phtg-01 | `amsi_probe.ps1` executed from `Bin` directory — AMSI bypass probe | T1562.001 |
| 2025-12-13 10:13:56 | azwks-phtg-01 | Second encoded PowerShell beacon — `status.health-cloud.cc` (status) | T1027, T1071.001, T1090 |
| 2025-12-13 10:14:30 | azwks-phtg-01 | Permanent Defender exclusions written — `Cache` path and `PHTGHealthCloudSvc.exe` process | T1562.001 |
| 2025-12-13 10:14:37 | azwks-phtg-01 | `lsass.exe` `OpenProcessApiCall` — probe (`DesiredAccess` 5136) | T1003.001 |
| 2025-12-13 10:14:38 | azwks-phtg-01 | `lsass.exe` `OpenProcessApiCall` — `PROCESS_ALL_ACCESS` (`DesiredAccess` 2047999 / `0x1FFFFF`) | T1003.001 |
| 2025-12-13 10:17:35 | azwks-phtg-01 | `ReadProcessMemoryApiCall` against `lsass.exe` — credential dump confirmed | T1003.001 |

---

## 👤 Attacker Profile

| Attribute | Detail |
|-----------|--------|
| **Attacker Handle / ID** | `Not identified — no email, alias, or named persona observed in this hunt's telemetry` |
| **Email / Account** | `N/A — not observed` |
| **Cloud Account** | `N/A — not observed` |
| **C2 Infrastructure** | `health-cloud.cc — updates.health-cloud.cc (task retrieval), status.health-cloud.cc (status reporting); operator RDP from 173.244.55.131 (Uruguay, established in prior hunt)` |
| **Staging Server** | `C:\ProgramData\PHTG\HealthCloud — local staging directory nested inside legitimate application folder structure (Cache, TempCache, Bin subdirectories)` |
| **Tools Used** | `PowerShell (hidden/bypass execution), cmd.exe (lineage breaking), attrib.exe (file hiding), PHTGHealthCloudSvc.exe (masquerade binary), encoded PowerShell beacons, scheduled tasks, registry Run keys, Startup folder LNK, amsi_probe.ps1, hc_lineage.ps1` |
| **TTPs** | `Credential reuse for re-entry, automated scheduled-task lateral movement, redundant multi-mechanism persistence (Run key + Startup LNK + EventLog source registration), LOLBin masquerading, file attribute concealment, two-channel encoded C2 beaconing, download-and-execute deployment loop, AMSI probing, process lineage breaking via cmd.exe, layered Defender evasion (permanent + transient exclusions), full LSASS credential dump chain` |
| **Targeting** | `Targeted, hands-on operator activity following an opportunistic initial foothold established in a prior session — this hunt shows deliberate post-access tradecraft, not automated malware` |
| **Sophistication Level** | `High — redundant persistence and C2 channels, deliberate process lineage manipulation, AMSI evasion checks, surgical transient Defender exclusions, and a complete textbook LSASS credential dump chain all within a single 7-hour window` |
| **Credential OPSEC Failures** | `vmadminusername reused across sessions — once compromised, the same credential gave the operator continued access without needing to re-establish a foothold` |

### 🔍 OPSEC Mistakes Observed
- Both C2 beacon domains (`updates.health-cloud.cc`, `status.health-cloud.cc`) share the same parent domain (`health-cloud.cc`), making both traceable once one is identified
- `PHTGHealthCloudSvc.exe` masquerade as `bitsadmin.exe` is detectable via a simple `FileName` vs `ProcessVersionInfoOriginalFileName` mismatch check — no obfuscation of the version metadata itself
- The `_.ps1` filename (a single underscore) is unusual enough to stand out under manual review despite being easy to overlook in bulk
- Registry `RegistryValueDeleted` events for the transient Defender exclusion were not captured, but the timestamp correlation with `_.ps1` execution still exposed the technique
- Two probe-then-escalate `OpenProcessApiCall` events against `lsass.exe` one second apart is a textbook pattern that any LSASS-access detection rule would catch

---

## 🔴 IOC Summary

### 🌐 Network Indicators

| Type | Indicator | Context | Action |
|------|-----------|---------|--------|
| Domain | `health-cloud.cc` | Parent C2 domain | `BLOCK` |
| Domain | `updates.health-cloud.cc` | C2 — task/payload retrieval channel | `BLOCK` |
| Domain | `status.health-cloud.cc` | C2 — status/checkin channel | `BLOCK` |
| IP | `173.244.55.131` | Operator RDP source (Uruguay) — established in prior hunt | `BLOCK` |
| IP | `10.0.0.152` | Internal source of lateral movement (azwks-phtg-02 → azwks-phtg-01) | `MONITOR / INVESTIGATE` |

### 📁 File Indicators

| Type | Indicator | Location | Hash (SHA256) |
|------|-----------|----------|--------------|
| Script | `_.ps1` | `C:\Users\vmAdminUsername\Documents\PHTG\` | `N/A — not captured` |
| Script | `HealthCloudTray.ps1` | `C:\ProgramData\PHTG\HealthCloud\Bin\` | `N/A — not captured` |
| Script | `amsi_probe.ps1` | `C:\ProgramData\PHTG\HealthCloud\Bin\` | `N/A — not captured` |
| Script | `hc_lineage.ps1` | `C:\ProgramData\PHTG\HealthCloud\Cache\` | `N/A — not captured` |
| Batch | `phtg_health_diag_update_FLAG-22.bat` | `C:\ProgramData\PHTG\HealthCloud\Cache\` (TempCache referenced) | `N/A — not captured` |
| Executable (masquerade) | `PHTGHealthCloudSvc.exe` | `C:\ProgramData\PHTG\HealthCloud\` | `N/A — not captured; ProcessVersionInfoOriginalFileName falsely reports bitsadmin.exe` |
| Shortcut (persistence) | `PHTG HealthCloud.lnk` | `C:\Users\vmAdminUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` | `N/A — Defender-detected, not blocked` |
| Directory (staging root) | `C:\ProgramData\PHTG\HealthCloud` | Root staging directory; `Cache` and `TempCache` subdirectories hidden via `attrib +h +s` | `N/A` |

### 👤 Account Indicators

| Account | Type | Action Required |
|---------|------|----------------|
| `vmadminusername` | `Compromised administrative account — credential reuse from prior compromise` | `Password reset + full audit of all activity under this account on both hosts` |

### 🔑 Credential Exposure

| Credential | Where Found | Reset Required |
|------------|-------------|---------------|
| `vmadminusername` | Reused from prior compromise; used for Batch logon re-entry and lateral movement | `YES — IMMEDIATE` |
| LSASS memory contents (azwks-phtg-01) | Read via `ReadProcessMemoryApiCall` after `PROCESS_ALL_ACCESS` handle to `lsass.exe` | `YES — treat all cached credentials on azwks-phtg-01 as compromised; reset accordingly` |

---

## 🧬 MITRE ATT&CK Summary

| # | Flag Name | Tactic | Technique ID | Technique Name | Priority |
|--:|-----------|--------|-------------|----------------|----------|
| 1 | The Brute Force Assumption | Initial Access | T1078 | Valid Accounts | 🔴 Critical |
| 2 | Lateral Movement Summary | Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | 🔴 Critical |
| 3 | Onward Movement Check | Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | 🟡 Medium |
| 4 | First Operator Script | Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | 🔴 Critical |
| 5 | Operator Concealment Flags | Defense Evasion | T1564 | Hide Artifacts | 🟠 High |
| 6 | Operator Tooling Workspace | Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | 🟠 High |
| 7 | Concealment Pattern | Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files and Directories | 🟠 High |
| 8 | LOLBin Masquerade Identification | Defense Evasion | T1036 | Masquerading | 🔴 Critical |
| 9 | Registry Activity Volume | Persistence | T1112 | Modify Registry | 🟡 Medium |
| 10 | Persistence Signal Isolation | Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | 🔴 Critical |
| 11 | Run Key Value Name | Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | 🔴 Critical |
| 12 | Run Key Persistence Command | Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | 🔴 Critical |
| 13 | Second Persistence Mechanism | Persistence | T1547.001 | Boot or Logon Autostart Execution: Startup Folder | 🔴 Critical |
| 14 | Third Persistence Mechanism | Defense Evasion | T1112 | Modify Registry | 🟠 High |
| 15 | Tooling Healthcheck Loop | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | 🟠 High |
| 16 | Encoded Beacon Endpoints | Command and Control | T1027 | Obfuscated Files or Information | 🔴 Critical |
| 17 | Two Beacons, Why? | Command and Control | T1090 | Proxy | 🟡 Medium |
| 18 | Deployment Pattern Recognition | Command and Control | T1105 | Ingress Tool Transfer | 🟠 High |
| 19 | Operator Outbound Domains | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | 🔴 Critical |
| 20 | AMSI Probe Identification | Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | 🟠 High |
| 21 | Lineage Break Pattern | Defense Evasion | T1036 | Masquerading | 🟠 High |
| 22 | Defender Tampering | Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | 🔴 Critical |
| 23 | Defender Detection Outcome | Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | 🟡 Medium |
| 24 | Temporary Defender Exclusion | Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | 🔴 Critical |
| 25 | Startup Execution Validation | Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | 🟡 Medium |
| 26 | Custom Event Log Source Purpose | Defense Evasion | T1036 | Masquerading | 🟡 Medium |
| 27 | LSASS Access Anomaly | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | 🔴 Critical |
| 28 | Access Right Escalation | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | 🔴 Critical |
| 29 | Credential Dump Confirmation | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | 🔴 Critical |

---

## 🔍 Flag Analysis

---

<details>
<summary>🚩 <strong>Flag: The Brute Force Assumption</strong> — <code>T1078</code> — 🔴 Critical</summary>

### 🎯 Objective
Determine whether the failed logons preceding the `vmadminusername` success constitute brute force, or whether the operator used a different access vector.

### 📌 Finding
The failures and the success share no common dimensions — different IPs, different accounts, different logon types. The `vmadminusername` success was a `Batch` logon with no `RemoteIP`, indicating automated local execution via previously held credentials, not brute force.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-02` |
| **Failure Pattern** | `External IPs targeting generic accounts (root, admin, administrator) — unrelated background noise` |
| **Success Account** | `vmadminusername` |
| **Success LogonType** | `Batch` |
| **Success RemoteIP** | `(none)` |
| **Confirmed Mechanism** | `Scheduled task ("PHTG User Baseline Report") cycling under vmadminusername` |

### 💡 Why It Matters
Misclassifying this as brute force would lead an investigation toward external credential-guessing defenses, when the actual issue is a previously planted persistence mechanism running with stolen credentials. The access vector — credential reuse — points directly at the need to find and remove that persistence.

### 🔗 Attack Chain Position
Establishes the foundation for the entire hunt — confirms the operator returned via existing access rather than fresh compromise, and immediately surfaces the scheduled task that performs the next action (lateral movement).

### 🔧 KQL Query Used

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| summarize count() by ActionType, LogonType, RemoteIP, AccountName
| order by ActionType asc
```

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-02"
| where ActionType contains "ScheduledTask"
| project TimeGenerated, ActionType, AdditionalFields
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceLogonEvents
AND AccountName == "vmadminusername"
AND LogonType == "Batch"
AND ActionType == "LogonSuccess"
AND isempty(RemoteIP)
THEN ALERT — HIGH (Unattended Logon for High-Privilege Account)
```

**Hunting Tip:**
Always compare source IP, account, and logon type between failures and successes — if they don't match, it's not brute force. A `Batch` logon with no `RemoteIP` means automated/scheduled execution, not an interactive login.

**MITRE Reference:** [T1078](https://attack.mitre.org/techniques/T1078)

</details>

---

<details>
<summary>🚩 <strong>Flag: Lateral Movement Summary</strong> — <code>T1021.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify where the operator moved laterally from the anchor time, including account, source IP, and target host.

### 📌 Finding
`vmadminusername` moved laterally from `10.0.0.152` (azwks-phtg-02's internal IP) to `azwks-phtg-01` via a `RemoteInteractive` logon at 09:48 — automatically, before the operator's manual RDP session arrived.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host (target)** | `azwks-phtg-01` |
| **Timestamp** | `2025-12-13 09:48 UTC` |
| **Account** | `vmadminusername` |
| **Source IP (RemoteIP)** | `10.0.0.152` |
| **LogonType** | `RemoteInteractive` |

### 💡 Why It Matters
This lateral movement was performed automatically by the persistence mechanism before the operator was even interactively logged in — a sign of a mature operator who set up automated actions rather than relying on manual interaction at every step.

### 🔗 Attack Chain Position
Establishes the second compromised host (`azwks-phtg-01`) as the primary location for the remainder of the operator's activity in this hunt.

### 🔧 KQL Query Used

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where AccountName == "vmadminusername"
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public" or isnotempty(RemoteIP)
| project TimeGenerated, AccountName, RemoteIP, DeviceName, LogonType
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceLogonEvents
AND ActionType == "LogonSuccess"
AND LogonType == "RemoteInteractive"
AND RemoteIP startswith "10."
AND AccountName == known_compromised_account
THEN ALERT — CRITICAL (Internal Lateral Movement from Compromised Account)
```

**Hunting Tip:**
`RemoteIP` in `DeviceLogonEvents` is recorded from the target device's perspective — it shows who connected to it, making it the source IP.

**MITRE Reference:** [T1021.001](https://attack.mitre.org/techniques/T1021/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Onward Movement Check</strong> — <code>T1021.001</code> — 🟡 Medium</summary>

### 🎯 Objective
Check whether the operator pivoted further from `azwks-phtg-01` to any other host in the fleet.

### 📌 Finding
No further pivoting was found — the lateral movement chain stopped at `azwks-phtg-01`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Source IP checked** | `10.0.0.105 (azwks-phtg-01 internal IP)` |
| **Result** | `No successful logons found fleet-wide using this IP as RemoteIP` |

### 💡 Why It Matters
Confirms the scope of lateral movement is bounded to two hosts (`azwks-phtg-02` and `azwks-phtg-01`), allowing remediation efforts to be scoped accordingly without assuming a wider fleet-wide compromise.

### 🔗 Attack Chain Position
Closes the lateral movement investigation thread — confirms the operator's activity for the remainder of this hunt is confined to `azwks-phtg-01` (and the previously established `azwks-phtg-02`).

### 🔧 KQL Query Used

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RemoteIP == "10.0.0.105"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, DeviceName, LogonType
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Checking for onward movement is a standard step after identifying lateral movement — always ask "did they stop here or keep going?" Use the newly compromised host's internal IP as the `RemoteIP` filter and search fleet-wide by dropping the `DeviceName` filter. A clean result means the lateral movement stopped at that host.

**MITRE Reference:** [T1021.001](https://attack.mitre.org/techniques/T1021/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: First Operator Script</strong> — <code>T1059.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the first script the operator launched under their own account context on the newly compromised host.

### 📌 Finding
`C:\Users\vmAdminUsername\Documents\PHTG\_.ps1` — a deliberately inconspicuous, single-underscore-named PowerShell script, executed at 10:11 on `azwks-phtg-01`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Timestamp** | `2025-12-13 10:11 UTC` |
| **Account** | `vmadminusername` |
| **Script** | `C:\Users\vmAdminUsername\Documents\PHTG\_.ps1` |

### 💡 Why It Matters
This is the first observable operator action on the new host — everything that follows in this hunt (staging directory discovery, persistence, C2, AMSI probing, credential access) traces back to this initial execution.

### 🔗 Attack Chain Position
First operator action after lateral movement — the entry point into all subsequent staged activity.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName in ("azwks-phtg-01", "azwks-phtg-02")
| where AccountName == "vmadminusername"
| where ProcessCommandLine has ".ps1" or ProcessCommandLine has ".bat" or ProcessCommandLine has ".vbs"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
| take 10
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Use `has` to filter `ProcessCommandLine` by file extension — it's the fastest way to cut session noise down to only script executions. Always sort ascending when looking for the first occurrence of something. Single-character or single-underscore filenames are deliberately inconspicuous and worth flagging on their own.

**MITRE Reference:** [T1059.001](https://attack.mitre.org/techniques/T1059/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Operator Concealment Flags</strong> — <code>T1564</code> — 🟠 High</summary>

### 🎯 Objective
Identify the PowerShell flags used to conceal the execution of `_.ps1`.

### 📌 Finding
`-WindowStyle Hidden -ExecutionPolicy Bypass` — suppresses the console window and overrides the unsigned-script policy.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Command Line** | `"powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Users\vmAdminUsername\Documents\PHTG\_.ps1"` |
| **Flags** | `-WindowStyle Hidden, -ExecutionPolicy Bypass` |

### 💡 Why It Matters
These two flags together are a high-fidelity indicator of malicious PowerShell execution. Legitimate scripts rarely need both — seeing them together is an immediate red flag worth alerting on.

### 🔗 Attack Chain Position
Establishes the operator's signature concealment pattern, which recurs in the `PHTGHealthCloudTray` Run key entry later in this hunt.

### 🔧 KQL Query Used

No additional query needed — visible in the previous flag's `ProcessCommandLine` output.

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceProcessEvents
AND FileName == "powershell.exe"
AND ProcessCommandLine contains "-WindowStyle Hidden"
AND ProcessCommandLine contains "-ExecutionPolicy Bypass"
THEN ALERT — HIGH (Concealed PowerShell Execution)
```

**Hunting Tip:**
`-WindowStyle Hidden` suppresses the console window so the user doesn't see anything running, and `-ExecutionPolicy Bypass` overrides the policy that would otherwise block unsigned scripts. Seeing them together is rarely legitimate.

**MITRE Reference:** [T1564](https://attack.mitre.org/techniques/T1564)

</details>

---

<details>
<summary>🚩 <strong>Flag: Operator Tooling Workspace</strong> — <code>T1036.005</code> — 🟠 High</summary>

### 🎯 Objective
Identify the root staging directory used by the operator for their tooling.

### 📌 Finding
`C:\ProgramData\PHTG\HealthCloud` — the root directory containing all subsequent task scripts, visible directly in the `_.ps1` command line output.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Root Staging Directory** | `C:\ProgramData\PHTG\HealthCloud` |
| **Subdirectories Referenced** | `Cache, TempCache, Bin` |

### 💡 Why It Matters
`ProgramData` is a common attacker staging location because it's writable by non-admin users and looks legitimate when named after a real application. Nesting inside an existing application's directory structure (`PHTG\HealthCloud`) provides additional camouflage.

### 🔗 Attack Chain Position
Identifies the central location for all of the operator's staged tooling — the anchor for subsequent file concealment, masquerade binary, and persistence findings.

### 🔧 KQL Query Used

Same query as the previous flag — `ProcessCommandLine` already projected.

### 🛡️ Detection Recommendation

**Hunting Tip:**
Always project `ProcessCommandLine` — full file paths are frequently embedded in command lines and can answer follow-on questions about staging directories without needing to pivot into `DeviceFileEvents`.

**MITRE Reference:** [T1036.005](https://attack.mitre.org/techniques/T1036/005)

</details>

---

<details>
<summary>🚩 <strong>Flag: Concealment Pattern</strong> — <code>T1564.001</code> — 🟠 High</summary>

### 🎯 Objective
Identify how many files the operator hid using `attrib.exe`, broken down by subdirectory.

### 📌 Finding
The operator used `attrib.exe` to set hidden (`+h`) and system (`+s`) attributes on files in the `Cache` and `TempCache` subdirectories, with `TempCache` receiving heavier treatment — making the files invisible in normal Explorer views and basic directory listings.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Binary** | `attrib.exe` |
| **Subdirectories Affected** | `Cache, TempCache` |
| **Attributes Set** | `+h +s (hidden, system)` |

### 💡 Why It Matters
`attrib +h +s` makes files invisible to a defender browsing the staging directory normally — they would need `dir /a` or specific queries to find them, meaning casual inspection of the staging directory would appear empty or benign.

### 🔗 Attack Chain Position
Conceals the staging directory contents identified in the previous flag, protecting the operator's tooling from discovery during this and any future investigation.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName == "attrib.exe"
| extend SubDir = tostring(split(ProcessCommandLine, "\\")[4])
| summarize count() by SubDir
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceProcessEvents
AND FileName == "attrib.exe"
AND ProcessCommandLine contains "+h"
AND ProcessCommandLine contains "+s"
AND FolderPath contains "ProgramData"
THEN ALERT — HIGH (File Hiding in Non-Standard Directory)
```

**Hunting Tip:**
`attrib +h +s` makes files invisible in normal Explorer views and basic directory listings — a defender would need `dir /a` or specific queries to find them. Using `split` with a path delimiter and an index is a reusable pattern any time you need to extract a specific folder level from a full file path in KQL.

**MITRE Reference:** [T1564.001](https://attack.mitre.org/techniques/T1564/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: LOLBin Masquerade Identification</strong> — <code>T1036</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify any process whose filename doesn't match its claimed identity (per compiled version metadata), excluding legitimate Windows system processes.

### 📌 Finding
`PHTGHealthCloudSvc.exe`, running from `C:\ProgramData\PHTG\HealthCloud\`, falsely claims via `ProcessVersionInfoOriginalFileName` to be `bitsadmin.exe`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **FileName** | `PHTGHealthCloudSvc.exe` |
| **ProcessVersionInfoOriginalFileName** | `bitsadmin.exe` |
| **FolderPath** | `C:\ProgramData\PHTG\HealthCloud\` |

### 💡 Why It Matters
This binary is masquerading as a legitimate Microsoft tool (`bitsadmin.exe`) while actually running from an attacker-controlled directory. This is the central "service" the operator built — it later beacons continuously and is given a permanent Defender exclusion.

### 🔗 Attack Chain Position
Identifies the operator's core masquerade binary, which becomes the primary C2 healthcheck mechanism (later flag) and a Defender exclusion target (later flag).

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName != ProcessVersionInfoOriginalFileName
| where FolderPath !startswith "C:\\Windows\\"
| project TimeGenerated, FileName, ProcessVersionInfoOriginalFileName, FolderPath, ProcessVersionInfoCompanyName
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceProcessEvents
AND FileName != ProcessVersionInfoOriginalFileName
AND FolderPath !startswith "C:\\Windows\\"
THEN ALERT — CRITICAL (Binary Masquerade Outside System Directory)
```

**Hunting Tip:**
`ProcessVersionInfoOriginalFileName` is the name the binary claims to be at compile time — comparing it against the actual `FileName` surfaces masquerading. Always add `ProcessVersionInfoCompanyName` to confirm — a binary claiming to be a Microsoft tool should show Microsoft Corporation.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036)

</details>

---

<details>
<summary>🚩 <strong>Flag: Registry Activity Volume</strong> — <code>T1112</code> — 🟡 Medium</summary>

### 🎯 Objective
Count registry modification events under the compromised account on `azwks-phtg-01` after the lateral movement anchor.

### 📌 Finding
280 registry modification events recorded under `vmadminusername` after the anchor time.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Account** | `vmadminusername` |
| **Registry Events (post-anchor)** | `280` |

### 💡 Why It Matters
280 registry modifications under the attacker's account after lateral movement is significant — registry changes are commonly used for persistence, defense evasion, and configuration modification, and this volume warranted further filtering to isolate the meaningful entries.

### 🔗 Attack Chain Position
Establishes the scale of registry activity requiring triage — sets up the persistence-focused filtering in the following flags.

### 🔧 KQL Query Used

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| count
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
`count` at the end of any query returns a single integer — the total number of matching rows. When a flag asks for a volume or total, swap `take N` or `project` for `count`.

**MITRE Reference:** [T1112](https://attack.mitre.org/techniques/T1112)

</details>

---

<details>
<summary>🚩 <strong>Flag: Persistence Signal Isolation</strong> — <code>T1547.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Filter the 280 registry events down to the path that matters for persistence.

### 📌 Finding
`HKEY_CURRENT_USER\S-1-5-21-1521579525-3948531162-803360686-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — the Run key, which executes automatically on every user login.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Registry Key** | `HKEY_CURRENT_USER\S-1-5-21-1521579525-3948531162-803360686-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |

### 💡 Why It Matters
The Run key is the most common registry persistence location — anything written here executes automatically at every user logon without further operator interaction.

### 🔗 Attack Chain Position
Narrows the 280 registry events down to the single most relevant persistence path, setting up the value-name and command identification in the following two flags.

### 🔧 KQL Query Used

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where RegistryKey contains "Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceRegistryEvents
AND RegistryKey contains "CurrentVersion\\Run"
AND RegistryValueData contains "-WindowStyle Hidden"
THEN ALERT — CRITICAL (Hidden PowerShell in Run Key)
```

**Hunting Tip:**
When faced with high-volume registry noise, filter toward known persistence locations rather than trying to exclude churn. `HKCU\...\CurrentVersion\Run` is the most common persistence key — start here first, then broaden to Services, Winlogon, or AppInit_DLLs only if Run comes back clean.

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Run Key Value Name</strong> — <code>T1547.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the malicious value name added to the Run key, distinguishing it from legitimate entries.

### 📌 Finding
`PHTGHealthCloudTray` — alongside two legitimate entries (`MicrosoftEdgeAutoLaunch_*` and a OneDrive cleanup entry), this value runs a hidden PowerShell script from the operator's staging directory.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Registry Value Name** | `PHTGHealthCloudTray` |
| **Other Values (legitimate)** | `MicrosoftEdgeAutoLaunch_*, Delete Cached Update Binary` |

### 💡 Why It Matters
Legitimate auto-launch entries point to signed binaries in Program Files. This entry runs a hidden PowerShell script from `ProgramData` — the same concealment pattern (`-WindowStyle Hidden -ExecutionPolicy Bypass`) seen throughout this hunt.

### 🔗 Attack Chain Position
Identifies the specific persistence entry; the next flag extracts its full command for the IOC summary.

### 🔧 KQL Query Used

Same query as the previous flag — `RegistryValueName` and `RegistryValueData` already projected.

### 🛡️ Detection Recommendation

**Hunting Tip:**
Always project both `RegistryValueName` and `RegistryValueData` together — the name tells you what the entry is called, the data tells you what it actually runs.

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Run Key Persistence Command</strong> — <code>T1547.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Extract the full command configured to run via the `PHTGHealthCloudTray` Run key entry.

### 📌 Finding
`powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"`

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **RegistryValueName** | `PHTGHealthCloudTray` |
| **RegistryValueData** | `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"` |

### 💡 Why It Matters
This is the complete, weaponized persistence command — it confirms the script that will execute at every user logon, where it lives, and the concealment flags used. This is the third use of the `-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass` operator signature in this hunt.

### 🔗 Attack Chain Position
Completes the registry persistence finding (Run key path → value name → full command), feeding directly into the persistence validation flag later in this hunt.

### 🔧 KQL Query Used

Same query as the Persistence Signal Isolation flag — `RegistryValueData` already projected.

### 🛡️ Detection Recommendation

**Hunting Tip:**
Always project `RegistryKey`, `RegistryValueName`, and `RegistryValueData` together when hunting registry persistence — they tell the complete story of what was planted, where it lives, and what it runs.

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Second Persistence Mechanism</strong> — <code>T1547.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify a second, registry-independent persistence mechanism on `azwks-phtg-01`.

### 📌 Finding
`PHTG HealthCloud.lnk` — a shortcut file dropped into the Startup folder, which Windows executes automatically at user logon without any registry entry.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **FileName** | `PHTG HealthCloud.lnk` |
| **FolderPath** | `C:\Users\vmAdminUsername\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` |

### 💡 Why It Matters
The Startup folder is a classic second persistence mechanism that doesn't touch the registry at all — making it harder to find if a defender is only hunting Run keys. Using two independent mechanisms ensures the operator survives cleanup of either one alone.

### 🔗 Attack Chain Position
Second of three persistence mechanisms found in this hunt (Run key, Startup folder, EventLog source registration) — this artifact is also the subject of the Defender Detection Outcome flag later in this hunt.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where FolderPath contains "Startup"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceFileEvents
AND FolderPath contains "Start Menu\\Programs\\Startup"
AND ActionType == "FileCreated"
AND FileName endswith ".lnk"
THEN ALERT — HIGH (New Startup Shortcut)
```

**Hunting Tip:**
When hunting persistence always check Run keys, Startup folders, scheduled tasks, and services as a minimum — an operator using two mechanisms ensures they survive cleanup of either one alone.

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Third Persistence Mechanism</strong> — <code>T1112</code> — 🟠 High</summary>

### 🎯 Objective
Identify a system-level (HKLM) registry change made by the operator, distinct from the user-level (HKCU) persistence already found.

### 📌 Finding
`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloudSvc` — the operator registered their tooling as a custom Application event log source.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Timestamp** | `2025-12-13 10:11 UTC` |
| **Registry Key** | `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloudSvc` |

### 💡 Why It Matters
This wasn't classic persistence — it was capability. Registering under the EventLog Application key gives tooling the ability to write events to the Windows Application log via the standard Event Log API, an area defenders rarely scrutinize compared to the Security log.

### 🔗 Attack Chain Position
Third of three persistence/blending mechanisms — directly informs the operator's reasoning explored in the Custom Event Log Source Purpose flag.

### 🔧 KQL Query Used

```kql
DeviceRegistryEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE"
| where InitiatingProcessAccountName == "vmadminusername"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceRegistryEvents
AND RegistryKey startswith "HKEY_LOCAL_MACHINE\\SYSTEM"
AND RegistryKey contains "EventLog\\Application"
AND InitiatingProcessAccountName != "SYSTEM"
THEN ALERT — HIGH (Non-System Account Registering Application Event Log Source)
```

**Hunting Tip:**
HKLM = system-wide settings requiring admin privileges. HKCU = per-user settings. HKLM changes require elevated privileges and affect the whole system, making them higher impact and more suspicious when made by a compromised user account.

**MITRE Reference:** [T1112](https://attack.mitre.org/techniques/T1112)

</details>

---

<details>
<summary>🚩 <strong>Flag: Tooling Healthcheck Loop</strong> — <code>T1071.001</code> — 🟠 High</summary>

### 🎯 Objective
Count how many times the masquerade binary executed its healthcheck beacon during post-access activity.

### 📌 Finding
22 executions of `PHTGHealthCloudSvc.exe` with `/healthcheck` in the command line.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **FileName** | `PHTGHealthCloudSvc.exe` |
| **Healthcheck Executions** | `22` |

### 💡 Why It Matters
22 executions within the investigation window confirms this is a regular automated beaconing loop, not a one-off action — this is the primary C2 channel for the operator's tooling.

### 🔗 Attack Chain Position
First of two parallel C2 channels found in this hunt — paired with the encoded PowerShell beacons in the following flags.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName == "PHTGHealthCloudSvc.exe"
| where ProcessCommandLine has "healthcheck"
| count
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceProcessEvents
AND FileName == "PHTGHealthCloudSvc.exe"
AND ProcessCommandLine has "healthcheck"
AND count() by DeviceName > threshold (e.g. 10 in 1 hour)
THEN ALERT — HIGH (Repeated Beaconing from Masquerade Binary)
```

**Hunting Tip:**
Read the hunt lead carefully — it often contains the exact filter values you need. "Masquerade binary" = the filename from the LOLBin masquerade flag, "beaconing with /healthcheck" = the command line filter, "how many" = `count`.

**MITRE Reference:** [T1071.001](https://attack.mitre.org/techniques/T1071/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Encoded Beacon Endpoints</strong> — <code>T1027</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the encoded PowerShell beacons fired alongside the healthcheck loop and decode their target endpoints.

### 📌 Finding
Two base64-encoded `Invoke-WebRequest` commands decoded to `status.health-cloud.cc/api/checkin?flag=FLAG-09` and `status.health-cloud.cc/api/status?flag=FLAG-10`, both under the parent domain `health-cloud.cc`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Account** | `vmadminusername` |
| **Checkin Endpoint** | `https://status.health-cloud.cc/api/checkin?flag=FLAG-09&device=azwks-phtg-01` |
| **Status Endpoint** | `https://status.health-cloud.cc/api/status?flag=FLAG-10&device=azwks-phtg-01` |
| **Parent Domain** | `health-cloud.cc` |

### 💡 Why It Matters
`-EncodedCommand` is PowerShell's base64 execution flag, almost always used to obscure what's being run. Both endpoints reporting to the same parent domain confirms a single operator framework with multiple reporting channels.

### 🔗 Attack Chain Position
Second C2 channel, running in parallel with the healthcheck loop — directly sets up the "why two channels" reasoning flag that follows.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| where ProcessCommandLine has "EncodedCommand" or ProcessCommandLine has "-enc"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceProcessEvents
AND FileName == "powershell.exe"
AND (ProcessCommandLine has "-EncodedCommand" or ProcessCommandLine has "-enc")
THEN ALERT — CRITICAL (Base64-Encoded PowerShell Execution)
```

**Hunting Tip:**
`-EncodedCommand` is a red flag in any `ProcessCommandLine` — always decode it. "Alongside" in hunt lead language means look for parallel activity under the same account, not child processes.

**MITRE Reference:** [T1027](https://attack.mitre.org/techniques/T1027)

</details>

---

<details>
<summary>🚩 <strong>Flag: Two Beacons, Why?</strong> — <code>T1090</code> — 🟡 Medium</summary>

### 🎯 Objective
Explain the operational benefit of running two parallel C2 channels.

### 📌 Finding
Redundancy (operational continuity if one channel is detected and cut) and detection evasion (the second channel acts as a silent fallback that defenders may not know to look for, complicating correlation and response).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Channel 1** | `PHTGHealthCloudSvc.exe /healthcheck loop (22 executions)` |
| **Channel 2** | `Encoded PowerShell beacons to health-cloud.cc` |

### 💡 Why It Matters
Mature threat actors build redundant C2 infrastructure deliberately. A defender who finds and neutralizes one channel may believe the threat is resolved while the second channel remains fully operational.

### 🔗 Attack Chain Position
Synthesizes the two C2 findings into an operational assessment — informs the "Attacker Profile" sophistication rating for this report.

### 🔧 KQL Query Used

No query needed — operational reasoning based on the previous two flags' findings.

### 🛡️ Detection Recommendation

**Hunting Tip:**
This technique maps to MITRE T1090 (Proxy/Redundant Access) — real operators don't stand up a second channel without reason. When investigating C2, always ask "is there a second channel?" even after finding the first.

**MITRE Reference:** [T1090](https://attack.mitre.org/techniques/T1090)

</details>

---

<details>
<summary>🚩 <strong>Flag: Deployment Pattern Recognition</strong> — <code>T1105</code> — 🟠 High</summary>

### 🎯 Objective
Identify the operator's deployment pattern from a one-second gap between an outbound action and a local execution.

### 📌 Finding
A download-and-execute pattern — an outbound C2 request fires, and one second later, the retrieved task or payload is executed locally. This pattern repeats for every `FLAG` task throughout the session.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Timestamp 1** | `2025-12-13 10:12:16 UTC — outbound request` |
| **Timestamp 2** | `2025-12-13 10:12:17 UTC — local execution (one second later)` |

### 💡 Why It Matters
The tight, consistent one-second timing is deliberate — the operator's tooling was designed to fetch and execute in a single automated sequence. Identifying this pattern means defenders can predict and correlate future task executions with the preceding outbound request.

### 🔗 Attack Chain Position
Confirms the operator's standard deployment loop, which is then used to identify the AMSI probe and lineage-breaking activities in the following flags.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T10:12:10Z) .. datetime(2025-12-13T10:12:25Z))
| where DeviceName == "azwks-phtg-01"
| where AccountName == "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
A one-second gap between an outbound action and a local execution is a classic download-and-execute signature. Narrow time window queries are useful for isolating exactly what fired around a specific timestamp.

**MITRE Reference:** [T1105](https://attack.mitre.org/techniques/T1105)

</details>

---

<details>
<summary>🚩 <strong>Flag: Operator Outbound Domains</strong> — <code>T1071.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the domains contacted by PowerShell under the operator's account during post-access activity.

### 📌 Finding
`updates.health-cloud.cc` and `status.health-cloud.cc` — both confirmed in network telemetry, matching the decoded beacon endpoints from the Encoded Beacon Endpoints flag.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Account** | `vmadminusername` |
| **Initiating Process** | `powershell.exe` |
| **Domains** | `updates.health-cloud.cc, status.health-cloud.cc` |

### 💡 Why It Matters
Confirms both domains via network telemetry (RemoteUrl), independent of the process-level decoded command findings — corroborating evidence from a second telemetry source. `updates` for pulling tasks, `status` for beaconing back — a clean two-channel operator framework.

### 🔗 Attack Chain Position
Corroborates and finalizes the C2 infrastructure identification from the Encoded Beacon Endpoints flag — both domains now confirmed as IOCs.

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where InitiatingProcessFileName == "powershell.exe"
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceNetworkEvents
AND RemoteUrl contains "health-cloud.cc"
THEN ALERT — CRITICAL (Connection to Known C2 Domain)
```

**Hunting Tip:**
When hunting outbound connections from a specific process, use `InitiatingProcessFileName` in `DeviceNetworkEvents` — it ties network activity back to the process that made the connection.

**MITRE Reference:** [T1071.001](https://attack.mitre.org/techniques/T1071/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: AMSI Probe Identification</strong> — <code>T1562.001</code> — 🟠 High</summary>

### 🎯 Objective
Identify the script the operator ran after outbound C2 connections succeeded, and determine its purpose.

### 📌 Finding
`amsi_probe.ps1`, executed from the `Bin` staging directory — testing whether Windows' Antimalware Scan Interface (AMSI) is active or bypassable before deploying further payloads.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Timestamp** | `2025-12-13 10:13:44 UTC` |
| **Script** | `C:\ProgramData\PHTG\HealthCloud\Bin\amsi_probe.ps1` |
| **Other Bin Script (same window)** | `hc_lineage.ps1` |

### 💡 Why It Matters
AMSI probing is a pre-execution check — operators test defensive tooling before deploying further payloads to avoid triggering detections. The self-describing script name makes the operator's intent unambiguous.

### 🔗 Attack Chain Position
Occurs immediately after outbound C2 connections succeed — represents the operator preparing for further payload deployment, validating the environment is safe to proceed in.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T10:13:44Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where ProcessCommandLine has "Bin" or ProcessCommandLine has "HealthCloud\\Bin"
| project InitiatingProcessCommandLine, ProcessCommandLine
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceProcessEvents
AND ProcessCommandLine contains "amsi"
AND FolderPath contains "ProgramData"
THEN ALERT — HIGH (Potential AMSI Bypass Probe)
```

**Hunting Tip:**
Script names often reveal their purpose directly — `amsi_probe`, `hc_lineage`, `task_FLAG` are all self-describing. "Plain non-encoded" in hunt lead language means the script path is visible directly in `ProcessCommandLine` without needing base64 decoding.

**MITRE Reference:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Lineage Break Pattern</strong> — <code>T1036</code> — 🟠 High</summary>

### 🎯 Objective
Identify the two occasions where `cmd.exe` was used as an intermediary to launch follow-on payloads, breaking direct process lineage.

### 📌 Finding
`cmd.exe` was used twice — once to launch `hc_lineage.ps1` (spawned by `task_FLAG-17.ps1`) and once to launch `phtg_health_diag_update_FLAG-22.bat` (spawned by `task_FLAG-22.ps1`).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Account** | `vmadminusername` |
| **Invocation 1** | `"cmd.exe" /c powershell.exe ... hc_lineage.ps1 — spawned by task_FLAG-17.ps1` |
| **Invocation 2** | `"cmd.exe" /c "...phtg_health_diag_update_FLAG-22.bat" — spawned by task_FLAG-22.ps1` |

### 💡 Why It Matters
Inserting `cmd.exe` between the parent PowerShell and the payload breaks the direct parent-child relationship in the process tree — a deliberate tradecraft choice that makes automated detection and manual triage harder by obscuring attribution.

### 🔗 Attack Chain Position
Continues the operator's deployment loop pattern (from the Deployment Pattern Recognition flag), showing two specific instances of obfuscation within that loop.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where FileName == "cmd.exe"
| where ProcessCommandLine !has "whoami"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceProcessEvents
AND FileName == "cmd.exe"
AND InitiatingProcessFileName == "powershell.exe"
AND InitiatingProcessCommandLine contains "ProgramData"
THEN ALERT — HIGH (Process Lineage Break via cmd.exe)
```

**Hunting Tip:**
When hunting `cmd.exe` as an intermediary, filter on `FileName == "cmd.exe"` to see the invocations themselves, not `InitiatingProcessFileName == "cmd.exe"` which shows what cmd spawned.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036)

</details>

---

<details>
<summary>🚩 <strong>Flag: Defender Tampering</strong> — <code>T1562.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify what the operator excluded from Defender scanning after persistence was established.

### 📌 Finding
Two permanent Defender exclusions: a path exclusion for `C:\ProgramData\PHTG\HealthCloud\Cache` (the script staging directory) and a process exclusion for `C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe` (the masquerade binary).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Path Exclusion** | `C:\ProgramData\PHTG\HealthCloud\Cache` |
| **Process Exclusion** | `C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe` |

### 💡 Why It Matters
Adding exclusions is a common post-persistence step — the attacker plants their tooling first, then silences Defender against it so subsequent executions don't trigger alerts. Both exclusions target artifacts already identified in this hunt (staging directory and masquerade binary).

### 🔗 Attack Chain Position
Final defense-evasion step after persistence and C2 are established — protects the operator's tooling from ongoing detection for the remainder of the operation.

### 🔧 KQL Query Used

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey contains "Defender"
| where RegistryKey contains "Exclusion"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceRegistryEvents
AND RegistryKey contains "Windows Defender\\Exclusions"
AND InitiatingProcessAccountName != "SYSTEM"
THEN ALERT — CRITICAL (Defender Exclusion Added by Non-System Account)
```

**Hunting Tip:**
Defender exclusions live at `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\` with separate subkeys for Paths and Processes. Always check Defender exclusion keys when investigating registry tampering.

**MITRE Reference:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Defender Detection Outcome</strong> — <code>T1562.001</code> — 🟡 Medium</summary>

### 🎯 Objective
Determine whether Defender's detection of the LNK persistence artifact resulted in it being blocked.

### 📌 Finding
Defender generated two `AntivirusReport` events against `PHTG HealthCloud.lnk`, both showing `WasExecutingWhileDetected: false` — the file was detected at rest, not while running, and was not blocked. Persistence remained in place.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **FileName** | `PHTG HealthCloud.lnk` |
| **AntivirusReport Events** | `2` |
| **WasExecutingWhileDetected** | `false (both events)` |

### 💡 Why It Matters
An `AntivirusReport` event is not the same as a block — detection and prevention are different outcomes. Defender saw the artifact but did not remediate it, meaning the Startup folder persistence (identified in the Second Persistence Mechanism flag) remained fully functional despite being flagged.

### 🔗 Attack Chain Position
Confirms that the Startup folder persistence mechanism survived Defender's detection — relevant to remediation scoping (this artifact must be manually removed, Defender will not have done so).

### 🔧 KQL Query Used

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "AntivirusDetection" or ActionType contains "AntivirusReport"
| where FileName contains "HealthCloud" or FileName contains ".lnk"
| project TimeGenerated, FileName, ActionType, AdditionalFields
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
`WasExecutingWhileDetected` is a critical field — `true` means Defender caught something actively running and likely blocked it, `false` means it was detected at rest and may not have been remediated. Always check this field when assessing whether Defender actually stopped something or just logged it.

**MITRE Reference:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Temporary Defender Exclusion</strong> — <code>T1562.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify a transient Defender exclusion added immediately before `_.ps1` executed and removed seconds later.

### 📌 Finding
A Defender exclusion for `C:\Users\vmAdminUsername\Documents\PHTG` was added at exactly 10:11:42 — the same timestamp as `_.ps1`'s execution — and removed within seconds (the delete event itself was not captured in telemetry, but the timestamp correlation confirms the pattern).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Timestamp** | `2025-12-13 10:11:42 UTC` |
| **Excluded Path** | `C:\Users\vmAdminUsername\Documents\PHTG` |
| **Add Event** | `Captured (RegistryValueSet)` |
| **Delete Event** | `Not captured — registry deletes not always logged by MDE` |

### 💡 Why It Matters
This is a transient exclusion technique — it allows a payload to drop or execute without Defender scanning it, then cleans up the exclusion to reduce forensic evidence of tampering. The window can be seconds, making this one of the hardest defensive evasion techniques to catch.

### 🔗 Attack Chain Position
The most surgical Defender evasion in this hunt — directly protected the execution of `_.ps1`, the first operator script identified at the start of this investigation.

### 🔧 KQL Query Used

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T10:11:40Z) .. datetime(2025-12-13T10:13:00Z))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey contains "Defender"
| where ActionType in ("RegistryValueSet", "RegistryValueDeleted")
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceRegistryEvents
AND RegistryKey contains "Windows Defender\\Exclusions"
AND ActionType == "RegistryValueSet"
AND (correlate with DeviceProcessEvents for script execution within same 5-second window)
THEN ALERT — CRITICAL (Transient Defender Exclusion Correlated with Script Execution)
```

**Hunting Tip:**
The timestamp correlation between the exclusion add and the script execution is the key evidence. MDE does not always log `RegistryValueDeleted` events — absence of a delete event doesn't mean the exclusion wasn't removed; cross-reference with process timestamps to confirm the pattern.

**MITRE Reference:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Startup Execution Validation</strong> — <code>T1547.001</code> — 🟡 Medium</summary>

### 🎯 Objective
Confirm how many times the `PHTGHealthCloudTray` Run key persistence actually fired.

### 📌 Finding
2 — the Run key was written to `azwks-phtg-02` at 09:38:02 (earlier than on `azwks-phtg-01`), and counting `RemoteInteractive` logons on `azwks-phtg-02` after that time returned 2 executions.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host (where it fired)** | `azwks-phtg-02` |
| **Run Key Write Time** | `2025-12-13 09:38:02 UTC` |
| **RemoteInteractive Logons (post-write)** | `2` |

### 💡 Why It Matters
Persistence only matters if it fires. This confirms the registry persistence wasn't merely planted but actually executed — twice — validating it as an active, functioning mechanism rather than dormant configuration.

### 🔗 Attack Chain Position
Validates the registry persistence findings from earlier in this hunt — closes the persistence investigation thread with confirmation of actual execution.

### 🔧 KQL Query Used

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where RegistryValueName == "PHTGHealthCloudTray"
| project TimeGenerated, DeviceName, RegistryValueData
```

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13T09:38:02Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-02"
| where AccountName == "vmadminusername"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| count
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Run key persistence fires at every interactive logon — count the logons after the key was written to know how many times it executed. Always check all devices for persistence, not just the one you're investigating.

**MITRE Reference:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Custom Event Log Source Purpose</strong> — <code>T1036</code> — 🟡 Medium</summary>

### 🎯 Objective
Explain what registering a custom Application event log source enables, and why the operator wanted it.

### 📌 Finding
Registering under `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\` enables the operator's tooling to write events to the Windows Application log via the standard Event Log API. The Application log is high-volume and filled with legitimate software entries — defenders focus on the Security log, not Application, making this a blending technique.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Registered Source** | `PHTGHealthCloudSvc` |
| **Registry Location** | `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloudSvc` |

### 💡 Why It Matters
Registry changes don't always mean persistence — sometimes they grant capability. The Application log is trusted, noisy, and rarely flagged — writing malicious telemetry there is harder to detect than writing to a custom log or leaving no trace at all.

### 🔗 Attack Chain Position
Closes out the persistence/blending investigation thread with operational reasoning about the EventLog registration found earlier in this hunt.

### 🔧 KQL Query Used

No query needed — reasoning based on the Third Persistence Mechanism flag's findings.

### 🛡️ Detection Recommendation

**Hunting Tip:**
Registering an event log source is a blending technique, not a persistence mechanism. When investigating HKLM EventLog registry changes, ask "what capability does this grant" rather than assuming it's purely about surviving reboots.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036)

</details>

---

<details>
<summary>🚩 <strong>Flag: LSASS Access Anomaly</strong> — <code>T1003.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Isolate the anomalous process accessing `lsass.exe`, filtering out known legitimate security tooling.

### 📌 Finding
`powershell.exe`, running under `vmadminusername`, spawned by `task_FLAG-13.ps1` — the only `OpenProcessApiCall` against `lsass.exe` not attributable to `MsMpEng.exe`, `WmiPrvSE.exe`, `SenseIR.exe`, or system context, out of 139 total events.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Total OpenProcessApiCall events vs lsass.exe** | `139` |
| **Anomalous Process** | `powershell.exe` |
| **Account** | `vmadminusername` |
| **Spawning Script** | `task_FLAG-13.ps1` |

### 💡 Why It Matters
`OpenProcessApiCall` against `lsass.exe` is a high-fidelity credential access indicator — it's how tools like Mimikatz read credentials from memory. Filtering out the known security tooling baseline (MsMpEng = Defender, SenseIR = MDE sensor) leaves only genuinely anomalous activity.

### 🔗 Attack Chain Position
First step of the three-step LSASS credential dump chain — sets up the access-right escalation found in the next flag.

### 🔧 KQL Query Used

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T09:00:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessFileName !in ("MsMpEng.exe", "WmiPrvSE.exe", "SenseIR.exe")
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceEvents
AND ActionType == "OpenProcessApiCall"
AND FileName == "lsass.exe"
AND InitiatingProcessFileName !in (known_security_tooling)
AND InitiatingProcessAccountName != "system"
THEN ALERT — CRITICAL (Non-Standard Process Accessing LSASS)
```

**Hunting Tip:**
Always filter out known security tooling (`MsMpEng.exe` = Defender, `SenseIR.exe` = MDE sensor, `WmiPrvSE.exe`) when hunting `lsass` access — they legitimately open lsass and will dominate the results without exclusion.

**MITRE Reference:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Access Right Escalation</strong> — <code>T1003.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Decode the `DesiredAccess` values of two `OpenProcessApiCall` events against `lsass.exe` fired one second apart.

### 📌 Finding
The first event carried `DesiredAccess` 5136 (limited, specific rights — a probe). The second, one second later, carried `2047999` (`0x1FFFFF`) — `PROCESS_ALL_ACCESS`, every possible right including reading process memory.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Timestamp 1** | `2025-12-13 10:14:37 UTC — DesiredAccess 5136` |
| **Timestamp 2** | `2025-12-13 10:14:38 UTC — DesiredAccess 2047999 (0x1FFFFF, PROCESS_ALL_ACCESS)` |
| **Account** | `vmadminusername` |

### 💡 Why It Matters
`PROCESS_ALL_ACCESS` (`0x1FFFFF`) against `lsass.exe` is one of the strongest credential dumping indicators in Windows telemetry — it's the access right required to read lsass memory where cached credentials live. The probe-then-escalate pattern, one second apart, is deliberate operator tradecraft.

### 🔗 Attack Chain Position
Second step of the three-step LSASS credential dump chain — the elevated handle obtained here is used to read memory in the final flag.

### 🔧 KQL Query Used

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T10:14:37Z) .. datetime(2025-12-13T10:14:39Z))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessAccountName == "vmadminusername"
| project TimeGenerated, AdditionalFields
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceEvents
AND ActionType == "OpenProcessApiCall"
AND FileName == "lsass.exe"
AND AdditionalFields contains "2047999"
THEN ALERT — CRITICAL (PROCESS_ALL_ACCESS Handle to LSASS)
```

**Hunting Tip:**
Always decode `DesiredAccess` values when investigating lsass access; the difference between specific rights and `PROCESS_ALL_ACCESS` tells you whether it's routine system activity or credential theft.

**MITRE Reference:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)

</details>

---

<details>
<summary>🚩 <strong>Flag: Credential Dump Confirmation</strong> — <code>T1003.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Confirm whether the elevated LSASS handle was used to actually read process memory.

### 📌 Finding
`ReadProcessMemoryApiCall` against `lsass.exe` from `powershell.exe` under `vmadminusername` at 10:17:35 — confirming the full credential dump chain.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `azwks-phtg-01` |
| **Timestamp** | `2025-12-13 10:17:35 UTC` |
| **ActionType** | `ReadProcessMemoryApiCall` |
| **Target Process** | `lsass.exe` |
| **Initiating Process** | `powershell.exe` |
| **Account** | `vmadminusername` |

### 💡 Why It Matters
Opening a full-access handle to lsass is not dumping yet — the actual memory read is the confirmation. All three steps (open handle → escalate to PROCESS_ALL_ACCESS → read memory) together represent the complete MITRE T1003.001 execution chain visible in MDE telemetry — definitive evidence of credential theft.

### 🔗 Attack Chain Position
Final and conclusive step of the LSASS credential dump chain — the last operator action observed within this hunt's investigation window.

### 🔧 KQL Query Used

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T10:14:37Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where ActionType contains "Memory" or ActionType contains "Read" or ActionType contains "Dump"
| project TimeGenerated, ActionType, FileName, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DeviceEvents
AND ActionType == "ReadProcessMemoryApiCall"
AND FileName == "lsass.exe"
AND InitiatingProcessAccountName != "system"
THEN ALERT — CRITICAL (Confirmed LSASS Memory Read — Credential Dump)
```

**Hunting Tip:**
The credential dump chain in telemetry is three steps — `OpenProcessApiCall`, `DesiredAccess` escalation to `0x1FFFFF`, then `ReadProcessMemoryApiCall`. All three need to fire against lsass to confirm an actual dump rather than just a probe. Each step alone could be explained away; all three together is definitive.

**MITRE Reference:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)

</details>

---

## 🚨 Detection Gaps & Recommendations

### 🕳️ Observed Gaps

| Gap | Impact | Recommended Fix |
|-----|--------|----------------|
| No alerting on `Batch` logons with no `RemoteIP` for privileged accounts | Critical — allowed the operator's persistence to fire silently and perform lateral movement before any interactive session | Alert on `Batch`/unattended logons for administrative accounts, especially those followed by lateral movement |
| No alerting on internal lateral movement preceding external authentication | High — the automated lateral movement at 09:48 preceded the operator's manual RDP at 09:52, but no correlation alert existed | Build a correlation rule linking internal `RemoteInteractive` logons from a recently-compromised host to subsequent external authentication on the source host |
| No alerting on `-WindowStyle Hidden -ExecutionPolicy Bypass` PowerShell executions | Critical — this exact flag combination recurred at least three times across this hunt (`_.ps1`, `HealthCloudTray.ps1`, and others) with no detection | Alert on any PowerShell execution combining `-WindowStyle Hidden` and `-ExecutionPolicy Bypass` |
| No alerting on `FileName != ProcessVersionInfoOriginalFileName` outside `C:\Windows\` | Critical — allowed `PHTGHealthCloudSvc.exe` to masquerade as `bitsadmin.exe` undetected | Alert on any binary metadata mismatch for processes running from `C:\ProgramData\` or other non-standard directories |
| No alerting on `attrib +h +s` against files in `ProgramData` | High — allowed the operator's entire toolkit in `Cache` and `TempCache` to remain hidden from casual inspection | Alert on `attrib.exe` invocations with `+h` and `+s` flags targeting paths outside standard system directories |
| No alerting on new Registry Run key entries pointing to PowerShell with concealment flags | Critical — `PHTGHealthCloudTray` went unnoticed despite being a textbook malicious Run key entry | Alert on any `CurrentVersion\Run` entry where `RegistryValueData` contains `powershell.exe` and `-WindowStyle Hidden` |
| No alerting on new Startup folder `.lnk` files | High — `PHTG HealthCloud.lnk` was detected by Defender but not blocked, and no SOC alert was generated from the detection event itself | Alert on any `AntivirusReport` event regardless of `WasExecutingWhileDetected` value — detection-without-block events still require analyst review |
| No alerting on HKLM EventLog Application source registration by non-SYSTEM accounts | High — allowed the operator to register `PHTGHealthCloudSvc` as an Application log source without scrutiny | Alert on writes to `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\` by non-SYSTEM initiating processes |
| No alerting on repeated beaconing patterns (`/healthcheck` loop) | High — 22 executions of the same command within the window generated no volume-based alert | Implement frequency-based detection for repeated identical process executions with network-adjacent timing |
| No alerting on base64 `-EncodedCommand` PowerShell to non-Microsoft domains | Critical — both `health-cloud.cc` beacon channels went undetected | Alert on any `-EncodedCommand`/`-enc` PowerShell execution, and separately alert on any outbound connection to domains not on an allowlist |
| No alerting on `cmd.exe` spawned directly by `powershell.exe` from `ProgramData` paths | High — both lineage-breaking invocations went unnoticed | Alert on `cmd.exe` invocations where `InitiatingProcessFileName == "powershell.exe"` and `InitiatingProcessCommandLine` references `ProgramData` |
| No alerting on Defender exclusion additions by non-SYSTEM accounts | Critical — both permanent exclusions and the transient exclusion went unnoticed | Alert on any write to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\` where `InitiatingProcessAccountName != SYSTEM` |
| No correlation between transient registry changes and concurrent script execution | Critical — the transient Defender exclusion's delete event was never logged, and without timestamp correlation this technique would have gone entirely undetected | Build correlation rules that pair `RegistryValueSet` events on Defender exclusion keys with `DeviceProcessEvents` script executions within a tight time window (e.g. 10 seconds) |
| No alerting on `OpenProcessApiCall` against `lsass.exe` with `DesiredAccess` escalation | Critical — the entire LSASS credential dump chain (139 events, only 1 anomalous) went unnoticed without manual hunting | Alert on any non-security-tooling process accessing `lsass.exe` with `DesiredAccess` values matching or exceeding `PROCESS_ALL_ACCESS` (`0x1FFFFF`), especially when followed by `ReadProcessMemoryApiCall` |

### ✅ Recommended Detection Rules

```
RULE 1 — Unattended Batch Logon for Privileged Account
IF DeviceLogonEvents
AND AccountName in (privileged_accounts)
AND LogonType == "Batch"
AND isempty(RemoteIP)
THEN ALERT HIGH

RULE 2 — Concealed PowerShell Execution
IF DeviceProcessEvents
AND FileName == "powershell.exe"
AND ProcessCommandLine contains "-WindowStyle Hidden"
AND ProcessCommandLine contains "-ExecutionPolicy Bypass"
THEN ALERT CRITICAL

RULE 3 — Binary Identity Masquerade Outside System32
IF DeviceProcessEvents
AND FileName != ProcessVersionInfoOriginalFileName
AND FolderPath !startswith "C:\\Windows\\"
THEN ALERT CRITICAL

RULE 4 — File Hiding via attrib in Non-Standard Directory
IF DeviceProcessEvents
AND FileName == "attrib.exe"
AND ProcessCommandLine contains "+h"
AND ProcessCommandLine contains "+s"
AND FolderPath contains "ProgramData"
THEN ALERT HIGH

RULE 5 — Malicious Run Key Entry
IF DeviceRegistryEvents
AND RegistryKey contains "CurrentVersion\\Run"
AND RegistryValueData contains "powershell.exe"
AND RegistryValueData contains "-WindowStyle Hidden"
THEN ALERT CRITICAL

RULE 6 — Base64-Encoded PowerShell to Non-Allowlisted Domain
IF DeviceProcessEvents
AND FileName == "powershell.exe"
AND (ProcessCommandLine has "-EncodedCommand" or ProcessCommandLine has "-enc")
THEN ALERT CRITICAL

RULE 7 — Defender Exclusion by Non-SYSTEM Account
IF DeviceRegistryEvents
AND RegistryKey contains "Windows Defender\\Exclusions"
AND InitiatingProcessAccountName != "SYSTEM"
THEN ALERT CRITICAL

RULE 8 — LSASS PROCESS_ALL_ACCESS Followed by Memory Read
IF DeviceEvents
AND FileName == "lsass.exe"
AND ActionType == "OpenProcessApiCall"
AND AdditionalFields contains "2047999"
AND (correlate with subsequent ReadProcessMemoryApiCall within 10 minutes)
THEN ALERT CRITICAL
```

---

## 🛠️ Remediation & Containment Checklist

### 🔴 Immediate Actions (0–4 hours)

- [ ] Isolate `azwks-phtg-01` and `azwks-phtg-02` from the network — confirmed credential dump and active two-channel C2
- [ ] Reset `vmadminusername` credentials immediately on both hosts
- [ ] Treat all credentials cached in LSASS memory on `azwks-phtg-01` as compromised — reset accordingly across any accounts that may have authenticated to that host
- [ ] Block `health-cloud.cc` and all subdomains (`updates.health-cloud.cc`, `status.health-cloud.cc`) at DNS/firewall
- [ ] Block `173.244.55.131` (operator RDP source) at firewall
- [ ] Preserve forensic images of both `azwks-phtg-01` and `azwks-phtg-02` before any remediation
- [ ] Notify legal and compliance teams given confirmed LSASS credential dump

### 🟠 Short Term (4–24 hours)

- [ ] Remove all attacker tooling from `C:\ProgramData\PHTG\HealthCloud\` on both hosts:
  - [ ] `PHTGHealthCloudSvc.exe`
  - [ ] `Bin\HealthCloudTray.ps1`
  - [ ] `Bin\amsi_probe.ps1`
  - [ ] `Cache\hc_lineage.ps1`
  - [ ] `Cache\phtg_health_diag_update_FLAG-22.bat` (and any other `task_FLAG-*` scripts)
  - [ ] `Documents\PHTG\_.ps1`
- [ ] Remove persistence mechanisms:
  - [ ] Registry Run key: `PHTGHealthCloudTray` (both `azwks-phtg-01` and `azwks-phtg-02`)
  - [ ] Startup folder item: `PHTG HealthCloud.lnk`
  - [ ] Scheduled task: `PHTG User Baseline Report` (on `azwks-phtg-02`)
  - [ ] HKLM EventLog source registration: `PHTGHealthCloudSvc`
- [ ] Remove Defender exclusions:
  - [ ] Path exclusion: `C:\ProgramData\PHTG\HealthCloud\Cache`
  - [ ] Process exclusion: `C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe`
- [ ] Audit all activity performed under `vmadminusername` across both hosts for the full investigation window and beyond
- [ ] Review and restore any cleared/altered event logs from SIEM backup, including Application log entries that may contain operator-injected telemetry

### 🟡 Medium Term (1–7 days)

- [ ] Rebuild both `azwks-phtg-01` and `azwks-phtg-02` from clean images given confirmed credential dumping and deeply embedded redundant persistence
- [ ] Conduct full audit of `C:\ProgramData\` across the fleet for similarly disguised staging directories (`<AppName>\HealthCloud`-style nesting)
- [ ] Audit all administrative accounts for credential reuse patterns — `vmadminusername` was reused across sessions without re-compromise
- [ ] Conduct full audit of HKCU `CurrentVersion\Run` and Startup folders across the fleet for similar concealment-flagged PowerShell entries
- [ ] Audit HKLM `SYSTEM\ControlSet001\Services\EventLog\Application\` across the fleet for unauthorized event log source registrations
- [ ] Deploy and tune detection rules identified in this report
- [ ] Review Windows Defender exclusion lists across the fleet for unauthorized entries

### 🔵 Long Term (1–4 weeks)

- [ ] Implement Credential Guard to protect LSASS on all endpoints, particularly hosts handling administrative accounts
- [ ] Deploy Protected Process Light (PPL) for LSASS
- [ ] Implement application allowlisting to prevent execution of unsigned/unknown binaries from `ProgramData`
- [ ] Implement DNS-layer filtering with an allowlist approach for outbound PowerShell-initiated connections
- [ ] Conduct purple team exercise simulating credential-reuse re-entry, lateral movement via scheduled tasks, and LSASS dumping
- [ ] Update incident response playbooks to include the brute-force-vs-credential-reuse triage technique demonstrated in this hunt
- [ ] Brief CISO and board on findings — confirmed credential dump represents a significant escalation from the prior hunt's findings

---

## 🧾 Final Assessment

### Risk Conclusion

This hunt confirmed that the operator behind the prior session's Meterpreter foothold returned using previously stolen credentials and conducted a deliberate, methodical post-access operation across two hosts. Every stage of this investigation revealed redundancy: two persistence mechanisms on the registry/filesystem level plus a third for blending, two parallel C2 channels under one parent domain, and a layered approach to Defender evasion combining permanent exclusions, a transient exclusion timed to the second, and acceptance of detection-without-blocking as an acceptable outcome.

The operator's sophistication is rated High. The credential reuse for re-entry, automated scheduled-task lateral movement performed before interactive login, LOLBin masquerading with consistent version-metadata fabrication, AMSI pre-checks, deliberate process lineage breaking, and a complete textbook LSASS credential dump chain (probe → escalate → read) all point to a mature, hands-on adversary operating with a clear playbook rather than improvising.

The confirmed LSASS memory read on `azwks-phtg-01` is the most significant finding of this hunt — it represents potential compromise of any credential cached on that host beyond `vmadminusername`, and the scope of what was harvested and how it may be used requires investigation beyond what this hunt's window covers. Combined with the active two-channel C2 to `health-cloud.cc`, this operator retains both the means and the access to act on harvested credentials at any time. Immediate isolation and full credential rotation across both hosts is required.

### Evidence Quality Rating

| Evidence Type | Quality | Notes |
|--------------|---------|-------|
| Authentication logs | `🟢 High` | `DeviceLogonEvents — complete failure/success comparison and lateral movement tracking` |
| Process execution logs | `🟢 High` | `DeviceProcessEvents — complete operator script chain, beaconing, and lineage-breaking captured` |
| Registry activity | `🟢 High` | `DeviceRegistryEvents — all three persistence mechanisms and Defender exclusions captured, though one delete event was not logged` |
| File activity | `🟢 High` | `DeviceFileEvents — Startup folder persistence artifact confirmed` |
| Antivirus/EDR detection | `🟢 High` | `DeviceEvents — AntivirusReport and OpenProcessApiCall/ReadProcessMemoryApiCall events all captured` |
| Network telemetry | `🟢 High` | `DeviceNetworkEvents — both C2 domains corroborated via RemoteUrl` |

### Confidence Assessment

| Finding | Confidence |
|---------|-----------|
| Access vector (credential reuse, not brute force) | `🟢 High — confirmed by DeviceLogonEvents comparison and scheduled task evidence` |
| Lateral movement path (phtg-02 → phtg-01) | `🟢 High — confirmed by DeviceLogonEvents` |
| Persistence mechanisms (Run key, Startup LNK, EventLog registration) | `🟢 High — all three confirmed via DeviceRegistryEvents/DeviceFileEvents` |
| C2 infrastructure (health-cloud.cc, two channels) | `🟢 High — confirmed via DeviceProcessEvents decoded commands and DeviceNetworkEvents RemoteUrl` |
| Defender evasion (permanent + transient exclusions) | `🟢 High — permanent exclusions directly observed; transient exclusion confirmed via timestamp correlation despite missing delete event` |
| LSASS credential dump | `🟢 High — full three-step chain (open, escalate, read) confirmed in DeviceEvents` |
| Scope/use of harvested credentials | `🔴 Low — not addressed within this hunt's window; requires follow-on investigation` |
| Attacker identity | `🔴 Low — no handle, email, or persona observed` |

---

## 📎 Analyst Notes

- All evidence reproducible via KQL queries documented in each flag section
- The brute-force-vs-credential-reuse triage at the start of this hunt — comparing failures and successes across IP, account, and logon type — should be the first step in any "how did they get back in" investigation
- The operator's signature `-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass` flag combination recurred at least three times (`_.ps1`, `HealthCloudTray.ps1`, and within the Run key entry) and is the single highest-value detection signature from this hunt
- Persistence validation (confirming a Run key actually fired, on the correct device) was as important as persistence discovery — the key was found on `azwks-phtg-01` but fired on `azwks-phtg-02`, where it was written earlier
- The complete LSASS credential dump chain (139 events filtered to 1, then validated across two more flags) demonstrates the value of a structured three-step confirmation process rather than alerting on any single `OpenProcessApiCall` event

### 📝 Lessons Learned

- **What worked well:** Challenging the brute-force assumption at the very start reframed the entire investigation — every subsequent finding (scheduled task, lateral movement timing, credential reuse) followed directly from that first correction.
- **What to do differently:** The transient Defender exclusion's delete event was never captured — future hunts in this environment should proactively query tight time windows (seconds, not minutes) around every script execution for registry changes, rather than relying on delete events being logged.
- **New detection rules revealed:** Concealed PowerShell flag combinations, binary identity masquerade outside System32, repeated beaconing frequency, Defender exclusion additions by non-SYSTEM accounts, and the full LSASS PROCESS_ALL_ACCESS → ReadProcessMemory chain are all high-value additions not previously covered.
- **Log sources that were sufficient:** All six MDE tables used in this hunt (DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents, DeviceNetworkEvents) provided complete coverage with no apparent data gaps — the gap remains in alerting/correlation logic, not data collection.

---

*Report generated by: Michael Kirby | 2026-05 | PHTG HealthCloud — Threat Hunt (azwks-phtg-01 / azwks-phtg-02)*
*Classification: `TLP:RED — CONFIDENTIAL` — Do not distribute without authorisation*

---

*A huge thank you to Josh Madakor for building The Cyber Range and to Steven Cruz — the Threat Hunt Engineer behind this challenge.*
