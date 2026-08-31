# ⚡ SOC Incident Report — Suspicious PowerShell Execution

## Incident Summary

| Field | Details |
|---|---|
| Incident Type | Suspicious PowerShell Execution |
| Severity | High |
| Status | Simulated Investigation |
| Data Source | Microsoft Defender XDR |
| Primary Table | DeviceProcessEvents |
| MITRE ATT&CK | T1059.001 — PowerShell |

> This is a simulated SOC investigation created for portfolio demonstration purposes.

---

## 🔔 Alert Description

A security alert was generated after PowerShell executed with suspicious command-line parameters associated with encoded commands and remote content retrieval.

Because PowerShell is frequently used for legitimate administration, the alert requires additional endpoint and network analysis before determining whether the activity is malicious.

---

## 🧪 Example Scenario

**User:** `jsmith`  
**Device:** `WS-FIN-024`

Example command:

```powershell
powershell.exe -EncodedCommand <REDACTED_BASE64>
```

Example timeline:

| Time | Activity |
|---|---|
| 14:02 | PowerShell process launched |
| 14:02 | Encoded command observed |
| 14:03 | Suspicious child process activity identified |
| 14:04 | Outbound network activity observed |
| 14:06 | SOC investigation initiated |

All values above are fictional example data.

---

## 🔎 Initial Triage

The analyst should determine:

1. Which user executed PowerShell?
2. Which device generated the alert?
3. What process launched PowerShell?
4. What does the command line contain?
5. Is the command encoded or obfuscated?
6. Did PowerShell contact an external destination?
7. Were files downloaded or created?
8. Is the activity expected for this user or endpoint?

---

## 🔍 KQL — PowerShell Process Investigation

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName == "WS-FIN-024"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp asc
```

---

## 🌐 KQL — Network Activity Investigation

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName == "WS-FIN-024"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemoteUrl,
    RemotePort
| order by Timestamp asc
```

---

## 📁 KQL — File Activity Investigation

```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where DeviceName == "WS-FIN-024"
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName
| order by Timestamp asc
```

---

## 🧠 Investigation Analysis

The analyst should correlate:

- PowerShell command line
- Parent process
- User account
- Endpoint
- Network destinations
- File creation activity
- Child processes
- Defender alerts
- File hashes
- Other activity surrounding the event

Encoded PowerShell alone does not prove malicious activity.

Risk increases when encoded or obfuscated PowerShell is combined with unusual parent processes, external network connections, payload downloads, suspicious file creation, or unexpected user behavior.

---

## 🎯 MITRE ATT&CK Mapping

### Primary

**Tactic:** Execution  
**Technique:** T1059.001 — PowerShell

### Potential Additional Techniques

Depending on investigation evidence:

- **T1027 — Obfuscated Files or Information**
- **T1105 — Ingress Tool Transfer**

These should only be assigned when supported by the observed behavior.

---

## 📋 Evidence to Collect

Relevant evidence includes:

- Full PowerShell command line
- Parent and child processes
- User context
- Endpoint process timeline
- Network connections
- DNS activity
- Created or downloaded files
- File hashes
- Defender XDR alerts
- Authentication activity

---

## 🚧 Containment Recommendations

If malicious activity is confirmed:

1. Isolate the affected endpoint.
2. Terminate malicious processes.
3. Quarantine malicious files.
4. Block confirmed malicious network indicators.
5. Revoke compromised user sessions.
6. Reset affected credentials where appropriate.
7. Hunt for similar activity across other endpoints.

---

## 🔧 Remediation

Recommended remediation may include:

- Removing malicious payloads
- Removing persistence mechanisms
- Resetting compromised credentials
- Blocking confirmed malicious indicators
- Reviewing PowerShell logging configuration
- Reviewing endpoint security controls
- Applying required patches
- Improving detection coverage

---

## 📈 Detection Improvements

Following the incident, detection engineering could be improved by:

- Monitoring encoded PowerShell.
- Detecting suspicious PowerShell parent processes.
- Correlating PowerShell with network connections.
- Correlating PowerShell with file creation.
- Monitoring Script Block Logging where available.
- Baselining legitimate administrative PowerShell.
- Prioritizing combinations of suspicious behaviors instead of isolated keywords.

---

## 📝 Incident Classification

### If malicious activity is confirmed

**True Positive — Malicious PowerShell Execution**

### If authorized activity is confirmed

Classify according to the organization's alert-disposition process and use the findings to improve detection tuning where appropriate.

---

## 💡 Lessons Learned

PowerShell detections require context.

Command-line analysis should be combined with process ancestry, network activity, file activity, user behavior, and endpoint telemetry to distinguish legitimate administration from malicious execution.
