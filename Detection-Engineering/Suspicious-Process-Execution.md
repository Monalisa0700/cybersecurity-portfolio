# ⚠️ Suspicious Windows Process Execution Detection

## Overview

This detection identifies potentially suspicious use of legitimate Windows utilities that are commonly abused by attackers.

Rather than treating execution of these utilities as automatically malicious, the detection focuses on suspicious command-line behavior associated with tools such as `certutil.exe`, `mshta.exe`, `regsvr32.exe`, and `rundll32.exe`.

---

## 🎯 Detection Objective

Identify potentially malicious execution patterns involving trusted Windows binaries that may be abused for:

- Downloading remote content
- Executing scripts or payloads
- Proxy execution
- Bypassing application controls
- Executing DLL content

---

## 🧩 Threat Scenario

An attacker attempts to use legitimate Windows utilities instead of introducing an obviously malicious executable.

Example:

**Initial Access → Trusted Windows Utility → Payload Download/Execution → Further Compromise**

This behavior is often referred to as abuse of trusted or living-off-the-land binaries.

---

## 📊 Data Source

**Platform:** Microsoft Defender XDR

**Table:** `DeviceProcessEvents`

Relevant fields:

- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `SHA256`

---

## 🔎 Detection Query

```kusto
DeviceProcessEvents
| where Timestamp > ago(10m)
| where
    (FileName =~ "certutil.exe" and
        ProcessCommandLine has_any ("-urlcache", "-decode", "-decodehex"))
    or
    (FileName =~ "mshta.exe" and
        ProcessCommandLine has_any ("http://", "https://", "javascript:", "vbscript:"))
    or
    (FileName =~ "regsvr32.exe" and
        ProcessCommandLine has_any ("/i:http", "/i:https", "scrobj.dll"))
    or
    (FileName =~ "rundll32.exe" and
        ProcessCommandLine has_any ("javascript:", "http://", "https://"))
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

## ⚙️ Suggested Analytics Rule Configuration

| Setting | Value |
|---|---|
| Rule Type | Scheduled |
| Severity | High |
| Query Frequency | 5 minutes |
| Query Lookback | 10 minutes |
| Trigger | More than 0 results |
| Suppression | Environment dependent |

---

## 🎯 MITRE ATT&CK Mapping

### Primary

**Tactic:** Defense Evasion

**Technique:** T1218 — System Binary Proxy Execution

Specific sub-techniques may apply depending on the executable and behavior observed.

Additional techniques should only be assigned when supported by investigation evidence.

---

## 🧱 Entity Mapping

| Entity | Source Field |
|---|---|
| Host | `DeviceName` |
| Account | `AccountName` |
| File Hash | `SHA256` |

Process command-line and initiating-process information should also be retained as investigation context.

---

## 🔍 Alert Investigation

When this detection triggers:

1. Review the complete command line.
2. Identify the executable involved.
3. Identify the user account executing the process.
4. Review the initiating or parent process.
5. Investigate URLs, domains, IP addresses, or file paths present in the command.
6. Review files created or downloaded around the event time.
7. Examine related network activity.
8. Review additional processes executed on the endpoint.
9. Correlate the activity with Defender XDR and SIEM alerts.
10. Hunt for the same command or indicators across other devices.

---

## ⚠️ False Positive Considerations

Legitimate activity may include:

- Software installation
- Administrative scripts
- IT troubleshooting
- Enterprise management software
- Approved application behavior

Because these binaries are legitimate Windows components, executable name alone should not determine whether activity is malicious.

---

## 🔧 Tuning Recommendations

Improve detection quality by:

- Baselining legitimate use of these utilities.
- Creating narrowly scoped exclusions for validated activity.
- Prioritizing executions involving remote URLs.
- Prioritizing unusual parent-child process relationships.
- Correlating execution with file downloads.
- Correlating process activity with suspicious network connections.
- Increasing priority when the process is launched by Office or browser applications.

Avoid broadly excluding the executable itself.

---

## 🚨 Response Actions

If malicious activity is confirmed:

1. Isolate the affected endpoint where appropriate.
2. Terminate malicious processes.
3. Quarantine downloaded or malicious files.
4. Block confirmed malicious indicators.
5. Investigate the associated account.
6. Review persistence mechanisms.
7. Hunt for related activity across other endpoints.
8. Escalate according to the incident-response procedure.

---

## 📈 Detection Maturity

### Current Detection

Detects selected suspicious command-line patterns associated with commonly abused Windows utilities.

### Future Improvements

Future versions could include:

- Parent-child process scoring
- Network-event correlation
- File-creation correlation
- Threat-intelligence enrichment
- Rare-process analysis
- Environment-specific behavioral baselines
- Multi-signal detections

---

## 📌 Detection Engineering Note

Legitimate Windows binaries can be abused by attackers to blend malicious activity with normal system behavior.

Detection engineering should therefore focus on **how a binary is being used**, including its command line, parent process, network behavior, and surrounding activity, rather than alerting solely because the binary executed.
