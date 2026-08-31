# 🚨 Suspicious PowerShell Execution Detection

## Overview

This detection identifies potentially suspicious PowerShell execution based on command-line patterns commonly associated with malicious activity.

PowerShell is widely used for legitimate administration, but attackers may abuse it for payload execution, downloading files, obfuscating commands, and executing code in memory.

---

## 🎯 Detection Objective

Detect PowerShell processes containing potentially suspicious command-line indicators such as:

- Encoded commands
- Base64 decoding
- Download functionality
- `Invoke-Expression`
- Web requests
- WebClient usage
- BITS transfers

The detection is intended to provide actionable process, account, and device context for SOC investigation.

---

## 🧩 Threat Scenario

An attacker gains access to a Windows endpoint and executes PowerShell to download or execute malicious content.

Example attack flow:

**Initial Access → PowerShell Execution → Payload Download → Execution → Persistence / Lateral Movement**

The detection focuses primarily on identifying the suspicious PowerShell execution stage.

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
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-enc",
    "-encodedcommand",
    "FromBase64String",
    "DownloadString",
    "Invoke-WebRequest",
    "Invoke-Expression",
    "IEX",
    "Net.WebClient",
    "Start-BitsTransfer"
)
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
| Severity | Medium |
| Query Frequency | 5 minutes |
| Query Lookback | 10 minutes |
| Trigger | More than 0 results |
| Suppression | Environment dependent |

The overlapping lookback helps reduce the chance of missing events between scheduled executions. In production, duplicate-alert handling should be considered when using overlapping windows.

---

## 🎯 MITRE ATT&CK Mapping

### Primary

**Tactic:** Execution  
**Technique:** T1059.001 — PowerShell

### Context-Dependent

Depending on the observed command, the activity may also relate to:

- **T1027 — Obfuscated Files or Information**
- **T1105 — Ingress Tool Transfer**

These additional techniques should only be applied when supported by the actual command behavior.

---

## 🧱 Entity Mapping

Useful entities for investigation include:

| Entity | Source Field |
|---|---|
| Host | `DeviceName` |
| Account | `AccountName` |
| File Hash | `SHA256` |

Additional process and command-line information should be retained in the alert for investigation context.

---

## 🔍 Alert Investigation

When this detection triggers:

1. Review the complete PowerShell command line.
2. Identify the user account executing PowerShell.
3. Review the initiating process and parent-child relationship.
4. Determine whether the command contains encoded or obfuscated content.
5. Investigate URLs, domains, IP addresses, or files referenced by the command.
6. Review related process activity on the endpoint.
7. Check endpoint network telemetry for suspicious connections.
8. Review Defender XDR alerts associated with the device and user.
9. Determine whether the behavior is expected administrative activity.
10. Hunt for similar commands across other endpoints.

---

## ⚠️ False Positive Considerations

Potential legitimate activity includes:

- Administrative PowerShell scripts
- Software deployment systems
- Configuration-management platforms
- Security tooling
- Backup products
- IT automation

The presence of a suspicious keyword alone does not prove malicious execution.

---

## 🔧 Tuning Recommendations

To improve detection quality:

- Maintain an allowlist of approved scripts where appropriate.
- Baseline common administrative PowerShell usage.
- Exclude trusted automation accounts only after validation.
- Consider trusted script paths and signatures.
- Increase severity when suspicious PowerShell is launched by unusual parent processes.
- Correlate PowerShell execution with network and file activity.
- Give greater priority to encoded commands combined with download or execution behavior.

Avoid broad exclusions that could create detection blind spots.

---

## 🚨 Response Actions

If malicious activity is confirmed:

1. Isolate the affected endpoint if necessary.
2. Terminate malicious processes.
3. Quarantine malicious files.
4. Block confirmed malicious indicators.
5. Reset or disable compromised credentials where appropriate.
6. Review persistence mechanisms.
7. Hunt for lateral movement.
8. Search the environment for related indicators.
9. Escalate according to the incident-response procedure.

---

## 📈 Detection Maturity

### Current Detection

Keyword-based identification of potentially suspicious PowerShell commands.

### Future Improvements

A more mature version could include:

- Parent-child process analysis
- PowerShell Script Block Logging
- Network telemetry correlation
- File creation correlation
- Known-good baselining
- Threat-intelligence enrichment
- Behavioral scoring
- Multiple signals combined into higher-confidence detections

---

## 📌 Detection Engineering Note

This rule is intentionally designed as a broad behavioral detection example.

In a production SOC, detection effectiveness should be measured using alert volume, true-positive rate, false-positive rate, analyst feedback, and coverage of relevant adversary behaviors. Thresholds and exclusions should then be continuously tuned.
