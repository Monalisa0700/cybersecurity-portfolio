# ⚡ Suspicious PowerShell Hunting

## Overview

This threat-hunting scenario identifies PowerShell executions that contain potentially suspicious command-line arguments or behaviors commonly associated with attacker activity.

PowerShell is a legitimate administrative tool, but adversaries frequently abuse it for downloading payloads, executing scripts in memory, bypassing security controls, and establishing persistence.

---

## 🎯 Hunting Objective

Identify PowerShell executions containing suspicious keywords such as:

- `-EncodedCommand`
- `-enc`
- `Invoke-Expression`
- `IEX`
- `DownloadString`
- `Invoke-WebRequest`
- `Net.WebClient`
- `Start-BitsTransfer`

These indicators can help analysts quickly identify potentially malicious PowerShell activity.

---

## 📊 Data Source

**Microsoft Defender XDR Table:** `DeviceProcessEvents`

Relevant fields:

- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `SHA256`

---
🧠 Hunting Logic

The query:

Searches Defender XDR process telemetry from the last 24 hours.

Filters for PowerShell processes.

Looks for suspicious command-line keywords.

Returns device, user, initiating process, and hash information.

Sorts results from newest to oldest.


🎯 MITRE ATT&CK Mapping

Execution - T1059.001 – PowerShell
Command and Control - T1105 – Ingress Tool Transfer
Defense Evasion - T1027 – Obfuscated Files or Information


🔍 Investigation Steps

When this hunt returns results, analysts should:

Review the full PowerShell command line.

Determine whether the command is administrator-approved.

Identify the initiating process.

Check whether encoded commands are present.

Investigate downloaded files.

Review network connections from the device.

Correlate with Defender alerts.

Review additional process activity on the endpoint.


⚠️ Possible False Positives

Legitimate activity may include:

Administrative scripts

Configuration management tools

Software deployment tools

Backup software

Security automation


🚨 Recommended Response

If malicious activity is confirmed:

Isolate the endpoint.

Terminate malicious PowerShell processes.

Remove downloaded payloads.

Reset affected credentials.

Investigate persistence mechanisms.

Review lateral movement activity.


💡 Detection Improvements

Improve this hunt by:

Creating allowlists for approved scripts.

Monitoring PowerShell launched by Office applications.

Detecting hidden PowerShell windows.

Correlating with network connections.

Monitoring parent-child process relationships.


📌 Analyst Note

PowerShell is one of the most abused Windows administration tools. Analysts should review both the command line and the initiating process before determining whether the activity is malicious.
