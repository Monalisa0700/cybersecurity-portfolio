# 🔎 KQL Threat Hunting

This folder contains KQL (Kusto Query Language) threat-hunting queries designed for Microsoft Sentinel and Microsoft Defender XDR environments.

## 🎯 Objectives

These hunts demonstrate how security telemetry can be used to:

- Identify suspicious authentication activity
- Detect potential brute-force attacks
- Hunt for suspicious PowerShell execution
- Investigate unusual process activity
- Identify potential account compromise
- Support SOC alert investigation

## 📂 Hunts

| Hunt | Description |
|---|---|
| Brute Force Detection | Identifies multiple failed authentication attempts that may indicate password guessing |
| Suspicious Login Activity | Hunts for unusual or potentially malicious authentication behavior |
| PowerShell Hunting | Identifies suspicious PowerShell command execution |
| Windows Process Hunting | Investigates suspicious process execution patterns |
| Account Compromise | Searches for indicators associated with compromised user accounts |

## 🛠️ Technologies

- Microsoft Sentinel
- Microsoft Defender XDR
- Kusto Query Language (KQL)
- Windows Security Logs
- MITRE ATT&CK

> **Note:** Queries in this portfolio are demonstration and learning examples. Table names, thresholds, and fields may require adjustment depending on the organization's telemetry and environment.
