# 🖥️ Suspicious Windows Process Hunting

## Overview

This threat-hunting scenario searches Microsoft Defender XDR process telemetry for Windows utilities that are legitimate but can also be abused by attackers.

Utilities such as `certutil.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wmic.exe`, and `cmd.exe` can appear during normal administration as well as malicious activity.

---

## 🎯 Hunting Objective

Identify executions of selected Windows utilities and provide sufficient process context for further investigation.

This is a broad hunting query rather than a high-confidence malicious-activity detection.

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
- `InitiatingProcessCommandLine`
- `SHA256`

---

## 🧠 Hunting Logic

The query:

1. Searches process events from the previous 24 hours.
2. Filters for selected Windows utilities that may be abused by attackers.
3. Captures the command line used during execution.
4. Records the parent or initiating process.
5. Provides device, account, and file-hash context.
6. Sorts the results from newest to oldest.

---

## 🎯 MITRE ATT&CK Mapping

Depending on the observed command and behavior, activity involving these utilities may map to techniques such as:

- **T1218** — System Binary Proxy Execution
- **T1059.003** — Windows Command Shell
- **T1047** — Windows Management Instrumentation

MITRE mapping should be based on the actual behavior observed rather than the executable name alone.

---

## 🔍 Investigation Steps

When reviewing results:

1. Examine the complete process command line.
2. Identify the user who executed the process.
3. Review the initiating or parent process.
4. Determine whether the activity matches normal administrative behavior.
5. Review related process executions on the endpoint.
6. Investigate associated network connections.
7. Check file hashes and downloaded artifacts where relevant.
8. Correlate the activity with other SIEM and EDR alerts.

---

## ⚠️ Possible False Positives

These Windows utilities have legitimate uses.

Common legitimate activity may include:

- System administration
- Software installation
- IT troubleshooting
- Configuration management
- Enterprise management tools
- Approved scripts

Therefore, execution of these utilities alone should not be treated as evidence of compromise.

---

## 🚨 Recommended Response

If investigation confirms malicious activity:

- Isolate the affected endpoint where appropriate.
- Terminate malicious processes.
- Quarantine malicious files.
- Investigate related user accounts.
- Review persistence mechanisms.
- Hunt for similar behavior across other endpoints.
- Escalate according to the incident-response procedure.

---

## 💡 Detection Improvements

Higher-confidence detections can be created by looking for specific suspicious behaviors, such as:

- `certutil.exe` downloading or decoding files
- `rundll32.exe` executing unusual DLL exports or remote content
- `regsvr32.exe` executing remotely hosted content
- `mshta.exe` accessing remote URLs
- Office applications spawning command shells
- Unusual parent-child process relationships

---

## 📌 Analyst Note

The presence of a legitimate Windows utility does not by itself indicate malicious activity. Analysts should evaluate the command line, parent process, user context, network behavior, and surrounding endpoint activity before determining severity.
