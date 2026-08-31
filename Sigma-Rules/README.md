# 🧪 Sigma Detection Rules

This section contains Sigma rules designed to detect suspicious Windows and PowerShell activity.

Sigma is a generic and open detection format that allows detection logic to be expressed independently of a specific SIEM platform.

---

## 🎯 Objectives

These rules demonstrate:

- Behavior-based detection
- Windows process monitoring
- PowerShell abuse detection
- Suspicious command-line analysis
- MITRE ATT&CK mapping
- False-positive consideration
- Detection rule documentation

---

## 📂 Rules

| Rule | Description | MITRE ATT&CK |
|---|---|---|
| Suspicious PowerShell Execution | Detects PowerShell commands containing suspicious execution patterns | T1059.001 |
| Encoded PowerShell Command | Detects use of encoded PowerShell commands | T1059.001 |
| Suspicious Certutil Usage | Detects potentially suspicious Certutil download or decode activity | T1105 / T1140 |

---

## 🧩 Sigma Rule Structure

A typical Sigma rule contains:

- `title`
- `id`
- `status`
- `description`
- `author`
- `date`
- `logsource`
- `detection`
- `falsepositives`
- `level`
- `tags`

---

## ⚠️ Important Note

These rules are portfolio and learning examples.

Field mappings and backend behavior may vary depending on the SIEM, EDR, log source, and Sigma conversion pipeline being used. Rules should be tested and tuned before production deployment.
