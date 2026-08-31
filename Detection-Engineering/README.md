# 🚨 Detection Engineering

This section contains detection engineering use cases designed around Microsoft Sentinel, Microsoft Defender XDR, Windows security telemetry, and common attacker behaviors.

The goal is to demonstrate the process of converting suspicious behavior into actionable security detections.

---

## 🎯 Detection Engineering Workflow

Each detection follows a structured lifecycle:

**Threat Behavior → Data Source → Detection Logic → KQL → MITRE ATT&CK → Alert Triage → Tuning → Response**

---

## 📂 Detection Use Cases

| Detection | Objective | MITRE ATT&CK |
|---|---|---|
| Multiple Failed Logins | Detect repeated authentication failures against user accounts | T1110 |
| Suspicious PowerShell | Detect potentially malicious PowerShell execution | T1059.001 |
| New Administrative Account | Identify suspicious privileged account creation | T1136 |
| Suspicious Process Execution | Detect potentially malicious Windows process behavior | T1218 |

---

## 🧩 Detection Components

Each detection includes:

- Detection objective
- Threat scenario
- Data source
- KQL detection logic
- MITRE ATT&CK mapping
- Severity
- Query frequency and lookback
- Alert threshold
- Entity mapping
- Investigation workflow
- False-positive analysis
- Tuning recommendations
- Response actions

---

## 🛠️ Technologies

- Microsoft Sentinel
- Microsoft Defender XDR
- Kusto Query Language (KQL)
- Windows Security Events
- Endpoint Process Telemetry
- MITRE ATT&CK

---

## 📌 Detection Engineering Principles

The detections in this portfolio are designed around several principles:

1. **Behavior over indicators** — Focus on attacker behavior rather than relying only on static IOCs.
2. **Context matters** — A suspicious event alone does not necessarily indicate compromise.
3. **Reduce false positives** — Detection logic should be tuned using known-good behavior and environmental baselines.
4. **Provide investigation context** — Alerts should contain useful entities such as accounts, hosts, IP addresses, and processes.
5. **Map detections to ATT&CK** — Detection coverage should be associated with relevant adversary tactics and techniques.
6. **Continuously tune detections** — Detection rules should evolve based on analyst feedback and changes in the environment.

---

## ⚠️ Disclaimer

The detection rules and thresholds in this portfolio are demonstration examples.

Production environments require validation, baseline analysis, testing, and tuning before deploying detection logic as active SIEM analytics rules.
