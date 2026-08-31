# 🛡️ SOC Incident Investigation Reports

This section contains simulated SOC incident-investigation scenarios designed to demonstrate the end-to-end security investigation process.

The reports focus on how a SOC analyst moves from an initial alert to investigation, evidence analysis, containment, remediation, and detection improvement.

---

## 🎯 Investigation Workflow

Each investigation follows a structured process:

**Alert → Triage → Evidence Collection → Analysis → Scope → MITRE ATT&CK → Containment → Remediation → Lessons Learned**

---

## 📂 Incident Scenarios

| Incident | Scenario | Primary Skill |
|---|---|---|
| Brute Force Investigation | Multiple failed logins followed by suspicious authentication activity | Authentication Analysis |
| Suspicious PowerShell Investigation | Potentially malicious PowerShell execution | Endpoint Investigation |
| Account Compromise Investigation | Suspicious activity involving a potentially compromised user account | Incident Response |

---

## 🔍 Investigation Areas

The reports demonstrate:

- Alert triage
- Log analysis
- KQL investigation
- Timeline reconstruction
- Account analysis
- Endpoint analysis
- IOC investigation
- MITRE ATT&CK mapping
- False-positive validation
- Incident scoping
- Containment recommendations
- Remediation
- Detection improvement

---

## ⚠️ Important Note

The incidents in this repository are **simulated portfolio scenarios** created for learning and demonstration purposes.

Usernames, hostnames, IP addresses, timestamps, and other indicators are fictional or example data and do not represent real organizational incidents.

---

## 🧠 SOC Investigation Principle

A security alert is the beginning of an investigation, not proof of compromise.

Analysts should validate the alert using surrounding telemetry, determine the scope of activity, assess impact, and gather sufficient evidence before assigning an incident classification.
