# 🚨 SOC Incident Report — Brute Force Authentication

## Incident Summary

| Field | Details |
|---|---|
| Incident Type | Suspected Brute Force / Account Compromise |
| Severity | High |
| Status | Simulated Investigation |
| Data Source | Microsoft Sentinel — SecurityEvent |
| Primary Events | Windows Event IDs 4625 and 4624 |
| MITRE ATT&CK | T1110 — Brute Force |

> This is a simulated SOC investigation created for portfolio demonstration purposes.

---

## 🔔 Alert Description

A security alert was generated after multiple failed authentication attempts were observed against a user account within a short period.

A successful authentication was subsequently observed, increasing the possibility that the credentials may have been successfully guessed or otherwise compromised.

---

## 🧪 Example Scenario

**Affected Account:** `jsmith`  
**Source IP:** `203.0.113.50`  
**Affected Host:** `WS-FIN-024`

Example timeline:

| Time | Event |
|---|---|
| 10:14 | Multiple Event ID 4625 failed logons begin |
| 10:17 | Failed authentication volume increases |
| 10:19 | Event ID 4624 successful logon observed |
| 10:21 | Account begins accessing the endpoint |

The values above are fictional example data.

---

## 🔎 Initial Triage

The initial investigation should answer:

1. How many failed authentication attempts occurred?
2. Which account was targeted?
3. Which source IP generated the attempts?
4. Was the source internal or external?
5. Did a successful login occur afterward?
6. Was MFA involved?
7. Is the authentication behavior normal for the user?

---

## 🔍 KQL — Failed Authentication Analysis

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| where TargetUserName == "jsmith"
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SourceIPs = make_set(IpAddress)
    by TargetUserName, Computer
```

---

## 🔍 KQL — Successful Authentication Check

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where TargetUserName == "jsmith"
| project
    TimeGenerated,
    TargetUserName,
    IpAddress,
    Computer,
    LogonType
| order by TimeGenerated asc
```

---

## 🔍 KQL — Identify Other Accounts Targeted by the IP

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| where IpAddress == "203.0.113.50"
| summarize
    FailedAttempts = count()
    by TargetUserName
| order by FailedAttempts desc
```

This helps determine whether the activity targeted one account or potentially represents password spraying against multiple accounts.

---

## 🧠 Investigation Analysis

The analyst should correlate:

- Failed authentication volume
- Successful authentication timing
- Source IP
- Target account
- Target host
- Logon type
- User's normal authentication behavior
- MFA activity
- Endpoint telemetry
- Other security alerts

A successful login immediately following repeated failures increases the priority of the investigation but does not alone prove compromise.

---

## 🎯 MITRE ATT&CK Mapping

**Tactic:** Credential Access

**Technique:** T1110 — Brute Force

Possible sub-techniques:

- T1110.001 — Password Guessing
- T1110.003 — Password Spraying

---

## 📋 Evidence to Collect

Relevant evidence includes:

- Windows authentication events
- Source IP information
- User authentication history
- MFA logs
- VPN or proxy logs
- Endpoint process telemetry
- Network connections
- Related SIEM alerts
- EDR alerts

---

## 🚧 Containment Recommendations

If compromise is confirmed:

1. Disable or temporarily restrict the affected account.
2. Revoke active sessions.
3. Reset credentials.
4. Review MFA configuration.
5. Block confirmed malicious infrastructure where appropriate.
6. Isolate affected endpoints if malicious activity is observed.
7. Hunt for additional affected accounts.

---

## 🔧 Remediation

Recommended remediation may include:

- Enforcing MFA
- Reviewing authentication policies
- Strengthening password controls
- Removing malicious persistence
- Resetting compromised credentials
- Reviewing privileged access
- Updating detection thresholds
- Blocking confirmed malicious indicators

---

## 📈 Detection Improvements

Following the incident, detection coverage could be improved by:

- Correlating failed logins with subsequent successes.
- Detecting one source IP targeting many accounts.
- Applying higher severity to privileged accounts.
- Enriching external IP addresses with threat intelligence.
- Correlating authentication anomalies with endpoint activity.
- Establishing normal authentication baselines.

---

## 📝 Incident Classification

### If malicious activity is confirmed

**True Positive — Account Compromise / Brute Force**

### If investigation confirms legitimate activity

**Benign True Positive / False Positive depending on rule intent and environment**

The final classification should be based on evidence collected during investigation.

---

## 💡 Lessons Learned

This scenario demonstrates why failed authentication events should not be investigated in isolation.

Correlating authentication failures with successful logins, user behavior, source infrastructure, MFA telemetry, and endpoint activity provides a much stronger basis for determining whether an account was compromised.
