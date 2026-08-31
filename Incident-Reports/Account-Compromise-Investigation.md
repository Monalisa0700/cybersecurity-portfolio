# 👤 SOC Incident Report — Suspected Account Compromise

## Incident Summary

| Field | Details |
|---|---|
| Incident Type | Suspected User Account Compromise |
| Severity | High |
| Status | Simulated Investigation |
| Data Sources | Microsoft Sentinel / Microsoft Defender XDR |
| Primary Tables | SigninLogs, DeviceLogonEvents, DeviceProcessEvents |
| MITRE ATT&CK | T1078 — Valid Accounts |

> This is a simulated SOC investigation created for portfolio demonstration purposes.

---

## 🔔 Alert Description

A user account generated suspicious authentication activity inconsistent with its expected behavior.

The activity included authentication from an unusual source followed by endpoint activity requiring investigation to determine whether valid credentials had been compromised.

---

## 🧪 Example Scenario

**User:** `jsmith@contoso.com`  
**Device:** `WS-FIN-024`  
**Source IP:** `203.0.113.50`

Example timeline:

| Time | Activity |
|---|---|
| 09:42 | Successful authentication from unusual source |
| 09:44 | User session established |
| 09:47 | PowerShell execution observed |
| 09:49 | External network connection detected |
| 09:52 | SOC investigation initiated |

All accounts, systems, IP addresses, and timestamps above are fictional example data.

---

## 🔎 Initial Triage

The analyst should determine:

1. Was the authentication successful?
2. Is the source IP expected for the user?
3. Is the location consistent with normal activity?
4. Was MFA successfully completed?
5. Is the device known and managed?
6. Were there failed logins before the successful authentication?
7. What activity occurred after login?
8. Were privileged actions performed?
9. Are other accounts showing similar activity?

---

## 🔍 KQL — Authentication Investigation

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ "jsmith@contoso.com"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    Location,
    DeviceDetail
| order by TimeGenerated asc
```

---

## 🔍 KQL — Review Source IP Across Accounts

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where IPAddress == "203.0.113.50"
| summarize
    Accounts = make_set(UserPrincipalName),
    Applications = make_set(AppDisplayName),
    SignInCount = count()
    by IPAddress
```

This helps determine whether the same source attempted to access multiple accounts.

---

## 💻 KQL — Endpoint Logon Investigation

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where AccountName =~ "jsmith"
| project
    Timestamp,
    DeviceName,
    AccountName,
    LogonType,
    ActionType,
    RemoteIP,
    RemoteDeviceName
| order by Timestamp asc
```

---

## ⚙️ KQL — Post-Authentication Process Activity

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where AccountName =~ "jsmith"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp asc
```

---

## 🧠 Investigation Analysis

Authentication anomalies should be correlated with activity occurring after the login.

Important questions include:

- Was the IP previously observed for this user?
- Was the device previously associated with the account?
- Was MFA completed normally?
- Did the user confirm the activity?
- Were unusual applications accessed?
- Were suspicious processes launched?
- Was sensitive information accessed?
- Were security settings modified?
- Were new authentication methods registered?
- Was the same infrastructure used against additional users?

A successful authentication from an unusual source is an investigation signal, not automatic proof of account compromise.

---

## 📋 Evidence to Collect

Relevant evidence includes:

- Sign-in history
- Source IP information
- Authentication location
- Device information
- MFA results
- Conditional Access results
- Endpoint logon telemetry
- Process execution
- Network connections
- Related Defender XDR alerts
- Other accounts associated with the source IP

---

## 🎯 MITRE ATT&CK Mapping

### Primary

**Tactic:** Defense Evasion / Persistence / Privilege Escalation / Initial Access

**Technique:** T1078 — Valid Accounts

The exact tactic depends on how the compromised credentials were used during the incident.

Additional techniques should only be assigned when supported by evidence.

---

## 🚧 Containment Recommendations

If account compromise is confirmed:

1. Disable or restrict the affected account where appropriate.
2. Revoke active sessions and refresh tokens.
3. Reset the user's credentials.
4. Review and reset authentication methods if required.
5. Isolate affected endpoints if malicious endpoint activity exists.
6. Block confirmed malicious infrastructure.
7. Review privileged group membership.
8. Hunt for additional affected users.

---

## 🔧 Remediation

Recommended remediation may include:

- Credential reset
- MFA re-registration
- Session revocation
- Removal of unauthorized authentication methods
- Removal of malicious persistence
- Endpoint remediation
- Review of mailbox or application rules where relevant
- Review of privileged access
- Improvement of Conditional Access policies
- Detection tuning

---

## 📈 Detection Improvements

Detection coverage could be improved by:

- Baselining user authentication behavior.
- Detecting unusual IP addresses or devices.
- Correlating failed and successful authentication.
- Monitoring suspicious MFA changes.
- Detecting authentication followed by suspicious endpoint activity.
- Identifying one source IP accessing multiple accounts.
- Applying higher priority to privileged accounts.
- Correlating identity and endpoint telemetry.

---

## 📝 Incident Classification

### If compromise is confirmed

**True Positive — Compromised Account / Valid Account Abuse**

### If activity is verified as legitimate

Document the evidence supporting the disposition and determine whether detection tuning is appropriate.

---

## 💡 Lessons Learned

Identity alerts become significantly more valuable when authentication telemetry is correlated with endpoint behavior.

A SOC analyst should investigate what happened **before, during, and after authentication** to determine whether valid credentials were abused and to establish the full scope of the incident.
