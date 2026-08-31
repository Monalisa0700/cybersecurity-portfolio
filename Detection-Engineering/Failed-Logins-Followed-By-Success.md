# 🔐 Multiple Failed Logins Followed by Successful Login

## Overview

This detection identifies user accounts that experience multiple failed Windows logon attempts followed by a successful authentication within a short time window.

This pattern may indicate that an attacker successfully guessed or obtained a user's password after repeated authentication attempts.

---

## 🎯 Detection Objective

Detect accounts with:

- Multiple failed authentication attempts
- Followed by a successful authentication
- Within the same monitoring period

This provides stronger context than alerting on failed logons alone.

---

## 🧩 Threat Scenario

An attacker attempts several passwords against a user account.

After repeated failures, one authentication succeeds.

Example:

**Failed Login → Failed Login → Failed Login → Successful Login**

This sequence warrants investigation because it may indicate successful credential compromise.

---

## 📊 Data Source

**Platform:** Microsoft Sentinel

**Table:** `SecurityEvent`

### Relevant Windows Events

| Event ID | Description |
|---|---|
| 4625 | Failed logon |
| 4624 | Successful logon |

Relevant fields include:

- `TimeGenerated`
- `TargetUserName`
- `IpAddress`
- `Computer`
- `EventID`

---

## 🔎 Detection Query

```kusto
let FailedLogins =
    SecurityEvent
    | where TimeGenerated > ago(15m)
    | where EventID == 4625
    | where isnotempty(TargetUserName)
    | summarize
        FailedAttempts = count(),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by TargetUserName, IpAddress, Computer
    | where FailedAttempts >= 5;

let SuccessfulLogins =
    SecurityEvent
    | where TimeGenerated > ago(15m)
    | where EventID == 4624
    | where isnotempty(TargetUserName)
    | project
        TargetUserName,
        IpAddress,
        Computer,
        SuccessfulLoginTime = TimeGenerated;

FailedLogins
| join kind=inner SuccessfulLogins
    on TargetUserName, IpAddress, Computer
| where SuccessfulLoginTime > LastFailure
| project
    TargetUserName,
    IpAddress,
    Computer,
    FailedAttempts,
    FirstFailure,
    LastFailure,
    SuccessfulLoginTime
| order by SuccessfulLoginTime desc
```

---

## ⚙️ Suggested Analytics Rule Configuration

| Setting | Value |
|---|---|
| Rule Type | Scheduled |
| Severity | High |
| Query Frequency | 5 minutes |
| Query Lookback | 15 minutes |
| Trigger | More than 0 results |
| Suppression | Environment dependent |

The threshold of five failed attempts is an example and should be tuned to the organization's authentication baseline.

---

## 🎯 MITRE ATT&CK Mapping

**Tactic:** Credential Access

**Technique:** T1110 — Brute Force

Potential sub-techniques may include:

- **T1110.001 — Password Guessing**
- **T1110.003 — Password Spraying**

The exact mapping depends on the authentication pattern observed during investigation.

---

## 🧱 Entity Mapping

| Entity | Source Field |
|---|---|
| Account | `TargetUserName` |
| IP Address | `IpAddress` |
| Host | `Computer` |

These entities provide useful pivots for investigation in Microsoft Sentinel.

---

## 🔍 Alert Investigation

When this detection triggers:

1. Review the number and timing of failed logons.
2. Identify the source IP address.
3. Verify whether the successful authentication originated from the same source.
4. Determine whether the IP is internal, external, VPN, proxy, or approved infrastructure.
5. Review other accounts targeted by the source IP.
6. Check the user's normal authentication behavior.
7. Review MFA activity where available.
8. Investigate activity performed after the successful login.
9. Review endpoint and EDR telemetry.
10. Search for additional alerts involving the account or source IP.

---

## ⚠️ False Positive Considerations

Legitimate scenarios may include:

- A user repeatedly entering an incorrect password and then remembering the correct one
- Recently changed passwords
- Cached credentials
- VPN authentication issues
- Applications using outdated credentials
- Service-account configuration problems

---

## 🔧 Tuning Recommendations

Detection quality can be improved by:

- Adjusting the failed-login threshold based on normal behavior.
- Excluding known authentication infrastructure where appropriate.
- Separating service accounts from interactive user accounts.
- Identifying one source IP targeting multiple accounts.
- Enriching external IP addresses with threat intelligence.
- Increasing severity for privileged accounts.
- Correlating authentication with endpoint activity after successful login.

Avoid excluding users or infrastructure without first validating that the exclusion will not create a detection gap.

---

## 🚨 Response Actions

If account compromise is confirmed:

1. Disable or reset the affected account.
2. Revoke active sessions.
3. Require credential reset according to organizational procedure.
4. Review MFA status and authentication activity.
5. Investigate actions performed after the successful login.
6. Review affected endpoints.
7. Block confirmed malicious infrastructure where appropriate.
8. Hunt for additional compromised accounts.
9. Escalate according to the incident-response process.

---

## 📈 Detection Maturity

### Current Detection

Correlates multiple authentication failures with a subsequent successful login from the same account, IP address, and computer.

### Future Improvements

Future versions could incorporate:

- Authentication baselines
- Privileged-account weighting
- Geographic anomalies
- Threat-intelligence enrichment
- Password-spray detection across multiple accounts
- UEBA risk signals
- MFA telemetry

---

## 📌 Detection Engineering Note

Failed authentication events alone are often noisy.

Correlating repeated failures with a subsequent successful login creates a more meaningful behavioral signal and gives analysts additional context for determining whether credential compromise occurred.
