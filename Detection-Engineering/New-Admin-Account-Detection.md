# 👤 New Account Added to Administrators Detection

## Overview

This detection identifies Windows security events associated with a user being added to a privileged local or domain group.

Unexpected changes to privileged group membership can indicate privilege escalation, persistence, account compromise, or unauthorized administrative activity.

---

## 🎯 Detection Objective

Identify accounts being added to security-enabled privileged groups and provide the SOC analyst with information about:

- The account that was added
- The privileged group
- The account that performed the change
- The affected system
- The time of the change

---

## 🧩 Threat Scenario

An attacker compromises an existing account or creates a new account and then grants it administrative privileges.

Example attack flow:

**Account Compromise → Account/Group Modification → Privileged Access → Persistence**

Monitoring privileged group membership changes can help identify this behavior.

---

## 📊 Data Source

**Platform:** Microsoft Sentinel

**Table:** `SecurityEvent`

### Relevant Windows Event IDs

| Event ID | Description |
|---|---|
| 4728 | Member added to a security-enabled global group |
| 4732 | Member added to a security-enabled local group |
| 4756 | Member added to a security-enabled universal group |

Event `4732` is particularly relevant when monitoring additions to a local Administrators group.

---

## 🔎 Detection Query

```kusto
SecurityEvent
| where TimeGenerated > ago(10m)
| where EventID in (4728, 4732, 4756)
| where TargetUserName has_any (
    "Administrators",
    "Domain Admins",
    "Enterprise Admins"
)
| project
    TimeGenerated,
    Computer,
    EventID,
    TargetGroup = TargetUserName,
    AddedMember = MemberName,
    AddedMemberSid = MemberSid,
    InitiatingAccount = SubjectUserName,
    SubjectDomainName
| order by TimeGenerated desc
```

---

## ⚙️ Suggested Analytics Rule Configuration

| Setting | Value |
|---|---|
| Rule Type | Scheduled |
| Severity | High |
| Query Frequency | 5 minutes |
| Query Lookback | 10 minutes |
| Trigger | More than 0 results |
| Suppression | Environment dependent |

Privileged-group membership changes should generally receive higher investigation priority because they can provide elevated access.

---

## 🎯 MITRE ATT&CK Mapping

**Tactic:** Persistence / Privilege Escalation

**Technique:** T1098 — Account Manipulation

Depending on the exact activity, additional account-related techniques may also be relevant.

---

## 🧱 Entity Mapping

| Entity | Source Field |
|---|---|
| Account | `AddedMember` |
| Host | `Computer` |
| Initiating Account | `InitiatingAccount` |

These entities allow analysts to pivot between the account receiving privileges, the system involved, and the account performing the modification.

---

## 🔍 Alert Investigation

When this detection triggers:

1. Identify the account that received privileged membership.
2. Identify the account that performed the modification.
3. Determine which privileged group was modified.
4. Verify whether the change was authorized.
5. Review recent authentication activity for both accounts.
6. Determine whether the initiating account normally performs administrative changes.
7. Review endpoint activity around the event time.
8. Check for recent account creation events.
9. Correlate with other SIEM and EDR alerts.
10. Review subsequent actions performed by the newly privileged account.

---

## ⚠️ False Positive Considerations

Legitimate activity may include:

- Approved administrator provisioning
- IT support activity
- Planned access changes
- Identity-management automation
- Temporary privileged access
- Server deployment or configuration

Administrative changes should therefore be validated against approved change-management activity where available.

---

## 🔧 Tuning Recommendations

Detection quality can be improved by:

- Maintaining a list of critical privileged groups.
- Prioritizing Domain Admins and Enterprise Admins.
- Correlating group membership changes with account creation.
- Monitoring whether newly privileged accounts immediately authenticate.
- Identifying modifications performed by unusual accounts.
- Correlating with change-management records where available.
- Increasing severity when the initiating account is unexpected.

Avoid permanently excluding administrative accounts simply because they frequently make group changes.

---

## 🚨 Response Actions

If the change is unauthorized:

1. Remove the unauthorized privileged membership.
2. Disable or reset the affected account where appropriate.
3. Investigate the initiating account for compromise.
4. Revoke suspicious active sessions.
5. Review actions performed after privilege assignment.
6. Investigate affected endpoints.
7. Hunt for additional account or group modifications.
8. Escalate according to the incident-response procedure.

---

## 📈 Detection Maturity

### Current Detection

Monitors additions to selected privileged Windows security groups.

### Future Improvements

A mature implementation could include:

- Account creation correlation
- Privileged Identity Management telemetry
- Change-management integration
- UEBA risk scoring
- Baselines for administrative behavior
- Detection of rapid privilege assignment followed by sensitive activity

---

## 📌 Detection Engineering Note

Privileged group membership changes are high-value security events, but not every change is malicious.

The analyst should determine **who made the change, who received access, whether the change was authorized, and what happened afterward** before determining incident severity.
