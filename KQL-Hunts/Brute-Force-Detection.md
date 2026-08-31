# 🚨 Brute Force Authentication Detection

## Overview

This threat-hunting scenario identifies user accounts experiencing a high number of failed Windows authentication attempts within a short period.

Repeated authentication failures can indicate password guessing, brute-force attacks, misconfigured applications, or legitimate users entering incorrect credentials.

---

## 🎯 Detection Objective

Identify accounts with **10 or more failed logon attempts within one hour** and provide the SOC analyst with relevant information for further investigation.

---

## 📊 Data Source

**Microsoft Sentinel Table:** `SecurityEvent`

**Windows Event ID:** `4625` — An account failed to log on.

Relevant fields:

- `TimeGenerated`
- `TargetUserName`
- `IpAddress`
- `Computer`
- `EventID`

---

## 🔎 KQL Query

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    SourceIPs = make_set(IpAddress, 10)
    by TargetAccount = TargetUserName, Computer
| where FailedAttempts >= 10
| order by FailedAttempts desc
