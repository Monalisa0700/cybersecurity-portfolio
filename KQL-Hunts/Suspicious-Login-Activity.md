# 🔐 Suspicious Login Activity Hunt

## Overview

This threat-hunting scenario identifies source IP addresses associated with successful Windows logons to multiple user accounts within a short period.

The activity is not inherently malicious, but it can provide a useful starting point for investigating unusual authentication behavior, compromised infrastructure, shared administrative systems, or activity following credential attacks.

---

## 🎯 Hunting Objective

Identify source IP addresses successfully authenticating to **five or more distinct user accounts within one hour**.

The threshold is intended as an example and should be tuned according to the environment.

---

## 📊 Data Source

**Microsoft Sentinel Table:** `SecurityEvent`

**Windows Event ID:** `4624` — An account was successfully logged on.

Relevant fields:

- `TimeGenerated`
- `TargetUserName`
- `IpAddress`
- `Computer`
- `EventID`

---

🧠 Hunting Logic

The query:

Searches successful Windows authentication events from the last hour.
Filters for Event ID 4624.
Removes empty and local loopback IP addresses.
Groups successful authentication events by source IP.
Counts the number of distinct accounts accessed.
Records the associated accounts and computers.
Returns IP addresses authenticating to five or more distinct accounts.


🔍 Investigation Steps

An analyst should:

Determine whether the source IP is internal or external.
Identify all accounts associated with the IP.
Review the computers accessed by those accounts.
Determine whether the source is an approved jump server, VPN, proxy, or administrative system.
Review failed logons preceding the successful authentication.
Check for unusual logon times or unexpected systems.
Review endpoint telemetry for suspicious process execution.
Correlate the activity with other SIEM and EDR alerts.
Investigate whether any affected credentials may have been compromised.


⚠️ Possible False Positives

Legitimate causes may include:

VPN gateways
Proxy infrastructure
Jump servers
Shared administrative systems
Terminal servers
NAT environments
Automated services


🚨 Recommended Response

If malicious activity is confirmed:

Disable or reset affected credentials as appropriate.
Revoke active sessions.
Investigate affected endpoints.
Block malicious infrastructure where appropriate.
Review MFA and authentication activity.
Search for additional affected accounts.
Escalate according to the incident-response process.


💡 Detection Improvements

This hunt can be improved by:

Excluding approved VPN and proxy infrastructure.
Establishing normal authentication baselines.
Correlating successful logons with preceding Event ID 4625 failures.
Incorporating threat-intelligence enrichment.
Adding geographic context where available.
Separating service accounts from interactive user accounts.


📌 Analyst Note

A single IP authenticating to multiple accounts does not automatically indicate malicious activity. Shared infrastructure such as VPNs, proxies, NAT gateways, and administrative servers can produce similar behavior. Additional context and telemetry are required before classifying the activity as an incident.
