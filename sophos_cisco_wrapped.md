
## Purpose
Detect potential phishing attempts using **pre-wrapped URLs** from external security platforms (e.g., Sophos, Cisco). Threat actors often abuse these redirectors to make malicious links look legitimate.

## How It Works
- **Baseline (`safe_group`)**: Collect sender domains seen in the past year (excluding last week) with URLs containing both "cisco" and "sophos".
- **Detection**: Find delivered emails with similar URLs but exclude:
  - Known benign Sophos redirect pattern
  - Trusted domains
  - Any sender domains from the baseline (focus on never-before-seen domains)
- **Output**: Earliest occurrence per unique email/URL combination.

## Why It Matters
Pre-wrapped URLs can bypass security filters and trick users. This query highlights **new, suspicious sender domains** using this tactic.


```kusto
let safe_group = EmailUrlInfo
| where Timestamp between ((ago(365d)) .. (ago(7d)))  // Past year, excluding last week
| where Url has "cisco" and Url has "sophos"
| join EmailEvents on NetworkMessageId
| distinct SenderFromDomain;
EmailUrlInfo
| where Url has "cisco" and Url has "sophos"
| join EmailEvents on NetworkMessageId
| where SenderFromDomain !in (safe_group)  // Exclude previously seen domains
| where DeliveryAction == "Delivered"
| where SenderMailFromDomain !in~ ("service-now.com","nm.org")
| project Timestamp, Subject, SenderDisplayName, SenderFromAddress, Url, DeliveryAction, DeliveryLocation, ThreatTypes
| summarize arg_min(Timestamp, *) by Subject, SenderDisplayName, SenderFromAddress, Url, DeliveryAction, DeliveryLocation, ThreatTypes | project-reorder Timestamp
```
