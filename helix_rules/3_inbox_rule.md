## Defense Evasion: Security Notification Deletion or Inbox Rule Post-MFA Change 
(T1070.004, T1564.008)

Threat actors routinely hide their tracks after enrolling a rogue MFA device by deleting the automated "Security info was added" email or creating an inbox rule to sweep security alerts into Trash/RSS Feeds. This query joins AuditLogs with OfficeActivity (and notes an alternative for CloudAppEvents) within a tight 15-minute window.

```kusto
// Point 3: Post-MFA Registration Inbox Rule or Security Email Deletion
// Data Sources: AuditLogs, OfficeActivity (Exchange Unified Audit Log)
let lookback = 2h;
let evasion_window = 15m;
let suspicious_keywords = dynamic(["security info", "authentication", "multi-factor", "mfa", "passkey", "authenticator", "sign-in", "password", "verification"]);
// Step 1: Get users who registered MFA / security info
let MfaEvents = AuditLogs
    | where TimeGenerated >= ago(lookback)
    | where OperationName has_any ("User registered security info", "User changed default security info")
    | where Result =~ "success"
    | mv-expand TargetResource = TargetResources
    | extend UserPrincipalName = tolower(coalesce(tostring(TargetResource.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName)))
    | where isnotempty(UserPrincipalName)
    | project MfaTime = TimeGenerated, UserPrincipalName, MfaOperation = OperationName, MfaIP = tostring(InitiatedBy.user.ipAddress);
// Step 2: Look for Exchange inbox rule creation or message deletion shortly after
let ExchangeEvasion = OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | where OfficeWorkload =~ "Exchange"
    | where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "SoftDelete", "HardDelete", "MoveToDeletedItems")
    | extend UserPrincipalName = tolower(UserId)
    | extend RawParams = tostring(Parameters), RawItems = tostring(AffectedItems)
    // Filter for either Inbox Rule manipulation OR deletion of security-related subjects
    | where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
        or RawItems has_any (suspicious_keywords)
        or RawParams has_any (suspicious_keywords)
    | project ExchTime = TimeGenerated, UserPrincipalName, ExchOperation = Operation, ClientIP, RawParams, RawItems;
// Step 3: Correlate within a 15-minute post-MFA window
MfaEvents
| join kind=inner (ExchangeEvasion) on UserPrincipalName
| where ExchTime between (MfaTime .. (MfaTime + evasion_window))
| project MfaTime, ExchTime, TimeDeltaSeconds = datetime_diff('second', ExchTime, MfaTime),
          UserPrincipalName, MfaOperation, ExchOperation, MfaIP, ExchClientIP = ClientIP, RawParams, RawItems

```
