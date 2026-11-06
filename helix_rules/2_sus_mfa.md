### Persistence: Rogue MFA Registration from Unmanaged Session or Post-MFA Failure 
(T1556.006)

This rule replaces the noisy standalone "User registered security info" alert. It correlates the Entra ID audit event with the underlying sign-in telemetry, alerting only when the session registering the new MFA factor comes from an unmanaged and non-compliant device (typical of AiTM token replay from a residential proxy) or follows recent MFA failures.

```kusto
// Point 2: Suspicious MFA Registration (Unmanaged Device or Post-Auth Failure)
// Data Sources: AuditLogs, SigninLogs
let lookback = 1h;
let auth_window = 30m;
// Step 1: Identify MFA / Security Info registration events
let MfaRegistrations = AuditLogs
    | where TimeGenerated >= ago(lookback)
    | where Category =~ "UserManagement"
    | where OperationName has_any ("User registered security info", "Admin registered security info")
    | where Result =~ "success"
    | mv-expand TargetResource = TargetResources
    | extend TargetUPN = tolower(tostring(TargetResource.userPrincipalName))
    | extend InitiatingUPN = tolower(tostring(InitiatedBy.user.userPrincipalName))
    | extend InitiatingIP = tostring(InitiatedBy.user.ipAddress)
    | extend UserPrincipalName = iff(isnotempty(TargetUPN), TargetUPN, InitiatingUPN)
    | where isnotempty(UserPrincipalName)
    | project RegTime = TimeGenerated, UserPrincipalName, OperationName, ResultDescription, InitiatingIP, CorrelationId;
// Step 2: Correlate with SigninLogs to inspect device trust state and prior MFA failures
MfaRegistrations
| join kind=inner (
    SigninLogs
    | where TimeGenerated >= ago(lookback + auth_window)
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | extend IsCompliant = tobool(DeviceDetail.isCompliant),
             IsManaged = tobool(DeviceDetail.isManaged),
             DeviceOS = tostring(DeviceDetail.operatingSystem),
             Browser = tostring(DeviceDetail.browser)
    | project SigninTime = TimeGenerated, UserPrincipalName, SigninIP = IPAddress,
              UserAgent, AppDisplayName, ResourceDisplayName,
              IsCompliant, IsManaged, DeviceOS, Browser,
              ResultType, Status, AutonomousSystemNumber, Location
) on UserPrincipalName
| where SigninTime between ((RegTime - auth_window) .. (RegTime + 5m))
| summarize
    RegTime = min(RegTime),
    OperationName = take_any(OperationName),
    ResultDescription = take_any(ResultDescription),
    InitiatingIP = take_any(InitiatingIP),
    SigninIPs = make_set(SigninIP, 5),
    ASNs = make_set(AutonomousSystemNumber, 5),
    Locations = make_set(Location, 5),
    UserAgents = make_set(UserAgent, 5),
    ManagedSessionSeen = max(iff(IsManaged == true or IsCompliant == true, 1, 0)),
    FailedAuthCount = countif(ResultType != "0"),
    DistinctIPCount = dcount(SigninIP)
    by UserPrincipalName
// Alert when session is unmanaged AND shows risk indicators (IP shift, prior failures, or OATH/Passkey addition)
| where ManagedSessionSeen == 0
| where DistinctIPCount > 1 or FailedAuthCount > 0 or ResultDescription has_any ("OATH", "Passkey", "Authenticator", "FIDO")
| project RegTime, UserPrincipalName, OperationName, ResultDescription, InitiatingIP, SigninIPs, ASNs, Locations, UserAgents, FailedAuthCount, DistinctIPCount

```
