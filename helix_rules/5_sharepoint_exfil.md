## Exfiltration: High-Velocity Multi-Site SharePoint Download with Risk Signals 
(T1213.002, T1530)

1. Standard flat thresholds on FileDownloaded are notoriously noisy because OneDrive sync clients (Microsoft SkyDriveSync) and heavy power users routinely pull hundreds of files. This detection eliminates false positives by:
Excluding legitimate OneDrive sync agents.

2. Requiring downloads across multiple distinct SharePoint sites (>= 3 sites) in a 15-minute window.

3. Requiring at least one high-risk corroborating signal: a scripting User-Agent, multiple distinct IPs, or a recent MFA registration by that user in the last 72 hours.

```kusto
// Point 5: High-Velocity Cross-Site SharePoint Exfiltration Correlated with Risk Signals
// Data Sources: OfficeActivity, AuditLogs
let velocity_window = 1h;
let bin_size = 15m;
let mfa_lookback = 3d;
let download_threshold = 75;
let min_distinct_sites = 3;
let scripting_uas = dynamic(["python-requests", "python-httpx", "aiohttp", "go-http-client", "curl/", "node", "powershell", "microsoft.graph"]);
// Step 1: Pre-fetch users who registered a new MFA factor in the last 72 hours
let RecentMfaUsers = AuditLogs
    | where TimeGenerated >= ago(mfa_lookback)
    | where OperationName has_any ("User registered security info", "Admin registered security info")
    | where Result =~ "success"
    | mv-expand TargetResource = TargetResources
    | extend UserPrincipalName = tolower(coalesce(tostring(TargetResource.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName)))
    | where isnotempty(UserPrincipalName)
    | distinct UserPrincipalName;
// Step 2: Aggregate SharePoint file downloads over 15-minute windows
OfficeActivity
| where TimeGenerated >= ago(velocity_window)
| where OfficeWorkload in~ ("SharePoint", "OneDrive")
| where Operation in~ ("FileDownloaded", "FileSyncDownloadedFull")
// Filter out benign OneDrive Sync client activity to drastically cut noise
| where not(UserAgent has_any ("SkyDriveSync", "OneDrive", "Microsoft Office"))
| extend UserPrincipalName = tolower(UserId)
| summarize
    DownloadCount = count(),
    DistinctFiles = dcount(OfficeObjectId),
    DistinctSites = dcount(Site_Url),
    SiteList = make_set(Site_Url, 10),
    ClientIPs = make_set(ClientIP, 5),
    UserAgents = make_set(UserAgent, 5),
    ScriptingUADetected = max(iff(UserAgent has_any (scripting_uas), 1, 0))
    by UserPrincipalName, bin(TimeGenerated, bin_size)
// Step 3: Apply velocity & multi-site thresholds
| where DistinctFiles >= download_threshold and DistinctSites >= min_distinct_sites
// Step 4: Enrich with recent MFA change status and require at least one high-confidence signal
| extend HasRecentMfaChange = UserPrincipalName in (RecentMfaUsers)
| where ScriptingUADetected == 1 or HasRecentMfaChange == true or DistinctSites >= 5
| project TimeGenerated, UserPrincipalName, DistinctFiles, DistinctSites, HasRecentMfaChange, ScriptingUADetected, ClientIPs, UserAgents, SiteList

```
