## Discovery: Automated SharePoint Reconnaissance & Pagination Queries 
(T1526, T1213.002)

Before bulk exfiltration, automated SharePoint harvesting scripts enumerate accessible sites and paginate through document indices using specific KQL search operators (contentclass:STS_Site, contentclass:STS_Web, and indexdocid>). Because standard OfficeActivity schemas sometimes truncate SearchQueryPerformed text depending on tenant configuration, this query covers both CloudAppEvents (Defender XDR) and OfficeActivity.

```kusto
// Point 4: Automated SharePoint Site Enumeration & Index Pagination
// Data Sources: CloudAppEvents (Defender XDR) or OfficeActivity (Purview UAL)
let lookback = 1h;
let recon_patterns = dynamic(["contentclass:sts_site", "contentclass:sts_web", "indexdocid>", "contentclass:sts_listitem_documentlibrary"]);
let scripting_uas = dynamic(["python-requests", "python-httpx", "aiohttp", "go-http-client", "curl/", "node-fetch", "axios/", "powershell"]);
union isfuzzy=true
(
    CloudAppEvents
    | where TimeGenerated >= ago(lookback)
    | where Application =~ "Microsoft SharePoint Online" or ActionType =~ "SearchQueryPerformed"
    | extend QueryText = tolower(tostring(RawEventData.QueryText)),
             UserAgent = tostring(UserAgent),
             UserPrincipalName = tolower(tostring(RawEventData.UserId)),
             ClientIP = IPAddress
    | where QueryText has_any (recon_patterns)
        or (ActionType =~ "SearchQueryPerformed" and UserAgent has_any (scripting_uas))
    | project TimeGenerated, DataSource = "CloudAppEvents", UserPrincipalName, ClientIP, UserAgent, ActionType, QueryText
),
(
    OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | where Operation =~ "SearchQueryPerformed"
    | extend QueryText = tolower(tostring(parse_json(ExtendedProperties)[0].Value)),
             RawRecord = tolower(tostring(pack_all())),
             UserPrincipalName = tolower(UserId)
    | where RawRecord has_any (recon_patterns)
        or UserAgent has_any (scripting_uas)
    | project TimeGenerated, DataSource = "OfficeActivity", UserPrincipalName, ClientIP, UserAgent, ActionType = Operation, QueryText = coalesce(QueryText, RawRecord)
)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SearchCount = count(),
    SampleQueries = make_set(QueryText, 10),
    UserAgents = make_set(UserAgent, 5),
    ClientIPs = make_set(ClientIP, 5)
    by UserPrincipalName, DataSource

```
