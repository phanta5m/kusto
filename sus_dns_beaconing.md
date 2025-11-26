## Dynamic scoring for sus DNS query patterns
### Relies on inspection of DNS logs, looks for
- Base64 patterns
- Hex patterns
- Mixed patterns
- Entropy like patterns

```kusto
let lookback = 24h; // <---set your lookback period here
let MinFQDNLength     = 180;
let MinSubdomainLength = 60;
let LongLabelRegex = strcat(@"([^.]{", tostring(MinSubdomainLength), @",})");
// Patterns for encoded/high-entropy-ish labels
let Base64Pattern        = @"([A-Za-z0-9+/]{20,}={0,2})";      // classic Base64 (non URL-safe)
let HexPattern           = @"\b[a-fA-F0-9]{20,}\b";
let MixedPattern         = @"\b[a-zA-Z0-9]{25,}\b";
let EntropyLikePattern   = @"\b[b-df-hj-np-tv-z0-9]{25,}\b";    // consonant-heavy + digits
cisco_umbrella_dns
| where timestamp > ago(lookback)
// --- Environment exclusions ---
| where not(domain endswith ".sophosxl.net" or domain endswith ".sophosxl.net.")// sophos is known to send long encoded dns strings
| where identities !in ("NM_GuestWifi_Out_ATT","QTS Infoblox","DFT Infoblox") // and internalip !startswith "10.88."
| extend domain_raw = tolower(domain)
| extend domain = iif(domain_raw endswith ".", substring(domain_raw, 0, strlen(domain_raw)-1), domain_raw)
| project timestamp, identities, domain, querytype, action,internalip // early project to try and shave off spicy time
| extend fqdnLength = strlen(domain)
| where fqdnLength >= MinFQDNLength // coarse length gating brah
// --- Entering CPU spicy time 🌶️ ---
| extend LongLabels = extract_all(LongLabelRegex, domain)
| extend HasLongSubdomain = array_length(LongLabels) > 0
| extend IsSuspiciousQueryType = querytype in ("TXT","NULL","ANY")
| extend IsBase64      = isnotempty(extract(Base64Pattern,      0, domain))
| extend IsHex         = isnotempty(extract(HexPattern,         0, domain))
| extend IsHighEntropy = isnotempty(extract(MixedPattern,       0, domain))
                      or isnotempty(extract(EntropyLikePattern, 0, domain))
// --- Final filter ---
| where HasLongSubdomain or IsSuspiciousQueryType or IsBase64 or IsHex or IsHighEntropy
| project timestamp, identities, domain, internalip,fqdnLength, querytype, action,
        HasLongSubdomain, IsSuspiciousQueryType, IsBase64, IsHex, IsHighEntropy
| order by timestamp desc
```
