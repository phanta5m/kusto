## Search for connections to known phishing links within Cisco proxy logs
#### List of phishing links updated reguarly, from the Phishing-Database repo found on github

<p>Normalize, then search over the last hour of proxy logs for any hits</p>

- The first one normalizes the domains from the OSINT source
- The second one normalizes the proxy log domains so they can be matched

``` kusto

let x = 1h;
let sus = externaldata (Word: string) [
    h'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-NEW-today.txt'
] with (format="txt");
let sus_cleaned = sus
| where isnotempty(Word)
| extend url_parts = parse_url(Word)
| extend host = url_parts.Host, path = url_parts.Path
| extend first_path_segment = split(path, "/")[1]
| extend normalized1 = strcat(host, "/", first_path_segment)
| where isnotempty(first_path_segment);
let proxy_cleaned = cisco_umbrella_proxy
| where timestamp > ago(x)
| extend url_parts = parse_url(url)
| extend host = url_parts.Host, path = url_parts.Path
| extend first_path_segment = split(path, "/")[1]
| extend normalized2 = strcat(host, "/", first_path_segment)
| where isnotempty(first_path_segment);
proxy_cleaned
| join kind=inner (
    sus_cleaned
    | project normalized1, phishing_url = Word
) on $left.normalized2 == $right.normalized1
| project-reorder timestamp, url, phishing_url, normalized2, referer, statuscode, categories, identities

```
