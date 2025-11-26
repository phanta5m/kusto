## converted from Kusto to YARA-L

```yara
rule suspicious_svchost_telegram_c2
{
    meta:
        author = "Jefferson Park"
        description = "Detect svchost.exe running from unexpected paths and making Telegram-related network connections"
        severity = "high"
        lookback = "24h"

    events:
        process_event:
            $p = process
            where $p.timestamp > now() - 24h
              and $p.file.name = "svchost.exe"
              and not starts_with($p.file.path, "C:\\Windows\\System32\\")
              and not starts_with($p.file.path, "C:\\Windows\\SysWOW64\\")
              and not starts_with($p.file.path, "\\Device\\VhdHardDisk{")

        network_event:
            $n = network
            where $n.timestamp > now() - 24h
              and starts_with($n.action, "Connection")
              and (
                    contains($n.remote.url, "telegram")
                 or starts_with($n.remote.url, "149.154.160.")
                 or starts_with($n.remote.url, "91.108.")
                 or starts_with($n.remote.url, "91.105.")
                 or starts_with($n.remote.url, "185.76.151.")
                 or starts_with($n.remote.url, "2001:b28:f23")
                 or starts_with($n.remote.ip, "149.154.160.")
                 or starts_with($n.remote.ip, "91.108.")
                 or starts_with($n.remote.ip, "91.105.")
                 or starts_with($n.remote.ip, "185.76.151.")
                 or starts_with($n.remote.ip, "2001:b28:f23")
                 or ends_with($n.remote.url, "workers.dev")
              )

    condition:
        $p.device_id = $n.device_id
        and (
            $p.process.unique_id = $n.initiating_process.unique_id
            or $p.file.sha256 = $n.initiating_process.sha256
        )
        and $n.timestamp >= $p.timestamp
        and $n.timestamp <= $p.timestamp + 6h
}
```
