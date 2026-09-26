# DNSentinel - Local DNS Proxy + Blocklist + Egress Monitor

Local UDP DNS proxy on 127.0.0.1:53 with upstream forward,
domain blocklist, JSONL query log, and egress monitor.

Upstreams: Cloudflare 1.1.1.1 and Google 8.8.8.8 (see config.yaml).

## Run

Run as ADMIN (port 53 needs privilege):

    python agent.py serve

Default config.yaml: listen 127.0.0.1, port 53, timeout 3.0,
blocklist blocklist.txt, log logs/dns.log,
egress_log logs/egress.log, egress_interval 10.
## Set DNS Windows to 127.0.0.1

1. Settings, Network, active adapter, Properties, IPv4.
2. Preferred DNS 127.0.0.1, Alternate 1.1.1.1.
3. Run ipconfig flushdns, then nslookup example.com.

## CLI blocklist

    python agent.py block add DOMAIN
    python agent.py block remove DOMAIN
    python agent.py block list

Blocked domains resolve to 0.0.0.0 and log blocked true.
## Monitoring

- logs/dns.log: one JSON line per query (ts, client, qname, qtype, action).
- logs/egress.log: outbound snapshot every egress_interval seconds.
- Watch live: Get-Content logs/dns.log -Tail 20 -Wait.

## Rollback

1. Stop the proxy with Ctrl+C.
2. Restore DNS to Automatic or 1.1.1.1.
3. Run ipconfig flushdns. No permanent system change.

## Limitations

- Exact-domain blocking: ads.com does not block sub.ads.com.
- DoH/DoT bypass: browsers with DNS-over-HTTPS or TLS skip this proxy.
- UDP only; needs admin for port 53; stdlib only (psutil optional).


## GUI

Run as ADMIN (port 53 needs privilege):

    python gui.py

Features: Start/Stop server, blocklist search, monitoring tail 200 auto 2s.

## Installer Windows

Cara build: jalankan build-exe.bat, hasil dist/DNSentinel.exe. Installer: compile installer/DNSentinel.iss via Inno Setup.
