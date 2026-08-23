# submap

Fast subdomain discovery CLI powered by 144 passive sources. Finds subdomains using certificate transparency logs, search engines, DNS databases, web archives, and more — without brute-force.

## Install

### From binary

Download from [Releases](https://github.com/s3c-krd/submap/releases).

### From source

```bash
go install github.com/s3c-krd/submap@latest
```

## Prerequisites

Submap connects to a [SubMap server](https://submap.net) instance for scanning. Set your credentials:

```bash
export SUBMAP_PASS="your-password"
export SUBMAP_USER="your-username"    # optional, default: secscope
export SUBMAP_HOST="127.0.0.1"        # optional
export SUBMAP_PORT="3838"             # optional
```

## Usage

```bash
# Scan a domain
submap -d uber.com

# Silent mode (subdomains only, pipeable)
submap -d uber.com -silent

# JSON output
submap -d uber.com -json

# Scan from file
submap -dL targets.txt -o results.txt

# Parallel scans
submap -dL targets.txt -p 10

# Pipe to other tools
submap -d uber.com -silent | httpx -silent
echo "tesla.com" | submap -silent | nuclei

# Count only
submap -d uber.com -count

# List cached results
submap --cached
```

## Options

```
-d  <domain>      Target domain
-dL <file>        File with domains (one per line)
-o  <file>        Output file (default: stdout)
-json             JSON output
-p  <n>           Parallel scans (default: 1, max: 20)
-silent           Only print subdomains
-count            Only print count
-server <host>    Server host (default: 127.0.0.1)
-port <n>         Server port (default: 3838)
-u <user>         Username (or SUBMAP_USER env)
-pw <pass>        Password (or SUBMAP_PASS env)
--no-color        Disable colors
--cached          List cached domains
```

## Sources

Submap uses 144 passive sources including:

- Certificate Transparency (crt.sh, certspotter, entrust, google CT, facebook CT, merklemap, crt.name)
- DNS databases (RapidDNS, HackerTarget, DNSRepo, DNSdumpster, Robtex, ThreatMiner)
- Search engines (Google, Bing, DuckDuckGo, Yandex dorking)
- Web archives (Wayback Machine, CommonCrawl, Arquivo.pt)
- Security APIs (AlienVault OTX, URLScan, Shodan InternetDB, LeakIX)
- And 100+ more

All sources are passive — no active DNS brute-force or port scanning.

## License

MIT
