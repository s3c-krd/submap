# submap

Fast subdomain discovery CLI. Finds subdomains across hundreds of passive intelligence sources — no brute-force.

## Install

### From binary

Download from [Releases](https://github.com/s3c-krd/submap/releases).

### From source

```bash
go install github.com/s3c-krd/submap@latest
```

## Authentication

Create a free account at [submap.net](https://submap.net) and generate an API key under **Settings > API Keys**.

```bash
export SUBMAP_KEY="sk_sub_..."
```

Free accounts get 500 results per scan. Upgrade for unlimited results.

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

# Resolve DNS records (A, AAAA, CNAME, MX, NS, TXT)
submap -d uber.com -resolve

# Resolve + JSON
submap -d uber.com -resolve -json

# Pipe to other tools
submap -d uber.com -silent | httpx -silent
echo "tesla.com" | submap -silent | nuclei

# Count only
submap -d uber.com -count
```

## Options

```
-d  <domain>      Target domain
-dL <file>        File with domains (one per line)
-o  <file>        Output file (default: stdout)
-json             JSON output
-resolve          Resolve DNS records (paid plans)
-p  <n>           Parallel scans (default: 1, max: 20)
-silent           Only print subdomains
-count            Only print count
-key <key>        API key (or SUBMAP_KEY env)
--no-color        Disable colors
```

## License

MIT
