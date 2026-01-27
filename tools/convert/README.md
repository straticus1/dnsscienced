# DNSScienced Zone Conversion Tools

This directory contains tools to help migrate existing DNS zones to the DNSScienced YAML-based zone format (`.dnszone`).

## bind2dnsscienced.py

Converts BIND-style zone files into `.dnszone`.

### Install dependencies

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

### Usage

- Convert a single zone:

```bash
./bind2dnsscienced.py --zone path/to/example.com.zone --dry-run
./bind2dnsscienced.py --zone path/to/example.com.zone --save
```

- Batch convert a directory of zones:

```bash
./bind2dnsscienced.py --batch /etc/bind/zones --save --out-dir ./converted
```

- Specify server type (auto|bind|djbdns|powerdns):

```bash
./bind2dnsscienced.py --zone example.com.zone --servertype bind --save
```

- Provide zone origin when not embedded in the file:

```bash
./bind2dnsscienced.py --zone db.example --origin example.com. --save
```

### Output format notes

- Top-level keys: `zone`, `serial`, optional `ttl`, optional `soa` (if present), `nameservers`, `mx`, and `records`.
- Each owner name (e.g., `@`, `www`) maps to a dict of RR types.
- Values are scalars when TTL equals the zone default; otherwise an object `{ value: <string>, ttl: <seconds> }` is emitted.
- Apex `NS` are promoted to top-level `nameservers`.
- Apex `MX` are promoted to top-level `mx` (list of `{priority, host}`).

### Supported record types

- A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, SOA, PTR, SPF, SSHFP, TLSA, SVCB/HTTPS, NAPTR

Records not recognized are serialized using their textual presentation.

### PowerDNS input

For native PowerDNS data (SQL), export to a BIND-style zone first:

- Using pdnsutil:

```bash
pdnsutil show-zone example.com > example.com.zone
```

Then convert with this tool (it will parse as BIND automatically):

```bash
./bind2dnsscienced.py --zone example.com.zone --save --out-dir ./converted
```

### Roadmap

- Add native support for djbdns and PowerDNS export formats.
- Add schema validation against DNSScienced native format.
- Integrate into `dnsscience-convert` CLI.
