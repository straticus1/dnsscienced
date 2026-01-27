#!/usr/bin/env python3
"""
Convert BIND (and other) zone files to DNSScienced YAML zone format (.dnszone).

Usage:
  bind2dnsscienced.py --zone <zonefile> [--servertype=auto|bind|djbdns|powerdns] [--dry-run] [--save] [--out-dir DIR]
  bind2dnsscienced.py --batch <dir> [--servertype=auto|bind|djbdns|powerdns] [--dry-run] [--save] [--out-dir DIR]

Notes:
- Requires: dnspython, PyYAML
- Supports input: BIND format today (auto detects as BIND). Hooks in place for djbdns/powerdns.
- Output schema aligns with README 'DNSScienced zone format'. Multiple values become lists. TTLs are preserved per RRSet when they differ from zone default by emitting objects {value, ttl}.
"""
import argparse
import os
import sys
import glob
from typing import Dict, Any, List, Tuple, Optional, Union

try:
    import dns.zone
    import dns.rdatatype
    import dns.name
    import yaml
except Exception as e:
    print("ERROR: This tool requires dnspython and PyYAML. Install with: pip install dnspython pyyaml", file=sys.stderr)
    sys.exit(2)

SUPPORTED_TYPES = {
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'CAA', 'SOA', 'PTR', 'SPF', 'NSAP', 'SSHFP', 'TLSA', 'SVCB', 'HTTPS', 'NAPTR'
}

ScalarOrList = Union[str, Dict[str, Any], List[Union[str, Dict[str, Any]]]]


def _owner_to_key(owner: dns.name.Name, origin: dns.name.Name) -> str:
    if owner == origin:
        return '@'
    rel = owner.relativize(origin)
    return rel.to_text().rstrip('.')


def _rr_to_value_text(rr) -> str:
    # textual presentation of rdata, similar to BIND zone file right-hand side
    # use to_text() which avoids owner name and class/type
    return rr.to_text()


def _append_value(node: Dict[str, Any], rtype: str, value: ScalarOrList) -> None:
    existing = node.get(rtype)
    if existing is None:
        node[rtype] = value
    else:
        if not isinstance(existing, list):
            node[rtype] = [existing]
        node[rtype].append(value)


def _value_with_optional_ttl(text_value: str, ttl: Optional[int], default_ttl: Optional[int]) -> ScalarOrList:
    # If ttl equals default, keep scalar. Else embed object with value+ttl.
    if ttl is None or default_ttl is None or ttl == default_ttl:
        return text_value
    return { 'value': text_value, 'ttl': int(ttl) }


def bind_zone_to_dnszone(path: str, origin_hint: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    warnings: List[str] = []
    # Load BIND zone; origin may be in file via $ORIGIN. If provided via hint, use it.
    origin = dns.name.from_text(origin_hint) if origin_hint else None
    try:
        z = dns.zone.from_file(path, origin=origin, relativize=False)
    except Exception as e:
        raise RuntimeError(f"Failed to parse BIND zone '{path}': {e}")

    origin_name: dns.name.Name = z.origin
    apex = z.get_node(origin_name)

    # Collect defaults
    default_ttl: Optional[int] = None
    try:
        default_ttl = z.ttl  # dnspython may expose default TTL
    except Exception:
        default_ttl = None

    doc: Dict[str, Any] = {
        'zone': origin_name.to_text().rstrip('.'),
        'serial': 'auto',
    }
    if default_ttl is not None:
        doc['ttl'] = int(default_ttl)

    nameservers: List[str] = []
    mx_list: List[Dict[str, Any]] = []

    records: Dict[str, Dict[str, Any]] = {}

    # Iterate through all nodes and rdatasets
    for (name, node) in z.nodes.items():
        key = _owner_to_key(name, origin_name)
        for rdataset in node.rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            ttl = rdataset.ttl
            if rtype not in SUPPORTED_TYPES:
                warnings.append(f"Unsupported/unknown RR type '{rtype}' at '{name}' — emitting as TXT string")
            # Special handling for SOA at apex
            if rtype == 'SOA' and name == origin_name:
                try:
                    soa = list(rdataset)[0]
                    doc.setdefault('soa', {})
                    doc['soa'] = {
                        'primary': soa.mname.to_text().rstrip('.'),
                        'admin': soa.rname.to_text().rstrip('.'),
                        'serial': int(soa.serial),
                        'refresh': int(soa.refresh),
                        'retry': int(soa.retry),
                        'expire': int(soa.expire),
                        'minimum': int(soa.minimum),
                    }
                    # If we have explicit serial, keep it
                    doc['serial'] = int(soa.serial)
                except Exception as e:
                    warnings.append(f"Failed to process SOA: {e}")
                continue

            # NS at apex -> nameservers
            if rtype == 'NS' and name == origin_name:
                for rr in rdataset:
                    ns = rr.target.to_text().rstrip('.')
                    nameservers.append(ns)
                continue

            # MX at apex -> mx list
            if rtype == 'MX' and name == origin_name:
                for rr in rdataset:
                    mx_list.append({'priority': int(rr.preference), 'host': rr.exchange.to_text().rstrip('.')})
                continue

            # General records mapping per owner
            recnode = records.setdefault(key, {})
            for rr in rdataset:
                if rtype == 'A':
                    val = _value_with_optional_ttl(rr.address, ttl, default_ttl)
                    _append_value(recnode, 'A', val)
                elif rtype == 'AAAA':
                    val = _value_with_optional_ttl(rr.address, ttl, default_ttl)
                    _append_value(recnode, 'AAAA', val)
                elif rtype == 'CNAME':
                    cname = rr.target.to_text().rstrip('.')
                    val = _value_with_optional_ttl(cname, ttl, default_ttl)
                    _append_value(recnode, 'CNAME', val)
                elif rtype == 'TXT':
                    # dnspython TXT may have multiple strings; join with spaces
                    txt = ' '.join([s.decode('utf-8') if isinstance(s, bytes) else str(s) for s in rr.strings])
                    val = _value_with_optional_ttl(txt, ttl, default_ttl)
                    _append_value(recnode, 'TXT', val)
                elif rtype == 'MX':
                    val = _value_with_optional_ttl(f"{rr.preference} {rr.exchange.to_text().rstrip('.')}", ttl, default_ttl)
                    _append_value(recnode, 'MX', val)
                elif rtype == 'NS':
                    val = _value_with_optional_ttl(rr.target.to_text().rstrip('.'), ttl, default_ttl)
                    _append_value(recnode, 'NS', val)
                elif rtype == 'SRV':
                    target = rr.target.to_text().rstrip('.')
                    val = _value_with_optional_ttl(f"{rr.priority} {rr.weight} {rr.port} {target}", ttl, default_ttl)
                    _append_value(recnode, 'SRV', val)
                elif rtype == 'CAA':
                    val = _value_with_optional_ttl(f"{rr.flags} {rr.tag} {rr.value}\n", ttl, default_ttl)
                    _append_value(recnode, 'CAA', val)
                else:
                    # Fallback to textual data
                    val = _value_with_optional_ttl(_rr_to_value_text(rr), ttl, default_ttl)
                    _append_value(recnode, rtype, val)

    if nameservers:
        doc['nameservers'] = sorted(list(dict.fromkeys(nameservers)))
    if mx_list:
        # sort by priority then host
        doc['mx'] = sorted(mx_list, key=lambda x: (x['priority'], x['host']))
    if records:
        doc['records'] = records

    return doc, warnings


def write_dnszone(doc: Dict[str, Any], out_path: str) -> None:
    # YAML dumping with stable order
    class LiteralString(str):
        pass
    def literal_str_representer(dumper, data):
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    yaml.add_representer(LiteralString, literal_str_representer)  # not used now but kept for future multi-line

    with open(out_path, 'w') as f:
        yaml.dump(doc, f, sort_keys=False, default_flow_style=False)


def detect_server_type(path: str) -> str:
    # Heuristics: tinydns data files often named 'data' or lines start with single-char codes
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            head = ''.join([next(f) for _ in range(10)])
        if any(head.startswith(c) for c in ('#', '.', '&', 'C', '@', '+', '=')):
            return 'djbdns'
    except Exception:
        pass
    return 'bind'


def djbdns_to_dnszone(path: str, origin_hint: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    warnings: List[str] = []
    origin = origin_hint.rstrip('.') if origin_hint else None
    if not origin:
        warnings.append("djbdns: --origin recommended; defaulting to first '&' NS line's domain if present")
    doc: Dict[str, Any] = {
        'zone': origin or 'UNKNOWN',
        'serial': 'auto',
    }
    nameservers: List[str] = []
    mx_list: List[Dict[str, Any]] = []
    records: Dict[str, Dict[str, Any]] = {}

    def recnode(owner: str) -> Dict[str, Any]:
        return records.setdefault(owner, {})

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            code = line[0]
            rest = line[1:]
            parts = rest.split(':')
            try:
                if code == '.':  # host with A and optional TTL
                    host = parts[0] or '@'
                    addr = parts[1]
                    ttl = int(parts[2]) if len(parts) > 2 and parts[2] else None
                    owner = host if host != '@' else '@'
                    val = addr if ttl is None else {'value': addr, 'ttl': ttl}
                    _append_value(recnode(owner), 'A', val)
                elif code == '&':  # NS
                    dom = parts[0]
                    ns = parts[1]
                    ttl = int(parts[2]) if len(parts) > 2 and parts[2] else None
                    if (origin or '').rstrip('.') == dom.rstrip('.') or owner == '@':
                        nameservers.append(ns.rstrip('.'))
                    owner = '@' if (origin or '').rstrip('.') == dom.rstrip('.') else dom
                    val = ns.rstrip('.') if ttl is None else {'value': ns.rstrip('.'), 'ttl': ttl}
                    _append_value(recnode(owner), 'NS', val)
                    if not origin:
                        doc['zone'] = dom.rstrip('.')
                        origin = doc['zone']
                elif code == 'C':  # CNAME
                    host = parts[0]
                    target = parts[1]
                    ttl = int(parts[2]) if len(parts) > 2 and parts[2] else None
                    owner = host or '@'
                    val = target.rstrip('.') if ttl is None else {'value': target.rstrip('.'), 'ttl': ttl}
                    _append_value(recnode(owner), 'CNAME', val)
                elif code == '@':  # MX
                    dom = parts[0]
                    mx = parts[1]
                    prio = int(parts[2]) if len(parts) > 2 and parts[2] else 10
                    mx_list.append({'priority': prio, 'host': mx.rstrip('.')})
                elif code == "'":  # TXT
                    host = parts[0]
                    txt = parts[1]
                    owner = host or '@'
                    _append_value(recnode(owner), 'TXT', txt)
                else:
                    warnings.append(f"djbdns: unsupported line '{line[:30]}...' skipped")
            except Exception as e:
                warnings.append(f"djbdns parse error: {e} in line: {line}")

    if nameservers:
        doc['nameservers'] = sorted(list(dict.fromkeys(nameservers)))
    if mx_list:
        doc['mx'] = sorted(mx_list, key=lambda x: (x['priority'], x['host']))
    if records:
        doc['records'] = records
    return doc, warnings


def convert_one(path: str, servertype: str, out_dir: Optional[str], save: bool, dry_run: bool, origin: Optional[str]) -> int:
    st = servertype
    if st == 'auto':
        st = detect_server_type(path)
    if st == 'bind':
        doc, warnings = bind_zone_to_dnszone(path, origin)
    elif st == 'djbdns':
        doc, warnings = djbdns_to_dnszone(path, origin)
    else:
        print(f"WARN: servertype '{st}' not fully supported; attempting as BIND...", file=sys.stderr)
        doc, warnings = bind_zone_to_dnszone(path, origin)
    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)

    if dry_run and not save:
        # print to stdout
        print(yaml.dump(doc, sort_keys=False, default_flow_style=False))
        return 0

    # Determine output path
    base = os.path.basename(path)
    name_no_ext = os.path.splitext(base)[0]
    out_name = f"{name_no_ext}.dnszone"
    out_path = os.path.join(out_dir or os.path.dirname(path), out_name)

    if save:
        write_dnszone(doc, out_path)
        print(f"Saved: {out_path}")
    else:
        print(yaml.dump(doc, sort_keys=False, default_flow_style=False))
    return 0


def iter_zone_files(directory: str) -> List[str]:
    patterns = ["*.zone", "*.db", "*.dns", "*.bind", "*"]
    files: List[str] = []
    for p in patterns:
        files.extend(glob.glob(os.path.join(directory, p)))
    # Filter regular files
    files = [f for f in files if os.path.isfile(f)]
    return sorted(list(dict.fromkeys(files)))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Convert BIND zones to DNSScienced YAML format")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--zone', help='Path to a single zone file')
    g.add_argument('--batch', help='Directory containing zone files to convert')
    ap.add_argument('--servertype', default='auto', choices=['auto', 'bind', 'djbdns', 'powerdns'], help='Input server/platform type')
    ap.add_argument('--dry-run', action='store_true', help='Do not write files; print result to stdout')
    ap.add_argument('--save', action='store_true', help='Write .dnszone files to disk')
    ap.add_argument('--out-dir', help='Output directory (default: alongside input)')
    ap.add_argument('--origin', help='Zone origin (if not embedded in file)')

    args = ap.parse_args(argv)

    if args.zone:
        if not os.path.isfile(args.zone):
            print(f"ERROR: file not found: {args.zone}", file=sys.stderr)
            return 2
        return convert_one(args.zone, args.servertype, args.out_dir, args.save, args.dry_run, args.origin)

    # batch
    if not os.path.isdir(args.batch):
        print(f"ERROR: directory not found: {args.batch}", file=sys.stderr)
        return 2
    files = iter_zone_files(args.batch)
    if not files:
        print("No zone files found", file=sys.stderr)
        return 1
    rc = 0
    for f in files:
        try:
            rc |= convert_one(f, args.servertype, args.out_dir, args.save, args.dry_run, args.origin)
        except Exception as e:
            print(f"ERROR converting {f}: {e}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
