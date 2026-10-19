#!/usr/bin/env python3
"""Static security-header audit for nginx, Apache and Caddy configs."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BASELINE = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}

FLAVOR_HINTS = {
    "nginx": {"add_header", "more_set_headers"},
    "apache": {"header always set", "header set"},
    "caddy": {"header"},
}


def detect_flavor(text: str) -> str:
    lowered = text.lower()
    if any(h in lowered for h in FLAVOR_HINTS["apache"]):
        return "apache"
    if re.search(r"^\s*header\s+", lowered, re.MULTILINE):
        return "caddy"
    return "nginx"


def extract_headers(text: str) -> dict:
    found = {}
    patterns = [
        re.compile(r"add_header\s+([A-Za-z-]+)\s+\"([^\"]*)\""),
        re.compile(r"Header\s+(?:always\s+)?set\s+([A-Za-z-]+)\s+\"([^\"]*)\"", re.I),
        re.compile(r"^\s*header\s+([A-Za-z-]+)\s+\"([^\"]*)\"", re.I | re.M),
    ]
    for line in text.splitlines():
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                found[match.group(1).lower()] = match.group(2)
    return found


def audit(headers: dict):
    findings = []
    for name, expected in BASELINE.items():
        value = headers.get(name)
        if value is None:
            findings.append({"header": name, "issue": "missing", "expected": expected})
        elif not value.strip():
            findings.append({"header": name, "issue": "empty", "expected": expected})
    return findings


def snippets(missing, flavor: str) -> str:
    lines = []
    if flavor == "nginx":
        for name in missing:
            lines.append(f'add_header {name} "{BASELINE[name]}" always;')
    elif flavor == "apache":
        for name in missing:
            lines.append(f'Header always set {name} "{BASELINE[name]}"')
    else:
        for name in missing:
            lines.append(f'header {name} "{BASELINE[name]}"')
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Audit web-server config for security headers")
    parser.add_argument("config", type=Path)
    parser.add_argument("--flavor", choices=["nginx", "apache", "caddy"])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not args.config.exists():
        print(f"file not found: {args.config}", file=sys.stderr)
        return 2
    text = args.config.read_text(encoding="utf-8", errors="replace")
    flavor = args.flavor or detect_flavor(text)
    headers = extract_headers(text)
    findings = audit(headers)
    missing = [f["header"] for f in findings]

    payload = {
        "config": str(args.config),
        "flavor": flavor,
        "headers_found": headers,
        "findings": findings,
        "suggested_snippet": snippets(missing, flavor) if missing else "",
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"config: {args.config}  (flavor: {flavor})")
        print(f"headers found: {len(headers)}")
        if not findings:
            print("no findings: baseline headers are present")
        for finding in findings:
            print(f"[MISS] {finding['header']}: {finding['issue']}")
        if missing:
            print("\nsuggested snippet:")
            print(payload["suggested_snippet"])
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
