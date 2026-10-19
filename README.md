# security-headers-audit

Audit web-server configuration files for security headers **before** deploying
them. It reads nginx, Apache or Caddy configuration text, detects which headers
are already set, lists what is missing and prints a ready-to-paste snippet.

No network access, no server required: it is a static review tool.

## Features

- Detects `add_header` (nginx), `Header always set` (Apache) and `header`
  (Caddy) directives.
- Reports missing or misconfigured headers against a strict baseline.
- Generates remediation snippets for the detected server flavor.
- JSON output for CI pipelines.

## Installation

```bash
git clone https://github.com/victor-harden/security-headers-audit.git
cd security-headers-audit
```

## Usage

```bash
python3 audit_config.py tests/fixtures/nginx.conf
python3 audit_config.py /etc/nginx/sites-enabled/default --json
python3 audit_config.py Caddyfile --flavor caddy
```

Exit codes: `0` no findings, `1` findings, `2` unusable input.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
