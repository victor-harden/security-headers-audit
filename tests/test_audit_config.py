import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
import audit_config

FIXTURES = BASE / "tests" / "fixtures"


class AuditTests(unittest.TestCase):
    def test_detect_nginx(self):
        text = (FIXTURES / "nginx.conf").read_text()
        self.assertEqual(audit_config.detect_flavor(text), "nginx")

    def test_detect_caddy(self):
        text = (FIXTURES / "caddy.conf").read_text()
        self.assertEqual(audit_config.detect_flavor(text), "caddy")

    def test_extract_headers(self):
        text = (FIXTURES / "nginx.conf").read_text()
        headers = audit_config.extract_headers(text)
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertIn("x-frame-options", headers)

    def test_missing_headers_reported(self):
        text = (FIXTURES / "nginx.conf").read_text()
        findings = audit_config.audit(audit_config.extract_headers(text))
        names = {f["header"] for f in findings}
        self.assertIn("strict-transport-security", names)
        self.assertNotIn("x-content-type-options", names)

    def test_caddy_is_clean(self):
        text = (FIXTURES / "caddy.conf").read_text()
        findings = audit_config.audit(audit_config.extract_headers(text))
        self.assertEqual(findings, [])

    def test_snippet_matches_flavor(self):
        snippet = audit_config.snippets(["referrer-policy"], "apache")
        self.assertTrue(snippet.startswith("Header always set"))

    def test_cli_exit_codes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit_config.main([str(FIXTURES / "nginx.conf")]), 1)
            self.assertEqual(audit_config.main([str(FIXTURES / "caddy.conf")]), 0)

    def test_cli_json(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = audit_config.main([str(FIXTURES / "nginx.conf"), "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["flavor"], "nginx")


if __name__ == "__main__":
    unittest.main()
