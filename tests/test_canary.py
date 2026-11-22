import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

import jsonschema
from stix2 import parse

import canary_httpd


class CanaryHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp.name) / "events.jsonl"
        self.store = canary_httpd.EventStore(self.log_path)
        self.server = canary_httpd.CanaryHTTPServer(
            ("127.0.0.1", 0), canary_httpd.make_handler(self.store)
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.store.close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body)
        response = connection.getresponse()
        data = response.read()
        headers = dict(response.getheaders())
        connection.close()
        return response.status, data, headers

    def test_get_to_allowlisted_route_records_minimal_event(self):
        status, body, headers = self.request("GET", "/admin?secret=query-value")
        self.assertEqual(status, 404)
        self.assertEqual(body, b"Not Found\n")
        self.assertEqual(headers["Cache-Control"], "no-store")
        events = canary_httpd.load_events(self.log_path)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["endpoint_id"], "admin-console")
        self.assertEqual(event["method"], "GET")
        self.assertEqual(event["status_code"], 404)
        self.assertNotIn("source_address", event)
        self.assertEqual(event["source_prefix"], "127.0.0.0/24")
        self.assertNotIn("query", event)
        raw = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn("secret", raw)
        self.assertNotIn("query-value", raw)
        self.assertNotIn("127.0.0.1", raw)

    def test_unknown_path_is_not_recorded(self):
        status, _, _ = self.request("GET", "/not-a-canary")
        self.assertEqual(status, 404)
        self.assertFalse(self.log_path.read_text(encoding="utf-8"))

    def test_head_records_event_without_response_body(self):
        status, body, _ = self.request("HEAD", "/.env")
        self.assertEqual(status, 404)
        self.assertEqual(body, b"")
        self.assertEqual(canary_httpd.load_events(self.log_path)[0]["method"], "HEAD")

    def test_post_is_logged_without_body_capture(self):
        status, _, _ = self.request("POST", "/wp-login.php", body="password=not-recorded")
        self.assertEqual(status, 405)
        raw = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn("password", raw)
        self.assertNotIn("not-recorded", raw)
        self.assertEqual(canary_httpd.load_events(self.log_path)[0]["status_code"], 405)

    def test_events_append_without_truncating(self):
        self.request("GET", "/admin")
        self.request("GET", "/backup.zip")
        events = canary_httpd.load_events(self.log_path)
        self.assertEqual(len(events), 2)
        self.assertEqual([e["endpoint_id"] for e in events], ["admin-console", "backup-archive"])

    def test_event_log_permissions_are_private(self):
        mode = self.log_path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_event_schema_accepts_recorded_event(self):
        self.request("GET", "/admin")
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "event.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        event = canary_httpd.load_events(self.log_path)[0]
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(event)

    def test_stix_export_is_parseable_stix_21_without_attribution(self):
        self.request("GET", "/admin")
        events = canary_httpd.load_events(self.log_path)
        serialized = canary_httpd.build_stix_bundle(events)
        bundle = parse(serialized, version="2.1")
        self.assertEqual(bundle.type, "bundle")
        types = [obj.type for obj in bundle.objects]
        self.assertIn("identity", types)
        self.assertIn("ipv4-addr", types)
        self.assertIn("network-traffic", types)
        self.assertIn("observed-data", types)
        self.assertIn("note", types)
        self.assertNotIn("threat-actor", types)
        self.assertNotIn("indicator", types)

    def test_stix_export_empty_log_is_valid_bundle(self):
        serialized = canary_httpd.build_stix_bundle([])
        bundle = parse(serialized, version="2.1")
        self.assertEqual(bundle.type, "bundle")
        self.assertEqual(len(bundle.objects), 1)

    def test_export_refuses_to_overwrite_existing_file(self):
        self.request("GET", "/admin")
        output = Path(self.temp.name) / "existing.stix.json"
        output.write_text("keep", encoding="utf-8")
        with self.assertRaises(canary_httpd.CanaryError):
            canary_httpd.write_new_private_file(output, "{}")
        self.assertEqual(output.read_text(encoding="utf-8"), "keep")

    def test_bind_defaults_to_loopback_and_requires_opt_in(self):
        self.assertEqual(canary_httpd.validate_bind_address("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(canary_httpd.CanaryError):
            canary_httpd.validate_bind_address("0.0.0.0")
        self.assertEqual(
            canary_httpd.validate_bind_address("0.0.0.0", allow_non_loopback=True),
            "0.0.0.0",
        )

    def test_ipv6_bind_is_not_claimed(self):
        with self.assertRaises(canary_httpd.CanaryError):
            canary_httpd.validate_bind_address("::1")

    def test_duplicate_event_keys_are_rejected(self):
        self.log_path.write_text('{"schema_version":"1.0","schema_version":"1.0"}\n', encoding="utf-8")
        with self.assertRaises(canary_httpd.CanaryError):
            canary_httpd.load_events(self.log_path)

    def test_event_log_symlink_is_rejected(self):
        target = Path(self.temp.name) / "target.jsonl"
        target.write_text("", encoding="utf-8")
        link = Path(self.temp.name) / "link.jsonl"
        link.symlink_to(target)
        with self.assertRaises(canary_httpd.CanaryError):
            canary_httpd.load_events(link)

    def test_event_rejects_extra_fields(self):
        event = {
            "schema_version": "1.0",
            "event_id": "5a8d9cb4-fb4f-4d1f-8e2b-2c0e1c2a7d34",
            "timestamp": "2026-01-01T00:00:00Z",
            "endpoint_id": "admin-console",
            "method": "GET",
            "status_code": 404,
            "source_family": "ipv4",
            "destination_port": 8080,
            "raw_path": "/admin",
        }
        with self.assertRaises(canary_httpd.CanaryError):
            canary_httpd.validate_event(event)


if __name__ == "__main__":
    unittest.main()
