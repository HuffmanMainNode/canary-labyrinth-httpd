#!/usr/bin/env python3
"""Local-first HTTP canary server with minimal append-only event records."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urlsplit


SCHEMA_VERSION = "1.0"
MAX_EVENT_LOG_BYTES = 64 * 1024 * 1024
MAX_REQUEST_TARGET_LENGTH = 2048
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
ROUTES = {
    "/admin": "admin-console",
    "/admin/": "admin-console",
    "/wp-login.php": "legacy-login",
    "/.env": "environment-config",
    "/backup.zip": "backup-archive",
    "/api/internal/config": "internal-config",
}
RESPONSE_BODY = b"Not Found\n"
METHOD_BODY = b"Method Not Allowed\n"


class CanaryError(ValueError):
    """Raised for invalid canary configuration or event data."""


class EventStoreError(OSError):
    """Raised when an event cannot be safely appended."""


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _unique_object(pairs: List[Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanaryError("duplicate JSON key: " + key)
        result[key] = value
    return result


def validate_event(event: Any) -> Dict[str, Any]:
    required = {
        "schema_version",
        "event_id",
        "timestamp",
        "endpoint_id",
        "method",
        "status_code",
        "source_family",
        "source_prefix",
        "destination_port",
    }
    if not isinstance(event, dict) or set(event) != required:
        raise CanaryError("event must contain exactly the versioned event fields")
    if event["schema_version"] != SCHEMA_VERSION:
        raise CanaryError("unsupported event schema_version")
    try:
        uuid.UUID(event["event_id"])
    except (ValueError, TypeError, AttributeError):
        raise CanaryError("event_id must be a UUID")
    if not isinstance(event["timestamp"], str):
        raise CanaryError("timestamp must be a string")
    try:
        parsed_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        raise CanaryError("timestamp must be an ISO 8601 date-time")
    if parsed_time.tzinfo is None or parsed_time.utcoffset().total_seconds() != 0:
        raise CanaryError("timestamp must be UTC and include a timezone")
    if not isinstance(event["endpoint_id"], str) or event["endpoint_id"] not in set(ROUTES.values()):
        raise CanaryError("endpoint_id is not in the configured route allowlist")
    if not isinstance(event["method"], str) or event["method"] not in ALLOWED_METHODS:
        raise CanaryError("method is not supported by the event schema")
    if isinstance(event["status_code"], bool) or event["status_code"] not in (404, 405):
        raise CanaryError("status_code must be 404 or 405")
    if event["source_family"] not in ("ipv4", "ipv6"):
        raise CanaryError("source_family must be ipv4 or ipv6")
    if not isinstance(event["source_prefix"], str):
        raise CanaryError("source_prefix must be a network prefix string")
    try:
        source_network = ipaddress.ip_network(event["source_prefix"], strict=True)
    except ValueError:
        raise CanaryError("source_prefix must be a canonical network prefix")
    expected_version = 4 if event["source_family"] == "ipv4" else 6
    expected_prefix_length = 24 if expected_version == 4 else 64
    if source_network.version != expected_version or source_network.prefixlen != expected_prefix_length:
        raise CanaryError("source_prefix must be IPv4 /24 or IPv6 /64 matching source_family")
    if str(source_network) != event["source_prefix"]:
        raise CanaryError("source_prefix must use canonical network notation")
    port = event["destination_port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise CanaryError("destination_port must be an integer from 1 to 65535")
    return event


class EventStore:
    """Append-only JSONL writer with restrictive file permissions."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(str(self.path), flags, 0o600)
        except OSError as exc:
            raise EventStoreError("cannot safely open event log: " + str(exc))
        info = os.fstat(self.fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(self.fd)
            raise EventStoreError("event log must be a regular file with one link")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            os.close(self.fd)
            raise EventStoreError("event log must be owned by the current user")
        os.fchmod(self.fd, 0o600)
        self.lock = threading.Lock()
        self.closed = False

    def append(self, event: Dict[str, Any]) -> None:
        validate_event(event)
        payload = (
            json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
            + "\n"
        ).encode("utf-8")
        with self.lock:
            if self.closed:
                raise EventStoreError("event log is closed")
            size = os.fstat(self.fd).st_size
            if size + len(payload) > MAX_EVENT_LOG_BYTES:
                raise EventStoreError("event log size limit reached; operator rotation is required")
            view = memoryview(payload)
            while view:
                written = os.write(self.fd, view)
                if written <= 0:
                    raise EventStoreError("short write while appending event")
                view = view[written:]
            os.fsync(self.fd)

    def close(self) -> None:
        with self.lock:
            if not self.closed:
                os.close(self.fd)
                self.closed = True


def load_events(path: Path) -> List[Dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise CanaryError("cannot safely read event log: " + str(exc))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise CanaryError("event log must be a regular file with one link")
        if info.st_size > MAX_EVENT_LOG_BYTES:
            raise CanaryError("event log exceeds the configured 64 MiB limit")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
            events = []
            seen_ids = set()
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    raise CanaryError("blank line in event log at line " + str(line_number))
                try:
                    event = json.loads(line, object_pairs_hook=_unique_object)
                except (json.JSONDecodeError, UnicodeError) as exc:
                    raise CanaryError("invalid JSON at event log line " + str(line_number) + ": " + str(exc))
                validate_event(event)
                if event["event_id"] in seen_ids:
                    raise CanaryError("duplicate event_id at line " + str(line_number))
                seen_ids.add(event["event_id"])
                events.append(event)
            return events
    finally:
        os.close(fd)


def build_stix_bundle(events: Iterable[Dict[str, Any]]) -> str:
    try:
        from stix2 import Bundle, Identity, IPv4Address, IPv6Address, NetworkTraffic, ObservedData, parse
    except ImportError as exc:
        raise CanaryError("STIX export requires the optional stix2 dependency; install requirements-stix.txt") from exc

    identity = Identity(
        name="Canary Labyrinth Sensor",
        identity_class="unknown",
        description="Local HTTP canary sensor. Observations do not assert threat-actor identity or attribution.",
    )
    objects = [identity]
    for raw_event in events:
        event = validate_event(raw_event)
        observed_at = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        source_object = (
            IPv4Address(value=event["source_prefix"])
            if event["source_family"] == "ipv4"
            else IPv6Address(value=event["source_prefix"])
        )
        traffic = NetworkTraffic(
            src_ref=source_object.id,
            protocols=[event["source_family"], "tcp", "http"],
            dst_port=event["destination_port"],
        )
        description = (
            "Canary endpoint "
            + event["endpoint_id"]
            + " received "
            + event["method"]
            + " and returned HTTP "
            + str(event["status_code"])
            + ". Local event ID: "
            + event["event_id"]
            + ". No source address, request body, cookie, credential, or actor attribution is included."
        )
        observed = ObservedData(
            first_observed=observed_at,
            last_observed=observed_at,
            number_observed=1,
            object_refs=[traffic.id],
            created_by_ref=identity.id,
            description=description,
        )
        objects.extend([source_object, traffic, observed])

    bundle = Bundle(objects=objects)
    serialized = bundle.serialize(pretty=True)
    # Parse the generated bundle again so export never silently emits invalid STIX.
    parse(serialized, version="2.1")
    return serialized


def write_new_private_file(path: Path, content: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise CanaryError("output must be a new file and must not be a symlink: " + str(exc))
    try:
        view = memoryview(content.encode("utf-8"))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise CanaryError("short write while creating STIX export")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o600)
    except Exception:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    else:
        os.close(fd)


def validate_bind_address(bind: str, allow_non_loopback: bool = False) -> str:
    try:
        address = ipaddress.ip_address(bind)
    except ValueError:
        raise CanaryError("--bind must be an IPv4 address literal")
    if not isinstance(address, ipaddress.IPv4Address):
        raise CanaryError("this prototype currently supports IPv4 bind addresses only")
    if not address.is_loopback and not allow_non_loopback:
        raise CanaryError("non-loopback binding requires explicit --allow-non-loopback")
    return str(address)


def make_handler(store: EventStore):
    class CanaryHandler(BaseHTTPRequestHandler):
        server_version = "CanaryLabyrinth"
        sys_version = ""

        def log_message(self, format_string: str, *args: Any) -> None:
            # Never write raw paths, headers, or client addresses to stderr.
            return

        def log_error(self, format_string: str, *args: Any) -> None:
            return

        def log_request(self, code: Any = "-", size: Any = "-") -> None:
            return

        def _respond(self, status: int, body: bytes, include_body: bool) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Connection", "close")
            if status == 405:
                self.send_header("Allow", "GET, HEAD")
            self.end_headers()
            if include_body:
                self.wfile.write(body)
            self.close_connection = True

        def _handle_canary(self) -> None:
            if len(self.path) > MAX_REQUEST_TARGET_LENGTH:
                self._respond(414, b"URI Too Long\n", self.command != "HEAD")
                return
            try:
                path = urlsplit(self.path).path
            except ValueError:
                self._respond(400, b"Bad Request\n", self.command != "HEAD")
                return
            endpoint_id = ROUTES.get(path)
            if endpoint_id is None:
                self._respond(404, RESPONSE_BODY, self.command != "HEAD")
                return

            method = self.command.upper()
            status = 404 if method in ("GET", "HEAD") else 405
            try:
                source = ipaddress.ip_address(self.client_address[0])
                event = {
                    "schema_version": SCHEMA_VERSION,
                    "event_id": str(uuid.uuid4()),
                    "timestamp": utc_timestamp(),
                    "endpoint_id": endpoint_id,
                    "method": method,
                    "status_code": status,
                    "source_family": "ipv4" if source.version == 4 else "ipv6",
                    "source_prefix": str(ipaddress.ip_network(
                        str(source) + ("/24" if source.version == 4 else "/64"),
                        strict=False,
                    )),
                    "destination_port": int(self.server.server_port),
                }
                store.append(event)
            except (CanaryError, EventStoreError, OSError):
                self._respond(503, b"Service Unavailable\n", self.command != "HEAD")
                return

            body = RESPONSE_BODY if status == 404 else METHOD_BODY
            self._respond(status, body, method != "HEAD")

        def do_GET(self) -> None:
            self._handle_canary()

        def do_HEAD(self) -> None:
            self._handle_canary()

        def do_POST(self) -> None:
            self._handle_canary()

        def do_PUT(self) -> None:
            self._handle_canary()

        def do_DELETE(self) -> None:
            self._handle_canary()

        def do_PATCH(self) -> None:
            self._handle_canary()

        def do_OPTIONS(self) -> None:
            self._handle_canary()

    return CanaryHandler


class CanaryHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(bind: str, port: int, event_log: Path, allow_non_loopback: bool = False) -> int:
    bind = validate_bind_address(bind, allow_non_loopback)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise CanaryError("port must be an integer from 1 to 65535")
    store = EventStore(event_log)
    try:
        server = CanaryHTTPServer((bind, port), make_handler(store))
    except Exception:
        store.close()
        raise
    print("Canary Labyrinth listening on " + bind + ":" + str(server.server_port))
    print("Event log: " + str(Path(event_log)))
    print("Only configured canary routes are recorded; request bodies and headers are not captured.")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping canary server.")
    finally:
        server.server_close()
        store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="canary-httpd", description="Local-first HTTP canary daemon and STIX 2.1 exporter.")
    commands = parser.add_subparsers(dest="command", required=True)

    serve_command = commands.add_parser("serve", help="serve allowlisted canary endpoints")
    serve_command.add_argument("--bind", default="127.0.0.1")
    serve_command.add_argument("--port", type=int, default=8080)
    serve_command.add_argument("--event-log", type=Path, default=Path("canary-events.jsonl"))
    serve_command.add_argument("--allow-non-loopback", action="store_true")

    validate_command = commands.add_parser("validate-log", help="validate an existing JSONL event log")
    validate_command.add_argument("--event-log", type=Path, default=Path("canary-events.jsonl"))

    export_command = commands.add_parser("export-stix", help="export recorded events as a STIX 2.1 bundle")
    export_command.add_argument("--event-log", type=Path, default=Path("canary-events.jsonl"))
    export_command.add_argument("--output", type=Path, default=Path("canary-events.stix.json"))
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "serve":
            return serve(args.bind, args.port, args.event_log, args.allow_non_loopback)
        if args.command == "validate-log":
            events = load_events(args.event_log)
            print(json.dumps({"status": "valid", "event_count": len(events)}, sort_keys=True))
            return 0
        if args.command == "export-stix":
            events = load_events(args.event_log)
            bundle = build_stix_bundle(events)
            write_new_private_file(args.output, bundle + "\n")
            print(json.dumps({"status": "exported", "event_count": len(events), "output": str(args.output)}, sort_keys=True))
            return 0
        raise CanaryError("unknown command")
    except (CanaryError, EventStoreError, OSError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
