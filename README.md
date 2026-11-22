# canary-labyrinth-httpd

Local-first HTTP canary daemon with privacy-conscious JSONL event records and STIX 2.1 export.

## Scope

The server exposes a fixed allowlist of decoy paths and returns static 404/405 responses. It does not serve files, authenticate users, accept credentials, proxy requests, execute commands, or contact external systems.

Configured endpoints:
- `/admin`
- `/admin/`
- `/wp-login.php`
- `/.env`
- `/backup.zip`
- `/api/internal/config`

Unknown paths return 404 and are not recorded.

## Run

Python 3.9+ is required. The HTTP server and JSONL event capture use only the Python standard library.

```sh
python3 canary_httpd.py serve --bind 127.0.0.1 --port 8080 --event-log ./canary-events.jsonl
```

Loopback is the default. A non-loopback IPv4 bind requires explicit `--allow-non-loopback`:

```sh
python3 canary_httpd.py serve --bind 192.0.2.10 --port 8080 --allow-non-loopback
```

The address above is documentation-only. Do not expose the service publicly without a separate deployment and threat review.

## Event records and privacy

Only requests to configured canary routes are recorded. Each JSONL event contains:
- UUID event identifier and UTC timestamp;
- configured endpoint identifier;
- HTTP method and response status;
- source address family only (IPv4/IPv6);
- local destination port.

The event log does not contain the source IP address, raw request path, query string, headers, cookies, authorization data, or request body. The server never reads request bodies. The event file is created with mode `0600`, appended without truncation, and capped at 64 MiB. Rotation is an explicit operator task.

Validate an event log:

```sh
python3 canary_httpd.py validate-log --event-log ./canary-events.jsonl
```

## STIX 2.1 export

STIX export is an optional local dependency:

```sh
python3 -m pip install -r requirements-stix.txt
python3 canary_httpd.py export-stix --event-log ./canary-events.jsonl --output ./canary-events.stix.json
```

The exporter emits a STIX 2.1 bundle containing a generic sensor identity, network-traffic observations, and observed-data objects. It does not create threat actors, indicators, malware objects, or attribution. Export refuses to overwrite an existing file.

## Tests

```sh
python3 -m pip install -r requirements-test.txt
python3 -m unittest discover -v
```

CI validates the shared contract, compatibility manifest, event schema, HTTP behavior, privacy boundaries, append-only event handling, and STIX 2.1 parsing.

See [SECURITY.md](SECURITY.md) and [CONTRACT.md](CONTRACT.md).
