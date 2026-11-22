# canary-labyrinth-httpd

Controlled HTTP canary daemon for local defensive observation.

## Responsibility

The daemon is intended to expose deliberately configured decoy HTTP endpoints, record requests delivered to those endpoints, and export structured observations in a validated STIX 2.1 representation.

## Safety boundary

- Observe only traffic delivered to explicitly configured local canary endpoints.
- No remote scanning, exploitation, credential harvesting, counter-attack, or retaliation.
- Do not collect more request data than required by the documented event schema.
- Distinguish test fixtures from real operational observations. Never label synthetic events as live telemetry.
- Bind addresses, ports, and exposure scope must be explicit and documented.

## Current status

**Lifecycle: planned.** No HTTP daemon, event store, STIX exporter, or test suite has yet been verified. See [COMPATIBILITY.json](COMPATIBILITY.json).
