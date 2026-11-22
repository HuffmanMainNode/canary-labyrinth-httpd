# Security Model

## Intended use

This prototype serves a small, fixed set of decoy HTTP paths for defensive canary observation. It binds to IPv4 loopback by default. Binding to a non-loopback address requires explicit `--allow-non-loopback`.

## Data minimization

The event record stores only:
- event UUID and UTC timestamp;
- configured endpoint identifier;
- HTTP method and response status;
- truncated source network prefix only (IPv4 /24 or IPv6 /64), never the full source address;
- local destination port.

The implementation does not record full source addresses, raw paths, query strings, request headers, cookies, authorization data, user-agent strings, or request bodies. Request bodies are not read. Unknown paths are not recorded. The HTTP handler suppresses default access/error logging to avoid accidental raw request metadata in stderr.

The JSONL event file is opened with no-follow semantics where supported, checked as a regular single-link file owned by the current user, and set to mode `0600`. Appends are serialized and fsynced. The file is append-only by application behavior, not tamper-proof against its owner. The log has a 64 MiB limit; rotation is operator-managed.

## Explicit boundaries

- No outbound scanning or network retrieval.
- No proxying, arbitrary file serving, directory listing, authentication, credential collection, or command execution.
- No request-body or cookie capture.
- No public bind by default.
- No external telemetry or hosted service.
- No threat-actor attribution, indicator creation, or malware claims from a canary hit alone.
- STIX export contains only the local recorded event observations and a generic sensor identity.

## Failure behavior

If event logging fails or reaches its configured size limit, the canary route returns HTTP 503 rather than silently reporting an unrecorded hit as successful. STIX export fails if the optional `stix2` dependency is unavailable or if an event record is invalid. Existing export files are never overwritten.

## Verification limits

- CI tests use local loopback requests and fixture events. They are not external threat observations.
- No public exposure, TLS termination, reverse proxy, load balancer, multi-process log coordination, or production deployment is claimed.
- STIX objects describe observed HTTP network traffic only; no actor, campaign, or intent is inferred.
- The prototype currently supports IPv4 bind addresses only.
