# Prototype Release Record

**Release stage:** Prototype candidate documentation complete  
**Lifecycle:** Prototype  
**Verified source commit:** `cbc27d34ae251e9104f7df42d041c576298aba7f`  
**Evidence ceiling:** TIER-2  
**GitHub Release/tag:** Not published by this record

## Purpose

A local-first HTTP canary daemon with fixed decoy endpoints, privacy-minimized JSONL event records, and optional STIX 2.1 export.

## Included capabilities

- Six fixed decoy paths with static 404/405 responses.
- Loopback IPv4 bind by default; non-loopback bind requires explicit opt-in.
- Unknown paths are not recorded.
- Event records include only event ID, UTC time, endpoint ID, method, status, destination port, and truncated source prefix.
- Full source IP, raw path, query, headers, cookies, credentials, and request body are not stored; request bodies are not read.
- Append-only event writes, mode 0600, 64 MiB cap, explicit operator-managed rotation.
- Optional STIX 2.1 bundle export without invented threat attribution.

## Verify locally

```sh
python3 canary_httpd.py serve --bind 127.0.0.1 --port 8080 --event-log ./canary-events.jsonl
python3 canary_httpd.py validate-log --event-log ./canary-events.jsonl
python3 -m pip install -r requirements-test.txt
python3 -m unittest discover -v
```

For STIX export, install the optional dependency listed in `requirements-stix.txt` and use a new output path.

## Evidence

The recorded CI run passed 15 deterministic tests, HTTP/privacy/schema checks, and STIX 2.1 parsing on Ubuntu 24.04 with Python 3.9 through 3.13: [workflow run](https://github.com/HuffmanMainNode/canary-labyrinth-httpd/actions/runs/44979166847).

## Explicit limitations

The service is not a production honeypot or public monitoring platform. Public exposure, non-loopback deployment, TLS/reverse proxy, multi-process log coordination, and external operational observations are not verified. Event logs are append-only by application behavior, not tamper-proof against their owner. Only Ubuntu 24.04 CI is verified.

## Next milestone

Perform a dedicated deployment and privacy review before any non-loopback exposure; add TLS/reverse-proxy guidance, multi-process log coordination tests, and explicit retention/rotation operations.

## Ecosystem context

Related public components:
- [cas-xdp-supervisor](https://github.com/HuffmanMainNode/cas-xdp-supervisor)
- [cas-threat-index](https://github.com/HuffmanMainNode/cas-threat-index)
- [posix-containment-kit](https://github.com/HuffmanMainNode/posix-containment-kit)
- [xdp-ingress-primitives](https://github.com/HuffmanMainNode/xdp-ingress-primitives)

This daemon is an independently usable prototype and is not represented as integrated with the other components.
