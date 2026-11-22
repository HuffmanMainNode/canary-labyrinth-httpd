# Definitions

- **Canary endpoint:** A configured decoy URL path that emits a minimal event when requested.
- **Endpoint ID:** Stable internal label for a configured route; raw request paths are not stored.
- **Event record:** Versioned JSON object appended to the local JSONL event log.
- **Source family:** Address family only (`ipv4` or `ipv6`); the source address itself is not recorded.
- **STIX 2.1 bundle:** A local export containing a sensor identity, network-traffic SCOs, and observed-data SDOs derived from validated event records.
- **Operational observation:** A request received by a running canary. CI fixture requests are tests, not external threat observations.
