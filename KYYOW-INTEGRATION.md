# Kyyow integration

This repository is the source authority for **loki** in the Kyyow platform. Its Kyyow boundary is machine-readable in [kyyow-integration.v1.json](kyyow-integration.v1.json).

The component is **private** and its native ports are not made public by this contract. Keycloak owns identity, OpenBao owns secret delivery, and Middleware remains the sole writer to Odoo. Grafana consumes the private read-only query path. No Loki-to-Superset route is implemented here; `superset_read_only` is a platform authorization restriction, not a declaration of connectivity.

This contract is source-complete but deliberately does not claim a live deployment. Production activation requires an immutable image/configuration digest, private-network verification, restore and rollback evidence, and a separately approved cutover.

## Source topology and limits

`codestra/config/loki.yaml` configures HTTP 3100, gRPC 9095, and memberlist 7946; `codestra/deploy/compose.candidate.yaml` exposes these privately. Both Alloy push and the Telemetry collector OTLP exporter feed Loki directly. S3-compatible storage is required. The HTTP tenant header must be derived by the authenticated private gateway; it is not trusted caller authority.

All listed ports are private or loopback. This correction does not authorize runtime activation.
