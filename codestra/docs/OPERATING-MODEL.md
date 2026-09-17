# Codestra Loki Operating Model

## Corporate role

Loki is the private, centralized log authority for Codestra-managed infrastructure and businesses. It stores and queries operational logs; it is not a customer-data warehouse, message archive, financial ledger, communications platform, authentication provider, or incident router.

The native Loki HTTP and gRPC ports remain private. Access is mediated by the approved Grafana and internal ingestion paths. A public DNS record does not authorize public access.

## Business isolation

Loki multi-tenancy is enabled. `X-Scope-OrgID` represents a Codestra business domain, never an end customer or person.

Approved tenants are:

- `platform`
- `codestra`
- `moneybee`
- `beyvra`
- `breero`
- `larim-a`
- `transportation`
- `booked4seasons`
- `social`
- `klyrow`
- `telnexa`
- `kyqra`
- `restaurant`
- `provisioning`

The ingress gateway must authenticate workloads, map the workload identity to exactly one approved tenant, overwrite any caller-supplied tenant header, and deny unknown tenants. Grafana access must map Keycloak teams and roles to an allowlisted business tenant set. Business operators receive only their business tenant. Corporate SRE and security access is separately approved and audited.

## Required labels

Every stream must have these bounded, low-cardinality labels:

- `codestra_business`
- `application`
- `service`
- `environment`
- `server`
- `region`
- `deployment`

Allowed optional labels include `level`, `component`, `event_family`, `protocol`, and a bounded `route_template`.

Never create labels from customer IDs, tenant/customer account IDs, user IDs, email addresses, phone numbers, message IDs, order IDs, request IDs, correlation IDs, trace IDs, raw URLs, query strings, SQL, container IDs, pod UIDs, or unbounded exception text. Those values may appear only as protected structured fields when operationally necessary.

## Redaction boundary

Alloy and OpenTelemetry must redact before forwarding. Loki is the final rejection and storage boundary, not the first redaction layer. Logs must never contain:

- authorization, cookie, or session headers;
- passwords, API keys, private keys, client secrets, root tokens, or database DSNs;
- raw payment, lender, broker, exchange, email, SMS, voice, identity, or customer payloads;
- full request/response bodies by default;
- financial signing material or authoritative ledger state.

Beyvra logs may contain safe aggregate execution state and redacted identifiers, but never broker/exchange credentials, signing material, raw order payloads, or trade-mutation authority.

## Retention and volume

The default retention is 90 days. Financial and provisioning tenants receive 180 days; the high-volume Kyqra tenant receives 30 days. Development/test streams and debug/trace streams have shorter retention in the static policy. Any increase requires privacy, legal, storage-cost, and recovery review.

Runtime overrides also bound ingestion rate, burst size, stream count, query parallelism, line size, label count, and query lookback. A business cannot consume unbounded corporate logging capacity.

## Storage and availability

The candidate topology uses three HA monolithic Loki instances, TSDB schema v13, memberlist rings, replication factor three, per-instance WAL volumes, and S3-compatible object storage for chunks, indexes, ruler state, delete requests, and retention markers.

Before staging, operators must prove:

1. immutable image digest and upstream provenance;
2. private `codestra-observability` networking with no host port publication;
3. distinct chunks and ruler buckets with encryption, versioning, lifecycle, and access logging;
4. OpenBao-issued or deployment-secret credentials with least privilege and rotation;
5. object-store restore/rebuild procedure;
6. compactor singleton/coordinator behavior and retention deletion evidence;
7. tenant-header overwrite and cross-business access-denial tests;
8. Grafana query and trace-correlation behavior;
9. Alloy redaction and cardinality tests;
10. capacity, ingestion-loss, WAL replay, and node-failure tests.

## Corporate service objectives

Initial engineering objectives, to be calibrated from staging evidence:

- ingestion acceptance availability: at least 99.9%;
- acknowledged-log durability: no known silent loss;
- recent-log query availability: at least 99.9%;
- p95 interactive query latency for bounded 15-minute queries: under 5 seconds;
- WAL replay and ring recovery tested for one-node loss;
- retention and delete processing delay visible in Prometheus/Grafana;
- zero public native Loki listeners;
- zero unapproved cross-business queries.

## Release rule

This repository owns Loki source overlays and validation only. Promotion is `feature/* -> development -> test -> staging -> production -> main`. CI success is necessary but does not authorize deployment. Staging evidence, security approval, immutable artifacts, backup/restore proof, and a documented rollback are required before production promotion.

## Monitoring platform contract (2026-09-16)

- Loki stores sanitised operational logs on private listeners for business-domain tenants; it has no content filter of its own. `codestra/redaction-contract.v1.json` names, for every forbidden content class (bearer tokens, OpenBao tokens, OAuth secrets, passwords, authorization headers, webhook signatures, private keys, database and SMTP credentials, JWT-shaped values), the reviewed Alloy and OpenTelemetry stages that redact or drop it before ingestion.
- Labels stay bounded by `limits_config`; `correlation_id`, `trace_id`, `span_id` and the OpenBao audit `type`/`operation`/`error` are structured metadata only, never indexed labels. Tenant IDs are business domains and caller-supplied tenant headers are never trusted.
- `codestra/rules/platform/openbao-audit-rules.yml` is the pinned copy of the OpenBao audit ruler rules (audit stream silent, root-token use, permission-denial surge, policy and control-plane mutation, initialisation and authentication failures) evaluated for the `platform` tenant; the ruler API stays disabled.
- Object-storage credentials are OpenBao secret references (`codestra/<environment>/observability/loki/object-storage`, identity `loki-runtime`) rendered by the OpenBao agent as the AWS shared credentials file; nothing is committed.
- `scripts/validate_codestra_loki_platform.py [--openbao-repo PATH]` fails closed on any drift of these guarantees.
