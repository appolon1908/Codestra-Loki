# Codestra Loki Corporate Features

## Mission

Loki is the central searchable log authority for Codestra-operated systems. It provides operational evidence for every managed business while remaining a read-oriented observability system rather than a business-state authority.

## Required sources

Collect structured logs through Alloy/OpenTelemetry from Linux/systemd, Docker, Caddy, Kong, Keycloak, Middleware, Odoo, n8n, PostgreSQL, Redis, VICIdial/Asterisk, OpenBao, workers and every managed application backend.

## Corporate business views

Every safe log stream must identify the owning business using the low-cardinality `codestra_business` field. Supported corporate business IDs are maintained in `codestra/enterprise-profile.v1.json` and cover Codestra, MoneyBee, Beyvra, Breero, LARIM-A, Transportation, Booked4Seasons, Social, Klyrow, Telnexa, Kyqra, Restaurant and Provisioning.

## Incident correlation

Logs must preserve `correlation_id` and `trace_id` as structured fields so Grafana can move from an error metric to a Tempo trace and then to the relevant logs. Deployment/version metadata must be present so operators can answer what changed before an incident.

## Privacy and security

PII, credentials, tokens and secret-bearing headers are redacted before ingestion. Tenant/customer identifiers may be stored as protected structured fields when operationally required, but never as high-cardinality Loki labels. Access to sensitive streams is role- and environment-scoped.

For Beyvra, logging is explicitly non-authoritative for balances, positions, executions or financial ledgers. Safe event metadata may be logged, but trade-signing credentials and raw order authorization material are forbidden.

## Expansion features

- environment-specific retention tiers;
- security/audit log streams;
- log-volume budgets and noisy-service detection;
- slow-query and dependency-error views;
- deployment/config-change correlation;
- recurring-error clustering;
- standardized error codes across Codestra services;
- tenant-safe incident search;
- Grafana links to matching Tempo traces and Prometheus metrics.

## Release rule

All Codestra-specific files stay outside `upstream/`. Merge does not activate ingestion or public exposure. `loki.codestra.media` remains an internal/private service endpoint even when DNS resolves externally.
