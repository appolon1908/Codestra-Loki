# Codestra Loki Authority

Principal repository: `ingtrader21-spec/Codestra-Loki`
Canonical service host: `loki.codestra.media`
Canonical DNS target: `37.27.128.39`

Use no alternate authoritative hostname.

## Ownership
Own Loki configuration, tenancy, ingestion limits, storage/schema, retention, compaction, query limits and upgrade runbooks. Do not own application log instrumentation, Grafana, Alloy, OpenTelemetry or Caddy.

## Exposure
Private/internal only. DNS may exist; Loki API ports must not be public.

## Integration
Upstream: Grafana Alloy and/or OpenTelemetry-approved log pipelines. Downstream: Grafana read-only queries and approved operational tooling.

## Branch policy
Persistent: `main`, `development`, `test`, `staging`, `production`. Temporary: `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, optional `release/*`, `rollback/*`. Promotion: work -> development -> test -> staging -> production -> main.
