# Codestra Loki Production Server and Native API Contract

## Authority

- Repository: `appolon1908-hue/Codestra-Loki`
- Component role: central business-isolated log authority
- Canonical hostname: `loki.codestra.media`
- Central production host: `37.27.128.39`
- Core application host `65.109.65.169`: remote collection source only; Loki is not installed there
- Status: `SOURCE_CONTRACT_PREPARED_NOT_DEPLOYED`

This repository owns Loki source, production configuration, native API policy, image construction, tests, backup/recovery procedures, release evidence, and rollback instructions. It must not invent a duplicate business API or absorb Alloy, OpenTelemetry, Grafana, Prometheus, or application authority.

## Native API surface

| Method | Path | Purpose | Production boundary |
|---|---|---|---|
| `GET` | `/ready` | readiness | private/read-only |
| `GET` | `/metrics` | internal operational metrics | private Prometheus scrape only |
| `POST` | `/loki/api/v1/push` | log ingestion | private mTLS; deployment-assigned tenant |
| `GET` | `/loki/api/v1/query_range` | bounded log query | authenticated; business-scoped |
| `GET` | `/loki/api/v1/labels` | bounded label discovery | authenticated; business-scoped |

Expected protected responses may include `401`, `403`, `405`, `415`, `422`, or rate-limit responses. Unexpected `404` and `5xx` responses are release blockers.

## Authentication, tenancy, and privacy

- Native ingestion and administration ports are never Internet-published.
- The approved edge may expose operator query access only after authentication.
- mTLS and CA verification are mandatory for ingestion. The ingress must require a client certificate, reject certificate-less clients, and reject untrusted, expired, or revoked client certificates.
- `codestra_business` and the Loki tenant are assigned by deployment-controlled identity. Caller-supplied tenant headers, including `X-Scope-OrgID`, and caller-supplied business attributes are overwritten with the assigned value or rejected before ingestion.
- A positive mTLS request alone is not tenancy proof: certification must attempt an authenticated cross-business tenant override and prove that the event is written only to the deployment-assigned tenant or is rejected.
- Cross-business queries fail closed.
- Customer IDs, tenant IDs, emails, phones, request IDs, trace IDs, message IDs, order IDs, payment IDs, and transaction IDs are prohibited as stream labels.
- Secrets, credentials, cookies, raw bodies, database statements, signing material, and private keys are redacted or rejected before storage.

## Source and artifact gates

Production installation on `37.27.128.39` requires all of the following:

```text
PROTECTED_PRODUCTION_SHA=PASS
CONFIG_CHECKSUM=PASS
IMMUTABLE_IMAGE_DIGEST=PASS
IMAGE_SIGNATURE=PASS
SBOM=PASS
PROVENANCE=PASS
SECRET_SCAN=PASS
VULNERABILITY_GATE=PASS
BACKUP_RECOVERY=PASS
ROLLBACK_MANIFEST=PASS
```

No `latest` tag, placeholder digest, unreviewed server edit, force push, admin merge bypass, or local-only artifact is permitted.

## Runtime certification

The server mission must prove:

```text
GET_/ready=PASS
GET_/metrics=PASS
POST_/loki/api/v1/push_ROUTE_EXISTS=PASS
GET_/loki/api/v1/query_range_ROUTE_EXISTS=PASS
GET_/loki/api/v1/labels_ROUTE_EXISTS=PASS
UNAUTHENTICATED_QUERY_DENIED=PASS
WRONG_BUSINESS_QUERY_DENIED=PASS
MTLS_INGESTION=PASS
NO_CLIENT_CERT_INGESTION_DENIED=PASS
UNTRUSTED_CLIENT_CERT_INGESTION_DENIED=PASS
EXPIRED_OR_REVOKED_CLIENT_CERT_DENIED=PASS
CALLER_TENANT_OVERRIDE_DENIED=PASS
DEPLOYMENT_ASSIGNED_INGESTION_TENANT=PASS
TLS_VERIFY=PASS
UNEXPECTED_404=0
UNEXPECTED_5XX=0
SOURCE_RUNTIME_DRIFT=0
```

Use only synthetic, clearly marked staging/canary log fixtures. Do not ingest customer payloads merely to prove routing. The tenant-override fixture must be queried from both the assigned and attempted foreign tenant to prove no cross-business placement occurred.

## Recovery and rollback

Before activation, validate object-store recovery, configuration restore, tenant-index integrity, retention behavior, and rollback to the previous exact image digest and configuration checksum. Preserve the old healthy runtime until the new candidate passes health, query, ingestion, authorization, storage, and rollback checks.

## Repository-first remediation

When a server defect is found, stop the affected wave, preserve the old healthy Loki workload, fix the owning source/configuration here, add a regression test, commit and push, obtain exact-head CI and review, merge normally, build/sign a new immutable artifact, update the BOM, and only then retry.

## Safety

This document does not deploy Loki or activate ingestion. SSH configuration changes, business writes, communications delivery, provider actions, financial mutation, and trading authority are outside this repository and remain disabled.