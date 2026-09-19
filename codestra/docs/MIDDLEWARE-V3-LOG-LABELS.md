# Middleware V3 log labels (Lane E preparation)

Status: **PREPARED_DISABLED**. `MIDDLEWARE_PREP_BASE=22d023a9c65b0789a0f7ee6c28548753521a9eff`,
`V3_FINAL_SHA=PENDING`. Loki stores sanitised operational logs; it has no content filter of its
own, so the collectors redact and this repository bounds what may become a label.

Flow: applications / exporters -> Codestra-Alloy (or the Codestra-Telemetry agent -> gateway)
-> Loki over mutual TLS with a server-side tenant.

## Contract (`codestra/contracts/middleware-v3-log-labels.v1.json`)

| Class | Names |
| --- | --- |
| Indexed labels allowed | `codestra_business`, `application`, `service`, `environment`, `server`, `region`, `deployment`, `log_source`, `level`, `detected_level` |
| Never labels | tenant/customer/account/user ids, `email`, `phone`, `command_id`, `operation_id`, `correlation_id`, `trace_id`, `span_id`, `request_id`, `incident_id`, `lease_id`, `fingerprint`, `secret_ref`, `reference_uri`, `deployment_sha`, paths/URLs, container/image/pod/process ids |
| Structured metadata | `correlation_id`, `trace_id`, `span_id`, `operation_id` (new), `deployment_sha` (new), `audit_type`, `audit_operation`, `audit_error` |

The six V3 common fields (`service_id`, `environment`, `deployment_sha`, `correlation_id`,
`operation_id`, `trace_id`) stay structured fields in the line; `service_id` and `environment`
are the only ones that also appear as labels (`service`, `environment`). Bounds come from
`codestra/config/loki.yaml`: structured metadata enabled, 15 label names per series, 128/2048
name/value length, 256KB lines, old samples rejected.

`codestra/redaction-contract.v1.json` was extended in step: `operation_id` and
`deployment_sha` join the structured-metadata allow-list and the never-indexed list, and the
SMTP, database and OpenBao-token classes now name the suffix and URL-credential stages added
in Codestra-Alloy and Codestra-Telemetry.

## Proof

`scripts/validate_middleware_v3_log_labels.py` (in
`validate-codestra-enterprise-profile.yml`) proves the contract is dark and pinned, mirrors the
redaction contract and `loki.yaml`, and that every LogQL rule under `codestra/rules` aggregates
and selects only on allowed labels. `tests/test_middleware_v3_log_labels.py` adds drift and
synthetic-rule cases.
