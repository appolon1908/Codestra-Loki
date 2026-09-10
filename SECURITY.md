# Security policy

Report vulnerabilities privately to the repository owner. Do not file credentials,
tokens, private keys, or incident-sensitive logs in public issues.

Runtime secrets must be mounted as files. The repository must not contain secret
values, public Loki native ports, insecure object-store transport, or mutable image
references. Production activation requires protected-lineage review outside this
source-readiness change.

The JSON/YAML credential detector covers both common object-store secret spellings:
`secret_access_key` and `access_key_secret`. Normalization must retain negative
samples for both token orders so an OSS/Alibaba-style alias cannot bypass the
repository gate. The scan includes the signed `codestra/config/loki.yaml`
bundle, Compose candidates, and all Codestra control JSON.
