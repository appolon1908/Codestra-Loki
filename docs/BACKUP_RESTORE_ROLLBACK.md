# Backup, restore, and rollback

Before a runtime change, capture the active image digest, signed configuration
artifact digest, expanded configuration checksum, object-store recovery evidence,
WAL and volume locations, and the previous approved bundle. Restore or rollback
one instance at a time and prove cluster health before continuing.

A rollback source is eligible only when its sensitive-value gate rejects both
`secret_access_key` and `access_key_secret` values. Do not restore a configuration
bundle whose source lacks either negative detector sample. The gate must scan
both JSON and YAML, including the signed Loki YAML configuration; checking
control JSON alone is insufficient.
The corporate exact-head gate installs the pinned validation requirements
before invoking that detector, so YAML coverage cannot silently disappear on a
clean runner.

This document does not execute a backup, restore, deployment, or rollback.
