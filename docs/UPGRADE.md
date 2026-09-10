# Upgrade policy

Resolve the upstream version tag to its exact source commit, multi-platform image
digest, and linux/amd64 child digest. Update the runtime lock and deterministic
configuration manifest in one reviewed change. Validate the exact image against
the configuration, then promote the same protected source through development,
test, staging, production, and main. Never rebuild on a production host.

The exact-head gate resolves the accepted index and requires its single
`linux/amd64` child manifest to match `linuxAmd64Manifest`. A mismatch blocks
release. Roll back this source change or update both identities from independently
verified registry evidence in a focused, reviewed lock-update change.
