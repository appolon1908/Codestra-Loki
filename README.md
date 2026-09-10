# Codestra Loki

Repository authority for the private Codestra Loki configuration and its verified
upstream runtime image. Source changes do not deploy or activate production.

The canonical candidate is `codestra/deploy/compose.candidate.yaml`. It uses a
digest-pinned upstream image, publishes no host ports, and reads object-storage
credentials only from a mounted AWS shared-credentials file.

Run `python3 scripts/validate_repository_readiness.py` before proposing a release.
