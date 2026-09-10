# Repository profile

- Authority: `appolon1908-hue/Codestra-Loki`
- Component: `loki`
- Artifact model: verified upstream image plus signed configuration bundle
- Canonical runtime: `codestra/deploy/compose.candidate.yaml`
- Native exposure: private container network only
- Runtime credentials: mounted files only
- Production activation from source: disabled

The configuration release workflow accepts only an exact protected production
head and delegates signing, SBOM, vulnerability scanning, and provenance to the
canonical Telemetry reusable workflow.
