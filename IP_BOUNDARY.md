# IP Boundaries

This is not legal advice. It is an engineering-oriented boundary definition intended to
support product packaging and procurement conversations.

## Vendor IP
- Cadence protocol schemas authored by AzzCraft Inc. (重庆艾之舟科技有限公司) (RunManifest/PipelineResult/JobEnvelope, etc.)
- Cadence Core CLI orchestration logic and evidence format implementation
- Official plugins and policy packs (unless explicitly published as OSS under a different license)
- UI generator/visual verification algorithms and runners
- Control Plane services (policy distribution, metadata index, dashboards)
- Forge components (gateway, dataset builder, adapters, training/serving scripts)

## Customer IP
- Customer repositories, source code, build artifacts
- Customer contracts (OpenAPI/Protobuf), fixtures, and semantics
- Screenshots/baselines and evidence artifacts produced from customer systems
- Fine-tuned adapters/weights trained on customer data (recommended: customer-exclusive ownership)

## Third-party IP
- Dependencies listed in go.mod / package.json / requirements.txt are subject to their own licenses.
