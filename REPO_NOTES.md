# Safeguard LLM Public Documentation Repository

This repository is a public documentation-only publication copy for Safeguard LLM technical, operational, and regulatory materials.

Purpose:
- publish selected product, architecture, operations, and assurance documentation
- keep public technical documentation separate from the private engineering/runtime repository
- provide reviewers and stakeholders with implementation-oriented context without exposing application source code or local runtime material

Documentation layout:
- `Technical/` for architecture, implementation, API-contract, SBOM, local-development, and handoff materials
- `Regulatory/` for compliance, assurance, analyst, model-card, and threat-model materials
- root Markdown files for top-level product, operations, file-structure, model-card, ATLAS, EU AI Act, and threat-model references

Allowed contents:
- Markdown documentation
- documentation images and brand assets
- non-secret metadata needed to render or organize the documentation

Not allowed:
- application source code
- backend/runtime source code
- package manifests or lockfiles
- Dockerfiles, compose files, infrastructure templates, or deployment scripts
- build output
- local databases, logs, or generated runtime artifacts
- secrets, credentials, environment files, tokens, private keys, or private configuration

If implementation excerpts are needed for public review, describe them in prose or add sanitized pseudocode inside Markdown. Do not add source snapshots to this repository.
