# Secure Generative AI Workload on AWS

Reference implementation of a guarded LLM inference service: multi-account AWS,
Bedrock with retrieval augmentation, tenant-isolated, guardrail-enforced.

## Layout

```
infrastructure/   19 CloudFormation templates across 6 accounts
sql/              Aurora bootstrap — schema, IAM roles, pgvector
src/              Lambda source (partial — see Status)
ci/               GitHub Actions workflow and Dependabot config
docs/             Architecture spec, MAESTRO threat model, AppSec audit
```

`infrastructure/README.md` is the operational document: stack order,
cross-account deploy sequence, and the design notes for each layer. Read it
before deploying anything.

## Quick start

```bash
# Validate everything
pip install cfn-lint checkov
cfn-lint infrastructure/*.yaml
checkov -d infrastructure/ --framework cloudformation
```

Deployment is cross-account and ordered. The short version:

1. **Management** — Organizations all-features, register delegated admins
2. **Log Archive** → `20`, **Backup** → `21`, **Shared Services** → `22` (twice)
3. **Each target account** → `22b`
4. **Security** → `24`
5. **Workload** → `00`–`08`, `10`, `11`
6. **us-east-1** → `09`
7. **Management** → `23` (SCPs last — they block earlier steps)
8. **Backup** → re-run `21` with `VaultLockEnabled=true`

Full sequence with parameter dependencies in `infrastructure/README.md`.

## What this implements

**Network isolation is structural.** The adapter has no `0.0.0.0/0` route. Every
AWS service call resolves to a VPC endpoint, and `aws:SourceVpce` makes that path
a condition of authorization rather than a convention.

**Guardrails are non-optional.** Identity policy, SCP, and endpoint policy must
all be misconfigured before a model can be invoked unguarded. The guardrail is
pinned to a numeric version, so weakening it requires a deployment.

**The audit trail sits outside the blast radius.** No workload-account principal
can reach the audit bucket, the backup vault, or their keys. Model invocation
logging closes the content gap CloudTrail structurally cannot cover.

**Identity is scoped on three axes.** A leaked credential must also be presented
from the expected endpoint, against an enumerated resource, within the
organization. At the API tier only access tokens are accepted, and the two caller
paths carry different validation profiles by necessity: human tokens are bound to
the API via an RFC 8707 resource indicator and validated on `aud`; machine tokens
cannot carry an audience under `client_credentials` and are validated on
`client_id`, with the *absence* of `aud` asserted. Both are checked against a
revocation denylist that closes the gap offline verification otherwise leaves
open.

## Status

| | |
|---|---|
| CloudFormation | 19 templates, `cfn-lint` clean, **not deployed** |
| Lambda source | Authorizer + 3 adapter modules. **Missing:** Express handler, egress proxy, secrets rotation, lifecycle, pre-token-generation trigger |
| SQL bootstrap | Written, not run |
| Entitlement seed | Not written — no client can authenticate without a `clientId → defaultTenant` row |

`cfn-lint` validates schema and intrinsic functions, not runtime behaviour. IAM
condition evaluation, endpoint policy enforcement, firewall rule matching, and
the Bedrock resource types need a real deployment to confirm.

## Known gaps

Carried from the threat model and audit in `docs/`, unresolved in this build:

- **Corpus ingestion has no content validation.** The KB source bucket restricts
  *writers*; nothing validates what they write. Anything landing there is
  chunked, embedded, and served to the model as grounding context.
- **Output handling is unspecified** because the downstream consumer is
  unstated. Rendering, storage, and pass-through each need a different control.
- **`bedrock-mantle` guardrail enforcement is unconfirmed.** The
  `bedrock:GuardrailIdentifier` condition covers `InvokeModel` and `Converse` on
  `bedrock-runtime`; whether it reaches the OpenAI-compatible surface is not
  established. Treat that path as external inference until it is.
- **No adversarial regression corpus.** Guardrail quality is inferred from
  intervention rate, which moves with attack volume rather than control
  effectiveness.
- **Bearer tokens are not sender-constrained.** Possession is sufficient, which
  matters most on the machine path where a credential leaked from a third
  party's environment is replayable from anywhere. Cognito does not support
  DPoP, so closing this needs mTLS at CloudFront or a different IdP — a design
  decision rather than unfinished work.

## Documents

| File | What it is |
|---|---|
| `docs/aws-secure-genai-workload-architecture.md` | The specification these templates implement |
| `docs/maestro-assessment-aws-genai-workload.md` | MAESTRO v2.0 threat model of the specification |
| `docs/appsec-audit.md` | Application-layer audit, OWASP LLM Top 10 coverage |
| `docs/request-flow-detailed.md` | One request end to end — every step, where it is implemented, and what happens when it fails |
| `docs/authorization-flow-detailed.md` | Token acquisition and validation for both caller paths, and where they diverge |
| `docs/governance.md` | Agent-governance and control-plane assessment: identity, credentials, authorization, lifecycle, revocation |
| `docs/control-mapping-aws.md` | AICM / FAIR-CAM / ISO 42001 controls mapped to the templates and source files that implement them |
