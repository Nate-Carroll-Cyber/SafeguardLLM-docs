# Control Mapping — AWS Target-State Architecture

**Purpose.** Bridges the control vocabulary used in the MAESTRO threat model and
the governance assessment (CSA AICM v1.1, FAIR-CAM function classes, ISO/IEC
42001:2023) to the CloudFormation templates and source files that implement them.

**Reading the status column.**

| Status | Meaning |
|---|---|
| **Implemented** | A template or source file implements it; `cfn-lint` clean |
| **Partial** | Implemented in one layer or context but not where the control needs it |
| **Infrastructure only** | Template exists; the code it invokes is unwritten |
| **Absent** | No implementation |
| **N/A** | The surface the control governs does not exist in this architecture |

**Caveat that governs the whole document.** Nothing has been deployed.
`cfn-lint` validates schema and intrinsic functions, not runtime behaviour. A
control marked Implemented is evidenced *as designed*, not as operating. IAM
condition evaluation, endpoint policy enforcement, and firewall rule matching are
unverified.

---

## 1. AICM v1.1 — control register

### Identity and Access Management

| Control | AWS implementation | Where | Status |
|---|---|---|---|
| `IAM-07` Access Revocation | `origin_jti` / `sub` denylist, consistent read, checked before authorization, fails closed | `04-data` `RevocationTable`; `src/authorizer/index.mjs` | **Infrastructure only** — read path written, no writer |
| `IAM-09` Segregation of Privileged Roles | 13 runtime + 4 delivery roles, enumerated actions, no wildcard resource ARNs; `DeploymentBoundary` denies self-elevation | `03-identity`, `22-pipeline`, `22b-deployment-roles` | **Implemented** |
| `IAM-14` Strong Authentication | Cognito user pool; REQUEST authorizer verifying signature against pinned JWKS, `iss`, `exp`, `nbf`, `token_use`, `client_id`, scope | `05-cognito`, `07-compute`, `08-api`, `src/authorizer/index.mjs` | **Implemented** |
| `IAM-15` Secrets Management | Secrets Manager under `cmk/secrets`; no secret in any Lambda environment variable; RDS Proxy `IAMAuth: REQUIRED` means no DB password exists | `00-kms`, `04-data`, `07-compute` | **Implemented** |
| `IAM-16` Authorization | Scope per method with deny-by-default; server-side tenant entitlement; `dynamodb:LeadingKeys`; pgvector RLS with `FORCE`; retrieval metadata filter | `03-identity`, `08-api`, `sql/01-bootstrap.sql`, `src/adapter/*` | **Implemented** |
| `IAM-18` Special Authorization | — | — | **Absent** — no out-of-band approval for guardrail change, corpus promotion, or entitlement write |

**Note.** `IAM-07` is the control the pilot could not implement at all against a
shared static token. Here the read path exists and the write path does not, so
the denylist is a table nothing populates. That is a narrower gap than the
pilot's but it is still a gap: a control that cannot be triggered is not a
control.

### AI Security

| Control | AWS implementation | Where | Status |
|---|---|---|---|
| `AIS-08` Input Validation | API Gateway request model with `additionalProperties: false`; required `X-Request-ID`; body ceiling in the adapter; retrieved-context and assembled-context caps | `08-api`, `src/adapter/security.mjs`, `src/adapter/inference.mjs` | **Implemented** |
| `AIS-09` Output Validation | Guardrail output filters and contextual grounding; schema-constrained ledger writes | `06-bedrock`, `src/adapter/data.mjs` | **Partial** — response handling before display is unspecified because the downstream consumer is unstated |
| `AIS-10` API Security | Resource policy pinned to the CloudFront distribution; regional WAF with origin-verify and per-token rate limiting; stage throttle | `08-api`, `09-edge` | **Implemented** |
| `AIS-11` Agent Authorization | `KBRetrieveRole` assumed with `sts:ExternalId`; explicit `Deny` on `RetrieveAndGenerate` and `InvokeAgent` | `03-identity` | **Implemented** |
| `AIS-15` Prompt Differentiation | Every content block is a `guardContent` block; retrieved chunks structurally delimited in `<document>` elements and instructed as quoted material | `src/adapter/inference.mjs` | **Implemented** |

**Note on `AIS-15`.** Partial `guardContent` tagging is the hazard, not tagging.
Bedrock evaluates the whole message set only when no tagged blocks are present;
one tagged block narrows evaluation to tagged blocks alone. Tagging everything is
the implementation of this control, and a future change that tags selectively
would silently create an unevaluated channel.

### Data Security and Privacy

| Control | AWS implementation | Where | Status |
|---|---|---|---|
| `DSP-21` Data Poisoning Prevention | KB source bucket restricts writers by IAM principal, enforces TLS and SSE-KMS | `06-bedrock` | **Partial** — writers restricted, content unvalidated |
| `DSP-23` Data Integrity Check | Post-retrieval tenant assertion on every chunk; Zod schema validation on ledger writes; idempotent write via `ConditionExpression` | `src/adapter/inference.mjs`, `src/adapter/data.mjs` | **Implemented** |
| `DSP-24` Data Differentiation | Tenant metadata filter at retrieval; chunk delimiting; separate CMK per data class | `00-kms`, `06-bedrock`, `src/adapter/inference.mjs` | **Implemented** |
| `DSP-17` Data Deletion | Ledger TTL (30d content / 400d metadata); Aurora partition rotation; erasure receipts from Streams; `DataDeletionPolicy: RETAIN` on the KB data source | `04-data`, `06-bedrock`, `07-compute`, `sql/01-bootstrap.sql` | **Infrastructure only** — lifecycle function unwritten |

**Note on `DSP-21`.** This is the highest-yield remaining gap in the
architecture. Corpus content is the one injection route that arrives *inside* the
trust boundary — it bypasses `ApplyGuardrail` entirely and reaches a compute
identity holding `dynamodb:PutItem` and `s3:PutObject`.

**Note on `DSP-17`.** TTL deletion is asynchronous — items remain readable for up
to 48 hours past expiry. The adapter filters at read time so behaviour matches
policy, but this is a hygiene mechanism and should not be described as a
compliance-grade deletion guarantee.

### Logging and Monitoring

| Control | AWS implementation | Where | Status |
|---|---|---|---|
| `LOG-02` Audit Logs Protection | Object Lock compliance mode; bucket in the Log Archive account; explicit `Deny` on workload-account read, list, and every delete action | `20-log-archive` | **Implemented** |
| `LOG-03` Security Monitoring & Alerting | CloudWatch alarms on token anomaly bands, guardrail throttle, judge latency p95, authorizer errors; EventBridge to a Security-account SNS topic | `10-observability`, `24-security` | **Implemented** |
| `LOG-07` Logging Scope | Telemetry carries prompt hashes only; invocation logs (content) segregated to their own prefix with a single-role read restriction; WAF redacts `authorization` | `10-observability`, `11-log-delivery`, `20-log-archive` | **Implemented** |
| `LOG-09` Log Protection | `cmk/audit` in the Log Archive account excludes workload principals; `DenyKeyDestruction` on every principal; Firehose role holds `GenerateDataKey` without `Decrypt` | `20-log-archive`, `11-log-delivery` | **Implemented** |
| `LOG-13` Anomalies Reporting | Anomaly-detection bands on `InputTokenCount` / `OutputTokenCount`; Cost Anomaly Detection routed to the security bus | `10-observability` | **Implemented** |
| `LOG-16` Behavioral Drift Detection *(proposed)* | `GuardrailInterventionDropAlarm` — fires on an unexplained *drop* in intervention rate | `10-observability` | **Partial** — AICM structural gap; this is the nearest available signal |

**Note on `LOG-09`.** The `DenyKeyDestruction` statement is the one that makes
Object Lock meaningful. Without it an account administrator renders every archived
log unreadable without deleting a single object — the bytes are protected and the
ability to decrypt them is not.

**Note on `LOG-16`.** A weakened guardrail and a quieter attack environment look
identical in aggregate. The drop alarm is a lagging signal; separating the two
requires a fixed adversarial evaluation set (`MDS-06`), which is absent.

### Model Development and Supply Chain

| Control | AWS implementation | Where | Status |
|---|---|---|---|
| `MDS-06` Adversarial Attack Analysis | Pipeline gate declared, calling `scripts/guardrail-regression.mjs` | `ci/deploy.yml` | **Infrastructure only** — the script does not exist |
| `MDS-07` Model Hardening | — | — | **N/A** — managed model; hardening is the model provider's |
| `MDS-10` Model Continuous Monitoring | — | — | **Absent** — no per-decision model version recorded, no efficacy baseline |
| `STA-08` Supply Chain Inventory | — | — | **Absent** — 13 workload identities, no owner/intent/egress record |
| `STA-12` Supply Chain Compliance | Dependabot across npm, GitHub Actions, and IaC; `npm ci --ignore-scripts`; actions pinned to commit SHAs; Inspector before artifact promotion | `ci/dependabot.yml`, `ci/deploy.yml` | **Partial** — no SBOM produced |
| `STA-16` Service Bill of Material | — | — | **Absent** — same artifact as `STA-08`; build once |

**Note on `MDS-06`.** This is the control that would convert every *Implemented*
mark in this document into a *measured* one. Guardrail quality is currently
inferred from intervention rate, which moves with attack volume rather than with
control effectiveness.

### Threat and Vulnerability

| Control | AWS implementation | Where | Status |
|---|---|---|---|
| `TVM-11` Guardrails | Three independent enforcement layers: identity policy with paired explicit `Deny`, SCP `Null` check, endpoint policy restricting principal and inference profile | `03-identity`, `02-endpoints`, `23-scp`, `06-bedrock` | **Implemented** |
| `TVM-13` Threat Response | EventBridge rules → containment runbook: WAF blocked-identity set, reserved concurrency to zero, revocation write, Security Hub finding | `10-observability`, `24-security` | **Infrastructure only** — runbook functions unwritten |

**Note on `TVM-11`.** All three layers must be misconfigured before an unguarded
call lands. The guardrail is pinned to `identifier:version`, not a bare
identifier — a bare identifier lets a guardrail be weakened in place with no
deployment and no review, which is precisely the gap the condition exists to
close.

### Infrastructure and Change Control

| Control | AWS implementation | Where | Status |
|---|---|---|---|
| `I&S-06` Segmentation and Segregation | Five subnet tiers per AZ; compute has no `0.0.0.0/0`; egress proxy in its own tier reached by Lambda invoke, not routing; Network Firewall FQDN allow-list with `aws:drop_established` under `STRICT_ORDER` | `01-network` | **Implemented** |
| `CCC-04` Change Authorization | `CfnDeploymentRole` can start a stack operation and pass exactly one role, only to CloudFormation; `CfnServiceRole` assumable only by `cloudformation.amazonaws.com`; two-person production approval | `22b-deployment-roles`, `ci/deploy.yml` | **Implemented** |
| `CCC-07` Detection of Baseline Deviation | Scheduled drift detection raising a Security Hub finding; Config with conformance packs | `ci/deploy.yml`, `24-security` | **Partial** — infrastructure drift covered, model and detector drift not |
| `UEM-*` Endpoint Management | — | — | **N/A** — no managed endpoints; serverless compute only |

### Governance, Risk, Compliance

| Control | AWS implementation | Where | Status |
|---|---|---|---|
| `GRC-09` Acceptable Use of AI | — | — | **Absent** |
| `GRC-10` AI Impact Assessment | — | — | **Absent** |
| `GRC-11` Bias and Fairness | — | — | **Absent** |
| `GRC-12` Ethics Committee | — | — | **Absent** |
| `GRC-15` Human Supervision | Two-person production approval gate | `ci/deploy.yml` | **Partial** — deployment-time only; no runtime human authorization |

**Note.** These five are **AIC-owned regardless of deployment model.** Nothing in
the AWS migration shifts them to a platform provider, and no template can
implement them. They are documents.

`GRC-10` is the one to produce first, because it determines whether the others
attach — and it is currently unanswerable, since what consumes the model output
and whether any consequential decision follows from it is not stated anywhere.

---

## 2. FAIR-CAM function-class coverage

The same lens applied to the pilot, applied here. This is the comparison that
shows what the architecture actually changed.

| Function class | Pilot | AWS target | What moved it |
|---|---|---|---|
| LEC · Prevention · Avoidance | Partial | **Strong** | Data perimeter: `aws:PrincipalOrgID`, `aws:SourceVpce`, `aws:ResourceOrgID` applied across identity, resource, and endpoint policies |
| LEC · Prevention · Deterrence | Partial | **Strong** | Object Lock compliance mode with a defined retention period, in a segregated account |
| LEC · Prevention · Resistance | Strong | **Strong** | Guardrails, no default route, WAF at two scopes, Network Firewall, RLS |
| LEC · Detection · Visibility | Present | **Present** | Alarms, guardrail interventions as findings, cost anomalies on the security bus |
| LEC · Detection · Monitoring | Partial | **Partial** | GuardDuty, Config, Macie, Inspector — but GuardDuty reads no WAF logs and the compute tier generates little flow-log signal |
| LEC · Response · Event Termination | Present | **Infrastructure only** | Containment runbook defined; functions unwritten |
| LEC · Response · Loss Reduction | Absent | **Implemented** | Backup plan with cross-account copy, PITR, Vault Lock — new capability, no pilot equivalent |
| VMC · Prevention · Reduce Variance | Absent | **Absent** | No training, no acceptable-use policy |
| VMC · Identification · Monitoring | Absent | **Absent** | No access review, no component inventory, no periodic detector testing, no policy review |
| VMC · Correction · Implementation | Absent | **Partial** | Rotation infrastructure exists (function unwritten); revocation read path exists (writer unwritten); access pruning still absent |
| DSC · Prevention · Expectations | Absent | **Absent** | No AUP, no data classification policy |
| DSC · Prevention · Awareness | Partial | **Partial** | Threat model and governance assessment exist |
| DSC · Misaligned Decisions · Analysis | Partial | **Absent** | No equivalent of the pilot's Golden Set curation loop |

**The finding this table produces.** The migration substantially strengthens
**Loss Event Controls** — three classes move from Partial to Strong, and one
(Loss Reduction) appears for the first time. It moves **Variance Management
Controls** barely at all: one class from Absent to Partial, two unchanged.

That is the same asymmetry identified in the pilot, carried forward. The
architecture is better at preventing and detecting loss and no better at keeping
its own controls current. Access review, component inventory, periodic detector
testing, and policy review remain absent — and every one of them is a document or
a process, not a template.

**One regression worth naming.** DSC · Misaligned Decisions · Analysis was
*Partial* in the pilot via Golden Set curation — analyst-reviewed escapes fed
back into the detection corpus. The AWS architecture has no equivalent loop. The
corpus is a retrieval store rather than a detection-improvement mechanism, and
nothing routes a missed detection back into it.

---

## 3. Controls with no pilot counterpart

Capabilities the AWS architecture adds that the pilot control set had no row for.

| Capability | Implementation | Nearest control |
|---|---|---|
| **Data perimeter** | Three conditions applied consistently: trusted identity (`PrincipalOrgID`), trusted resource (`ResourceOrgID`), expected network (`SourceVpce`) | `I&S-06`, `IAM-16` |
| **Tenant isolation at four layers** | Scope → `LeadingKeys` → bound query parameter → RLS `FORCE` → retrieval filter with post-assertion | `IAM-16`, `DSP-24` |
| **Server-side tenant derivation** | V3_0 pre-token-generation trigger reads the entitlement table and ignores client metadata | `IAM-16` — closes the confused-deputy path |
| **Cost as a security control** | Three-tier circuit breaker; Cost Anomaly Detection routed to the security bus, not finance | `TVM-13` |
| **Cross-account recovery custody** | Vault Lock compliance mode; workload principals excluded from `cmk/backup` | `BCR-*` family |
| **Egress capability asymmetry** | Egress proxy holds `ApplyGuardrail` and an explicit `Deny` on every inference action | `AIS-11` |

**On the last row.** The proxy can guard a model call and not make one; the
adapter can make one and cannot reach the internet. Neither component alone can
send an unguarded payload outside the boundary. That property has no single
control ID and is the clearest structural improvement over the pilot.

---

## 4. ISO/IEC 42001 coverage

Eleven controls in §1 have **no ISO/IEC 42001 equivalent** — the entire `LOG-*`
family and the entire `MDS-*` family.

| Family | ISO 42001 position |
|---|---|
| `LOG-01` … `LOG-16` | No equivalent |
| `MDS-01` … `MDS-13` | No equivalent |
| `IAM-*` | Maps only to a generic alignment clause (A.2.3) |
| `GRC-*` | Well covered — A.9.4, B.5.3, B.5.4 |
| `DSP-*`, `STA-*` | Covered — A.4.3, A.7.4, A.10.3 |

**Practical consequence.** The layers this architecture depends on most heavily —
logging integrity and model-security discipline — are the least ISO-anchored. An
ISO 42001 certification would not attest the controls the design is actually
built on. **ISO 27001 and SOC 2 are the correct citations** for the logging and
access-control controls; the model-security controls have no certification
counterpart in any of the three and must be evidenced directly, which is the
practical argument for `MDS-06`.

---

## 5. Summary by status

| Status | Count | Where they cluster |
|---|---|---|
| Implemented | 20 | IAM, AIS, LOG, TVM, I&S — the layers with template representation |
| Partial | 7 | Split across output handling, corpus, supply chain, drift |
| Infrastructure only | 5 | Every one blocked on an unwritten function |
| Absent | 8 | GRC (four), registry (two), `MDS-10`, `IAM-18` |
| N/A | 2 | `MDS-07`, `UEM-*` |

**The eight absences are not evenly distributed.** Four are governance documents
that no template can produce. Two are the same registry artifact viewed from
different angles. `IAM-18` is the missing authorization control behind every
high-consequence operation. `MDS-10` is detector drift.

None of the eight is blocked on engineering. All eight are blocked on decisions
that have not been made — most immediately, what this system is for and who it
affects, which `GRC-10` exists to answer and which currently blocks the
output-handling control at `AIS-09` as well.

---

## 6. Sequenced remediation

| Priority | Action | Closes |
|---|---|---|
| P0 | Write the five missing functions: egress proxy, secrets rotation, lifecycle, pre-token-generation, containment runbook | Every *Infrastructure only* row |
| P0 | AI impact assessment; state what consumes the model output | `GRC-10`, and unblocks `AIS-09` |
| P1 | Corpus ingestion validation with provenance before indexing | `DSP-21` — highest-yield remaining gap |
| P1 | Adversarial regression corpus as a blocking pipeline gate | `MDS-06`, and converts the `LOG-16` lagging signal into a test |
| P1 | Component registry: owner, intent, egress, review date | `STA-08` + `STA-16`; unblocks the VMC Identification class |
| P2 | Out-of-band approval for guardrail change, corpus promotion, entitlement write | `IAM-18`, `GRC-15` runtime half |
| P2 | Record model identity and version per decision; establish an efficacy baseline | `MDS-10` |
| P2 | Quarterly entitlement and role certification, owner-attested | VMC Identification · Monitoring |
| P3 | Acceptable use policy, bias position, ethics review | `GRC-09`, `GRC-11`, `GRC-12` |

---

## References

| Document | Relationship |
|---|---|
| `docs/aws-secure-genai-workload-architecture.md` | The specification these controls implement |
| `docs/maestro-assessment-aws-genai-workload.md` | Threat model; source of the layer findings |
| `docs/governance.md` | Control-plane assessment; source of the domain status |
| `docs/appsec-audit.md` | Application layer; source of the `AIS-*` findings |
| `docs/request-flow-detailed.md` | Runtime view; §9 failure-mode table evidences the fail-closed claims |
| `infrastructure/README.md` | Per-layer design notes and deploy order |
