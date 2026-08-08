# Authorization Flow — Detailed Reference

**Scope:** how a caller obtains a token and how that token is validated on every
request. Covers both caller classes and the points where they diverge.

**Companion to** `request-flow-detailed.md`, which covers the whole request path.
This document expands the two steps that document treats as single lines: token
acquisition (outside the request path entirely) and authorizer validation.

---

## 1. Two transactions, separated in time

The most common source of confusion here is treating this as one flow. It is two,
and Cognito participates in only the first.

| | Transaction 1 — acquire | Transaction 2 — use |
|---|---|---|
| When | Before any API call | Every API call |
| Cognito contacted | **Yes** | **No** |
| Frequency | Once per token lifetime (15 min) | Every request, minus authorizer cache |
| Failure mode | Cannot obtain a token | Cannot use one |

The authorizer verifies signatures **offline** against public keys cached from a
one-time JWKS fetch. That is why `cognito-idp` matters as a VPC endpoint at cold
start and is irrelevant afterward, and why a Cognito outage breaks new token
issuance rather than in-flight requests.

On the machine path the separation is wide: a token is fetched once and cached
for its 15-minute life while hundreds of API calls happen with no visible
authentication step. Each of those calls still hits the authorizer.

---

## 2. Transaction 1 — acquiring a token

### 2.1 Human path — authorization code + PKCE, resource-bound

```
Browser                          Cognito                    Entitlement table
  │                                 │                                │
  │ 1. generate code_verifier       │                                │
  │    challenge = S256(verifier)   │                                │
  │                                 │                                │
  │ 2. GET /oauth2/authorize        │                                │
  │    response_type=code           │                                │
  │    client_id=<human>            │                                │
  │    resource=<API_RESOURCE>   ◄──┼── RFC 8707. Without this the   │
  │    scope=openid <API>/invoke    │   token has no aud and the     │
  │    code_challenge_method=S256   │   authorizer rejects it.       │
  │    code_challenge=<challenge>   │                                │
  │    redirect_uri=<exact>         │                                │
  │                                 │                                │
  │           ◄── managed login ────┤                                │
  │           ── credentials ──────►│                                │
  │                                 │  3. authenticate (SRP), MFA    │
  │                                 │                                │
  │ 4. 302 → redirect_uri?code=...  │                                │
  │                                 │                                │
  │ 5. POST /oauth2/token           │                                │
  │    grant_type=authorization_code│                                │
  │    code=<code>                  │                                │
  │    code_verifier=<verifier>  ◄──┼── proves same client instance  │
  │    redirect_uri=<exact>         │                                │
  │                                 │                                │
  │                                 │  6. verify S256(verifier)      │
  │                                 │     == stored challenge        │
  │                                 │                                │
  │                                 │  7. PreTokenGen V3_0 ─────────►│
  │                                 │     GetItem(clientId)          │
  │                                 │  ◄──── defaultTenant ──────────┤
  │                                 │     inject custom:tenant       │
  │                                 │                                │
  │ 8. ◄── access + id + refresh ───┤     aud = <API_RESOURCE>       │
```

**PKCE substitutes for a client secret.** A browser cannot hold one. The verifier
is generated per authorization attempt and never leaves the client until the
token exchange, so an intercepted authorization code is useless without it. This
also covers the CSRF role `state` would otherwise play.

**Only S256 is accepted.** Cognito's authorization server does not support the
`plain` method. That is the correct restriction — `plain` sends the verifier in
the authorization request, defeating the point.

**Resource binding is the new part.** Cognito validates that `resource` is a URL
following the same scheme rules as callback URLs, then sets it as the access
token's `aud` claim. A refresh grant carries the same `aud` forward. Available in
authorization-code and implicit grants from the Authorize endpoint only, on
Managed Login, on Essentials or Plus tier.

**Redirect URI matching is exact.** No wildcards, no prefix matching. This is
registered in `CallbackURLs` on the app client and is the primary defense against
authorization-code redirection.

### 2.2 Machine path — client credentials

```
MCP server                       Cognito                    Entitlement table
  │                                 │                                │
  │ 1. POST /oauth2/token           │                                │
  │    grant_type=client_credentials│                                │
  │    scope=llm/invoke             │                                │
  │    Authorization: Basic         │                                │
  │      base64(id:secret)          │                                │
  │                                 │                                │
  │                                 │  2. validate client secret     │
  │                                 │  3. check scopes against the   │
  │                                 │     app client's allowed set   │
  │                                 │                                │
  │                                 │  4. PreTokenGen V3_0 ─────────►│
  │                                 │     GetItem(clientId)          │
  │                                 │  ◄──── defaultTenant ──────────┤
  │                                 │     inject custom:tenant       │
  │                                 │     IGNORE aws_client_metadata │
  │                                 │                                │
  │ 5. ◄──── access token only ─────┤     NO aud claim               │
```

**No redirect, no user, no consent.** Under `client_credentials` there is no
resource owner. The client acts for itself, and the entire authorization decision
is "does this client hold the right secret and is it configured for this scope."

**No resource binding is possible.** Cognito does not permit a resource indicator
on a `client_credentials` grant. These tokens have no `aud` claim and cannot be
made to have one. Client binding is `client_id`, and this is a platform
constraint rather than a configuration choice.

**No ID token, no refresh token.** Only an access token, so the caller re-fetches
on expiry rather than refreshing.

### 2.3 The pre-token-generation trigger

The same trigger runs on both paths and is where tenant provenance is decided.

```javascript
// Runs inside Cognito's flow, before signing.
const clientId = event.callerContext?.clientId;   // ← authoritative
// event.request.clientMetadata is present on client_credentials
// requests and is DELIBERATELY NOT READ.
const { Item } = await ddb.send(new GetCommand({
  TableName: ENTITLEMENT_TABLE,
  Key: { clientId },
  ProjectionExpression: "defaultTenant",
  ConsistentRead: true,
}));
if (!Item?.defaultTenant) return event;  // no claim rather than a wrong one
```

**Why this matters more than it looks.** Cognito passes `aws_client_metadata`
from the token request straight through to this trigger. A tenant read from that
metadata is a value the *caller* chose. Deriving it from an entitlement lookup
keyed on `clientId` makes the claim a fact; reading client metadata would make it
an assertion — and an assertion validated only for membership in a known tenant
set is the confused-deputy pattern, where every credential is valid, the
authorization decision is wrong, and the audit trail faithfully records the
attacker's claim.

**Version matters.** V3_0 is the only trigger version that fires for
`client_credentials`, and it requires the Essentials or Plus feature plan. On LITE
or on V2_0 the trigger silently never fires for machine callers: no tenant claim
appears, every machine request is denied by the authorizer, and nothing in any
log points at the cause.

**Returning `event` unmodified is the failure mode.** No claim is added, so the
authorizer's entitlement lookup finds no tenant and denies. Fail-closed by
omission.

---

## 3. Transaction 2 — validating a token

Runs in the isolated compute subnet, VPC-attached so its DynamoDB lookups carry
`aws:SourceVpce`.

### 3.1 Order of checks

Each denies. None upgrades. The order is deliberate.

```
 1. Route in scope map?              → no: throw Unauthorized (401)
 2. Bearer header present?           → no: throw Unauthorized (401)
 3. Signature + standard claims      → fail: throw Unauthorized (401)
 4. Revocation denylist              → hit: Deny policy
 5. Audience, per caller class       → mismatch: Deny policy
 6. Scope for this method            → miss: Deny policy
 7. Tenant entitlement               → not entitled: Deny policy
 8. Build Allow(single method ARN)
```

**Why revocation precedes scope and entitlement.** A revoked token should not
reach a log line describing what it asked for. The entitlement lookup is also a
DynamoDB read that a revoked caller should not be able to force.

**Why the route check precedes everything.** An unmapped route is unauthorized
regardless of how valid the token is, and checking it first avoids parsing
attacker-supplied input for a route that does not exist.

### 3.2 Signature and standard claims

```javascript
try {
  claims = await machineVerifier.verify(token);   // tried first: higher volume
  callerClass = "machine";
} catch {
  try {
    claims = await humanVerifier.verify(token);
    callerClass = "human";
  } catch {
    throw new Error("Unauthorized");
  }
}
```

| Check | Enforced by | Value |
|---|---|---|
| `alg` | Library, Cognito verifier | RS256 only; `none` and HMAC rejected |
| Signature | JWKS from the **configured** issuer | Never read `iss` from the presented token |
| `kid` | JWKS lookup | `jku` / `x5u` / `jwk` headers ignored |
| `iss` | Verifier | Derived from `userPoolId` |
| `exp` / `nbf` | Verifier | `graceSeconds: 30` |
| `token_use` | Verifier | `access` — both verifiers |
| Client binding | Verifier | `client_id` ∈ permitted list |
| `aud` | Verifier (human only) | `API_RESOURCE` |

**The JWKS resolution point is the one that matters most.** `aws-jwt-verify`
derives the issuer from `userPoolId` and fetches keys from there. It never reads
`iss` out of the token being verified. That distinction is the difference between
key pinning and signature forgery, and it is the single most common failure in
hand-rolled JWT verification.

**No ID-token path exists.** Every route requires a scope; ID tokens carry none;
an ID-token verifier could never succeed. A fallback that cannot succeed is worse
than absent — it reads as though ID tokens are accepted somewhere.

**Failure reasons are not disclosed.** Distinguishing "expired" from "wrong
client" from "bad signature" is an oracle. The caller gets 401.

### 3.3 Revocation

Two consistent reads:

```
GetItem  pk = JTI#<origin_jti>     → one token family
GetItem  pk = SUB#<sub>            → every token for a caller
```

**Fails closed.** An unreachable store gives an unknown answer, and "unknown" for
*is this credential revoked* is not a yes. A missing `origin_jti` is treated the
same way — Cognito emits it on all current access tokens, so absence means an
unexpected token shape.

**`ConsistentRead: true` on both.** An eventually-consistent read can return a
stale miss for a token revoked seconds ago, which is precisely the window that
matters.

**Why this exists.** JWTs are stateless: a valid signature says nothing about
whether the token was revoked after issuance. Cognito's `RevokeToken` invalidates
tokens sharing an `origin_jti` and is invisible to offline verification. This is
the bridge.

### 3.4 Audience — where the paths diverge

```javascript
if (callerClass === "human" && claims.aud !== API_RESOURCE) return deny;
if (callerClass === "machine" && claims.aud)                return deny;
```

The human verifier already enforces `audience`. The explicit check repeats it and
adds its inverse.

**The second line is the load-bearing one.** A machine-path token carrying an
audience was not issued by the grant this path expects. Without that check, a
future change that moves a client between paths — or a token type introduced
later — passes silently with the wrong validation rule applied.

| | Human | Machine |
|---|---|---|
| `aud` | Required, equals `API_RESOURCE` | **Must be absent** |
| Set by | RFC 8707 `resource` parameter | n/a |
| Client binding | `client_id` **and** `aud` | `client_id` only |
| Rationale | Token proves intent to call *this* API | Platform cannot issue `aud` here |

**What resource binding buys.** It stops a token minted for one resource working
at another. On the human path a token issued for a different API — even by the
same user pool, even for the same user — now fails here. That is the confused-
deputy mitigation RFC 8707 exists for, and it is available on one of the two
paths.

### 3.5 Scope

```javascript
const SCOPE_BY_ROUTE = {
  "POST /v1/inference": ["llm/invoke",  `${API_RESOURCE}/invoke`],
  "POST /v1/retrieve":  ["llm/retrieve", `${API_RESOURCE}/retrieve`],
};
```

Two accepted forms per route. A resource-bound human token carries scopes
prefixed with the resource identifier; a machine token carries the bare `llm/*`
form. Either satisfies the route.

**This is not a weakening.** The binding is enforced by the `aud` check in §3.4,
not by the scope string. Accepting both forms keeps the scope check about *what
the caller may do* and leaves *which API the token is for* to the audience —
which is the correct separation of the two concerns.

### 3.6 Tenant entitlement

```
GetItem  clientId → { defaultTenant, allowedTenants }
```

| Token's `custom:tenant` | Result |
|---|---|
| Absent | `defaultTenant`, `delegated: false` |
| Equals `defaultTenant` | `defaultTenant`, `delegated: false` |
| In `allowedTenants` | requested value, `delegated: true` |
| Anything else | **Deny** |

**Checked here even though the trigger already derived it.** A claim minted at
issuance is just a claim by the time it reaches the API — it has travelled
through the caller's hands. The trigger and the authorizer are separately
compromisable, and the entitlement table is the authoritative record in both
cases.

**Membership is not authorization.** The check is "may this `clientId` act for
this tenant," not "does this tenant exist." That distinction is the whole
control.

### 3.7 The returned policy

```javascript
{
  principalId: sub,
  policyDocument: {
    Statement: [{ Action: "execute-api:Invoke",
                  Effect: "Allow",
                  Resource: methodArn }]   // ← ONE ARN. Never a wildcard.
  },
  context: { sub, clientId, tenantId, callerClass,
             scopes, delegated, originJti, audience }
}
```

**The single method ARN is half of the cache fix.** API Gateway caches the
returned policy against the authorizer's identity sources. Those are declared as
`Authorization` + `httpMethod` + `resourcePath`, so the key is per-method — but a
wildcard resource in the cached policy would still authorize every route from the
second request onward, with no error and no visible symptom.

Both halves are required: per-method cache key **and** never returning a
wildcard. Either alone leaves the hole.

**Context is populated by API Gateway and cannot be influenced by the caller.**
It is the only sanctioned identity source downstream. Handlers read
`$context.authorizer.*`; they must never read identity from a request header.

All values must be strings — API Gateway silently drops non-string context
entries, which fails as a missing tenant rather than as an error.

---

## 4. The authorizer cache

| Property | Value |
|---|---|
| Key | `Authorization` + `httpMethod` + `resourcePath` |
| TTL | `AuthorizerCacheSeconds`, must stay below token lifetime |
| Effect on revocation | A revoked token remains accepted for up to the TTL |

**The revocation interaction.** Revocation is checked in the authorizer, so a
cached Allow bypasses it. Three surfaces at three latencies exist for that
reason:

| Surface | Latency | Cached? |
|---|---|---|
| WAF blocked-identity set | Immediate | **No** |
| Revocation denylist | Up to one cache TTL | Behind the cache |
| Token expiry | ≤15 minutes | n/a |

For urgent containment, the WAF layer is the one to use. The denylist is the
precise one — it can target a single token family via `originJti` — but it takes
effect on the next uncached evaluation.

---

## 5. Failure modes

| Stage | Failure | Response | Notes |
|---|---|---|---|
| Authorize | Missing `resource` param (human) | Token issues **successfully** | Fails later at §3.4 — the confusing one |
| Authorize | Redirect URI mismatch | Cognito error page | Exact match required |
| Token | PKCE verifier mismatch | `invalid_grant` | |
| Token | Trigger returns no tenant | Token issues without `custom:tenant` | Fails later at §3.6 |
| Token | Wrong feature plan / trigger version | Token issues without `custom:tenant` | Machine path only; no log points at it |
| Authorizer | Unmapped route | 401 | Before token parse |
| Authorizer | Any signature/claim defect | 401 | Reason not disclosed |
| Authorizer | Revoked, or store unreachable | Deny | Fails closed |
| Authorizer | Wrong or missing `aud` (human) | Deny | |
| Authorizer | Unexpected `aud` (machine) | Deny | |
| Authorizer | Insufficient scope | Deny | |
| Authorizer | Tenant not entitled | Deny | |

**Three of these fail late.** A missing `resource` parameter, a trigger that
returns no tenant, and a wrong feature plan all produce a *successful* token
issuance and a denial one hop later. That is fail-closed and correct, but it
means the error surfaces at the API rather than at login — worth knowing before
debugging the wrong component.

---

## 6. What this design does not do

- **No sender-constrained tokens.** Bearer possession is sufficient. Cognito does not support DPoP; closing this requires mTLS at CloudFront or a different IdP.
- **No end-user identity on the machine path.** `sub` is the app client ID. Where an MCP server serves multiple end users, no verified human identity reaches this system — the tenant claim gives per-tenant attribution, which is coarser than per-user.
- **No consent screen.** Cognito has no scope-approval UI for its own app clients and no user-grant object to revoke. This matters if the API is ever exposed to third-party clients acting for users.
- **No dynamic client registration.** Every client is provisioned, which is what makes the entitlement lookup possible. This is a deliberate trade against MCP-ecosystem compatibility.
- **`aud` on the machine path.** Not a gap that can be closed at this layer — Cognito cannot issue it on `client_credentials`.

---

## 7. Implementation index

| Element | Where |
|---|---|
| User pool, app clients, resource servers, trigger | `infrastructure/05-cognito.yaml` |
| Entitlement and revocation tables | `infrastructure/04-data.yaml` |
| Authorizer role, entitlement read, write deny | `infrastructure/03-identity.yaml` |
| Authorizer function, environment, VPC config | `infrastructure/07-compute.yaml` |
| REQUEST authorizer, identity sources, cache TTL | `infrastructure/08-api.yaml` |
| `cognito-idp` endpoint for JWKS | `infrastructure/02-endpoints.yaml` |
| Validation logic | `src/authorizer/index.mjs` |
| Context consumption | `src/adapter/security.mjs` — `requestContext` |
